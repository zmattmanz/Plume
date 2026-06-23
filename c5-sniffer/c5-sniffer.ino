// ════════════════════════════════════════════════════════════════════════════
// Plume C5 — 5 GHz surveillance sniffer (co-processor for Plume / Cardputer ADV)
//
// Flash this to a Waveshare ESP32-C5-WIFI6-KIT (or any ESP32-C5 dev board). It
// is the 5 GHz "radio ear" the Cardputer's ESP32-S3 can't be: it sniffs 5 GHz
// Wi-Fi management frames, runs the SAME Flock signatures Plume uses on 2.4 GHz,
// and reports each hit as one line over UART. Plume reads those lines on its
// Grove port and folds them into its normal detection pipeline.
//
// Passive only: receive-only promiscuous mode. It never transmits, associates,
// or interacts with any device. No screen, no SD, no BLE, no GPS (GPS lives on
// the Cardputer's hat).
//
// ── Wiring (C5 -> Cardputer Grove) ─────────────────────────────────────────
//   C5 TXD  -> Grove yellow (G2 / S3 RX)        <- the detection stream
//   C5 RXD  <- Grove white  (G1 / S3 TX)        <- optional, unused for now
//   C5 5V   <- Grove red    (or power the C5 from its own USB-C / battery)
//   C5 GND  <- Grove black
//
// ── Build settings (Arduino IDE) ────────────────────────────────────────────
//   Board:            "ESP32C5 Dev Module"  (needs Arduino-ESP32 core >= 3.1.x;
//                     esp_wifi_set_band_mode / WIFI_BAND_MODE_5G_ONLY require it)
//   USB CDC On Boot:  Enabled   <-- REQUIRED. Puts the debug console on USB-C so
//                     UART0 (the TXD/RXD pads) is free for the Cardputer link.
//   Upload/flash over the USB-C port (native USB-Serial/JTAG, the COM5 you saw).
//
// ── Wire protocol (must match Plume's c5_link.h) ──  PROTOCOL_VERSION 1
//   D|mac|name|rssi|ch|conf|methods     a detection
//   H|plume-c5|<ver>                    hello / heartbeat (lights Plume's 5G badge)
//   example:  D|aa:bb:cc:dd:ee:ff|flock-1a2b|-67|149|85|ssid_fmt
// ════════════════════════════════════════════════════════════════════════════

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <string.h>
#include <ctype.h>

struct RawEvent;   // fwd-decl: lets Arduino's auto-generated prototypes resolve
                   // (sig_seed_defaults sits above the full struct definition,
                   //  which shifts the IDE's prototype-insertion point upward)

// ── Protocol / link ─────────────────────────────────────────────────────────
#define PROTOCOL_VERSION   1
#define LINK_BAUD          115200       // must match Plume's C5_BAUD
#define HEARTBEAT_MS       3000         // H|... cadence (Plume's badge times out at 8 s)
#define LinkSerial         Serial0      // UART0 = the C5's TXD/RXD pads -> Cardputer
#define DbgSerial          Serial       // USB CDC on the USB-C port (debug only)

// ── Scoring — MUST MATCH Plume (FlockDetection_Cardputer_ADV.ino) ────────────
#define SCORE_DEFINITIVE   100
#define SCORE_STRONG       60
#define SCORE_WEAK         25
#define SCORE_BONUS_RSSI   10
#define ALARM_THRESHOLD    75           // = CONFIDENCE_ALARM_THRESHOLD in Plume
#define IGNORE_WEAK_RSSI   -80

// ── 5 GHz channels (non-DFS only) ────────────────────────────────────────────
// UNII-1 (36-48) + UNII-3 (149-165). DFS channels 52-144 are intentionally
// omitted: the C5 cannot detect radar, so it must not dwell on DFS channels.
static const uint8_t kChannels[] = { 36, 40, 44, 48, 149, 153, 157, 161, 165 };
static const int     kNumChannels   = sizeof(kChannels) / sizeof(kChannels[0]);
#define CHANNEL_DWELL_MS   300          // per-channel listen time before hopping

// ── Ambient 5 GHz feed ────────────────────────────────────────────────────────
// One F| line per AMBIENT_COMMIT_MS containing the strongest not-recently-seen
// sub-threshold candidate observed since the last commit.  A separate dedup ring
// (shorter cooldown than g_dedup) rotates through different MACs so the S3 feed
// shows variety rather than repeating the loudest AP every window.
#define AMBIENT_COMMIT_MS          1200   // one F| per ~1.2 s
#define AMBIENT_DEDUP_SIZE           16   // slots in the ambient-seen ring
#define AMBIENT_DEDUP_COOLDOWN_MS  15000  // exclude a MAC for 15 s after sending it

// ── Signatures — MUST MATCH Plume ────────────────────────────────────────────
static const char* kSsidPatterns[] = {
    "FS Ext Battery", "Penguin", "Pigvision", "FlockOS",
    "flocksafety", "OFS_IoT", "PFS_"
};
static const int kNumSsidPatterns = sizeof(kSsidPatterns) / sizeof(kSsidPatterns[0]);

static const char* kMacTier1[] = {           // high-confidence Flock OUIs
    "b4:1e:52", "e4:aa:ea", "00:09:01",
    "4c:6e:44", "d8:a0:d8", "a0:b7:65", "f0:82:c0", "b4:e3:f9", "04:0d:84"
};
static const int kNumMacTier1 = sizeof(kMacTier1) / sizeof(kMacTier1[0]);

static const char* kMacTier2[] = {           // component-vendor OUIs (weaker)
    "74:4c:a1", "94:34:69", "38:5b:44", "94:08:53", "1c:34:f1", "a4:cf:12",
    "3c:91:80", "80:30:49", "14:5a:fc", "9c:2f:9d", "c8:c9:a3", "70:c9:4e",
    "24:b2:b9", "00:f4:8d", "08:3a:88", "d8:f3:bc", "ec:1b:bd", "58:8e:81",
    "90:35:ea", "b8:35:32", "c0:35:32", "f4:6a:dd", "f8:a2:d6", "e8:d0:fc",
    "e0:4f:43", "b8:1e:a4", "70:08:94", "3c:71:bf", "58:00:e3", "5c:93:a2",
    "64:6e:69", "48:27:ea", "82:6b:f2", "d0:39:57", "e0:0a:f6", "e8:2a:44",
    "30:d1:6b", "b8:ee:65", "a4:db:30", "40:f0:2f", "30:52:cb", "94:97:4f"
};
static const int kNumMacTier2 = sizeof(kMacTier2) / sizeof(kMacTier2[0]);

// ── Runtime signature tables — seeded from the compile-time defaults above,
//    optionally overwritten by a batch pushed from the S3 over the link. ──
#define RT_OUI_MAX     72
#define RT_SSID_MAX    32
#define OUI_PREFIX_LEN 9      // "xx:xx:xx" + NUL
#define SSID_PAT_LEN   33

struct OuiRT { char prefix[OUI_PREFIX_LEN]; uint8_t tier; };  // tier 1=strong, 2=weak
static OuiRT g_oui[RT_OUI_MAX];                 static int g_oui_count  = 0;
static char  g_ssid[RT_SSID_MAX][SSID_PAT_LEN]; static int g_ssid_count = 0;

static void sig_seed_defaults() {
    g_oui_count = 0;
    for (int i = 0; i < kNumMacTier1 && g_oui_count < RT_OUI_MAX; i++) {
        strlcpy(g_oui[g_oui_count].prefix, kMacTier1[i], OUI_PREFIX_LEN);
        g_oui[g_oui_count].tier = 1; g_oui_count++;
    }
    for (int i = 0; i < kNumMacTier2 && g_oui_count < RT_OUI_MAX; i++) {
        strlcpy(g_oui[g_oui_count].prefix, kMacTier2[i], OUI_PREFIX_LEN);
        g_oui[g_oui_count].tier = 2; g_oui_count++;
    }
    g_ssid_count = 0;
    for (int i = 0; i < kNumSsidPatterns && g_ssid_count < RT_SSID_MAX; i++) {
        strlcpy(g_ssid[g_ssid_count], kSsidPatterns[i], SSID_PAT_LEN);
        g_ssid_count++;
    }
}

// ── 802.11 management frame header (24 bytes) ────────────────────────────────
typedef struct {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];   // receiver / destination
    uint8_t  addr2[6];   // transmitter
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} __attribute__((packed)) mac_hdr_t;

// ── Raw-event ring buffer ────────────────────────────────────────────────────
// The promiscuous callback runs in the Wi-Fi driver task; keep it fast. It only
// copies metadata + a frame-body snapshot here. All parsing/scoring/sending is
// deferred to loop() (same pattern Plume uses with process_wifi_event_queue).
struct RawEvent {
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    int8_t   rssi;
    uint8_t  channel;
    bool     is_beacon;
    bool     is_probe_req;
    uint8_t  body[128];     // frame body (fixed params + tagged params)
    uint16_t body_len;
    volatile bool ready;
};
#define EVENT_QUEUE_SIZE 16
static RawEvent          g_queue[EVENT_QUEUE_SIZE];
static volatile uint32_t g_write_idx = 0;
static uint32_t          g_read_idx  = 0;

// ── Dedup table — suppress repeats of the same device within a cooldown ──────
#define DEDUP_SIZE        48
#define DEDUP_COOLDOWN_MS 30000     // re-report a given MAC at most every 30 s
struct DedupEntry { uint8_t mac[6]; uint32_t last_ms; bool used; };
static DedupEntry g_dedup[DEDUP_SIZE];

// Ambient-feed dedup: tracks MACs recently forwarded as F| so the pending-
// candidate stage selects a different (not-recently-seen) MAC each window.
struct AmbDedup { uint8_t mac[6]; uint32_t last_ms; bool used; };
static AmbDedup   g_amb_dedup[AMBIENT_DEDUP_SIZE];

// Single pending slot: strongest eligible candidate observed since last commit.
static struct {
    uint8_t mac[6];
    char    name[33];
    int8_t  rssi;
    uint8_t channel;
    bool    valid;
} g_feed_pending;

// ───────────────────────────── matching (uses runtime tables) ───────────────
static int mac_prefix_tier(const uint8_t* mac) {   // 1=tier1, 2=tier2, 0=none
    char s[9];
    snprintf(s, sizeof(s), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    for (int i = 0; i < g_oui_count; i++)
        if (strncmp(s, g_oui[i].prefix, 8) == 0) return g_oui[i].tier;
    return 0;
}
static bool ssid_pattern_match(const char* ssid) {
    if (!ssid || ssid[0] == '\0') return false;
    for (int i = 0; i < g_ssid_count; i++)
        if (strcasestr(ssid, g_ssid[i])) return true;
    return false;
}
static bool is_flock_ssid_format(const char* ssid) {
    if (!ssid) return false;
    if (strncmp(ssid, "Flock-", 6) != 0 && strncmp(ssid, "flock-", 6) != 0) return false;
    const char* sfx = ssid + 6;
    int n = (int)strlen(sfx);
    if (n < 2 || n > 12) return false;
    for (int i = 0; i < n; i++) if (!isxdigit((unsigned char)sfx[i])) return false;
    return true;
}

// Pull the SSID out of a mgmt frame body. Beacons carry 12 fixed bytes
// (timestamp+interval+caps) before the tagged params; probe requests carry
// none. SSID is element id 0.
static void extract_ssid(const uint8_t* body, uint16_t len, bool is_beacon,
                         char* out, size_t out_sz) {
    out[0] = '\0';
    uint16_t off = is_beacon ? 12 : 0;
    while (off + 2 <= len) {
        uint8_t id = body[off];
        uint8_t ln = body[off + 1];
        if (off + 2 + ln > len) break;
        if (id == 0) {                               // SSID element
            uint8_t copy = (ln < out_sz - 1) ? ln : (uint8_t)(out_sz - 1);
            memcpy(out, &body[off + 2], copy);
            out[copy] = '\0';
            return;
        }
        off += 2 + ln;
    }
}

// ───────────────────────────── sniffer callback ─────────────────────────────
static void sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    if (pkt->rx_ctrl.sig_len < sizeof(mac_hdr_t)) return;

    const mac_hdr_t* hdr = (const mac_hdr_t*)pkt->payload;
    uint8_t ftype = (hdr->frame_ctrl & 0x0C) >> 2;
    uint8_t fsub  = (hdr->frame_ctrl & 0xF0) >> 4;
    if (ftype != 0) return;                          // management frames only
    bool is_beacon    = (fsub == 8);
    bool is_probe_req = (fsub == 4);
    if (!is_beacon && !is_probe_req) return;

    uint32_t idx = g_write_idx % EVENT_QUEUE_SIZE;
    if (g_queue[idx].ready) return;                  // queue full — drop

    RawEvent* e = &g_queue[idx];
    memcpy(e->addr1, hdr->addr1, 6);
    memcpy(e->addr2, hdr->addr2, 6);
    e->rssi         = pkt->rx_ctrl.rssi;
    e->channel      = pkt->rx_ctrl.channel;
    e->is_beacon    = is_beacon;
    e->is_probe_req = is_probe_req;

    uint16_t body_len = (pkt->rx_ctrl.sig_len > sizeof(mac_hdr_t))
                      ? (uint16_t)(pkt->rx_ctrl.sig_len - sizeof(mac_hdr_t)) : 0;
    if (body_len > sizeof(e->body)) body_len = sizeof(e->body);
    memcpy(e->body, pkt->payload + sizeof(mac_hdr_t), body_len);
    e->body_len = body_len;

    e->ready = true;
    g_write_idx++;
}

// ───────────────────────────── scoring (mirrors Plume) ──────────────────────
// Fills methods[] and returns confidence 0-100. report_mac receives the MAC to
// report (normally the transmitter, but addr1 for a sleeping-device hit).
static int score_event(const RawEvent* e, const char* ssid,
                       char* methods, size_t msz, uint8_t report_mac[6]) {
    methods[0] = '\0';
    memcpy(report_mac, e->addr2, 6);

    bool ssid_present = (ssid[0] != '\0');
    bool is_random    = (e->addr2[0] & 0x02) != 0;       // locally-administered MAC
    int  mac_score    = is_random ? 0 : mac_prefix_tier(e->addr2);
    bool ssid_generic = ssid_present && ssid_pattern_match(ssid);
    bool ssid_fmt     = ssid_present && is_flock_ssid_format(ssid);
    int  conf         = 0;

    // CVE-2025-59409 hardcoded probe SSID — definitive, Flock-only.
    if (e->is_probe_req && ssid_present && strcmp(ssid, "test_flck") == 0) {
        conf = SCORE_DEFINITIVE; strlcat(methods, "test_flck_cve ", msz);
    }

    if (ssid_fmt) {
        conf = SCORE_DEFINITIVE; strlcat(methods, "ssid_fmt ", msz);
    } else if (mac_score == 1) {
        conf = SCORE_STRONG; strlcat(methods, "mac_t1 ", msz);
        if (ssid_generic) { conf = SCORE_DEFINITIVE; strlcat(methods, "ssid ", msz); }
    } else {
        if (mac_score == 2) { conf += SCORE_WEAK; strlcat(methods, "mac_t2 ", msz); }
        if (ssid_generic)   { conf += SCORE_WEAK; strlcat(methods, "ssid ", msz); }
    }

    // Wildcard probe (empty SSID) from a known OUI.
    if (e->is_probe_req && mac_score > 0 && !ssid_present) {
        if (mac_score == 1) { conf = SCORE_DEFINITIVE; strlcat(methods, "wildcard_probe ", msz); }
        else                { conf = SCORE_STRONG;     strlcat(methods, "wildcard_probe_t2 ", msz); }
    }

    if (conf > 0 && e->rssi > -50) conf += SCORE_BONUS_RSSI;

    // Sleeping-device addr1 (receiver) OUI check.
    bool a1_mc  = (e->addr1[0] & 0x01);
    bool a1_rnd = (e->addr1[0] & 0x02);
    bool a1_bc  = (e->addr1[0] == 0xFF && e->addr1[1] == 0xFF);
    if (!a1_mc && !a1_rnd && !a1_bc) {
        int a1 = mac_prefix_tier(e->addr1);
        if (a1 > 0 && mac_score == 0) {
            if (a1 == 1) { conf = SCORE_STRONG; strlcat(methods, "addr1_t1 ", msz); }
            else         { conf += SCORE_WEAK;  strlcat(methods, "addr1_t2 ", msz); }
            memcpy(report_mac, e->addr1, 6);             // key off the device MAC
        }
    }

    if (conf > 100) conf = 100;
    int ml = (int)strlen(methods);
    if (ml > 0 && methods[ml - 1] == ' ') methods[ml - 1] = '\0';
    return conf;
}

// ───────────────────────────── dedup ────────────────────────────────────────
// True if this MAC should be reported now (first sight, or cooldown elapsed).
static bool should_report(const uint8_t* mac) {
    uint32_t now = millis();
    int  free_slot = -1, oldest = 0;
    uint32_t oldest_ms = 0xFFFFFFFFUL;
    for (int i = 0; i < DEDUP_SIZE; i++) {
        if (g_dedup[i].used && memcmp(g_dedup[i].mac, mac, 6) == 0) {
            if (now - g_dedup[i].last_ms < DEDUP_COOLDOWN_MS) return false;
            g_dedup[i].last_ms = now;
            return true;
        }
        if (!g_dedup[i].used && free_slot < 0) free_slot = i;
        if (g_dedup[i].used && g_dedup[i].last_ms < oldest_ms) {
            oldest_ms = g_dedup[i].last_ms; oldest = i;
        }
    }
    int slot = (free_slot >= 0) ? free_slot : oldest;    // evict oldest if full
    memcpy(g_dedup[slot].mac, mac, 6);
    g_dedup[slot].last_ms = now;
    g_dedup[slot].used    = true;
    return true;
}

// ───────────────────────────── ambient-feed dedup helpers ───────────────────
static bool ambient_recently_sent(const uint8_t* mac) {
    uint32_t now = millis();
    for (int i = 0; i < AMBIENT_DEDUP_SIZE; i++)
        if (g_amb_dedup[i].used && memcmp(g_amb_dedup[i].mac, mac, 6) == 0)
            return (now - g_amb_dedup[i].last_ms < AMBIENT_DEDUP_COOLDOWN_MS);
    return false;
}
static void ambient_mark_sent(const uint8_t* mac) {
    uint32_t now = millis();
    int free_slot = -1, oldest = 0; uint32_t oldest_ms = 0xFFFFFFFFUL;
    for (int i = 0; i < AMBIENT_DEDUP_SIZE; i++) {
        if (g_amb_dedup[i].used && memcmp(g_amb_dedup[i].mac, mac, 6) == 0)
            { g_amb_dedup[i].last_ms = now; return; }
        if (!g_amb_dedup[i].used && free_slot < 0) free_slot = i;
        if (g_amb_dedup[i].used && g_amb_dedup[i].last_ms < oldest_ms)
            { oldest_ms = g_amb_dedup[i].last_ms; oldest = i; }
    }
    int slot = (free_slot >= 0) ? free_slot : oldest;
    memcpy(g_amb_dedup[slot].mac, mac, 6);
    g_amb_dedup[slot].last_ms = now;
    g_amb_dedup[slot].used    = true;
}

// ───────────────────────────── reporting ────────────────────────────────────
static void send_detection(const uint8_t* mac, const char* name, int rssi,
                           int ch, int conf, const char* methods) {
    char safe[33];
    strlcpy(safe, (name && name[0]) ? name : "Hidden", sizeof(safe));
    for (char* p = safe; *p; p++)
        if (*p == '|' || *p == '\n' || *p == '\r') *p = '_';

    uint32_t ep = c5_now_epoch();                 // 0 until first T| sync
    char line[200];
    snprintf(line, sizeof(line),
             "D|%02x:%02x:%02x:%02x:%02x:%02x|%s|%d|%d|%d|%s|%lu",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             safe, rssi, ch, conf, methods, (unsigned long)ep);
    LinkSerial.println(line);

    if (ep > 0) {
        uint32_t s = ep % 86400UL;
        DbgSerial.printf("[HIT %02u:%02u:%02u] %s\n",
                         (unsigned)(s/3600), (unsigned)((s/60)%60), (unsigned)(s%60), line);
    } else {
        DbgSerial.printf("[HIT] %s\n", line);
    }
}

// ───────────────────────────── channel hopping ──────────────────────────────
static int      g_ch_idx   = 0;
static uint32_t g_last_hop = 0;
static void hop_channel() {
    g_ch_idx = (g_ch_idx + 1) % kNumChannels;
    esp_wifi_set_channel(kChannels[g_ch_idx], WIFI_SECOND_CHAN_NONE);
}

// ── Inbound link (S3 -> C5): time sync + signature push ──────────────────────
static uint32_t g_epoch_base    = 0;   // UTC epoch at last sync (0 = unsynced)
static uint32_t g_epoch_base_ms = 0;   // millis() at the moment of that sync
static uint32_t c5_now_epoch() {
    if (g_epoch_base == 0) return 0;
    return g_epoch_base + (millis() - g_epoch_base_ms) / 1000UL;
}

// Signature-sync staging — accumulate a batch, commit atomically on SE.
static OuiRT g_oui_stage[RT_OUI_MAX];                 static int g_oui_stage_n  = 0;
static char  g_ssid_stage[RT_SSID_MAX][SSID_PAT_LEN]; static int g_ssid_stage_n = 0;
static bool  g_sig_syncing = false;

// Channel dwell-on-hit
#define DWELL_ON_HIT_MS 2500
static uint32_t g_channel_lock_until = 0;

static int link_split(char* buf, char* fields[], int max_fields) {
    int n = 0; fields[n++] = buf;
    for (char* p = buf; *p && n < max_fields; p++)
        if (*p == '|') { *p = '\0'; fields[n++] = p + 1; }
    return n;
}

static void link_handle_line(char* line) {
    int len = (int)strlen(line);
    while (len > 0 && (line[len-1] == '\r' || line[len-1] == '\n')) line[--len] = '\0';
    if (len == 0) return;

    char* f[4];
    int nf = link_split(line, f, 4);
    if (nf < 1) return;

    // T|<epoch>
    if (strcmp(f[0], "T") == 0 && nf >= 2) {
        uint32_t ep = (uint32_t)strtoul(f[1], NULL, 10);
        if (ep > 1500000000UL) { g_epoch_base = ep; g_epoch_base_ms = millis(); }
        return;
    }
    // SB  — begin batch (reset staging)
    if (strcmp(f[0], "SB") == 0) { g_oui_stage_n = 0; g_ssid_stage_n = 0; g_sig_syncing = true; return; }
    // SO|<prefix>|<tier>
    if (strcmp(f[0], "SO") == 0 && nf >= 3 && g_sig_syncing) {
        if (g_oui_stage_n < RT_OUI_MAX) {
            strlcpy(g_oui_stage[g_oui_stage_n].prefix, f[1], OUI_PREFIX_LEN);
            g_oui_stage[g_oui_stage_n].tier = (uint8_t)atoi(f[2]);
            g_oui_stage_n++;
        }
        return;
    }
    // SS|<pattern>   (patterns may contain spaces; never pipes)
    if (strcmp(f[0], "SS") == 0 && nf >= 2 && g_sig_syncing) {
        if (g_ssid_stage_n < RT_SSID_MAX) { strlcpy(g_ssid_stage[g_ssid_stage_n], f[1], SSID_PAT_LEN); g_ssid_stage_n++; }
        return;
    }
    // SE|<oui_count>|<ssid_count>  — commit only if counts match
    if (strcmp(f[0], "SE") == 0 && g_sig_syncing) {
        g_sig_syncing = false;
        int want_oui  = (nf >= 2) ? atoi(f[1]) : g_oui_stage_n;
        int want_ssid = (nf >= 3) ? atoi(f[2]) : g_ssid_stage_n;
        if (g_oui_stage_n == want_oui && g_ssid_stage_n == want_ssid && g_oui_stage_n > 0) {
            memcpy(g_oui, g_oui_stage, sizeof(OuiRT) * g_oui_stage_n);
            g_oui_count = g_oui_stage_n;
            for (int i = 0; i < g_ssid_stage_n; i++) memcpy(g_ssid[i], g_ssid_stage[i], SSID_PAT_LEN);
            g_ssid_count = g_ssid_stage_n;
            DbgSerial.printf("[C5] signatures synced: OUI=%d SSID=%d\n", g_oui_count, g_ssid_count);
        } else {
            DbgSerial.printf("[C5] sig sync mismatch (oui %d/%d ssid %d/%d) — kept previous\n",
                             g_oui_stage_n, want_oui, g_ssid_stage_n, want_ssid);
        }
        return;
    }
}

static char    g_in_buf[96];
static uint8_t g_in_len = 0;
static void process_link_inbound() {
    while (LinkSerial.available() > 0) {
        char c = (char)LinkSerial.read();
        if (c == '\n')                              { g_in_buf[g_in_len] = '\0'; link_handle_line(g_in_buf); g_in_len = 0; }
        else if (g_in_len < sizeof(g_in_buf) - 1)   { g_in_buf[g_in_len++] = c; }
        else                                        { g_in_len = 0; }   // overlong — resync on next NL
    }
}

// ───────────────────────────── setup / loop ─────────────────────────────────
void setup() {
    DbgSerial.begin(115200);
    LinkSerial.setRxBufferSize(2048);                    // headroom for a full sig batch
    LinkSerial.begin(LINK_BAUD, SERIAL_8N1);
    delay(300);

    sig_seed_defaults();                                 // tables live before first sync
    LinkSerial.printf("H|plume-c5|%d\n", PROTOCOL_VERSION);  // announce immediately
    DbgSerial.println("\n[C5] Plume 5GHz sniffer booting...");

    WiFi.mode(WIFI_MODE_STA);                            // brings up the Wi-Fi stack
    esp_wifi_set_ps(WIFI_PS_NONE);

    // Force the single radio onto 5 GHz (the C5 can't do both bands at once).
    esp_err_t berr = esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY);
    DbgSerial.printf("[C5] set_band_mode(5G_ONLY): %s\n", esp_err_to_name(berr));

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_channel(kChannels[0], WIFI_SECOND_CHAN_NONE);

    DbgSerial.println("[C5] sniffing 5 GHz; reporting over UART0 (TXD).");
}

void loop() {
    uint32_t now = millis();

    process_link_inbound();                              // T| and SB/SO/SS/SE from S3

    if (now >= g_channel_lock_until && now - g_last_hop >= CHANNEL_DWELL_MS) {
        hop_channel(); g_last_hop = now;
    }

    static uint32_t last_hb = 0;
    if (now - last_hb >= HEARTBEAT_MS) { last_hb = now; LinkSerial.printf("H|plume-c5|%d\n", PROTOCOL_VERSION); }

    while (g_queue[g_read_idx % EVENT_QUEUE_SIZE].ready) {
        RawEvent* e = &g_queue[g_read_idx % EVENT_QUEUE_SIZE];
        if (e->rssi >= IGNORE_WEAK_RSSI) {
            char ssid[33];
            extract_ssid(e->body, e->body_len, e->is_beacon, ssid, sizeof(ssid));
            char methods[64]; uint8_t report_mac[6];
            int conf = score_event(e, ssid, methods, sizeof(methods), report_mac);
            if (conf >= ALARM_THRESHOLD) {
                g_channel_lock_until = millis() + DWELL_ON_HIT_MS;
                if (should_report(report_mac)) {
                    const char* name = (ssid[0] != '\0') ? ssid : "Hidden";
                    send_detection(report_mac, name, e->rssi, e->channel, conf, methods);
                }
            } else if (!ambient_recently_sent(e->addr2)) {
                // Stage as ambient candidate if stronger than current pending.
                // Keyed on addr2 (transmitter) regardless of report_mac — we
                // want the visible device, not a sleeping addr1 hit, in the feed.
                if (!g_feed_pending.valid || e->rssi > g_feed_pending.rssi) {
                    memcpy(g_feed_pending.mac, e->addr2, 6);
                    strlcpy(g_feed_pending.name, ssid, sizeof(g_feed_pending.name));
                    g_feed_pending.rssi    = (int8_t)e->rssi;
                    g_feed_pending.channel = e->channel;
                    g_feed_pending.valid   = true;
                }
            }
        }
        e->ready = false;
        g_read_idx++;
    }

    // Commit one ambient candidate per interval as F|mac|name|rssi|ch.
    // Clears the pending slot so the next window starts fresh.
    static uint32_t last_feed_push = 0;
    if (now - last_feed_push >= AMBIENT_COMMIT_MS && g_feed_pending.valid) {
        last_feed_push = now;
        char safe[33];
        strlcpy(safe, g_feed_pending.name[0] ? g_feed_pending.name : "Hidden", sizeof(safe));
        for (char* p = safe; *p; p++)
            if (*p == '|' || *p == '\n' || *p == '\r') *p = '_';
        LinkSerial.printf("F|%02x:%02x:%02x:%02x:%02x:%02x|%s|%d|%d\n",
                          g_feed_pending.mac[0], g_feed_pending.mac[1],
                          g_feed_pending.mac[2], g_feed_pending.mac[3],
                          g_feed_pending.mac[4], g_feed_pending.mac[5],
                          safe, (int)g_feed_pending.rssi, (int)g_feed_pending.channel);
        ambient_mark_sent(g_feed_pending.mac);
        g_feed_pending.valid = false;
    }
}
