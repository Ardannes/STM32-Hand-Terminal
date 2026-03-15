/**
 * @file sniffer_tools.h
 * @brief Packet Sniffer — WiFi Promiscuous Mode ile Ağ Trafiği Analizi
 *
 * Özellikler:
 *   - WiFi promiscuous mode ile raw 802.11 frame yakalama
 *   - IPv4 / TCP / UDP / ICMP / ARP protokol parse
 *   - HTTP header sniffing (method, host, path, auth)
 *   - DNS query/response parse
 *   - Passive OS fingerprinting (TTL + TCP Window)
 *   - TCP Flow tracking (bidirectional)
 *   - Top Talkers (en çok trafik yapan IP'ler)
 *   - Alert Engine (ARP spoof, SYN scan, port scan, NULL/XMAS scan,
 *                   ICMP flood, DNS tunnel, telnet, HTTP cred leak)
 *   - UART üzerinden STM32'ye parsed data gönderimi
 */

#ifndef SNIFFER_TOOLS_H
#define SNIFFER_TOOLS_H

#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <Arduino.h>
#include <cstdint>
#include <cstring>

// ════════════════════════════════════════════════════════════════
//  SABİTLER
// ════════════════════════════════════════════════════════════════

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

// TCP flag bitleri
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// Sniffer yapılandırma
#define SNIFFER_CHANNEL_HOP_INTERVAL_MS 2000
#define SNIFFER_MAX_CHANNELS 13
#define SNIFFER_RING_SIZE 32

// ════════════════════════════════════════════════════════════════
//  FILTRE TİPLERİ
// ════════════════════════════════════════════════════════════════

enum SnifferFilter : uint8_t {
  SFILT_ALL = 0,
  SFILT_TCP,
  SFILT_UDP,
  SFILT_ICMP,
  SFILT_ARP,
  SFILT_HTTP,
  SFILT_DNS,
  SFILT_ALERT,
  SFILT_COUNT
};

const char *snifferFilterName(SnifferFilter f);

// ════════════════════════════════════════════════════════════════
//  PARSED YAPILAR
// ════════════════════════════════════════════════════════════════

// ── IPv4 ────────────────────────────────────────────────────────
struct IPv4Info {
  uint8_t ihl;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t totalLen;
  char srcIp[16];
  char dstIp[16];
  const uint8_t *payload;
  uint16_t payloadLen;
  bool valid;
};

// ── TCP ─────────────────────────────────────────────────────────
struct TCPInfo {
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seq;
  uint32_t ack;
  uint8_t flags;
  uint16_t window;
  const uint8_t *payload;
  uint16_t payloadLen;
  bool valid;
};

// ── UDP ─────────────────────────────────────────────────────────
struct UDPInfo {
  uint16_t srcPort;
  uint16_t dstPort;
  uint16_t length;
  const uint8_t *payload;
  uint16_t payloadLen;
  bool valid;
};

// ── ICMP ────────────────────────────────────────────────────────
struct ICMPInfo {
  uint8_t type;
  uint8_t code;
  char typeStr[20];
  bool valid;
};

// ── ARP ─────────────────────────────────────────────────────────
struct ARPInfo {
  uint16_t opcode;
  char opStr[8]; // "REQUEST" / "REPLY"
  char senderMac[18];
  char senderIp[16];
  char targetMac[18];
  char targetIp[16];
  bool valid;
};

// ── HTTP ────────────────────────────────────────────────────────
struct HTTPSniff {
  char method[8];
  char path[64];
  char host[48];
  char authorization[64];
  bool isResponse;
  char statusCode[4];
  bool valid;
};

// ── DNS ─────────────────────────────────────────────────────────
struct DNSSniff {
  uint16_t txId;
  bool isQuery;
  char domain[64];
  char qtype[8];
  uint16_t answers;
  bool valid;
};

// ── Ana paket bilgisi (UI'a gönderilecek) ───────────────────────
struct SnifferPacket {
  uint32_t timestamp;
  char proto[8];
  char srcIp[16];
  char dstIp[16];
  uint16_t srcPort;
  uint16_t dstPort;
  char srcSvc[12]; // port servis adı
  char dstSvc[12];
  char flags[24]; // "SYN|ACK"
  uint8_t ttl;
  uint16_t window;
  char osGuess[24];
  char info[128];
  char payloadHex[64];
  uint16_t rawLen;
  char srcMac[18];
  char dstMac[18];

  // Alert
  bool hasAlert;
  char alertMsg[80];

  void clear();
};

// ════════════════════════════════════════════════════════════════
//  PARSER FONKSİYONLARI
// ════════════════════════════════════════════════════════════════

IPv4Info parseIPv4(const uint8_t *data, uint16_t len);
TCPInfo parseTCP(const uint8_t *data, uint16_t len);
UDPInfo parseUDP(const uint8_t *data, uint16_t len);
ICMPInfo parseICMP(const uint8_t *data, uint16_t len);
ARPInfo parseARP(const uint8_t *data, uint16_t len);
HTTPSniff sniffHTTP(const uint8_t *data, uint16_t len);
DNSSniff sniffDNS(const uint8_t *data, uint16_t len);

// ── Yardımcılar ─────────────────────────────────────────────────
void formatIP(char *buf, const uint8_t *b);
void formatMAC(char *buf, const uint8_t *b);
const char *portName(uint16_t port);
void formatFlags(char *buf, uint8_t flags);
void hexPreview(char *buf, const uint8_t *data, uint16_t len,
                uint8_t maxBytes = 16);
const char *osFingerprint(uint8_t ttl, uint16_t window);
const char *icmpTypeName(uint8_t type);

// ════════════════════════════════════════════════════════════════
//  ALERT ENGINE
// ════════════════════════════════════════════════════════════════

enum AlertLevel : uint8_t {
  ALRT_NONE = 0,
  ALRT_LOW,
  ALRT_MEDIUM,
  ALRT_HIGH,
  ALRT_CRITICAL
};

const char *alertLevelStr(AlertLevel lvl);

struct AlertEntry {
  uint32_t timestamp;
  AlertLevel level;
  char message[80];
};

class AlertEngine {
public:
  static const uint8_t MAX_ALERTS = 64;

  AlertEngine();
  bool check(const SnifferPacket &pkt, char *outMsg, size_t outLen);
  uint16_t alertCount() const { return _count; }
  const AlertEntry *getAlerts(uint8_t &outN, uint8_t maxN = 10) const;
  void reset();

private:
  AlertEntry _ring[MAX_ALERTS];
  uint16_t _count;
  uint8_t _head;

  // ARP tablosu
  struct {
    char ip[16];
    char mac[18];
  } _arpTable[32];
  uint8_t _arpN;

  // SYN sayaçları
  struct {
    char ip[16];
    uint16_t count;
  } _synTable[32];
  uint8_t _synN;

  // Port scan
  struct {
    char ip[16];
    uint16_t ports[16];
    uint8_t n;
  } _portTable[16];
  uint8_t _portN;

  // ICMP flood
  struct {
    char ip[16];
    uint16_t count;
    uint32_t windowMs;
  } _icmpTable[16];
  uint8_t _icmpN;

  void _emit(AlertLevel lvl, const char *msg);
  int _findARP(const char *ip) const;
  int _findSyn(const char *ip) const;
  int _findPort(const char *ip) const;
  int _findICMP(const char *ip) const;
};

// ════════════════════════════════════════════════════════════════
//  FLOW TRACKER
// ════════════════════════════════════════════════════════════════

enum FlowState : uint8_t {
  FLOW_NEW = 0,
  FLOW_SYN,
  FLOW_SYN_ACK,
  FLOW_ESTABLISHED,
  FLOW_CLOSING,
  FLOW_RESET
};

const char *flowStateStr(FlowState s);

struct FlowEntry {
  char srcIp[16];
  uint16_t srcPort;
  char dstIp[16];
  uint16_t dstPort;
  FlowState state;
  uint32_t packets;
  uint32_t bytes;
  uint32_t startMs;
  bool active;
};

class FlowTracker {
public:
  static const uint8_t MAX_FLOWS = 48;

  FlowTracker();
  FlowEntry *update(const char *srcIp, uint16_t srcPort, const char *dstIp,
                    uint16_t dstPort, uint8_t flags, uint16_t pktLen);
  uint8_t activeCount() const;
  uint8_t topFlows(FlowEntry *out, uint8_t maxN = 5) const;
  void reset();

private:
  FlowEntry _flows[MAX_FLOWS];
  int _find(const char *a, uint16_t pa, const char *b, uint16_t pb) const;
  int _alloc();
};

// ════════════════════════════════════════════════════════════════
//  TOP TALKERS
// ════════════════════════════════════════════════════════════════

struct TalkerEntry {
  char ip[16];
  uint32_t txBytes;
  uint32_t rxBytes;
  uint32_t packets;
  bool active;
};

struct TalkerSummary {
  char ip[16];
  uint32_t packets;
  uint32_t totalBytes;
};

class TopTalkers {
public:
  static const uint8_t MAX_TALKERS = 32;

  TopTalkers();
  void update(const char *srcIp, const char *dstIp, uint16_t pktLen);
  uint8_t summary(TalkerSummary *out, uint8_t maxN = 5) const;
  void reset();

private:
  TalkerEntry _entries[MAX_TALKERS];
  int _find(const char *ip) const;
  int _alloc();
};

// ════════════════════════════════════════════════════════════════
//  SNIFFER İSTATİSTİKLERİ
// ════════════════════════════════════════════════════════════════

struct SnifferStats {
  uint32_t total;
  uint32_t tcp;
  uint32_t udp;
  uint32_t icmp;
  uint32_t arp;
  uint32_t http;
  uint32_t dns;
  uint32_t other;
  uint8_t activeFlows;
  uint16_t alertCount;
  uint8_t currentFilter;
};

// ════════════════════════════════════════════════════════════════
//  ANA SNIFFER API (MF_Terminal_ESP32.ino için)
// ════════════════════════════════════════════════════════════════

/**
 * Sniffer'ı başlatır — WiFi promiscuous mode + channel hopping
 */
void snifferStart();

/**
 * Sniffer'ı durdurur — WiFi normal moda döner
 */
void snifferStop();

/**
 * loop() içinde çağrılır — yeni paket varsa parse edip UART'a gönderir
 * @return true = paket işlendi, false = paket yok
 */
bool snifferLoop();

/**
 * Filtreyi değiştirir (döngüsel: ALL→TCP→UDP→...→ALERT→ALL)
 */
void snifferNextFilter();

/**
 * Belirli bir filtre indeksine set eder
 */
void snifferSetFilter(uint8_t idx);

/**
 * Mevcut istatistikleri döner
 */
SnifferStats snifferGetStats();

/**
 * STM32'den gelen sniffer komutlarını işler
 * Komutlar: CMD:SNIFFER_FILTER, CMD:SNIFFER_STATS
 */
void snifferHandleCommand(const String &cmd);

#endif // SNIFFER_TOOLS_H
