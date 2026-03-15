/**
 * @file sniffer_tools.cpp
 * @brief Packet Sniffer — Tam implementasyon
 *
 * WiFi promiscuous mode, protokol parse, alert engine,
 * flow tracker, top talkers ve UART iletişim.
 */

#include "sniffer_tools.h"
#include "globals.h"
#include <WiFi.h>

// ════════════════════════════════════════════════════════════════
//  GLOBAL SNIFFER DEĞİŞKENLERİ
// ════════════════════════════════════════════════════════════════

static AlertEngine _alertEng;
static FlowTracker _flowTrack;
static TopTalkers _topTalk;

static SnifferStats _stats;
static SnifferFilter _currentFilter = SFILT_ALL;

// Ring buffer — promiscuous callback'ten loop()'a aktarım
static volatile uint8_t _ringBuf[SNIFFER_RING_SIZE][512];
static volatile uint16_t _ringLen[SNIFFER_RING_SIZE];
static volatile uint8_t _ringHead = 0;
static volatile uint8_t _ringTail = 0;

static bool _snifferRunning = false;
static uint8_t _currentChannel = 1;
static unsigned long _lastChannelHop = 0;

// ════════════════════════════════════════════════════════════════
//  FİLTRE İSİMLERİ
// ════════════════════════════════════════════════════════════════

static const char *_filterNames[] = {"ALL", "TCP",  "UDP", "ICMP",
                                     "ARP", "HTTP", "DNS", "ALERT"};

const char *snifferFilterName(SnifferFilter f) {
  if (f < SFILT_COUNT)
    return _filterNames[f];
  return "?";
}

// ════════════════════════════════════════════════════════════════
//  PORT İSİMLERİ TABLOSU
// ════════════════════════════════════════════════════════════════

struct PortEntry {
  uint16_t port;
  const char *name;
};

static const PortEntry _portTable[] = {
    {21, "FTP"},        {22, "SSH"},         {23, "TELNET"}, {25, "SMTP"},
    {53, "DNS"},        {67, "DHCP"},        {80, "HTTP"},   {110, "POP3"},
    {143, "IMAP"},      {161, "SNMP"},       {443, "HTTPS"}, {445, "SMB"},
    {389, "LDAP"},      {636, "LDAPS"},      {993, "IMAPS"}, {995, "POP3S"},
    {1433, "MSSQL"},    {3306, "MySQL"},     {3389, "RDP"},  {5432, "PgSQL"},
    {8080, "HTTP-ALT"}, {8443, "HTTPS-ALT"}, {0, nullptr}};

const char *portName(uint16_t port) {
  for (int i = 0; _portTable[i].name != nullptr; i++) {
    if (_portTable[i].port == port)
      return _portTable[i].name;
  }
  return nullptr; // bilinmiyor
}

// ════════════════════════════════════════════════════════════════
//  OS FINGERPRINT TABLOSU
// ════════════════════════════════════════════════════════════════

struct OSEntry {
  uint8_t ttlMin;
  uint8_t ttlMax;
  uint16_t winMin;
  uint16_t winMax;
  const char *os;
};

static const OSEntry _osTable[] = {
    {1, 64, 5840, 5840, "Linux 2.4/2.6"},
    {1, 64, 65535, 65535, "Linux 3.x/4.x"},
    {1, 64, 29200, 29200, "Linux 5.x"},
    {65, 128, 8192, 8192, "Windows XP"},
    {65, 128, 65535, 65535, "Windows Vista/7"},
    {65, 128, 64240, 64240, "Windows 10/11"},
    {65, 128, 8760, 8760, "Windows Server"},
    {129, 255, 65535, 65535, "Cisco IOS/Solaris"},
    {1, 64, 65534, 65535, "macOS/FreeBSD"},
    {65, 128, 65534, 65535, "Windows(generic)"},
    {0, 0, 0, 0, nullptr}};

const char *osFingerprint(uint8_t ttl, uint16_t window) {
  for (int i = 0; _osTable[i].os != nullptr; i++) {
    if (ttl >= _osTable[i].ttlMin && ttl <= _osTable[i].ttlMax &&
        window >= _osTable[i].winMin && window <= _osTable[i].winMax) {
      return _osTable[i].os;
    }
  }
  if (ttl <= 64)
    return "Linux/Unix(TTL~64)";
  if (ttl <= 128)
    return "Windows(TTL~128)";
  return "Unknown";
}

// ════════════════════════════════════════════════════════════════
//  ICMP TİP İSİMLERİ
// ════════════════════════════════════════════════════════════════

const char *icmpTypeName(uint8_t type) {
  switch (type) {
  case 0:
    return "ECHO_REPLY";
  case 3:
    return "UNREACHABLE";
  case 5:
    return "REDIRECT";
  case 8:
    return "ECHO_REQ";
  case 11:
    return "TTL_EXCEEDED";
  case 30:
    return "TRACEROUTE";
  default:
    return "ICMP";
  }
}

// ════════════════════════════════════════════════════════════════
//  YARDIMCI FORMAT FONKSİYONLARI
// ════════════════════════════════════════════════════════════════

void formatIP(char *buf, const uint8_t *b) {
  sprintf(buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

void formatMAC(char *buf, const uint8_t *b) {
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4],
          b[5]);
}

void formatFlags(char *buf, uint8_t flags) {
  buf[0] = '\0';
  bool first = true;
  struct {
    uint8_t bit;
    const char *name;
  } flagMap[] = {{TCP_FIN, "FIN"}, {TCP_SYN, "SYN"}, {TCP_RST, "RST"},
                 {TCP_PSH, "PSH"}, {TCP_ACK, "ACK"}, {TCP_URG, "URG"},
                 {0, nullptr}};
  for (int i = 0; flagMap[i].name; i++) {
    if (flags & flagMap[i].bit) {
      if (!first)
        strcat(buf, "|");
      strcat(buf, flagMap[i].name);
      first = false;
    }
  }
  if (buf[0] == '\0')
    strcpy(buf, "-");
}

void hexPreview(char *buf, const uint8_t *data, uint16_t len,
                uint8_t maxBytes) {
  uint8_t n = (len < maxBytes) ? len : maxBytes;
  char *p = buf;
  for (uint8_t i = 0; i < n; i++) {
    sprintf(p, "%02X ", data[i]);
    p += 3;
  }
  if (n > 0) {
    *(p - 1) = ' ';
    *p++ = '|';
    *p++ = ' ';
    for (uint8_t i = 0; i < n; i++) {
      *p++ = (data[i] >= 32 && data[i] < 127) ? (char)data[i] : '.';
    }
  }
  *p = '\0';
}

// ════════════════════════════════════════════════════════════════
//  SnifferPacket::clear()
// ════════════════════════════════════════════════════════════════

void SnifferPacket::clear() { memset(this, 0, sizeof(SnifferPacket)); }

// ════════════════════════════════════════════════════════════════
//  PROTOKOL PARSERLERİ
// ════════════════════════════════════════════════════════════════

IPv4Info parseIPv4(const uint8_t *data, uint16_t len) {
  IPv4Info r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 20)
    return r;
  if ((data[0] >> 4) != 4)
    return r; // IPv4 check

  r.ihl = (data[0] & 0x0F) * 4;
  r.ttl = data[8];
  r.protocol = data[9];
  r.totalLen = (data[2] << 8) | data[3];
  formatIP(r.srcIp, &data[12]);
  formatIP(r.dstIp, &data[16]);

  if (r.ihl <= len) {
    r.payload = data + r.ihl;
    r.payloadLen = len - r.ihl;
  } else {
    r.payload = nullptr;
    r.payloadLen = 0;
  }
  r.valid = true;
  return r;
}

TCPInfo parseTCP(const uint8_t *data, uint16_t len) {
  TCPInfo r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 20)
    return r;

  uint8_t dataOff = (data[12] >> 4) * 4;
  r.srcPort = (data[0] << 8) | data[1];
  r.dstPort = (data[2] << 8) | data[3];
  r.seq = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
          ((uint32_t)data[6] << 8) | data[7];
  r.ack = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
          ((uint32_t)data[10] << 8) | data[11];
  r.flags = data[13];
  r.window = (data[14] << 8) | data[15];

  if (dataOff <= len) {
    r.payload = data + dataOff;
    r.payloadLen = len - dataOff;
  } else {
    r.payload = nullptr;
    r.payloadLen = 0;
  }
  r.valid = true;
  return r;
}

UDPInfo parseUDP(const uint8_t *data, uint16_t len) {
  UDPInfo r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 8)
    return r;

  r.srcPort = (data[0] << 8) | data[1];
  r.dstPort = (data[2] << 8) | data[3];
  r.length = (data[4] << 8) | data[5];
  r.payload = data + 8;
  r.payloadLen = len - 8;
  r.valid = true;
  return r;
}

ICMPInfo parseICMP(const uint8_t *data, uint16_t len) {
  ICMPInfo r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 4)
    return r;

  r.type = data[0];
  r.code = data[1];
  strncpy(r.typeStr, icmpTypeName(r.type), sizeof(r.typeStr) - 1);
  r.valid = true;
  return r;
}

ARPInfo parseARP(const uint8_t *data, uint16_t len) {
  ARPInfo r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 28)
    return r;

  r.opcode = (data[6] << 8) | data[7];
  strcpy(r.opStr, r.opcode == 1 ? "REQUEST" : "REPLY");
  formatMAC(r.senderMac, &data[8]);
  formatIP(r.senderIp, &data[14]);
  formatMAC(r.targetMac, &data[18]);
  formatIP(r.targetIp, &data[24]);
  r.valid = true;
  return r;
}

HTTPSniff sniffHTTP(const uint8_t *data, uint16_t len) {
  HTTPSniff r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 10)
    return r;

  // Null-terminate kopyala (güvenli)
  char text[512];
  uint16_t copyLen = (len < sizeof(text) - 1) ? len : sizeof(text) - 1;
  memcpy(text, data, copyLen);
  text[copyLen] = '\0';

  // HTTP methods check
  const char *methods[] = {"GET",   "POST", "PUT",     "DELETE",
                           "PATCH", "HEAD", "OPTIONS", nullptr};

  // İstek satırı: GET /path HTTP/1.1
  char *firstLine = strtok(text, "\r\n");
  if (!firstLine)
    return r;

  // Response check
  if (strncmp(firstLine, "HTTP/", 5) == 0) {
    r.isResponse = true;
    char *sp = strchr(firstLine, ' ');
    if (sp)
      strncpy(r.statusCode, sp + 1, 3);
    r.valid = true;
  } else {
    for (int i = 0; methods[i]; i++) {
      size_t mLen = strlen(methods[i]);
      if (strncmp(firstLine, methods[i], mLen) == 0 && firstLine[mLen] == ' ') {
        strncpy(r.method, methods[i], sizeof(r.method) - 1);
        char *pathStart = firstLine + mLen + 1;
        char *pathEnd = strchr(pathStart, ' ');
        if (pathEnd) {
          size_t pLen = pathEnd - pathStart;
          if (pLen >= sizeof(r.path))
            pLen = sizeof(r.path) - 1;
          strncpy(r.path, pathStart, pLen);
        }
        r.valid = true;
        break;
      }
    }
  }

  // Header'ları parse et — ancak strtok text'i bozduğu için tekrar kopyala
  char text2[512];
  copyLen = (len < sizeof(text2) - 1) ? len : sizeof(text2) - 1;
  memcpy(text2, data, copyLen);
  text2[copyLen] = '\0';

  char *line = strtok(text2, "\r\n");
  line = strtok(nullptr, "\r\n"); // ilk satırı atla
  while (line) {
    if (line[0] == '\0')
      break; // boş satır = body başlangıcı
    char *colon = strchr(line, ':');
    if (colon) {
      *colon = '\0';
      char *val = colon + 1;
      while (*val == ' ')
        val++;

      if (strcasecmp(line, "Host") == 0) {
        strncpy(r.host, val, sizeof(r.host) - 1);
      } else if (strcasecmp(line, "Authorization") == 0) {
        strncpy(r.authorization, val, sizeof(r.authorization) - 1);
      }
    }
    line = strtok(nullptr, "\r\n");
  }

  return r;
}

DNSSniff sniffDNS(const uint8_t *data, uint16_t len) {
  DNSSniff r;
  memset(&r, 0, sizeof(r));
  r.valid = false;

  if (len < 12)
    return r;

  r.txId = (data[0] << 8) | data[1];
  uint16_t flags = (data[2] << 8) | data[3];
  r.isQuery = !(flags & 0x8000);
  r.answers = (data[6] << 8) | data[7];

  // QNAME parse
  uint16_t offset = 12;
  char *dp = r.domain;
  char *dEnd = r.domain + sizeof(r.domain) - 1;
  bool first = true;

  while (offset < len) {
    uint8_t labelLen = data[offset];
    if (labelLen == 0) {
      offset++;
      break;
    }
    if (labelLen >= 0xC0) {
      offset += 2;
      break;
    } // pointer
    offset++;
    if (!first && dp < dEnd)
      *dp++ = '.';
    first = false;
    for (uint8_t i = 0; i < labelLen && offset < len && dp < dEnd; i++) {
      *dp++ = (char)data[offset++];
    }
  }
  *dp = '\0';

  // QTYPE
  if (offset + 4 <= len) {
    uint16_t qtype = (data[offset] << 8) | data[offset + 1];
    switch (qtype) {
    case 1:
      strcpy(r.qtype, "A");
      break;
    case 2:
      strcpy(r.qtype, "NS");
      break;
    case 5:
      strcpy(r.qtype, "CNAME");
      break;
    case 15:
      strcpy(r.qtype, "MX");
      break;
    case 28:
      strcpy(r.qtype, "AAAA");
      break;
    case 255:
      strcpy(r.qtype, "ANY");
      break;
    default:
      snprintf(r.qtype, sizeof(r.qtype), "%u", qtype);
      break;
    }
  }

  r.valid = true;
  return r;
}

// ════════════════════════════════════════════════════════════════
//  ALERT ENGINE İMPLEMENTASYONU
// ════════════════════════════════════════════════════════════════

const char *alertLevelStr(AlertLevel lvl) {
  switch (lvl) {
  case ALRT_LOW:
    return "LOW";
  case ALRT_MEDIUM:
    return "MEDIUM";
  case ALRT_HIGH:
    return "HIGH";
  case ALRT_CRITICAL:
    return "CRITICAL";
  default:
    return "NONE";
  }
}

AlertEngine::AlertEngine() { reset(); }

void AlertEngine::reset() {
  _count = 0;
  _head = 0;
  _arpN = 0;
  _synN = 0;
  _portN = 0;
  _icmpN = 0;
  memset(_ring, 0, sizeof(_ring));
  memset(_arpTable, 0, sizeof(_arpTable));
  memset(_synTable, 0, sizeof(_synTable));
  memset(_portTable, 0, sizeof(_portTable));
  memset(_icmpTable, 0, sizeof(_icmpTable));
}

void AlertEngine::_emit(AlertLevel lvl, const char *msg) {
  AlertEntry &e = _ring[_head % MAX_ALERTS];
  e.timestamp = millis();
  e.level = lvl;
  strncpy(e.message, msg, sizeof(e.message) - 1);
  e.message[sizeof(e.message) - 1] = '\0';
  _head = (_head + 1) % MAX_ALERTS;
  _count++;
}

int AlertEngine::_findARP(const char *ip) const {
  for (uint8_t i = 0; i < _arpN; i++)
    if (strcmp(_arpTable[i].ip, ip) == 0)
      return i;
  return -1;
}

int AlertEngine::_findSyn(const char *ip) const {
  for (uint8_t i = 0; i < _synN; i++)
    if (strcmp(_synTable[i].ip, ip) == 0)
      return i;
  return -1;
}

int AlertEngine::_findPort(const char *ip) const {
  for (uint8_t i = 0; i < _portN; i++)
    if (strcmp(_portTable[i].ip, ip) == 0)
      return i;
  return -1;
}

int AlertEngine::_findICMP(const char *ip) const {
  for (uint8_t i = 0; i < _icmpN; i++)
    if (strcmp(_icmpTable[i].ip, ip) == 0)
      return i;
  return -1;
}

bool AlertEngine::check(const SnifferPacket &pkt, char *outMsg, size_t outLen) {
  char msg[80];

  // ── ARP Spoofing ────────────────────────────────────────
  if (strcmp(pkt.proto, "ARP") == 0 && pkt.srcIp[0] != '\0') {
    int idx = _findARP(pkt.srcIp);
    if (idx >= 0) {
      if (strcmp(_arpTable[idx].mac, pkt.srcMac) != 0) {
        snprintf(msg, sizeof(msg), "ARP Spoof! %s MAC changed", pkt.srcIp);
        _emit(ALRT_CRITICAL, msg);
        strncpy(outMsg, msg, outLen - 1);
        return true;
      }
    } else if (_arpN < 32) {
      strncpy(_arpTable[_arpN].ip, pkt.srcIp, 15);
      strncpy(_arpTable[_arpN].mac, pkt.srcMac, 17);
      _arpN++;
    }
  }

  // ── SYN Scan ────────────────────────────────────────────
  if (strcmp(pkt.proto, "TCP") == 0 && strstr(pkt.flags, "SYN") &&
      !strstr(pkt.flags, "ACK")) {
    int idx = _findSyn(pkt.srcIp);
    if (idx >= 0) {
      _synTable[idx].count++;
      if (_synTable[idx].count == 16) {
        snprintf(msg, sizeof(msg), "SYN Scan from %s", pkt.srcIp);
        _emit(ALRT_HIGH, msg);
        strncpy(outMsg, msg, outLen - 1);
        return true;
      }
    } else if (_synN < 32) {
      strncpy(_synTable[_synN].ip, pkt.srcIp, 15);
      _synTable[_synN].count = 1;
      _synN++;
    }
  }

  // ── Port Scan ───────────────────────────────────────────
  if (strcmp(pkt.proto, "TCP") == 0 || strcmp(pkt.proto, "UDP") == 0) {
    int idx = _findPort(pkt.srcIp);
    if (idx < 0 && _portN < 16) {
      idx = _portN++;
      strncpy(_portTable[idx].ip, pkt.srcIp, 15);
      _portTable[idx].n = 0;
    }
    if (idx >= 0) {
      // Portu ekle (yoksa)
      bool found = false;
      for (uint8_t i = 0; i < _portTable[idx].n; i++) {
        if (_portTable[idx].ports[i] == pkt.dstPort) {
          found = true;
          break;
        }
      }
      if (!found && _portTable[idx].n < 16) {
        _portTable[idx].ports[_portTable[idx].n++] = pkt.dstPort;
      }
      if (_portTable[idx].n > 10) {
        snprintf(msg, sizeof(msg), "Port Scan from %s (%u ports)", pkt.srcIp,
                 _portTable[idx].n);
        _emit(ALRT_HIGH, msg);
        strncpy(outMsg, msg, outLen - 1);
        return true;
      }
    }
  }

  // ── NULL Scan (flags = "-") ─────────────────────────────
  if (strcmp(pkt.proto, "TCP") == 0 && strcmp(pkt.flags, "-") == 0) {
    snprintf(msg, sizeof(msg), "NULL Scan from %s", pkt.srcIp);
    _emit(ALRT_HIGH, msg);
    strncpy(outMsg, msg, outLen - 1);
    return true;
  }

  // ── XMAS Scan (FIN+PSH+URG) ────────────────────────────
  if (strcmp(pkt.proto, "TCP") == 0 && strstr(pkt.flags, "FIN") &&
      strstr(pkt.flags, "PSH") && strstr(pkt.flags, "URG")) {
    snprintf(msg, sizeof(msg), "XMAS Scan from %s", pkt.srcIp);
    _emit(ALRT_HIGH, msg);
    strncpy(outMsg, msg, outLen - 1);
    return true;
  }

  // ── Telnet ──────────────────────────────────────────────
  if (strcmp(pkt.proto, "TCP") == 0 &&
      (pkt.dstPort == 23 || pkt.srcPort == 23)) {
    snprintf(msg, sizeof(msg), "Cleartext TELNET: %s > %s", pkt.srcIp,
             pkt.dstIp);
    _emit(ALRT_MEDIUM, msg);
    strncpy(outMsg, msg, outLen - 1);
    return true;
  }

  // ── HTTP Credential Leak ────────────────────────────────
  if (strcmp(pkt.proto, "HTTP") == 0) {
    // info alanında authorization var mı?
    char infoLower[128];
    strncpy(infoLower, pkt.info, sizeof(infoLower) - 1);
    infoLower[sizeof(infoLower) - 1] = '\0';
    for (char *c = infoLower; *c; c++)
      *c = tolower(*c);
    if (strstr(infoLower, "authorization")) {
      snprintf(msg, sizeof(msg), "HTTP Credentials from %s", pkt.srcIp);
      _emit(ALRT_HIGH, msg);
      strncpy(outMsg, msg, outLen - 1);
      return true;
    }
  }

  // ── ICMP Flood ──────────────────────────────────────────
  if (strcmp(pkt.proto, "ICMP") == 0) {
    uint32_t now = millis();
    int idx = _findICMP(pkt.srcIp);
    if (idx >= 0) {
      if (now - _icmpTable[idx].windowMs < 1000) {
        _icmpTable[idx].count++;
        if (_icmpTable[idx].count > 20) {
          snprintf(msg, sizeof(msg), "ICMP Flood from %s", pkt.srcIp);
          _emit(ALRT_HIGH, msg);
          strncpy(outMsg, msg, outLen - 1);
          return true;
        }
      } else {
        _icmpTable[idx].count = 1;
        _icmpTable[idx].windowMs = now;
      }
    } else if (_icmpN < 16) {
      strncpy(_icmpTable[_icmpN].ip, pkt.srcIp, 15);
      _icmpTable[_icmpN].count = 1;
      _icmpTable[_icmpN].windowMs = now;
      _icmpN++;
    }
  }

  // ── DNS Tüneli Şüphesi ──────────────────────────────────
  if (strcmp(pkt.proto, "DNS") == 0 && strlen(pkt.info) > 50) {
    snprintf(msg, sizeof(msg), "DNS Tunnel? Long domain: %.30s...", pkt.info);
    _emit(ALRT_MEDIUM, msg);
    strncpy(outMsg, msg, outLen - 1);
    return true;
  }

  outMsg[0] = '\0';
  return false;
}

const AlertEntry *AlertEngine::getAlerts(uint8_t &outN, uint8_t maxN) const {
  uint16_t avail = (_count < MAX_ALERTS) ? _count : MAX_ALERTS;
  outN = (avail < maxN) ? avail : maxN;
  // En son eklenen alert indeksinden geriye doğru
  return _ring; // Basit: tüm ring'i dön, çağıran kısıtlar
}

// ════════════════════════════════════════════════════════════════
//  FLOW TRACKER İMPLEMENTASYONU
// ════════════════════════════════════════════════════════════════

const char *flowStateStr(FlowState s) {
  switch (s) {
  case FLOW_NEW:
    return "NEW";
  case FLOW_SYN:
    return "SYN";
  case FLOW_SYN_ACK:
    return "SYN-ACK";
  case FLOW_ESTABLISHED:
    return "ESTAB";
  case FLOW_CLOSING:
    return "CLOSING";
  case FLOW_RESET:
    return "RESET";
  default:
    return "?";
  }
}

FlowTracker::FlowTracker() { reset(); }

void FlowTracker::reset() { memset(_flows, 0, sizeof(_flows)); }

int FlowTracker::_find(const char *a, uint16_t pa, const char *b,
                       uint16_t pb) const {
  for (uint8_t i = 0; i < MAX_FLOWS; i++) {
    if (!_flows[i].active)
      continue;
    // Yön bağımsız eşleştirme
    if ((strcmp(_flows[i].srcIp, a) == 0 && _flows[i].srcPort == pa &&
         strcmp(_flows[i].dstIp, b) == 0 && _flows[i].dstPort == pb) ||
        (strcmp(_flows[i].srcIp, b) == 0 && _flows[i].srcPort == pb &&
         strcmp(_flows[i].dstIp, a) == 0 && _flows[i].dstPort == pa)) {
      return i;
    }
  }
  return -1;
}

int FlowTracker::_alloc() {
  // Boş slot bul
  for (uint8_t i = 0; i < MAX_FLOWS; i++) {
    if (!_flows[i].active)
      return i;
  }
  // En eski flow'u override et
  uint32_t oldest = UINT32_MAX;
  int oldIdx = 0;
  for (uint8_t i = 0; i < MAX_FLOWS; i++) {
    if (_flows[i].startMs < oldest) {
      oldest = _flows[i].startMs;
      oldIdx = i;
    }
  }
  return oldIdx;
}

FlowEntry *FlowTracker::update(const char *srcIp, uint16_t srcPort,
                               const char *dstIp, uint16_t dstPort,
                               uint8_t flags, uint16_t pktLen) {
  int idx = _find(srcIp, srcPort, dstIp, dstPort);
  if (idx < 0) {
    idx = _alloc();
    memset(&_flows[idx], 0, sizeof(FlowEntry));
    strncpy(_flows[idx].srcIp, srcIp, 15);
    _flows[idx].srcPort = srcPort;
    strncpy(_flows[idx].dstIp, dstIp, 15);
    _flows[idx].dstPort = dstPort;
    _flows[idx].state = FLOW_NEW;
    _flows[idx].startMs = millis();
    _flows[idx].active = true;
  }

  FlowEntry &f = _flows[idx];
  f.packets++;
  f.bytes += pktLen;

  // TCP state machine
  if ((flags & TCP_SYN) && !(flags & TCP_ACK)) {
    f.state = FLOW_SYN;
  } else if ((flags & TCP_SYN) && (flags & TCP_ACK)) {
    f.state = FLOW_SYN_ACK;
  } else if ((flags & TCP_ACK) && !(flags & TCP_SYN)) {
    if (f.state == FLOW_SYN || f.state == FLOW_SYN_ACK)
      f.state = FLOW_ESTABLISHED;
  } else if (flags & TCP_FIN) {
    f.state = FLOW_CLOSING;
  } else if (flags & TCP_RST) {
    f.state = FLOW_RESET;
    f.active = false;
    return nullptr;
  }

  return &f;
}

uint8_t FlowTracker::activeCount() const {
  uint8_t n = 0;
  for (uint8_t i = 0; i < MAX_FLOWS; i++)
    if (_flows[i].active)
      n++;
  return n;
}

uint8_t FlowTracker::topFlows(FlowEntry *out, uint8_t maxN) const {
  // Basit insertion sort — aktif flow'ları byte'a göre sırala
  uint8_t count = 0;
  for (uint8_t i = 0; i < MAX_FLOWS && count < maxN; i++) {
    if (!_flows[i].active)
      continue;
    // Insertion sort yerine ekle
    out[count++] = _flows[i];
  }
  // Bubble sort (küçük N için yeterli)
  for (uint8_t i = 0; i < count; i++) {
    for (uint8_t j = i + 1; j < count; j++) {
      if (out[j].bytes > out[i].bytes) {
        FlowEntry tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
      }
    }
  }
  return count;
}

// ════════════════════════════════════════════════════════════════
//  TOP TALKERS İMPLEMENTASYONU
// ════════════════════════════════════════════════════════════════

TopTalkers::TopTalkers() { reset(); }

void TopTalkers::reset() { memset(_entries, 0, sizeof(_entries)); }

int TopTalkers::_find(const char *ip) const {
  for (uint8_t i = 0; i < MAX_TALKERS; i++) {
    if (_entries[i].active && strcmp(_entries[i].ip, ip) == 0)
      return i;
  }
  return -1;
}

int TopTalkers::_alloc() {
  for (uint8_t i = 0; i < MAX_TALKERS; i++) {
    if (!_entries[i].active)
      return i;
  }
  return -1; // dolu
}

void TopTalkers::update(const char *srcIp, const char *dstIp, uint16_t pktLen) {
  // TX (gönderen)
  int si = _find(srcIp);
  if (si < 0)
    si = _alloc();
  if (si >= 0) {
    if (!_entries[si].active) {
      memset(&_entries[si], 0, sizeof(TalkerEntry));
      strncpy(_entries[si].ip, srcIp, 15);
      _entries[si].active = true;
    }
    _entries[si].txBytes += pktLen;
    _entries[si].packets++;
  }

  // RX (alıcı)
  int di = _find(dstIp);
  if (di < 0)
    di = _alloc();
  if (di >= 0) {
    if (!_entries[di].active) {
      memset(&_entries[di], 0, sizeof(TalkerEntry));
      strncpy(_entries[di].ip, dstIp, 15);
      _entries[di].active = true;
    }
    _entries[di].rxBytes += pktLen;
  }
}

uint8_t TopTalkers::summary(TalkerSummary *out, uint8_t maxN) const {
  uint8_t count = 0;
  TalkerSummary tmp[MAX_TALKERS];

  for (uint8_t i = 0; i < MAX_TALKERS; i++) {
    if (!_entries[i].active)
      continue;
    strncpy(tmp[count].ip, _entries[i].ip, 15);
    tmp[count].ip[15] = '\0';
    tmp[count].packets = _entries[i].packets;
    tmp[count].totalBytes = _entries[i].txBytes + _entries[i].rxBytes;
    count++;
  }

  // Sort by totalBytes desc
  for (uint8_t i = 0; i < count; i++) {
    for (uint8_t j = i + 1; j < count; j++) {
      if (tmp[j].totalBytes > tmp[i].totalBytes) {
        TalkerSummary sw = tmp[i];
        tmp[i] = tmp[j];
        tmp[j] = sw;
      }
    }
  }

  uint8_t n = (count < maxN) ? count : maxN;
  memcpy(out, tmp, n * sizeof(TalkerSummary));
  return n;
}

// ════════════════════════════════════════════════════════════════
//  FİLTRE KONTROLÜ
// ════════════════════════════════════════════════════════════════

static bool _filterOk(const char *proto) {
  if (_currentFilter == SFILT_ALL)
    return true;
  if (_currentFilter == SFILT_ALERT)
    return true;

  const char *filterProto = snifferFilterName(_currentFilter);
  return (strcmp(proto, filterProto) == 0);
}

// ════════════════════════════════════════════════════════════════
//  WiFi PROMISCUOUS MODE CALLBACK
// ════════════════════════════════════════════════════════════════

static void IRAM_ATTR _promiscuousCallback(void *buf,
                                           wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT)
    return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if (len < 24 || len > 500)
    return; // 802.11 min header + reasonable max

  // Ring buffer'a kopyala (Atomic olmayan ama pratikte çalışır,
  // worst case = bir paket kaybı)
  uint8_t next = (_ringHead + 1) % SNIFFER_RING_SIZE;
  if (next == _ringTail)
    return; // buffer dolu, drop

  uint16_t copyLen = (len > 500) ? 500 : len;
  memcpy((void *)_ringBuf[_ringHead], pkt->payload, copyLen);
  _ringLen[_ringHead] = copyLen;
  _ringHead = next;
}

// ════════════════════════════════════════════════════════════════
//  PAKET İŞLEME (ring buffer'dan oku + parse et + UART'a gönder)
// ════════════════════════════════════════════════════════════════

static void _processPacket(const uint8_t *raw, uint16_t rawLen) {
  SnifferPacket pkt;
  pkt.clear();
  pkt.timestamp = millis();
  pkt.rawLen = rawLen;

  // 802.11 frame — ilk 24 byte MAC header
  // Biz data frame'lerden Ethernet payload'ını çıkarıyoruz
  // 802.11 header: Frame Control (2) + Duration (2) + Addr1 (6) + Addr2 (6) +
  // Addr3 (6) + SeqCtrl (2) = 24
  if (rawLen < 34)
    return; // 24 (802.11) + 8 (LLC/SNAP) + 2 (ethertype) minimum

  // MAC adresleri çıkar
  formatMAC(pkt.dstMac, &raw[4]);  // Addr1 = Destination
  formatMAC(pkt.srcMac, &raw[10]); // Addr2 = Source

  // LLC/SNAP header check (802.11 data frame → Ethernet frame)
  const uint8_t *llc = raw + 24;
  uint16_t llcLen = rawLen - 24;

  // SNAP: AA AA 03 00 00 00 + EtherType (2)
  uint16_t ethType = 0;
  const uint8_t *ethPayload = nullptr;
  uint16_t ethPayloadLen = 0;

  if (llcLen >= 8 && llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
    ethType = (llc[6] << 8) | llc[7];
    ethPayload = llc + 8;
    ethPayloadLen = llcLen - 8;
  } else {
    // Bazı frame'ler direkt Ethernet payload taşır
    if (llcLen >= 2) {
      ethType = (llc[0] << 8) | llc[1];
      ethPayload = llc + 2;
      ethPayloadLen = llcLen - 2;
    } else {
      return;
    }
  }

  // ── IPv4 ────────────────────────────────────────────────
  if (ethType == ETHERTYPE_IP && ethPayload && ethPayloadLen > 0) {
    IPv4Info ip = parseIPv4(ethPayload, ethPayloadLen);
    if (!ip.valid)
      return;

    strncpy(pkt.srcIp, ip.srcIp, 15);
    strncpy(pkt.dstIp, ip.dstIp, 15);
    pkt.ttl = ip.ttl;

    // ── TCP ──────────────────────────────────────────────
    if (ip.protocol == IP_PROTO_TCP && ip.payload && ip.payloadLen > 0) {
      TCPInfo tcp = parseTCP(ip.payload, ip.payloadLen);
      if (!tcp.valid)
        return;

      bool isHTTP = (tcp.srcPort == 80 || tcp.dstPort == 80 ||
                     tcp.srcPort == 8080 || tcp.dstPort == 8080);
      const char *proto = isHTTP ? "HTTP" : "TCP";

      if (!_filterOk(proto))
        return;

      strcpy(pkt.proto, proto);
      pkt.srcPort = tcp.srcPort;
      pkt.dstPort = tcp.dstPort;

      const char *sn = portName(tcp.srcPort);
      const char *dn = portName(tcp.dstPort);
      if (sn)
        strncpy(pkt.srcSvc, sn, sizeof(pkt.srcSvc) - 1);
      else
        snprintf(pkt.srcSvc, sizeof(pkt.srcSvc), "%u", tcp.srcPort);
      if (dn)
        strncpy(pkt.dstSvc, dn, sizeof(pkt.dstSvc) - 1);
      else
        snprintf(pkt.dstSvc, sizeof(pkt.dstSvc), "%u", tcp.dstPort);

      formatFlags(pkt.flags, tcp.flags);
      pkt.window = tcp.window;
      strncpy(pkt.osGuess, osFingerprint(ip.ttl, tcp.window),
              sizeof(pkt.osGuess) - 1);
      hexPreview(pkt.payloadHex, tcp.payload, tcp.payloadLen);

      if (isHTTP && tcp.payloadLen > 0) {
        HTTPSniff http = sniffHTTP(tcp.payload, tcp.payloadLen);
        if (http.valid) {
          snprintf(pkt.info, sizeof(pkt.info), "%s %s %s", http.method,
                   http.host, http.path);
        } else {
          strncpy(pkt.info, pkt.flags, sizeof(pkt.info) - 1);
        }
      } else {
        strncpy(pkt.info, pkt.flags, sizeof(pkt.info) - 1);
      }

      // Flow tracker
      _flowTrack.update(ip.srcIp, tcp.srcPort, ip.dstIp, tcp.dstPort, tcp.flags,
                        rawLen);

      _stats.tcp++;
      if (isHTTP)
        _stats.http++;

      // ── UDP ──────────────────────────────────────────────
    } else if (ip.protocol == IP_PROTO_UDP && ip.payload && ip.payloadLen > 0) {
      UDPInfo udp = parseUDP(ip.payload, ip.payloadLen);
      if (!udp.valid)
        return;

      bool isDNS = (udp.srcPort == 53 || udp.dstPort == 53);
      const char *proto = isDNS ? "DNS" : "UDP";

      if (!_filterOk(proto))
        return;

      strcpy(pkt.proto, proto);
      pkt.srcPort = udp.srcPort;
      pkt.dstPort = udp.dstPort;

      const char *sn = portName(udp.srcPort);
      const char *dn = portName(udp.dstPort);
      if (sn)
        strncpy(pkt.srcSvc, sn, sizeof(pkt.srcSvc) - 1);
      else
        snprintf(pkt.srcSvc, sizeof(pkt.srcSvc), "%u", udp.srcPort);
      if (dn)
        strncpy(pkt.dstSvc, dn, sizeof(pkt.dstSvc) - 1);
      else
        snprintf(pkt.dstSvc, sizeof(pkt.dstSvc), "%u", udp.dstPort);

      hexPreview(pkt.payloadHex, udp.payload, udp.payloadLen);

      if (isDNS && udp.payloadLen > 0) {
        DNSSniff dns = sniffDNS(udp.payload, udp.payloadLen);
        if (dns.valid) {
          snprintf(pkt.info, sizeof(pkt.info), "%s %s %s",
                   dns.isQuery ? "Q" : "R", dns.domain, dns.qtype);
        } else {
          strcpy(pkt.info, "DNS");
        }
      } else {
        snprintf(pkt.info, sizeof(pkt.info), "%s>%s", pkt.srcSvc, pkt.dstSvc);
      }

      _stats.udp++;
      if (isDNS)
        _stats.dns++;

      // ── ICMP ─────────────────────────────────────────────
    } else if (ip.protocol == IP_PROTO_ICMP && ip.payload &&
               ip.payloadLen > 0) {
      if (!_filterOk("ICMP"))
        return;

      ICMPInfo icmp = parseICMP(ip.payload, ip.payloadLen);
      strcpy(pkt.proto, "ICMP");
      if (icmp.valid) {
        strncpy(pkt.info, icmp.typeStr, sizeof(pkt.info) - 1);
        char ttlStr[16];
        snprintf(ttlStr, sizeof(ttlStr), " TTL=%u", ip.ttl);
        strncat(pkt.info, ttlStr, sizeof(pkt.info) - strlen(pkt.info) - 1);
      }
      _stats.icmp++;

    } else {
      _stats.other++;
      return;
    }

    // ── ARP ─────────────────────────────────────────────────
  } else if (ethType == ETHERTYPE_ARP && ethPayload && ethPayloadLen > 0) {
    if (!_filterOk("ARP"))
      return;

    ARPInfo arp = parseARP(ethPayload, ethPayloadLen);
    if (!arp.valid)
      return;

    strcpy(pkt.proto, "ARP");
    strncpy(pkt.srcIp, arp.senderIp, 15);
    strncpy(pkt.dstIp, arp.targetIp, 15);
    strncpy(pkt.srcMac, arp.senderMac, 17);
    snprintf(pkt.info, sizeof(pkt.info), "%s %s>%s", arp.opStr, arp.senderMac,
             arp.targetIp);

    _stats.arp++;
  } else {
    _stats.other++;
    return;
  }

  // ── Top Talkers ─────────────────────────────────────────
  _topTalk.update(pkt.srcIp, pkt.dstIp, rawLen);

  // ── Alert Check ─────────────────────────────────────────
  char alertMsg[80] = {0};
  bool hasAlert = _alertEng.check(pkt, alertMsg, sizeof(alertMsg));
  pkt.hasAlert = hasAlert;
  if (hasAlert) {
    strncpy(pkt.alertMsg, alertMsg, sizeof(pkt.alertMsg) - 1);
  }

  // ALERT filtresi: sadece alert olan paketleri gönder
  if (_currentFilter == SFILT_ALERT && !hasAlert)
    return;

  _stats.total++;

  // ── UART'a gönder (Serial — STM32'ye) ───────────────────
  // Kompakt format: [PKT] proto|src_ip:port|dst_ip:port|flags|ttl|info|alert
  char line[256];
  if (pkt.srcPort > 0) {
    snprintf(line, sizeof(line), "[PKT] %s|%s:%u|%s:%u|%s|TTL%u|%s%s%s",
             pkt.proto, pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort,
             pkt.flags, pkt.ttl, pkt.info, hasAlert ? "|!" : "",
             hasAlert ? alertMsg : "");
  } else {
    snprintf(line, sizeof(line), "[PKT] %s|%s|%s|%s%s%s", pkt.proto, pkt.srcIp,
             pkt.dstIp, pkt.info, hasAlert ? "|!" : "",
             hasAlert ? alertMsg : "");
  }
  Serial.println(line);
}

// ════════════════════════════════════════════════════════════════
//  ANA SNIFFER API
// ════════════════════════════════════════════════════════════════

void snifferStart() {
  if (_snifferRunning)
    return;

  // İstatistikleri sıfırla
  memset(&_stats, 0, sizeof(_stats));
  _alertEng.reset();
  _flowTrack.reset();
  _topTalk.reset();
  _ringHead = 0;
  _ringTail = 0;
  _currentChannel = 1;

  // WiFi'ı promiscuous mode'a al
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(_promiscuousCallback);
  esp_wifi_set_channel(_currentChannel, WIFI_SECOND_CHAN_NONE);

  _snifferRunning = true;
  _lastChannelHop = millis();

  Serial.println("[SNIFFER] Promiscuous mode STARTED ch:" +
                 String(_currentChannel));
}

void snifferStop() {
  if (!_snifferRunning)
    return;

  esp_wifi_set_promiscuous(false);
  _snifferRunning = false;

  Serial.println("[SNIFFER] Stopped. Total pkts: " + String(_stats.total));

  // Final istatistik gönder
  char statsLine[160];
  snprintf(statsLine, sizeof(statsLine),
           "[STATS] "
           "total:%lu|tcp:%lu|udp:%lu|icmp:%lu|arp:%lu|http:%lu|dns:%lu|flows:%"
           "u|alerts:%u",
           _stats.total, _stats.tcp, _stats.udp, _stats.icmp, _stats.arp,
           _stats.http, _stats.dns, _flowTrack.activeCount(),
           _alertEng.alertCount());
  Serial.println(statsLine);
}

bool snifferLoop() {
  if (!_snifferRunning)
    return false;

  // Channel hopping
  unsigned long now = millis();
  if (now - _lastChannelHop >= SNIFFER_CHANNEL_HOP_INTERVAL_MS) {
    _currentChannel++;
    if (_currentChannel > SNIFFER_MAX_CHANNELS)
      _currentChannel = 1;
    esp_wifi_set_channel(_currentChannel, WIFI_SECOND_CHAN_NONE);
    _lastChannelHop = now;
  }

  // Ring buffer'dan paket oku
  bool processed = false;
  while (_ringTail != _ringHead) {
    uint8_t data[512];
    uint16_t len = _ringLen[_ringTail];
    memcpy(data, (void *)_ringBuf[_ringTail], len);
    _ringTail = (_ringTail + 1) % SNIFFER_RING_SIZE;

    _processPacket(data, len);
    processed = true;
  }

  return processed;
}

void snifferNextFilter() {
  _currentFilter = (SnifferFilter)(((uint8_t)_currentFilter + 1) % SFILT_COUNT);
  Serial.println("[SNIFFER] Filter: " +
                 String(snifferFilterName(_currentFilter)));
}

void snifferSetFilter(uint8_t idx) {
  if (idx < SFILT_COUNT) {
    _currentFilter = (SnifferFilter)idx;
    Serial.println("[SNIFFER] Filter: " +
                   String(snifferFilterName(_currentFilter)));
  }
}

SnifferStats snifferGetStats() {
  _stats.activeFlows = _flowTrack.activeCount();
  _stats.alertCount = _alertEng.alertCount();
  _stats.currentFilter = (uint8_t)_currentFilter;
  return _stats;
}

void snifferHandleCommand(const String &cmd) {
  if (cmd == "CMD:SNIFFER_FILTER") {
    snifferNextFilter();
  } else if (cmd.startsWith("CMD:SNIFFER_FILTER:")) {
    uint8_t idx = cmd.substring(19).toInt();
    snifferSetFilter(idx);
  } else if (cmd == "CMD:SNIFFER_STATS") {
    SnifferStats s = snifferGetStats();
    char statsLine[200];
    snprintf(statsLine, sizeof(statsLine),
             "[STATS] "
             "total:%lu|tcp:%lu|udp:%lu|icmp:%lu|arp:%lu|http:%lu|dns:%lu|"
             "flows:%u|alerts:%u|filter:%s",
             s.total, s.tcp, s.udp, s.icmp, s.arp, s.http, s.dns, s.activeFlows,
             s.alertCount, snifferFilterName((SnifferFilter)s.currentFilter));
    Serial.println(statsLine);
  } else if (cmd == "CMD:SNIFFER_FLOWS") {
    FlowEntry top[5];
    uint8_t n = _flowTrack.topFlows(top, 5);
    Serial.println("[FLOWS] count:" + String(n));
    for (uint8_t i = 0; i < n; i++) {
      char line[120];
      snprintf(line, sizeof(line), "[FLOW] %s:%u>%s:%u|%s|pkts:%lu|bytes:%lu",
               top[i].srcIp, top[i].srcPort, top[i].dstIp, top[i].dstPort,
               flowStateStr(top[i].state), top[i].packets, top[i].bytes);
      Serial.println(line);
    }
  } else if (cmd == "CMD:SNIFFER_TALKERS") {
    TalkerSummary top[5];
    uint8_t n = _topTalk.summary(top, 5);
    Serial.println("[TALKERS] count:" + String(n));
    for (uint8_t i = 0; i < n; i++) {
      char line[80];
      snprintf(line, sizeof(line), "[TALK] %s|pkts:%lu|bytes:%lu", top[i].ip,
               top[i].packets, top[i].totalBytes);
      Serial.println(line);
    }
  } else if (cmd == "CMD:SNIFFER_ALERTS") {
    uint8_t n;
    const AlertEntry *alerts = _alertEng.getAlerts(n, 10);
    Serial.println("[ALERTS] count:" + String(n));
    for (uint8_t i = 0; i < n; i++) {
      char line[100];
      snprintf(line, sizeof(line), "[ALRT] [%s] %s",
               alertLevelStr(alerts[i].level), alerts[i].message);
      Serial.println(line);
    }
  }
}
