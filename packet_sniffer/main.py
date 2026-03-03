# packet_sniffer/main.py — Gelişmiş Ağ Paket Sniffer
# MicroPython | STM32 Hand Terminal
#
# Çalıştırma: mpremote run packet_sniffer/main.py
#             Thonny → Run
#
# Özellikler:
#   - IPv4 / TCP / UDP / ICMP / ARP parse
#   - HTTP derin parse (method, path, host, user-agent, cookie, body)
#   - DNS sorgu + yanıt parse
#   - Passive OS Fingerprinting (TTL + TCP window → OS tahmini)
#   - ARP Spoofing tespiti
#   - SYN Scan / Port Tarama tespiti
#   - ICMP tip analizi (ping, unreachable, redirect, traceroute)
#   - Flow Tracker (aktif TCP bağlantıları)
#   - Top Talkers (en çok trafik yapan IP'ler)
#   - Kural tabanlı Alert sistemi
#   - Payload hex/ASCII önizlemesi
#   - CSV loglama

import usocket
import uselect
import ustruct
import utime

# ── Sabitler ──────────────────────────────────────────────────

IP_PROTO_ICMP = 1
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17

ETHERTYPE_IP  = 0x0800
ETHERTYPE_ARP = 0x0806

TCP_FLAG_BITS = {
    0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST',
    0x08: 'PSH', 0x10: 'ACK', 0x20: 'URG',
}

ICMP_TYPES = {
    0:  'ECHO_REPLY',    3:  'UNREACHABLE', 5:  'REDIRECT',
    8:  'ECHO_REQ',      11: 'TTL_EXCEEDED',30: 'TRACEROUTE',
}

PORT_NAMES = {
    21: 'FTP',   22: 'SSH',    23: 'TELNET',  25: 'SMTP',
    53: 'DNS',   67: 'DHCP',  80: 'HTTP',    110: 'POP3',
   143: 'IMAP', 161: 'SNMP', 443: 'HTTPS',  445: 'SMB',
   389: 'LDAP', 636: 'LDAPS',993: 'IMAPS',  995: 'POP3S',
  1433: 'MSSQL',3306:'MySQL',3389:'RDP',   5432:'PgSQL',
  8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
}

FILTERS = ['ALL', 'TCP', 'UDP', 'ICMP', 'ARP', 'HTTP', 'DNS', 'ALERT']

SNIFF_LOG_PATH = '/sniff.log'
SNIFF_BUF_SIZE = 4096   # büyütüldü: body yakalamak için

# ── OS Fingerprint tablosu (TTL, TCP window → OS) ─────────────
# Format: (ttl_eşik, window_boyutu_aralığı) → OS ismi
_OS_FINGERPRINTS = [
    # (min_ttl, max_ttl, win_lo, win_hi, os_name)
    (  1,  64,  5840,  5840, 'Linux 2.4/2.6'),
    (  1,  64, 65535, 65535, 'Linux 3.x/4.x'),
    (  1,  64, 29200, 29200, 'Linux 5.x'),
    ( 65, 128,  8192,  8192, 'Windows XP'),
    ( 65, 128, 65535, 65535, 'Windows Vista/7'),
    ( 65, 128, 64240, 64240, 'Windows 10/11'),
    ( 65, 128,  8760,  8760, 'Windows Server'),
    (129, 255, 65535, 65535, 'Cisco IOS / Solaris'),
    (  1,  64, 65535, 65534, 'macOS / FreeBSD'),
    ( 65, 128, 65535, 65534, 'Windows (generic)'),
]

def os_fingerprint(ttl, window):
    """TTL ve TCP window size'a göre OS tahmini yapar."""
    for mn, mx, wlo, whi, name in _OS_FINGERPRINTS:
        if mn <= ttl <= mx and wlo <= window <= whi:
            return name
    if ttl <= 64:   return 'Linux/Unix (TTL~64)'
    if ttl <= 128:  return 'Windows (TTL~128)'
    return 'Unknown (TTL={})'.format(ttl)


# ── Yardımcılar ───────────────────────────────────────────────

def _ip(b):    return '{}.{}.{}.{}'.format(b[0], b[1], b[2], b[3])
def _mac(b):   return '{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}'.format(*b)
def _port(p):  return PORT_NAMES.get(p, str(p))
def _flags(f): return '|'.join(n for b, n in TCP_FLAG_BITS.items() if f & b) or '-'

def _hex_preview(data, n=16):
    """İlk n byte'ı hem hex hem ASCII olarak verir."""
    chunk = data[:n]
    hex_s = ' '.join('{:02X}'.format(b) for b in chunk)
    asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    return '{} | {}'.format(hex_s, asc_s)

def _log(line):
    try:
        with open(SNIFF_LOG_PATH, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


# ── Parser'lar ────────────────────────────────────────────────

def parse_ipv4(raw):
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0x0F) * 4
    return {
        'ihl':      ihl,
        'dscp':     raw[1] >> 2,
        'length':   ustruct.unpack('!H', raw[2:4])[0],
        'ttl':      raw[8],
        'protocol': raw[9],
        'src_ip':   _ip(raw[12:16]),
        'dst_ip':   _ip(raw[16:20]),
        'payload':  raw[ihl:],
    }

def parse_tcp(raw):
    if len(raw) < 20:
        return None
    data_off = (raw[12] >> 4) * 4
    flags    = raw[13]
    window   = ustruct.unpack('!H', raw[14:16])[0]
    return {
        'src_port':  ustruct.unpack('!H', raw[0:2])[0],
        'dst_port':  ustruct.unpack('!H', raw[2:4])[0],
        'seq':       ustruct.unpack('!I', raw[4:8])[0],
        'ack':       ustruct.unpack('!I', raw[8:12])[0],
        'flags':     flags,
        'flags_str': _flags(flags),
        'window':    window,
        'payload':   raw[data_off:],
    }

def parse_udp(raw):
    if len(raw) < 8:
        return None
    return {
        'src_port': ustruct.unpack('!H', raw[0:2])[0],
        'dst_port': ustruct.unpack('!H', raw[2:4])[0],
        'length':   ustruct.unpack('!H', raw[4:6])[0],
        'payload':  raw[8:],
    }

def parse_icmp(raw):
    if len(raw) < 4:
        return None
    icmp_type = raw[0]
    icmp_code = raw[1]
    return {
        'type':     icmp_type,
        'code':     icmp_code,
        'type_str': ICMP_TYPES.get(icmp_type, 'ICMP/{}'.format(icmp_type)),
        'payload':  raw[4:],
    }

def parse_arp(raw):
    if len(raw) < 28:
        return None
    op = ustruct.unpack('!H', raw[6:8])[0]
    return {
        'opcode':     op,
        'op_str':     'REQUEST' if op == 1 else 'REPLY',
        'sender_mac': _mac(raw[8:14]),
        'sender_ip':  _ip(raw[14:18]),
        'target_mac': _mac(raw[18:24]),
        'target_ip':  _ip(raw[24:28]),
    }


# ── Protokol sniffer'ları ─────────────────────────────────────

def sniff_http(payload):
    """HTTP header'larını bir dict halinde ayıklar."""
    try:
        text   = payload.decode('utf-8', 'ignore')
        lines  = text.split('\r\n')
        result = {}

        # İstek satırı: GET /path HTTP/1.1
        first = lines[0]
        if ' ' in first:
            parts = first.split(' ', 2)
            if parts[0] in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
                result['method']  = parts[0]
                result['path']    = parts[1] if len(parts) > 1 else ''
                result['version'] = parts[2] if len(parts) > 2 else ''

        # Response satırı: HTTP/1.1 200 OK
        if first.startswith('HTTP/'):
            parts = first.split(' ', 2)
            result['response'] = first
            result['status']   = parts[1] if len(parts) > 1 else ''

        # Header'lar
        for line in lines[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                key = k.strip().lower()
                val = v.strip()
                if key in ('host', 'user-agent', 'cookie', 'authorization',
                           'content-type', 'content-length', 'referer', 'x-forwarded-for'):
                    result[key] = val[:120]
            elif line == '':
                break   # body başlıyor

        return result if result else None
    except Exception:
        return None

def sniff_dns(payload):
    """DNS paketini parse eder: sorgu + yanıt."""
    try:
        if len(payload) < 12:
            return None
        tx_id  = ustruct.unpack('!H', payload[0:2])[0]
        flags  = ustruct.unpack('!H', payload[2:4])[0]
        qcount = ustruct.unpack('!H', payload[4:6])[0]
        acount = ustruct.unpack('!H', payload[6:8])[0]
        is_qry = not (flags & 0x8000)

        # QNAME parse
        offset, labels = 12, []
        while offset < len(payload):
            ln = payload[offset]
            if ln == 0:
                offset += 1
                break
            if ln >= 0xC0:
                offset += 2
                break
            offset += 1
            labels.append(payload[offset:offset+ln].decode('ascii', 'ignore'))
            offset += ln
        domain = '.'.join(labels)

        qtype_str = ''
        if offset + 4 <= len(payload):
            qtype = ustruct.unpack('!H', payload[offset:offset+2])[0]
            qtype_str = {1:'A',2:'NS',5:'CNAME',15:'MX',28:'AAAA',
                         255:'ANY'}.get(qtype, str(qtype))

        return {
            'tx_id':   tx_id,
            'query':   is_qry,
            'domain':  domain,
            'qtype':   qtype_str,
            'answers': acount,
        }
    except Exception:
        return None


# ── Flow Tracker ─────────────────────────────────────────────

class FlowTracker:
    """
    Aktif TCP bağlantılarını takip eder.
    Key: (src_ip, src_port, dst_ip, dst_port)
    Value: {'state': str, 'packets': int, 'bytes': int, 'start': int}
    """

    def __init__(self, max_flows=128):
        self.flows    = {}
        self.max      = max_flows

    def _key(self, src_ip, src_port, dst_ip, dst_port):
        # Yön bağımsız key (A↔B aynı flow)
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        return (min(a, b), max(a, b))

    def update(self, src_ip, src_port, dst_ip, dst_port, flags, pkt_len):
        key = self._key(src_ip, src_port, dst_ip, dst_port)

        if key not in self.flows:
            if len(self.flows) >= self.max:
                # En eski flow'u sil
                oldest = min(self.flows, key=lambda k: self.flows[k]['start'])
                del self.flows[oldest]
            self.flows[key] = {
                'state':   'NEW',
                'packets': 0,
                'bytes':   0,
                'start':   utime.ticks_ms(),
            }

        f = self.flows[key]
        f['packets'] += 1
        f['bytes']   += pkt_len

        # TCP state machine (basit)
        if flags & 0x02 and not (flags & 0x10):  # SYN
            f['state'] = 'SYN'
        elif flags & 0x02 and flags & 0x10:       # SYN-ACK
            f['state'] = 'SYN-ACK'
        elif flags & 0x10 and not (flags & 0x02): # ACK
            if f['state'] in ('SYN', 'SYN-ACK'):
                f['state'] = 'ESTABLISHED'
        elif flags & 0x01:                         # FIN
            f['state'] = 'CLOSING'
        elif flags & 0x04:                         # RST
            f['state'] = 'RESET'
            del self.flows[key]
            return None

        return f

    def active_count(self):
        return len(self.flows)

    def top_flows(self, n=5):
        """En çok byte akan n flow'u döner."""
        return sorted(self.flows.items(),
                      key=lambda x: -x[1]['bytes'])[:n]


# ── Top Talkers ───────────────────────────────────────────────

class TopTalkers:
    """En çok trafik yapan IP'leri takip eder (src + dst)."""

    def __init__(self, max_entries=64):
        self.tx    = {}   # ip → gönderilen byte
        self.rx    = {}   # ip → alınan byte
        self.pkts  = {}   # ip → paket sayısı
        self.max   = max_entries

    def update(self, src_ip, dst_ip, pkt_len):
        for table, ip in [(self.tx, src_ip), (self.rx, dst_ip)]:
            if ip not in table and len(table) >= self.max:
                continue
            table[ip]     = table.get(ip, 0) + pkt_len
        self.pkts[src_ip] = self.pkts.get(src_ip, 0) + 1

    def top(self, n=5, by='tx'):
        table = self.tx if by == 'tx' else self.rx
        return sorted(table.items(), key=lambda x: -x[1])[:n]

    def summary(self, n=5):
        merged = {}
        for ip, b in self.tx.items():
            merged[ip] = merged.get(ip, 0) + b
        for ip, b in self.rx.items():
            merged[ip] = merged.get(ip, 0) + b
        ranked = sorted(merged.items(), key=lambda x: -x[1])[:n]
        return [(ip, self.pkts.get(ip, 0), tot) for ip, tot in ranked]


# ── Alert Sistemi ─────────────────────────────────────────────

class AlertEngine:
    """
    Kural tabanlı saldırı/anomali tespit sistemi.

    Varsayılan kurallar:
    - ARP Spoofing (değişen MAC)
    - SYN Scan (tek IP'den >15 SYN)
    - Port Scan (tek IP'den >10 farklı port)
    - Telnet trafiği (şifresiz protokol)
    - Şifresiz HTTP kimlik bilgisi (Authorization header)
    - ICMP flood (tek IP'den >20 ICMP/s)
    - DNS tüneli şüphesi (çok uzun domain)
    - NULL / XMAS scan (anormal TCP flag kombinasyonları)
    """

    def __init__(self):
        self.arp_table   = {}   # ip → mac
        self.syn_table   = {}   # src_ip → count
        self.port_table  = {}   # src_ip → set(ports)
        self.icmp_table  = {}   # src_ip → (count, window_start)
        self.alerts      = []   # [(ts, level, msg)]
        self.custom_rules = []  # [(fn(pkt) → str|None)]

    def add_rule(self, fn):
        """Özel kural ekle. fn(pkt_dict) → alert_str veya None."""
        self.custom_rules.append(fn)

    def _emit(self, level, msg):
        ts = utime.ticks_ms()
        entry = (ts, level, msg)
        self.alerts.append(entry)
        if len(self.alerts) > 200:
            self.alerts.pop(0)
        return '⚠ [{}] {}'.format(level, msg)

    def check(self, pkt):
        """
        Paketi tüm kurallardan geçirir.
        Döner: str (alert mesajı) veya None
        """
        proto  = pkt.get('proto', '')
        src_ip = pkt.get('src_ip', '')
        dst_ip = pkt.get('dst_ip', '')
        flags  = pkt.get('flags', '')
        info   = pkt.get('info', '')

        # ── ARP Spoofing ─────────────────────────────────────
        if proto == 'ARP':
            mac = pkt.get('info', '').split('>')[-2].strip() if '>' in pkt.get('info','') else ''
            if src_ip and src_ip in self.arp_table:
                if self.arp_table[src_ip] != pkt.get('src_mac',''):
                    return self._emit('CRITICAL', 'ARP Spoof! {} MAC changed'.format(src_ip))
            if src_ip:
                self.arp_table[src_ip] = pkt.get('src_mac', '')

        # ── SYN Scan ─────────────────────────────────────────
        if proto == 'TCP' and 'SYN' in flags and 'ACK' not in flags:
            self.syn_table[src_ip] = self.syn_table.get(src_ip, 0) + 1
            if self.syn_table[src_ip] == 16:
                return self._emit('HIGH', 'SYN Scan from {}'.format(src_ip))

        # ── Port Scan ─────────────────────────────────────────
        if proto in ('TCP', 'UDP'):
            dp = pkt.get('dst_port', 0)
            if src_ip not in self.port_table:
                self.port_table[src_ip] = set()
            self.port_table[src_ip].add(dp)
            if len(self.port_table[src_ip]) > 10:
                return self._emit('HIGH', 'Port Scan from {} ({} ports)'.format(
                    src_ip, len(self.port_table[src_ip])))

        # ── NULL Scan (flags=0) ───────────────────────────────
        if proto == 'TCP' and flags == '-':
            return self._emit('HIGH', 'NULL Scan from {}'.format(src_ip))

        # ── XMAS Scan (FIN+PSH+URG) ──────────────────────────
        if proto == 'TCP' and all(f in flags for f in ('FIN', 'PSH', 'URG')):
            return self._emit('HIGH', 'XMAS Scan from {}'.format(src_ip))

        # ── Telnet ───────────────────────────────────────────
        if proto == 'TCP' and (pkt.get('dst_port') == 23 or pkt.get('src_port') == 23):
            return self._emit('MEDIUM', 'Cleartext TELNET: {}→{}'.format(src_ip, dst_ip))

        # ── HTTP Basic Auth ───────────────────────────────────
        if proto == 'HTTP' and 'authorization' in str(info).lower():
            return self._emit('HIGH', 'HTTP Credentials exposed from {}'.format(src_ip))

        # ── ICMP Flood ────────────────────────────────────────
        if proto == 'ICMP':
            now = utime.ticks_ms()
            if src_ip in self.icmp_table:
                cnt, win = self.icmp_table[src_ip]
                if utime.ticks_diff(now, win) < 1000:
                    cnt += 1
                    self.icmp_table[src_ip] = (cnt, win)
                    if cnt > 20:
                        return self._emit('HIGH', 'ICMP Flood from {}'.format(src_ip))
                else:
                    self.icmp_table[src_ip] = (1, now)
            else:
                self.icmp_table[src_ip] = (1, now)

        # ── DNS Tüneli Şüphesi ────────────────────────────────
        if proto == 'DNS':
            domain = str(info)
            if len(domain) > 50:
                return self._emit('MEDIUM', 'DNS Tunnel? Long domain: {}...'.format(domain[:30]))

        # ── Özel kurallar ────────────────────────────────────
        for fn in self.custom_rules:
            try:
                result = fn(pkt)
                if result:
                    return self._emit('CUSTOM', result)
            except Exception:
                pass

        return None

    def recent_alerts(self, n=10):
        return self.alerts[-n:]

    def alert_count(self):
        return len(self.alerts)


# ── Ana Sniffer Sınıfı ────────────────────────────────────────

class PacketSniffer:
    """
    Gelişmiş ağ paket yakalayıcı + analizci.

    API:
        s = PacketSniffer()
        ok = s.start()          # True/False
        pkt = s.next_packet()   # dict veya None — UI katmanına verir
        s.stop()

    Yardımcılar (Arda'nın UI'ı için):
        s.get_stats()           # istatistik dict
        s.flows.top_flows()     # en aktif bağlantılar
        s.talkers.summary()     # en çok trafik yapan IP'ler
        s.alerts.recent_alerts()# son alert'ler
        s.set_filter(idx)       # FILTERS[idx]
        s.next_filter()         # döngüsel filtre değiştir
    """

    def __init__(self, filter_idx=0):
        self.filter_idx = filter_idx
        self.sock    = None
        self.poller  = None
        self.stats   = {'TCP': 0, 'UDP': 0, 'ICMP': 0,
                        'ARP': 0, 'HTTP': 0, 'DNS': 0, 'OTHER': 0}
        self.total   = 0
        self.flows   = FlowTracker()
        self.talkers = TopTalkers()
        self.alerts  = AlertEngine()
        _log('ts,proto,src,dst,sport,dport,info,alert')

    # ── Soket ────────────────────────────────────────────────────
    def start(self):
        try:
            self.sock = usocket.socket(
                usocket.AF_INET, usocket.SOCK_RAW, usocket.IPPROTO_IP)
            self.sock.settimeout(0)
            self.sock.bind(('', 0))
            self.poller = uselect.poll()
            self.poller.register(self.sock, uselect.POLLIN)
            return True
        except Exception:
            self.sock = None
            return False

    def stop(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass
            self.sock = None

    # ── Filtre ───────────────────────────────────────────────────
    def set_filter(self, idx):
        if 0 <= idx < len(FILTERS):
            self.filter_idx = idx

    def next_filter(self):
        self.filter_idx = (self.filter_idx + 1) % len(FILTERS)
        return FILTERS[self.filter_idx]

    def current_filter(self):
        return FILTERS[self.filter_idx]

    def _filter_ok(self, proto):
        f = FILTERS[self.filter_idx]
        if f == 'ALL':   return True
        if f == 'ALERT': return True   # alert modunda her şeyi geç, sonra filtrele
        return f == proto

    # ── İstatistik ───────────────────────────────────────────────
    def get_stats(self):
        return dict(
            self.stats,
            total    = self.total,
            filter   = FILTERS[self.filter_idx],
            flows    = self.flows.active_count(),
            alerts   = self.alerts.alert_count(),
        )

    # ── Ana paket işleme ─────────────────────────────────────────
    def next_packet(self, timeout_ms=50):
        """
        Bir sonraki paketi okur, parse eder ve dict döner.
        Paket yoksa veya filtreden geçemezse None döner.

        Dönen dict anahtarları:
        {
          'ts'       : int   — utime.ticks_ms()
          'proto'    : str   — TCP/UDP/ICMP/ARP/HTTP/DNS
          'src_ip'   : str
          'dst_ip'   : str
          'src_port' : int
          'dst_port' : int
          'src_svc'  : str   — servis adı
          'dst_svc'  : str
          'flags'    : str   — SYN|ACK|FIN...
          'ttl'      : int
          'window'   : int   — TCP window size
          'os_guess' : str   — Passive OS fingerprint
          'info'     : str   — özet bilgi
          'http'     : dict  — HTTP parse (varsa)
          'dns'      : dict  — DNS parse (varsa)
          'icmp_type': str   — ICMP türü (varsa)
          'payload_hex': str — İlk 16 byte hex
          'alert'    : str   — saldırı/anomali uyarısı (None ise yok)
          'raw_len'  : int
        }
        """
        if not self.sock:
            return None

        events = self.poller.poll(timeout_ms)
        if not events:
            return None

        try:
            raw = self.sock.recv(SNIFF_BUF_SIZE)
        except Exception:
            return None

        if not raw:
            return None

        ts  = utime.ticks_ms()
        pkt = {
            'ts': ts, 'raw_len': len(raw),
            'src_port': 0, 'dst_port': 0,
            'src_svc': '', 'dst_svc': '',
            'flags': '', 'ttl': 0, 'window': 0,
            'os_guess': '', 'info': '',
            'http': None, 'dns': None, 'icmp_type': '',
            'payload_hex': '', 'alert': None,
        }

        # ── IPv4 ─────────────────────────────────────────────────
        ip = parse_ipv4(raw)
        if ip:
            pkt['src_ip'] = ip['src_ip']
            pkt['dst_ip'] = ip['dst_ip']
            pkt['ttl']    = ip['ttl']

            if ip['protocol'] == IP_PROTO_TCP:
                tcp = parse_tcp(ip['payload'])
                if not tcp: return None
                sp, dp     = tcp['src_port'], tcp['dst_port']
                is_http    = sp in (80, 8080) or dp in (80, 8080)
                proto      = 'HTTP' if is_http else 'TCP'

                if not self._filter_ok(proto): return None
                self.stats[proto] += 1

                pkt['proto']    = proto
                pkt['src_port'] = sp; pkt['dst_port'] = dp
                pkt['src_svc']  = _port(sp); pkt['dst_svc'] = _port(dp)
                pkt['flags']    = tcp['flags_str']
                pkt['window']   = tcp['window']
                pkt['os_guess'] = os_fingerprint(ip['ttl'], tcp['window'])
                pkt['payload_hex'] = _hex_preview(tcp['payload'])

                if is_http and tcp['payload']:
                    http = sniff_http(tcp['payload'])
                    pkt['http'] = http
                    if http:
                        method = http.get('method', http.get('response', ''))
                        path   = http.get('path', '')
                        host   = http.get('host', '')
                        pkt['info'] = '{} {} {}'.format(method, host, path).strip()
                    else:
                        pkt['info'] = tcp['flags_str']
                else:
                    pkt['info'] = tcp['flags_str']

                # Flow tracker
                self.flows.update(ip['src_ip'], sp, ip['dst_ip'], dp,
                                   tcp['flags'], len(raw))

            elif ip['protocol'] == IP_PROTO_UDP:
                udp = parse_udp(ip['payload'])
                if not udp: return None
                sp, dp  = udp['src_port'], udp['dst_port']
                is_dns  = sp == 53 or dp == 53
                proto   = 'DNS' if is_dns else 'UDP'

                if not self._filter_ok(proto): return None
                self.stats[proto] += 1

                pkt['proto']    = proto
                pkt['src_port'] = sp; pkt['dst_port'] = dp
                pkt['src_svc']  = _port(sp); pkt['dst_svc'] = _port(dp)
                pkt['payload_hex'] = _hex_preview(udp['payload'])

                if is_dns:
                    dns = sniff_dns(udp['payload'])
                    pkt['dns']  = dns
                    pkt['info'] = '{} {} {}'.format(
                        'Q' if dns and dns.get('query') else 'R',
                        dns.get('domain','') if dns else '',
                        dns.get('qtype','')  if dns else '').strip() if dns else 'DNS'
                else:
                    pkt['info'] = '{}→{}'.format(_port(sp), _port(dp))

            elif ip['protocol'] == IP_PROTO_ICMP:
                self.stats['ICMP'] += 1
                if not self._filter_ok('ICMP'): return None
                icmp = parse_icmp(ip['payload'])
                pkt['proto']     = 'ICMP'
                pkt['icmp_type'] = icmp['type_str'] if icmp else 'ICMP'
                pkt['info']      = '{} TTL={}'.format(
                    icmp['type_str'] if icmp else '', ip['ttl'])

            else:
                self.stats['OTHER'] += 1
                return None

        # ── ARP ──────────────────────────────────────────────────
        elif len(raw) >= 14:
            etype = ustruct.unpack('!H', raw[12:14])[0]
            if etype == ETHERTYPE_ARP:
                arp = parse_arp(raw[14:])
                if not arp: return None
                self.stats['ARP'] += 1
                if not self._filter_ok('ARP'): return None
                pkt['proto']   = 'ARP'
                pkt['src_ip']  = arp['sender_ip']
                pkt['dst_ip']  = arp['target_ip']
                pkt['src_mac'] = arp['sender_mac']
                pkt['info']    = '{} {}→{}'.format(
                    arp['op_str'], arp['sender_mac'], arp['target_ip'])
            else:
                self.stats['OTHER'] += 1
                return None
        else:
            self.stats['OTHER'] += 1
            return None

        # ── Top talkers + Alert ───────────────────────────────────
        self.talkers.update(
            pkt.get('src_ip',''), pkt.get('dst_ip',''), len(raw))

        alert = self.alerts.check(pkt)
        pkt['alert'] = alert

        # ALERT filtresi: sadece alert olan paketleri geçir
        if FILTERS[self.filter_idx] == 'ALERT' and not alert:
            return None

        self.total += 1
        _log('{},{},{},{},{},{},{},{}'.format(
            ts, pkt.get('proto','?'),
            pkt.get('src_ip',''), pkt.get('dst_ip',''),
            pkt.get('src_port',''), pkt.get('dst_port',''),
            pkt.get('info','')[:60], alert or ''))

        return pkt


# ── Standalone demo ──────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 50)
    print('   ADVANCED PACKET SNIFFER — CyberTerm')
    print('=' * 50)

    # ── Parser testleri ──
    print('\n[1] IPv4 + TCP SYN (Windows fingerprint):')
    raw_tcp = bytes([
        0x45,0x00,0x00,0x2C, 0x00,0x01,0x40,0x00,
        0x80,0x06,0x00,0x00,          # TTL=128 (Windows)
        192,168,1,100, 93,184,216,34,
        0x1F,0x90, 0x00,0x50,         # src=8080 dst=80
        0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00,
        0x50,0x02, 0xFA,0xF0,         # SYN, window=64240 → Win10
        0x00,0x00, 0x00,0x00,
    ])
    ip  = parse_ipv4(raw_tcp)
    tcp = parse_tcp(ip['payload'])
    print('  OS Guess:', os_fingerprint(ip['ttl'], tcp['window']))
    print('  Flags:   ', tcp['flags_str'])

    print('\n[2] HTTP sniff:')
    fake_http = b'GET /login HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpwYXNz\r\nCookie: session=abc123\r\n\r\n'
    http = sniff_http(fake_http)
    for k,v in (http or {}).items():
        print('  {:15} {}'.format(k+':', v))

    print('\n[3] DNS query: example.com')
    dns_pkt = bytes([
        0x12,0x34, 0x01,0x00, 0x00,0x01,
        0x00,0x00, 0x00,0x00, 0x00,0x00,
        7,101,120,97,109,112,108,101,
        3,99,111,109, 0,
        0x00,0x01, 0x00,0x01,
    ])
    dns = sniff_dns(dns_pkt)
    print('  Domain:', dns['domain'], '| Type:', dns['qtype'],
          '| Query:', dns['query'])

    print('\n[4] AlertEngine tests:')
    ae = AlertEngine()
    test_pkts = [
        {'proto':'TCP','src_ip':'10.0.0.1','dst_ip':'10.0.0.2',
         'dst_port':23,'src_port':54321,'flags':'SYN','info':''},   # Telnet
        {'proto':'HTTP','src_ip':'10.0.0.1','dst_ip':'10.0.0.2',
         'flags':'ACK','info':'authorization: Basic abc'},           # HTTP creds
        {'proto':'TCP','src_ip':'10.0.0.1','dst_ip':'10.0.0.2',
         'flags':'-','info':'','dst_port':80,'src_port':1234},       # NULL scan
    ]
    for p in test_pkts:
        p.setdefault('dst_port',80); p.setdefault('src_port',1234)
        a = ae.check(p)
        if a: print(' ', a)

    # SYN scan simülasyonu
    for i in range(20):
        ae.check({'proto':'TCP','src_ip':'192.168.1.99',
                  'dst_ip':'192.168.1.1','flags':'SYN',
                  'dst_port':i,'src_port':54321,'info':''})
    r = ae.recent_alerts(3)
    print('\n  Recent alerts:')
    for ts,lvl,msg in r:
        print('   [{}] {}'.format(lvl,msg))

    print('\n[5] FlowTracker + TopTalkers:')
    ft = FlowTracker()
    tt = TopTalkers()
    pairs = [('1.1.1.1','8.8.8.8',80,53,0x02,64),
             ('1.1.1.1','8.8.8.8',80,53,0x10,128),
             ('2.2.2.2','1.1.1.1',443,54321,0x02,96)]
    for s,d,sp,dp,fl,ln in pairs:
        ft.update(s,sp,d,dp,fl,ln)
        tt.update(s,d,ln)
    for flow,info in ft.top_flows(3):
        print('  Flow {} | pkts:{} bytes:{} state:{}'.format(
            flow, info['packets'], info['bytes'], info['state']))
    print('  Top talkers:')
    for ip,pkts,tot in tt.summary(3):
        print('   {:15} {:3} pkts  {:6} bytes'.format(ip, pkts, tot))

    print('\n[*] Ready. Call start() after WiFi connect for live capture.')
    print('    pkt = sniffer.next_packet()  →  dict to your UI layer')
