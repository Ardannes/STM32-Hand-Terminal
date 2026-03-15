# packet_sniffer/ — Ağ Paket Yakalayıcı

## Mimari

STM32 + ESP32 dual-MCU mimarisi ile çalışır:

| Modül | Görev |
|-------|-------|
| **ESP32** (`sniffer_tools.h/cpp`) | WiFi promiscuous mode, raw 802.11 frame yakalama, IPv4/TCP/UDP/ICMP/ARP/HTTP/DNS parse, alert engine, flow tracking, OS fingerprinting |
| **STM32** (`main.py → ESP32UARTSniffer`) | UART üzerinden parsed data alma, OLED/LCD'de gösterim, kullanıcı input yönetimi |

## UART Komutları (STM32 → ESP32)

| Komut | Açıklama |
|-------|----------|
| `CMD:SNIFFER_START` | Promiscuous mode başlat |
| `CMD:SNIFFER_STOP` | Durdur |
| `CMD:SNIFFER_FILTER` | Filtre döngüsü (ALL→TCP→UDP→...→ALERT) |
| `CMD:SNIFFER_FILTER:N` | Belirli filtre seç (0-7) |
| `CMD:SNIFFER_STATS` | İstatistik iste |
| `CMD:SNIFFER_FLOWS` | Aktif TCP flow'ları iste |
| `CMD:SNIFFER_TALKERS` | Top talker'ları iste |
| `CMD:SNIFFER_ALERTS` | Son alert'leri iste |

## ESP32 → STM32 Çıktı Formatı

```
[PKT] TCP|192.168.1.5:443|10.0.0.1:54321|SYN|ACK|TTL64|info
[STATS] total:150|tcp:80|udp:40|icmp:5|arp:10|http:10|dns:5|flows:3|alerts:1
[FLOW] 192.168.1.5:443>10.0.0.1:54321|ESTAB|pkts:42|bytes:8192
[TALK] 192.168.1.5|pkts:120|bytes:65536
[ALRT] [HIGH] SYN Scan from 10.0.0.99
```

## Alert Kuralları

- **ARP Spoofing** — IP'ye bağlı MAC değişimi (CRITICAL)
- **SYN Scan** — Tek IP'den >15 SYN (HIGH)
- **Port Scan** — Tek IP'den >10 farklı port (HIGH)
- **NULL / XMAS Scan** — Anormal TCP flag'lar (HIGH)
- **ICMP Flood** — >20 ICMP/s tek IP'den (HIGH)
- **HTTP Credential Leak** — Authorization header tespiti (HIGH)
- **Telnet** — Şifresiz protokol kullanımı (MEDIUM)
- **DNS Tunnel** — >50 karakter domain şüphesi (MEDIUM)

## STM32 Kullanımı

```python
from packet_sniffer.main import ESP32UARTSniffer

sniffer = ESP32UARTSniffer(uart_id=3, tx_pin='PD8', rx_pin='PD9')
sniffer.start()

while True:
    pkt = sniffer.next_packet()
    if pkt:
        print(pkt['proto'], pkt['src_ip'], '→', pkt['dst_ip'], pkt['info'])
```
