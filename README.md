# linux-network-torch

A real-time, MikroTik Torch-style network traffic monitor for Linux servers.  
Runs directly on the server using `tcpdump` — no agents, no dependencies beyond Python 3 stdlib.

![Python](https://img.shields.io/badge/python-3.6%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Live traffic table** — refreshes every 0.5 s with per-flow bandwidth rates
- **Precise protocol detection** — content-first parsing of tcpdump annotations, falls back to 60+ well-known port mappings
- **ICMP subtypes** — `PING`, `PONG`, `ICMP-TTL`, `ICMP-UNR`, `ICMP-RDR` …
- **DNS query types** — `DNS-A`, `DNS-AAAA`, `DNS-MX`, `DNS-PTR`, `DNS-R` …
- **NTP / DHCP direction** — `NTP-Q`/`NTP-R`, `DHCP-REQ`/`DHCP-REP`
- **IPv6 NDP** — `NDP-NS`, `NDP-NA`, `NDP-RS`, `NDP-RA`
- **Routing protocols** — `BGP-UPD/OPE/KEE`, `OSPF`
- **VPN / tunnel protocols** — OpenVPN, WireGuard, IPSec, L2TP, PPTP, SOCKS
- **Port numbers shown** — every flow displayed as `IP:port → IP:port`
- **Color coded** by protocol family
- **Auto-cleanup** — idle flows removed after 30 s

## Requirements

- Python 3.6+
- `tcpdump` installed on the server
- Run as root (or with `CAP_NET_RAW`)

## Installation

```bash
# copy to server
scp torch.py root@<server>:/home/torch.py

# or clone
git clone https://github.com/sajadonline/linux-network-torch.git
cd linux-network-torch
```

## Usage

```bash
# monitor default bridge (viifbr0) — shows all VM traffic
python3 torch.py

# monitor a specific interface
python3 torch.py eth0
python3 torch.py viifv8305
python3 torch.py viifbr0
```

Press **Q** or **ESC** to quit.

## Display

```
 TORCH  iface=viifv8305  2026-04-28 10:22:01  [Q] quit
SRC IP:PORT               DST IP:PORT               PROTOCOL       RATE          PKTS
──────────────────────────────────────────────────────────────────────────────────────
203.0.113.10:443          198.51.100.5:54812         HTTPS          2235.4 KB/s   82,341
198.51.100.5:51234        203.0.113.20:443            HTTPS          1775.8 KB/s   44,210
8.8.8.8:53                198.51.100.5:45231          DNS-R           120.3 KB/s    9,800
198.51.100.5:45231        8.8.8.8:53                  DNS-A            45.1 KB/s    4,200
198.51.100.5:0            192.0.2.1:0                 PING              0.5 KB/s       12
──────────────────────────────────────────────────────────────────────────────────────
  Total:   4.2 MB/s  │  Flows: 28  │  capturing on viifv8305…
```

## Protocol Color Codes

| Color   | Protocols |
|---------|-----------|
| Green   | HTTP, HTTPS |
| Yellow  | DNS, DHCP, NTP |
| Red     | ICMP, PING, PONG, ICMPv6, NDP |
| Magenta | SSH, OpenVPN, WireGuard, IPSec, PPTP, L2TP, SOCKS |
| Cyan    | BGP, OSPF, routing protocols |
| White   | TCP, UDP, and all others |

## Supported Protocols (port map)

FTP, SSH, Telnet, SMTP, DNS, DHCP, TFTP, HTTP, POP3, IMAP, SNMP, BGP, LDAP,
HTTPS, SMB, NFS, MSSQL, Oracle, MySQL, PostgreSQL, Redis, Elasticsearch,
MongoDB, Memcached, AMQP/RabbitMQ, Kafka, MQTT, OpenVPN, WireGuard, IPSec,
L2TP, PPTP, SOCKS, Squid, RDP, VNC, SIP, STUN, Syslog, NetFlow, sFlow,
Kubernetes API, Docker, Grafana, Prometheus, Node Exporter, and more.

## License

MIT
