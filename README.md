# linux-network-torch

A real-time, MikroTik Torch-style network traffic monitor for Linux servers.  
Runs directly on the server using `tcpdump` — no agents, no dependencies beyond Python 3 stdlib.

![Python](https://img.shields.io/badge/python-3.6%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Live traffic table** — refreshes every 0.5 s with per-flow bandwidth rates
- **Accurate total bandwidth** — reads directly from `/proc/net/dev` (kernel counters), immune to tcpdump packet drops
- **Sampled flow breakdown** — tcpdump identifies per-flow src/dst/protocol with high-throughput settings (`-B 65536 -s 96`)
- **IFACE column** — interface shown on every flow row
- **Auto interface detection** — detects the default route interface on startup; pass an interface name to override
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
# auto-detect default route interface and start immediately
python3 torch.py

# monitor a specific interface
python3 torch.py eth0
python3 torch.py viifbr0
python3 torch.py viifv8305
```

Press **Q** or **ESC** to quit.

## Display

```
 TORCH  iface=viifbr0  2026-04-29 11:42:05  [Q] quit
IFACE           SRC IP:PORT               DST IP:PORT               PROTOCOL       RATE          PKTS
──────────────────────────────────────────────────────────────────────────────────────────────────────
viifbr0         203.0.113.10:443          198.51.100.5:54812        HTTPS           2.18 MB/s   82,341
viifbr0         198.51.100.5:51234        203.0.113.20:443          HTTPS           1.74 MB/s   44,210
viifbr0         8.8.8.8:53               198.51.100.5:45231         DNS-R         120.3 KB/s    9,800
viifbr0         198.51.100.5:45231       8.8.8.8:53                 DNS-A          45.1 KB/s    4,200
viifbr0         198.51.100.5:0           192.0.2.1:0                PING            0.5 KB/s       12
──────────────────────────────────────────────────────────────────────────────────────────────────────
  Actual: 193.45 MB/s  │  Sampled: 87.20 MB/s  │  sampled 45%  │  Flows: 28  │  capturing on viifbr0…
```

### Footer explained

| Field | Source | Description |
|-------|--------|-------------|
| **Actual** | `/proc/net/dev` | True wire bandwidth — always accurate, never drops |
| **Sampled** | tcpdump | Bandwidth visible to the flow table |
| **sampled %** | ratio | How much of the traffic tcpdump managed to capture |
| **Flows** | tcpdump | Number of active flows in the table |

> On high-traffic bridge interfaces (100+ Mbit/s with thousands of flows), tcpdump may sample only a fraction of packets. The **Actual** figure always reflects real throughput.

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
