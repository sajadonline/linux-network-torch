#!/usr/bin/env python3
"""
Torch — MikroTik-style real-time traffic monitor for Linux servers
Usage:
    python3 torch.py              # monitors default bridge (viifbr0)
    python3 torch.py viifv8305    # monitors specific interface
Keys: Q / ESC = quit
"""

import sys, re, time, curses, threading, subprocess

BRIDGE   = "viifbr0"
REFRESH  = 1.0    # rate recalculation interval (seconds)
FLOW_TTL = 30     # seconds before idle flow is removed
TOP_N    = 100    # max flows to keep in display

# ── Port → protocol map ────────────────────────────────────────────────────────
PORT_MAP = {
    # File transfer
    20: "FTP-D",  21: "FTP",    69: "TFTP",   989: "FTPS",  990: "FTPS",
    # Remote access
    22: "SSH",    23: "TELNET", 3389: "RDP",  5900: "VNC",  5901: "VNC",
    # Mail
    25: "SMTP",   110: "POP3",  143: "IMAP",  465: "SMTPS",
   587: "SMTP",   993: "IMAPS", 995: "POP3S",
    # Web
    80: "HTTP",   443: "HTTPS", 8080: "HTTP", 8443: "HTTPS",
   8000: "HTTP",  8888: "HTTP", 8008: "HTTP",
    # DNS / NTP / DHCP
    53: "DNS",    123: "NTP",   67: "DHCP",   68: "DHCP",
    # Directory
   389: "LDAP",   636: "LDAPS", 88: "Kerberos",
    # File sharing
   137: "NetBIOS",138: "NetBIOS",139: "SMB",   445: "SMB",
  2049: "NFS",
    # Databases
  1433: "MSSQL", 1521: "Oracle",3306: "MySQL", 5432: "PgSQL",
  6379: "Redis",  9200: "ES",   9300: "ES",   27017: "Mongo",
 11211: "Memcache",5984:"CouchDB",6432:"PgBouncer",
    # Message queues / streaming
  5672: "AMQP",  5671: "AMQPS",15672:"RabbitMQ",
  9092: "Kafka",  2181:"ZooKeeper",4369:"Erlang",
  1883: "MQTT",   8883: "MQTTS",
    # VPN / tunnels
  1194: "OpenVPN",1701:"L2TP",  1723:"PPTP",
   500: "IKE",   4500: "IPSec", 51820:"WireGuard",
  1080: "SOCKS",  3128:"Squid",
    # Monitoring / infra
   161: "SNMP",   162: "SNMP",  514: "Syslog", 6514:"Syslog",
   199: "SNMP",   179: "BGP",   520: "RIP",    521: "RIPng",
  2055: "NetFlow",6343:"sFlow",
    # Kubernetes / containers
  6443: "k8s-API",10250:"k8s-Kubelet",10255:"k8s-ro",
  2375: "Docker", 2376:"Docker",
    # Voice / video
  5060: "SIP",   5061: "SIPS",  3478:"STUN",   3479:"STUN",
  5349: "TURNS",
    # Misc
   179: "BGP",    194: "IRC",   6667:"IRC",    6697:"IRC",
   873: "rsync",  993: "IMAPS",
  3000: "Grafana",9090:"Prometheus",9100:"node-exp",
  4000: "App",   5000: "App",   7000: "App",
}

# ── Shared state ───────────────────────────────────────────────────────────────
# flows[key] = [bytes_total, bytes_snap, rate_bps, packets, last_seen_monotonic]
flows      = {}
flows_lock = threading.Lock()
stop_event = threading.Event()
status_msg = "starting…"


# ── Protocol detection ─────────────────────────────────────────────────────────

def detect_protocol(full_line, src_port, dst_port, rest):
    """
    Layered protocol detection:
      1. Non-IP frames  (ARP, STP …)
      2. ICMP / ICMPv6 subtypes from tcpdump annotation
      3. Application protocols tcpdump names explicitly (NTP, DHCP, DNS)
      4. Well-known port map
      5. Transport-layer fallback (TCP / UDP)
    """

    # ── 1. Non-IP ─────────────────────────────────────────────────────────────
    if re.match(r'\d+:\d+:\d+\.\d+ ARP', full_line):
        return 'ARP'
    if re.match(r'\d+:\d+:\d+\.\d+ STP', full_line):
        return 'STP'

    # ── 2. ICMP subtypes ──────────────────────────────────────────────────────
    if rest.startswith('ICMP6') or 'icmp6' in rest[:10].lower():
        rl = rest.lower()
        if 'neighbor solicit'  in rl: return 'NDP-NS'
        if 'neighbor advert'   in rl: return 'NDP-NA'
        if 'router solicit'    in rl: return 'NDP-RS'
        if 'router advert'     in rl: return 'NDP-RA'
        if 'echo request'      in rl: return 'PINGv6'
        if 'echo reply'        in rl: return 'PONGv6'
        return 'ICMPv6'

    if rest.startswith('ICMP'):
        rl = rest.lower()
        if 'echo request'   in rl: return 'PING'
        if 'echo reply'     in rl: return 'PONG'
        if 'unreachable'    in rl: return 'ICMP-UNR'
        if 'time exceeded'  in rl: return 'ICMP-TTL'
        if 'redirect'       in rl: return 'ICMP-RDR'
        if 'timestamp'      in rl: return 'ICMP-TS'
        if 'source quench'  in rl: return 'ICMP-SQ'
        return 'ICMP'

    # ── 3. Protocols tcpdump names in the payload annotation ──────────────────
    if 'NTPv' in rest:
        if 'Client' in rest: return 'NTP-Q'
        if 'Server' in rest: return 'NTP-R'
        return 'NTP'

    if 'BOOTP' in rest or 'DHCP' in rest:
        if 'Request' in rest: return 'DHCP-REQ'
        if 'Reply'   in rest: return 'DHCP-REP'
        return 'DHCP'

    # DNS — tcpdump always annotates queries/responses for port 53
    if src_port == 53 or dst_port == 53:
        # Query: ends with "? domain. (N)" pattern
        if re.search(r'(A{1,4}|MX|NS|PTR|SOA|TXT|SRV|CNAME)\?', rest):
            m = re.search(r'(A{1,4}|MX|NS|PTR|SOA|TXT|SRV|CNAME)\? (\S+)', rest)
            qtype = m.group(1) if m else ''
            return f'DNS-{qtype}' if qtype else 'DNS-Q'
        return 'DNS-R'

    # BGP — tcpdump annotates BGP UPDATE, OPEN, KEEPALIVE
    if 'BGP' in rest[:10]:
        for t in ('UPDATE', 'OPEN', 'KEEPALIVE', 'NOTIFICATION'):
            if t in rest: return f'BGP-{t[:3]}'
        return 'BGP'

    # OSPF
    if 'OSPFv' in rest or rest.startswith('OSPFv'):
        return 'OSPF'

    # STP / LLDP / CDP (layer-2, rare on tcpdump IP lines but check anyway)
    if 'LLDP' in rest[:10]: return 'LLDP'

    # ── 4. Port-based ─────────────────────────────────────────────────────────
    for p in (dst_port, src_port):
        if p and p in PORT_MAP:
            return PORT_MAP[p]

    # Heuristic: high ephemeral ports with TCP → likely app data
    # ── 5. Transport fallback ─────────────────────────────────────────────────
    if 'Flags' in rest:
        # Show TCP flag combo for low-data control flows
        m = re.search(r'Flags \[([^\]]+)\]', rest)
        if m:
            flags = m.group(1)
            if flags == 'S':   return 'TCP-SYN'
            if flags == 'R':   return 'TCP-RST'
            if flags == 'F.':  return 'TCP-FIN'
            if flags == 'S.':  return 'TCP-SYN'
        return 'TCP'

    if 'UDP' in rest[:10]:
        return 'UDP'

    return 'OTHER'


def parse_tcpdump_line(line):
    """Return (src_ip, src_port, dst_ip, dst_port, proto, length) or None."""
    # Non-IP frames (ARP etc.)
    m_arp = re.match(r'\d+:\d+:\d+\.\d+ ARP.*length (\d+)', line)
    if m_arp:
        length = int(m_arp.group(1))
        src_m = re.search(r'tell (\S+),', line)
        dst_m = re.search(r'who-has (\S+)', line)
        src_ip = src_m.group(1) if src_m else 'ARP-src'
        dst_ip = dst_m.group(1) if dst_m else 'ARP-dst'
        return src_ip, 0, dst_ip, 0, 'ARP', length

    m = re.match(r'\d+:\d+:\d+\.\d+ (IP6?) (\S+) > (\S+): (.+)', line)
    if not m:
        return None

    _ver, src_raw, dst_raw, rest = m.groups()
    dst_raw = dst_raw.rstrip(':')

    def split_addr(raw):
        parts = raw.split('.')
        if len(parts) == 5 and parts[-1].isdigit():
            return '.'.join(parts[:4]), int(parts[-1])
        bm = re.match(r'\[?([0-9a-f:]+)\]?\.(\d+)$', raw)
        if bm:
            return bm.group(1), int(bm.group(2))
        return raw, 0

    src_ip, src_port = split_addr(src_raw)
    dst_ip, dst_port = split_addr(dst_raw)

    proto = detect_protocol(line, src_port, dst_port, rest)

    m_len = re.search(r'length (\d+)', rest)
    length = int(m_len.group(1)) if m_len else 64

    return src_ip, src_port, dst_ip, dst_port, proto, length


# ── tcpdump process ────────────────────────────────────────────────────────────

def run_tcpdump(iface):
    global status_msg
    status_msg = f"capturing on {iface}…"
    cmd = ["tcpdump", "-i", iface, "-nn", "-l"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1
    )
    try:
        for line in proc.stdout:
            if stop_event.is_set():
                break
            yield line.rstrip()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def capture_worker(iface):
    for line in run_tcpdump(iface):
        parsed = parse_tcpdump_line(line)
        if not parsed:
            continue
        src_ip, src_port, dst_ip, dst_port, proto, length = parsed
        key = (src_ip, src_port, dst_ip, dst_port, proto)
        now = time.monotonic()
        with flows_lock:
            if key not in flows:
                flows[key] = [0, 0, 0.0, 0, now]
            f = flows[key]
            f[0] += length
            f[3] += 1
            f[4] = now


def rate_worker():
    while not stop_event.wait(REFRESH):
        now = time.monotonic()
        with flows_lock:
            stale = []
            for key, f in flows.items():
                f[2] = (f[0] - f[1]) / REFRESH
                f[1] = f[0]
                if now - f[4] > FLOW_TTL:
                    stale.append(key)
            for k in stale:
                del flows[k]


# ── Display ────────────────────────────────────────────────────────────────────

def fmt_rate(bps):
    if bps >= 1_048_576:
        return f"{bps/1_048_576:7.2f} MB/s"
    if bps >= 1024:
        return f"{bps/1024:7.1f} KB/s"
    return f"{bps:7.0f}  B/s"


def proto_color(proto):
    p = proto.upper()
    if p in ('HTTP', 'HTTPS', 'HTTP-ALT'):          return 3   # green
    if p.startswith('DNS'):                          return 4   # yellow
    if p in ('DHCP', 'DHCP-REQ', 'DHCP-REP'):       return 4   # yellow
    if p in ('NTP', 'NTP-Q', 'NTP-R'):              return 4   # yellow
    if p.startswith('ICMP') or p in ('PING','PONG','PINGv6','PONGv6'): return 5  # red
    if p.startswith('NDP'):                          return 5   # red
    if p in ('SSH', 'OPENVRPN', 'WIREGUARD', 'PPTP', 'L2TP', 'IKE', 'IPSEC',
             'OPENVPN', 'WireGuard'):               return 7   # magenta
    if 'VPN' in p or p in ('SOCKS', 'SQUID'):       return 7   # magenta
    if p in ('BGP', 'OSPF', 'RIP', 'NDP-RA', 'NDP-RS'): return 6  # cyan
    if p.startswith('TCP-'):                         return 8   # dim
    if p in ('ARP', 'STP', 'LLDP'):                 return 8   # dim
    return 0   # default


def draw_ui(stdscr, iface):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK,   curses.COLOR_CYAN)   # header/footer bg
    curses.init_pair(2, curses.COLOR_CYAN,    -1)                  # column titles
    curses.init_pair(3, curses.COLOR_GREEN,   -1)                  # HTTP/HTTPS
    curses.init_pair(4, curses.COLOR_YELLOW,  -1)                  # DNS/DHCP/NTP
    curses.init_pair(5, curses.COLOR_RED,     -1)                  # ICMP/PING
    curses.init_pair(6, curses.COLOR_CYAN,    -1)                  # routing
    curses.init_pair(7, curses.COLOR_MAGENTA, -1)                  # VPN/SSH
    curses.init_pair(8, curses.COLOR_WHITE,   -1)                  # dim/control

    stdscr.nodelay(True)

    while not stop_event.is_set():
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q'), 27):
            stop_event.set()
            break

        h, w = stdscr.getmaxyx()
        stdscr.erase()

        # Header
        hdr = f" TORCH  iface={iface}  {time.strftime('%Y-%m-%d %H:%M:%S')}  [Q] quit "
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(0, 0, hdr.ljust(w)[:w - 1])
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        # Column headers
        col_hdr = f"{'SRC IP:PORT':<24}  {'DST IP:PORT':<24}  {'PROTOCOL':<12}  {'RATE':>14}  {'PKTS':>10}"
        stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(1, 0, col_hdr[:w - 1])
        stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(2, 0, ('─' * (w - 1))[:w - 1])

        # Flow rows
        with flows_lock:
            snapshot = sorted(flows.items(), key=lambda x: x[1][2], reverse=True)

        total_bps = sum(f[2] for _, f in snapshot)
        row = 3
        for (src, sport, dst, dport, proto), f in snapshot:
            if row >= h - 2:
                break
            bps  = f[2]
            pkts = f[3]
            src_col = f"{src}:{sport}" if sport else src
            dst_col = f"{dst}:{dport}" if dport else dst
            cp   = curses.color_pair(proto_color(proto))
            line = f"{src_col:<24}  {dst_col:<24}  {proto:<12}  {fmt_rate(bps):>14}  {pkts:>10,}"
            stdscr.attron(cp)
            try:
                stdscr.addstr(row, 0, line[:w - 1])
            except curses.error:
                pass
            stdscr.attroff(cp)
            row += 1

        # Footer
        foot = (
            f"  Total: {fmt_rate(total_bps)}  │  "
            f"Flows: {len(snapshot)}  │  {status_msg}  "
        )
        stdscr.attron(curses.color_pair(1))
        try:
            stdscr.addstr(h - 1, 0, foot.ljust(w)[:w - 1])
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(1))

        stdscr.refresh()
        time.sleep(0.5)


def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else BRIDGE

    t_cap  = threading.Thread(target=capture_worker, args=(iface,), daemon=True)
    t_rate = threading.Thread(target=rate_worker,    daemon=True)
    t_cap.start()
    t_rate.start()

    try:
        curses.wrapper(lambda s: draw_ui(s, iface))
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
