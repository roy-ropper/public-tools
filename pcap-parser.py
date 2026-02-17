#!/usr/bin/env python3
"""
pcap_to_drawio.py  v4.0  — Pentester Edition
----------------------------------------------
Converts a .pcap / .pcapng file into:

  1. draw.io diagram  (.drawio)
       - Subnet swim-lane containers, Cisco icons, role colours
       - Hostname / IP / MAC on each node
       - NO connector lines  — diagram is a clean host inventory
       - Pentest flags on nodes (cleartext, suspicious ports, etc.)

  2. Excel workbook   (.xlsx)  — pivot-ready, 5 sheets:
       • Connections      — every conversation (src→dst, proto, port, resource)
       • Node Summary     — per-host: role, OS guess, open ports, risk flags
       • Protocol Summary — proto breakdown
       • Pentest Findings — flagged events: cleartext, suspicious, ARP anomalies,
                            unusual outbound, beaconing, sensitive services
       • Port Inventory   — passive open-port map per host

Usage:
    python3 pcap_to_drawio.py capture.pcap
    python3 pcap_to_drawio.py capture.pcap -o out.drawio --xlsx out.xlsx
    python3 pcap_to_drawio.py capture.pcap --min-packets 3 --collapse-external
    python3 pcap_to_drawio.py capture.pcap --hostname-file hosts.txt

    hosts.txt format:
        192.168.1.1   router
        10.0.1.10     web-server-1

Dependencies: Python 3.6+ stdlib  +  openpyxl  (pip install openpyxl)
"""

import struct, socket, ipaddress, argparse, sys, math, os, re
from collections import defaultdict
from xml.dom import minidom
import xml.etree.ElementTree as ET

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

PCAP_MAGIC_LE    = 0xA1B2C3D4
PCAP_MAGIC_BE    = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC     = 0x0A0D0D0A
ETH_TYPE_IP      = 0x0800
ETH_TYPE_IP6     = 0x86DD
ETH_TYPE_ARP     = 0x0806
PROTO_TCP        = 6
PROTO_UDP        = 17
PROTO_ICMP       = 1
PROTO_ICMP6      = 58

WELL_KNOWN = {
    ("TCP",20):"FTP-data", ("TCP",21):"FTP",    ("TCP",22):"SSH",
    ("TCP",23):"Telnet",   ("TCP",25):"SMTP",   ("TCP",53):"DNS",
    ("TCP",80):"HTTP",     ("TCP",110):"POP3",  ("TCP",143):"IMAP",
    ("TCP",389):"LDAP",    ("TCP",443):"HTTPS", ("TCP",445):"SMB",
    ("TCP",636):"LDAPS",   ("TCP",993):"IMAPS", ("TCP",995):"POP3S",
    ("TCP",1433):"MSSQL",  ("TCP",3306):"MySQL",("TCP",3389):"RDP",
    ("TCP",5432):"PostgreSQL",("TCP",5900):"VNC",("TCP",6379):"Redis",
    ("TCP",8080):"HTTP-alt",  ("TCP",8443):"HTTPS-alt",
    ("TCP",27017):"MongoDB",  ("TCP",4444):"Metasploit?",
    ("TCP",4445):"Metasploit?",("TCP",31337):"BackOrifice?",
    ("UDP",53):"DNS",   ("UDP",67):"DHCP",  ("UDP",68):"DHCP",
    ("UDP",69):"TFTP",  ("UDP",123):"NTP",  ("UDP",137):"NetBIOS",
    ("UDP",138):"NetBIOS",("UDP",161):"SNMP",("UDP",162):"SNMP-trap",
    ("UDP",500):"IKE",  ("UDP",514):"Syslog",("UDP",1900):"SSDP",
    ("UDP",4500):"IKE-NAT",("UDP",5353):"mDNS",
}

HTTP_PORTS  = {80, 8080, 8000, 8008}
HTTPS_PORTS = {443, 8443, 4443}

# Pentest: protocols that send credentials in cleartext
CLEARTEXT_PROTOS = {"Telnet","FTP","FTP-data","HTTP","POP3","IMAP",
                    "SMTP","LDAP","SNMP","NetBIOS","TFTP","Syslog"}

# Pentest: interesting/suspicious ports
SUSPICIOUS_PORTS = {
    4444:"Metasploit default", 4445:"Metasploit alt",
    1337:"Leet shell?", 31337:"Back Orifice",
    1234:"Generic backdoor?", 9001:"Tor?", 9050:"Tor proxy",
    6667:"IRC/C2", 6666:"IRC/C2", 6668:"IRC/C2",
    8888:"Alt HTTP / Jupyter", 2222:"Alt SSH",
}

# Pentest: lateral movement indicators
LATERAL_PROTOS = {"SMB","RDP","VNC","NetBIOS","LDAP"}

# TTL → OS guess (coarse)
def _os_from_ttl(ttl):
    if ttl is None:     return "Unknown"
    if ttl <= 64:       return "Linux/Mac"
    if ttl <= 128:      return "Windows"
    if ttl <= 255:      return "Network Device"
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# PCAP / PCAPng parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_pcap(path):
    """Yield enriched packet dicts."""
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian = "<"
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            endian = ">"
        elif magic == PCAPNG_MAGIC:
            yield from _parse_pcapng(path)
            return
        else:
            raise ValueError(f"Unrecognised magic: {magic:#010x}")
        f.read(20)
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _, ts_us, incl_len, _ = struct.unpack(endian + "IIII", rec)
            raw = f.read(incl_len)
            r = _dissect(raw, 1, ts_us)
            if r:
                yield r


def _parse_pcapng(path):
    with open(path, "rb") as f:
        endian = "<"
        ltypes = {}
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            btype, blen = struct.unpack(endian + "II", hdr)
            body = f.read(blen - 12)
            f.read(4)
            if btype == 0x0A0D0D0A:
                endian = "<" if struct.unpack("<I", body[:4])[0] == 0x1A2B3C4D else ">"
            elif btype == 0x00000001:
                ltypes[len(ltypes)] = struct.unpack(endian + "H", body[:2])[0]
            elif btype == 0x00000006:
                iid = struct.unpack(endian + "I", body[:4])[0]
                ts_hi, ts_lo, cap_len, _ = struct.unpack(endian + "IIII", body[4:20])
                r = _dissect(body[20:20+cap_len], ltypes.get(iid,1), ts_lo)
                if r: yield r
            elif btype == 0x00000003:
                cap_len = struct.unpack(endian+"I", body[:4])[0]
                r = _dissect(body[4:4+cap_len], ltypes.get(0,1), 0)
                if r: yield r


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _dissect(raw, ltype, ts_us=0):
    try:
        smac = dmac = "ff:ff:ff:ff:ff:ff"
        if ltype == 1:
            if len(raw) < 14: return None
            dmac  = _mac(raw[0:6])
            smac  = _mac(raw[6:12])
            etype = struct.unpack(">H", raw[12:14])[0]
            off   = 14
            while etype == 0x8100 and off+4 <= len(raw):
                etype = struct.unpack(">H", raw[off+2:off+4])[0]; off += 4
            payload = raw[off:]
        elif ltype in (101,228): etype = ETH_TYPE_IP;  payload = raw
        elif ltype == 229:       etype = ETH_TYPE_IP6; payload = raw
        elif ltype == 113:
            if len(raw) < 16: return None
            etype = struct.unpack(">H", raw[14:16])[0]; payload = raw[16:]
        else:
            return None

        if   etype == ETH_TYPE_IP:  r = _ipv4(payload, ts_us)
        elif etype == ETH_TYPE_IP6: r = _ipv6(payload, ts_us)
        elif etype == ETH_TYPE_ARP: r = _arp(payload)
        else: return None

        if r:
            r["src_mac"] = smac
            r["dst_mac"] = dmac
        return r
    except Exception:
        return None


def _ipv4(d, ts_us):
    if len(d) < 20: return None
    ihl = (d[0] & 0x0F) * 4
    ttl = d[8]
    r = _transport(socket.inet_ntoa(d[12:16]), socket.inet_ntoa(d[16:20]),
                   d[9], d[ihl:], len(d), ts_us)
    if r: r["ttl"] = ttl
    return r


def _ipv6(d, ts_us):
    if len(d) < 40: return None
    r = _transport(socket.inet_ntop(socket.AF_INET6, d[8:24]),
                   socket.inet_ntop(socket.AF_INET6, d[24:40]),
                   d[6], d[40:], len(d), ts_us)
    if r: r["ttl"] = d[7]  # hop limit
    return r


def _arp(d):
    if len(d) < 28: return None
    return dict(src_ip=socket.inet_ntoa(d[14:18]),
                dst_ip=socket.inet_ntoa(d[24:28]),
                src_mac="", dst_mac="",
                src_port=0, dst_port=0, proto="ARP",
                length=len(d), resource="", ttl=None,
                ts_us=0, win_size=0, app_payload=b"",
                # ARP: capture sender MAC for ARP anomaly detection
                arp_sender_mac=_mac(d[8:14]),
                arp_sender_ip=socket.inet_ntoa(d[14:18]))


def _transport(src, dst, proto, data, pkt_len, ts_us):
    sp = dp = win = 0
    resource = ""
    app_payload = b""
    if proto == PROTO_TCP:
        name = "TCP"
        if len(data) >= 4:
            sp, dp = struct.unpack(">HH", data[:4])
            name = WELL_KNOWN.get(("TCP",dp)) or WELL_KNOWN.get(("TCP",sp)) or "TCP"
        if len(data) >= 14:
            win = struct.unpack(">H", data[14:16])[0]
        tcp_hdr_len = ((data[12] >> 4) * 4) if len(data) > 12 else 20
        app_payload = data[tcp_hdr_len:] if len(data) > tcp_hdr_len else b""
        if dp in HTTP_PORTS or sp in HTTP_PORTS:
            resource = _http_host(app_payload)
    elif proto == PROTO_UDP:
        name = "UDP"
        if len(data) >= 4:
            sp, dp = struct.unpack(">HH", data[:4])
            name = WELL_KNOWN.get(("UDP",dp)) or WELL_KNOWN.get(("UDP",sp)) or "UDP"
        app_payload = data[8:] if len(data) > 8 else b""
    elif proto == PROTO_ICMP:  name = "ICMP"
    elif proto == PROTO_ICMP6: name = "ICMPv6"
    else:                      name = f"IP/{proto}"
    return dict(src_ip=src, dst_ip=dst, src_mac="", dst_mac="",
                src_port=sp, dst_port=dp, proto=name,
                length=pkt_len, resource=resource,
                ttl=None, ts_us=ts_us, win_size=win,
                app_payload=app_payload,
                arp_sender_mac=None, arp_sender_ip=None)


def _http_host(payload):
    try:
        text = payload.decode("ascii", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":",1)[1].strip()
    except Exception:
        pass
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Cleartext data / credential extractor
# ─────────────────────────────────────────────────────────────────────────────

import base64 as _b64, re as _re

def extract_cleartext(pkt):
    """
    Inspect application payload for credentials and sensitive data.
    Returns list of dicts: {protocol, type, value, context, src_ip, dst_ip, src_port, dst_port}
    """
    payload = pkt.get("app_payload", b"")
    if not payload:
        return []

    proto  = pkt.get("proto","")
    src_ip = pkt.get("src_ip","")
    dst_ip = pkt.get("dst_ip","")
    sp     = pkt.get("src_port", 0)
    dp     = pkt.get("dst_port", 0)
    found  = []

    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    def hit(typ, value, context=""):
        found.append(dict(protocol=proto, type=typ,
                          value=str(value)[:250], context=str(context)[:350],
                          src_ip=src_ip, dst_ip=dst_ip,
                          src_port=sp, dst_port=dp))

    # ── FTP ────────────────────────────────────────────────────────────────
    if proto in ("FTP", "FTP-data"):
        for line in text.splitlines():
            l = line.strip()
            if _re.match(r"(?i)^USER\s+\S+", l):
                hit("FTP Username", l.split(None,1)[-1], l)
            elif _re.match(r"(?i)^PASS\s+", l):
                hit("FTP Password", l.split(None,1)[-1] if len(l.split()) > 1 else "(empty)", l)

    # ── Telnet ─────────────────────────────────────────────────────────────
    if proto == "Telnet":
        printable = "".join(c for c in text if c.isprintable() or c in "\r\n")
        clean = printable.strip()
        if clean:
            hit("Telnet Keystrokes/Data", clean[:300], f"{src_ip} -> {dst_ip}")

    # ── HTTP ───────────────────────────────────────────────────────────────
    if proto in ("HTTP", "HTTP-alt"):
        lines = text.splitlines()
        req_line = lines[0].strip() if lines else ""

        for line in lines:
            # Basic Auth
            m = _re.match(r"(?i)^Authorization:\s+Basic\s+(\S+)", line)
            if m:
                b64 = m.group(1)
                try:
                    decoded = _b64.b64decode(b64 + "==").decode("utf-8","replace")
                    hit("HTTP Basic Auth (decoded)", decoded, req_line)
                except Exception:
                    hit("HTTP Basic Auth (raw b64)", b64, req_line)

            # Bearer token
            m = _re.match(r"(?i)^Authorization:\s+Bearer\s+(\S+)", line)
            if m:
                hit("HTTP Bearer Token", m.group(1)[:120], req_line)

            # Cookie
            if _re.match(r"(?i)^Cookie:\s+", line):
                hit("HTTP Cookie", line.split(":",1)[-1].strip()[:250], req_line)

            # Proxy-Auth
            if _re.match(r"(?i)^Proxy-Authorization:", line):
                hit("HTTP Proxy Auth", line.split(":",1)[-1].strip(), line.strip())

        # POST body credential fields
        body = text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in text else ""
        if body:
            for field, val in _re.findall(
                    r"(?i)(password|passwd|pwd|pass|secret|token|apikey|api_key|"
                    r"auth|credential|session)=([^&\s]{1,120})", body):
                hit("HTTP POST Credential", f"{field}={val}", req_line)
            for field, val in _re.findall(
                    r'(?i)"(password|passwd|pwd|secret|token|api_?key|auth)"\s*:\s*"([^"]{1,120})"', body):
                hit("HTTP JSON Credential", f"{field}: {val}", req_line)

    # ── SMTP ───────────────────────────────────────────────────────────────
    if proto == "SMTP":
        for line in text.splitlines():
            l = line.strip()
            if _re.match(r"(?i)^AUTH\s+(LOGIN|PLAIN|CRAM)", l):
                hit("SMTP Auth Command", l, f"{src_ip} -> {dst_ip}")
            elif _re.match(r"(?i)^(MAIL FROM|RCPT TO):", l):
                hit("SMTP Email Address", l, "")
            elif _re.match(r"^[A-Za-z0-9+/=]{8,}$", l.strip()):
                try:
                    decoded = _b64.b64decode(l + "==").decode("utf-8","replace")
                    if decoded.isprintable() and len(decoded) >= 3:
                        hit("SMTP Auth (b64 decoded)", decoded, f"raw: {l}")
                except Exception:
                    pass

    # ── POP3 ───────────────────────────────────────────────────────────────
    if proto == "POP3":
        for line in text.splitlines():
            l = line.strip()
            if _re.match(r"(?i)^USER\s+\S+", l):
                hit("POP3 Username", l.split(None,1)[-1], l)
            elif _re.match(r"(?i)^PASS\s+", l):
                hit("POP3 Password", l.split(None,1)[-1] if len(l.split()) > 1 else "(empty)", l)

    # ── IMAP ───────────────────────────────────────────────────────────────
    if proto == "IMAP":
        for line in text.splitlines():
            l = line.strip()
            m = _re.search(r"(?i)LOGIN\s+(\S+)\s+(\S+)", l)
            if m:
                hit("IMAP Login", f"user={m.group(1)}  pass={m.group(2)}", l)

    # ── LDAP simple bind ───────────────────────────────────────────────────
    if proto == "LDAP":
        runs = _re.findall(rb"[\x20-\x7e]{4,}", payload)
        for run in runs:
            s = run.decode("ascii","replace")
            if any(k in s.lower() for k in ("cn=","dc=","ou=","uid=","password","pass")):
                hit("LDAP Bind Data", s, f"{src_ip} -> {dst_ip}")

    # ── SNMP community string ──────────────────────────────────────────────
    if proto == "SNMP":
        runs = _re.findall(rb"[\x20-\x7e]{3,}", payload)
        for run in runs:
            s = run.decode("ascii","replace")
            # Skip obvious non-community OID/version strings
            if s not in ("GET","SET","public","private") and not s.startswith("1.3") and len(s) <= 40:
                hit("SNMP Community String", s, f"{src_ip} -> {dst_ip}:{dp}")
                break

    # ── NetBIOS ────────────────────────────────────────────────────────────
    if proto == "NetBIOS":
        runs = _re.findall(rb"[\x20-\x7e]{4,}", payload)
        for run in runs[:3]:
            hit("NetBIOS Data", run.decode("ascii","replace"), f"{src_ip} -> {dst_ip}")

    # ── Generic API key / secret patterns (any cleartext protocol) ─────────
    if proto in CLEARTEXT_PROTOS and text:
        patterns = [
            (r"(?i)(api[_-]?key|apikey|x-api-key)[\s:=]+([A-Za-z0-9_\-]{16,80})", "API Key"),
            (r"(?i)(access_token|auth_token)[\s:=]+([A-Za-z0-9_.\-]{16,150})",     "Auth Token"),
            (r"(?i)(secret|private_key)[\s:=]+([A-Za-z0-9_.\-/+]{16,80})",         "Secret/Key"),
            (r"(AKIA[0-9A-Z]{16})",                                                   "AWS Access Key"),
            (r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",                  "Private Key"),
        ]
        for pattern, label in patterns:
            for m in _re.findall(pattern, text):
                val = m[-1] if isinstance(m, tuple) else m
                hit(label, val, f"{proto} {src_ip} -> {dst_ip}")

    return found



# ─────────────────────────────────────────────────────────────────────────────
# Graph / enrichment builder
# ─────────────────────────────────────────────────────────────────────────────

def build_graph(packets, min_packets=1, collapse_external=False, extra_hostnames=None):
    """
    Returns nodes, edges, rows, findings
    """
    nodes = defaultdict(lambda: dict(
        count=0, bytes=0, is_private=False, role="client",
        macs=set(), mac_to_ips=defaultdict(set),
        subnet="", hostname="",
        protocols=set(), open_ports=set(),
        ttls=[], win_sizes=[],
        os_guess="Unknown",
        flags=set(),           # pentest flags
        first_seen=None, last_seen=None,
    ))
    edges = defaultdict(lambda: dict(
        count=0, bytes=0, protocols=set(), ports=set(), resources=set(),
        timestamps=[],
    ))
    rows          = []   # raw per-packet rows for Excel connections sheet
    findings      = []   # pentest findings rows
    cleartext_hits = []  # extracted credentials / sensitive data

    FAKE = {"ff:ff:ff:ff:ff:ff","00:00:00:00:00:00",""}

    # ARP table: ip -> set of MACs seen (anomaly detection)
    arp_table = defaultdict(set)
    # Track connections per IP pair over time (beaconing detection)
    conn_times = defaultdict(list)

    for p in packets:
        src, dst = p["src_ip"], p["dst_ip"]
        if collapse_external:
            src = _collapse(src); dst = _collapse(dst)
        if src == dst:
            continue

        smac = p.get("src_mac","")
        dmac = p.get("dst_mac","")

        # ARP anomaly tracking
        if p.get("arp_sender_mac"):
            arp_table[p["arp_sender_ip"]].add(p["arp_sender_mac"])

        if smac and smac not in FAKE:
            nodes[src]["macs"].add(smac)
            nodes[src]["mac_to_ips"][smac].add(src)
        if dmac and dmac not in FAKE:
            nodes[dst]["macs"].add(dmac)
            nodes[dst]["mac_to_ips"][dmac].add(dst)

        nodes[src]["count"] += 1; nodes[src]["bytes"] += p["length"]
        nodes[dst]["count"] += 1; nodes[dst]["bytes"] += p["length"]

        ts = p.get("ts_us", 0)
        for ip in (src, dst):
            if nodes[ip]["first_seen"] is None or ts < nodes[ip]["first_seen"]:
                nodes[ip]["first_seen"] = ts
            if nodes[ip]["last_seen"] is None or ts > nodes[ip]["last_seen"]:
                nodes[ip]["last_seen"] = ts

        if p.get("ttl"):
            nodes[src]["ttls"].append(p["ttl"])
        if p.get("win_size"):
            nodes[src]["win_sizes"].append(p["win_size"])

        proto = p["proto"]
        port  = p["dst_port"] or p["src_port"]

        # Open ports: a host is "listening" if it receives connections on known service ports
        if port and port < 1024:
            nodes[dst]["open_ports"].add(port)
        nodes[dst]["protocols"].add(proto)
        nodes[src]["protocols"].add(proto)

        key = (src, dst)
        edges[key]["count"]    += 1
        edges[key]["bytes"]    += p["length"]
        edges[key]["protocols"].add(proto)
        if port:       edges[key]["ports"].add(port)
        if p.get("resource"): edges[key]["resources"].add(p["resource"])
        conn_times[key].append(ts)

        rows.append(dict(
            src_ip=src, dst_ip=dst,
            src_mac=smac, dst_mac=dmac,
            proto=proto, port=port,
            resource=p.get("resource",""),
            ttl=p.get("ttl"),
        ))

        # Cleartext credential / sensitive data extraction
        hits = extract_cleartext(p)
        cleartext_hits.extend(hits)

    # ── Filter ────────────────────────────────────────────────────────────────
    edges = {k:v for k,v in edges.items() if v["count"] >= min_packets}
    active = {ip for pair in edges for ip in pair}
    nodes  = {k:v for k,v in nodes.items() if k in active}

    # ── Annotate nodes ────────────────────────────────────────────────────────
    for ip, info in nodes.items():
        try:
            addr = ipaddress.ip_address(ip.split("/")[0])
            info["is_private"] = addr.is_private
            info["subnet"] = (str(ipaddress.ip_network(ip+"/24", strict=False))
                              if addr.is_private else "external")
        except ValueError:
            info["is_private"] = False; info["subnet"] = "external"

        info["role"] = _guess_role(ip, edges)

        # OS guess from most common TTL
        if info["ttls"]:
            common_ttl = max(set(info["ttls"]), key=info["ttls"].count)
            info["os_guess"] = _os_from_ttl(common_ttl)
            info["ttl_val"]  = common_ttl
        else:
            info["os_guess"] = "Unknown"
            info["ttl_val"]  = None

        # Pentest flags on node
        if info["protocols"] & CLEARTEXT_PROTOS:
            info["flags"].add("⚠ Cleartext protocol")
        if info["protocols"] & LATERAL_PROTOS and info["is_private"]:
            info["flags"].add("🔴 Lateral movement proto")

    # ── Passive hostname resolution from packet data ─────────────────────────
    passive_hostnames = resolve_hostnames_from_packets(packets)
    # Apply passive names first (lowest priority)
    for ip, hn in passive_hostnames.items():
        if ip in nodes and not nodes[ip]["hostname"]:
            nodes[ip]["hostname"] = hn
    # File-supplied hostnames override passive ones (highest priority)
    if extra_hostnames:
        for ip, hn in extra_hostnames.items():
            if ip in nodes:
                nodes[ip]["hostname"] = hn

    # ── Pentest Findings ──────────────────────────────────────────────────────

    # 1. Cleartext credential protocols
    for (src, dst), info in edges.items():
        ct = info["protocols"] & CLEARTEXT_PROTOS
        if ct:
            for proto in ct:
                findings.append(dict(
                    severity="HIGH",
                    category="Cleartext Protocol",
                    src=src, dst=dst,
                    detail=f"{proto} — credentials/data sent in cleartext",
                    recommendation="Upgrade to encrypted equivalent (SSH, HTTPS, LDAPS, IMAPS…)",
                ))

    # 2. Suspicious ports
    for (src, dst), info in edges.items():
        for port in info["ports"]:
            if port in SUSPICIOUS_PORTS:
                findings.append(dict(
                    severity="HIGH",
                    category="Suspicious Port",
                    src=src, dst=dst,
                    detail=f"Port {port} — {SUSPICIOUS_PORTS[port]}",
                    recommendation="Investigate — possible backdoor, C2, or misconfiguration",
                ))

    # 3. ARP anomalies (same IP, multiple MACs)
    for ip, macs in arp_table.items():
        if len(macs) > 1:
            findings.append(dict(
                severity="CRITICAL",
                category="ARP Anomaly / Possible MITM",
                src=ip, dst="N/A",
                detail=f"IP {ip} seen with MACs: {', '.join(sorted(macs))}",
                recommendation="Investigate for ARP spoofing / MITM attack",
            ))

    # 4. Unusual outbound (internal→external on non-standard ports)
    standard_out = {80,443,53,123,25,465,587,993,995,143,110,22}
    for (src, dst), info in edges.items():
        try:
            src_addr = ipaddress.ip_address(src.split("/")[0])
            dst_addr = ipaddress.ip_address(dst.split("/")[0])
        except ValueError:
            continue
        if src_addr.is_private and not dst_addr.is_private:
            odd_ports = info["ports"] - standard_out
            if odd_ports:
                findings.append(dict(
                    severity="MEDIUM",
                    category="Unusual Outbound",
                    src=src, dst=dst,
                    detail=f"Internal→External on non-standard port(s): {sorted(odd_ports)}",
                    recommendation="Verify legitimate — possible exfil or C2 beaconing",
                ))

    # 5. Beaconing detection (very regular inter-arrival times)
    for (src, dst), times in conn_times.items():
        if len(times) < 6:
            continue
        times_s = sorted(times)
        intervals = [times_s[i+1]-times_s[i] for i in range(len(times_s)-1)]
        intervals = [x for x in intervals if x > 0]
        if not intervals:
            continue
        mean = sum(intervals)/len(intervals)
        if mean == 0:
            continue
        variance = sum((x-mean)**2 for x in intervals)/len(intervals)
        cv = (variance**0.5) / mean  # coefficient of variation
        if cv < 0.15 and len(times) >= 8:  # very regular
            findings.append(dict(
                severity="MEDIUM",
                category="Potential Beaconing",
                src=src, dst=dst,
                detail=(f"{len(times)} connections, avg interval "
                        f"{mean/1e6:.1f}s, CoV={cv:.3f} (very regular)"),
                recommendation="Investigate for C2 callback / malware beaconing",
            ))

    # 6. Internal SMB/lateral movement between workstations
    for (src, dst), info in edges.items():
        if info["protocols"] & {"SMB","RDP","VNC"}:
            try:
                s = ipaddress.ip_address(src.split("/")[0])
                d = ipaddress.ip_address(dst.split("/")[0])
            except ValueError:
                continue
            if s.is_private and d.is_private:
                role_d = nodes.get(dst,{}).get("role","")
                if role_d == "client":   # workstation→workstation
                    findings.append(dict(
                        severity="MEDIUM",
                        category="Lateral Movement Indicator",
                        src=src, dst=dst,
                        detail=f"{', '.join(info['protocols'] & {'SMB','RDP','VNC'})} to a client workstation",
                        recommendation="Verify — unusual for workstations to accept SMB/RDP from peers",
                    ))

    # 7. SNMPv1/v2 (community strings in cleartext at scale)
    snmp_hosts = set()
    for (src, dst), info in edges.items():
        if "SNMP" in info["protocols"]:
            snmp_hosts.add(dst)
    if snmp_hosts:
        findings.append(dict(
            severity="MEDIUM",
            category="SNMP Cleartext",
            src="Multiple", dst=", ".join(sorted(snmp_hosts)[:5]),
            detail=f"SNMPv1/v2 traffic detected ({len(snmp_hosts)} hosts). Community strings in cleartext.",
            recommendation="Migrate to SNMPv3 with authentication and encryption",
        ))

    return nodes, edges, rows, findings, cleartext_hits


def _collapse(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if not addr.is_private:
            return str(ipaddress.ip_network(ip+"/24", strict=False))
    except ValueError:
        pass
    return ip


SERVER_PROTOS = {"HTTP","HTTPS","SSH","SMTP","DNS","MySQL","PostgreSQL","MSSQL",
                 "SMB","LDAP","RDP","HTTP-alt","HTTPS-alt","FTP","VNC",
                 "Redis","MongoDB","IMAP","POP3","SNMP","Syslog","NetBIOS"}


def _guess_role(ip, edges):
    peers = set()
    for s, d in edges:
        if s == ip: peers.add(d)
        elif d == ip: peers.add(s)
    for (s, d), info in edges.items():
        if d == ip and (info["protocols"] & SERVER_PROTOS):
            return "server"
    return "server" if len(peers)>=6 else ("host" if len(peers)>=3 else "client")


def _load_hostname_file(path):
    result = {}
    if not path or not os.path.exists(path): return result
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split(None, 1)
            if len(parts) == 2: result[parts[0]] = parts[1]
    return result



# ─────────────────────────────────────────────────────────────────────────────
# Passive hostname resolver  (DNS / DHCP / mDNS / NetBIOS / HTTP Host)
# ─────────────────────────────────────────────────────────────────────────────

def resolve_hostnames_from_packets(packets):
    """
    Single-pass scan to build ip→hostname from data inside the capture.
    Sources (priority, lower = more trusted):
      1. DNS A/AAAA responses
      2. DHCP Option 12 (client self-reported hostname)
      3. mDNS A/AAAA responses
      4. NetBIOS Name Service registrations
      5. HTTP Host header (lowest — labels the destination only)
    """
    pending = {}   # ip -> (hostname, priority)

    def _set(ip, name, priority):
        name = name.rstrip(".").strip()
        if not name or not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return
        existing = pending.get(ip)
        if existing is None or priority < existing[1]:
            pending[ip] = (name, priority)

    for p in packets:
        proto   = p.get("proto", "")
        payload = p.get("app_payload", b"")
        src_ip  = p.get("src_ip", "")
        dst_ip  = p.get("dst_ip", "")
        dp      = p.get("dst_port", 0)

        if proto in ("DNS", "mDNS") and payload:
            _parse_dns(payload, _set)

        if proto == "DHCP" and payload:
            _parse_dhcp(payload, _set)

        if proto == "NetBIOS" and payload:
            _parse_nbns(payload, src_ip, _set)

        if proto in ("HTTP", "HTTP-alt") and payload:
            try:
                text = payload.decode("ascii", errors="ignore")
                for line in text.split("\r\n"):
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip().split(":")[0]
                        if host and not host.replace(".", "").isdigit():
                            _set(dst_ip, host, 5)
                        break
            except Exception:
                pass

    return {ip: name for ip, (name, _) in pending.items()}


def _parse_dns(data, setter):
    """Parse DNS wire format; extract A/AAAA answer records -> ip -> name."""
    try:
        if len(data) < 12:
            return
        flags    = struct.unpack(">H", data[2:4])[0]
        is_resp  = (flags >> 15) & 1
        qd_count = struct.unpack(">H", data[4:6])[0]
        an_count = struct.unpack(">H", data[6:8])[0]
        if not is_resp or an_count == 0:
            return
        offset = 12
        for _ in range(qd_count):        # skip questions
            offset = _dns_skip_name(data, offset)
            offset += 4
        for _ in range(an_count):        # parse answers
            name, offset = _dns_read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlen]
            offset += rdlen
            if rtype == 1 and rdlen == 4:       # A
                setter(socket.inet_ntoa(rdata), name, 1)
            elif rtype == 28 and rdlen == 16:    # AAAA
                setter(socket.inet_ntop(socket.AF_INET6, rdata), name, 1)
    except Exception:
        pass


def _dns_read_name(data, offset):
    labels = []; jumped = False; orig = offset
    visited = set()
    try:
        while offset < len(data):
            if offset in visited: break
            visited.add(offset)
            ln = data[offset]
            if ln == 0:
                if not jumped: orig = offset + 1
                break
            elif (ln & 0xC0) == 0xC0:
                if offset + 1 >= len(data): break
                ptr = ((ln & 0x3F) << 8) | data[offset+1]
                if not jumped: orig = offset + 2
                offset = ptr; jumped = True
            else:
                offset += 1
                labels.append(data[offset:offset+ln].decode("ascii","replace"))
                offset += ln
    except Exception:
        pass
    return ".".join(labels), orig


def _dns_skip_name(data, offset):
    try:
        while offset < len(data):
            ln = data[offset]
            if ln == 0: return offset + 1
            elif (ln & 0xC0) == 0xC0: return offset + 2
            else: offset += ln + 1
    except Exception:
        pass
    return offset


def _parse_dhcp(data, setter):
    """Extract DHCP Option 12 (Hostname) and correlate with yiaddr/ciaddr."""
    try:
        if len(data) < 240: return
        yiaddr = socket.inet_ntoa(data[16:20])
        ciaddr = socket.inet_ntoa(data[12:16])
        i = 240; hostname = None
        while i < len(data):
            opt = data[i]; i += 1
            if opt == 255: break
            if opt == 0: continue
            if i >= len(data): break
            ln = data[i]; i += 1
            val = data[i:i+ln]; i += ln
            if opt == 12:
                hostname = val.decode("ascii","replace").strip("\x00").strip()
        if hostname:
            for ip in (yiaddr, ciaddr):
                if ip and ip not in ("0.0.0.0","255.255.255.255"):
                    setter(ip, hostname, 2)
    except Exception:
        pass


def _parse_nbns(data, src_ip, setter):
    """Extract NetBIOS name from NBNS registration/response packets."""
    try:
        if len(data) < 12: return
        an_count = struct.unpack(">H", data[6:8])[0]
        qd_count = struct.unpack(">H", data[4:6])[0]
        offset = 12
        for _ in range(qd_count):
            if offset + 35 < len(data): offset += 35
            else: return
        for _ in range(an_count):
            if offset + 33 >= len(data): break
            raw = data[offset+1:offset+33]
            name = _decode_nbns_name(raw).strip()
            if name and name not in ("*", "__MSBROWSE__", ""):
                setter(src_ip, name, 3)
            offset += 46
    except Exception:
        pass


def _decode_nbns_name(raw):
    try:
        chars = []
        for i in range(0, min(len(raw), 30), 2):
            c = ((raw[i] - 0x41) << 4) | (raw[i+1] - 0x41)
            if 0x20 < c < 0x7f:
                chars.append(chr(c))
        return "".join(chars)
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Diagram styles & layout
# ─────────────────────────────────────────────────────────────────────────────

SHAPE_SERVER = "shape=mxgraph.cisco.servers.standard_server;"
SHAPE_PC     = "shape=mxgraph.cisco.computers_and_peripherals.pc;"
SHAPE_CLOUD  = "shape=mxgraph.cisco.storage.cloud;"

ROLE_FILL_STROKE = {
    "server":   ("#dae8fc","#6c8ebf"),
    "host":     ("#d5e8d4","#82b366"),
    "client":   ("#fff2cc","#d6b656"),
    "external": ("#ffe6cc","#d79b00"),
}
FLAG_FILL_STROKE = ("#f8cecc","#b85450")  # red tint for flagged nodes

SUBNET_PALETTES = [
    ("#e8f5e9","#2e7d32"),
    ("#e3f2fd","#1565c0"),
    ("#fce4ec","#c62828"),
    ("#f3e5f5","#6a1b9a"),
    ("#fff8e1","#f57f17"),
    ("#e0f7fa","#00695c"),
    ("#fbe9e7","#bf360c"),
    ("#ede7f6","#4527a0"),
]

# ── Layout constants — wider spacing to prevent MAC overlap ─────────────────
NODE_W        = 72
NODE_H        = 72
NODE_LABEL_H  = 52    # taller: hostname + IP + MAC
NODE_GAP_X    = 90    # ← increased from 50 to 90
NODE_GAP_Y    = 70    # ← increased from 60 to 70
CONT_PAD      = 50    # ← increased from 40 to 50
CONT_TITLE    = 34
CONT_GAP_X    = 70
CONT_GAP_Y    = 55
LEGEND_W      = 185
PAGE_X        = 215
PAGE_Y        = 80
NODES_PER_ROW = 4
CONTS_PER_ROW = 3


def layout(nodes):
    subnets = defaultdict(list)
    for ip, info in nodes.items():
        subnets[info["subnet"]].append(ip)

    def skey(s):
        if s == "external": return (1,"")
        try: return (0, str(ipaddress.ip_network(s)))
        except: return (0,s)

    sorted_subs = sorted(subnets, key=skey)
    containers  = []
    node_pos    = {}
    cx, cy      = PAGE_X, PAGE_Y
    row_max_h   = 0
    col         = 0

    for si, sub in enumerate(sorted_subs):
        ips = subnets[sub]

        def isort(ip):
            r = {"server":0,"host":1,"client":2}.get(nodes[ip]["role"],3)
            try: return (r, int(ipaddress.ip_address(ip.split("/")[0])))
            except: return (r, ip)
        ips.sort(key=isort)

        n     = len(ips)
        ncols = min(n, NODES_PER_ROW)
        nrows = math.ceil(n / NODES_PER_ROW)

        cell_h  = NODE_H + NODE_LABEL_H
        inner_w = ncols * NODE_W + (ncols-1) * NODE_GAP_X
        inner_h = nrows * cell_h + (nrows-1) * NODE_GAP_Y
        cw = inner_w + CONT_PAD*2
        ch = inner_h + CONT_PAD*2 + CONT_TITLE

        for i, ip in enumerate(ips):
            r2, c2 = divmod(i, NODES_PER_ROW)
            nx = cx + CONT_PAD + c2*(NODE_W+NODE_GAP_X) + NODE_W//2
            ny = cy + CONT_TITLE + CONT_PAD + r2*(cell_h+NODE_GAP_Y) + NODE_H//2
            node_pos[ip] = (int(nx), int(ny))

        containers.append(dict(subnet=sub, palette_idx=si,
                               x=cx, y=cy, w=cw, h=ch, ips=ips))
        row_max_h = max(row_max_h, ch)
        col += 1
        if col >= CONTS_PER_ROW:
            cx = PAGE_X; cy += row_max_h + CONT_GAP_Y; row_max_h = 0; col = 0
        else:
            cx += cw + CONT_GAP_X

    return node_pos, containers


# ─────────────────────────────────────────────────────────────────────────────
# XML helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cell(gp, **attrs):
    c = ET.SubElement(gp, "mxCell")
    for k,v in attrs.items(): c.set(k, str(v))
    return c

def _geo(cell, x=0, y=0, w=10, h=10, relative=None):
    kw = {"x":str(int(x)),"y":str(int(y)),
          "width":str(int(w)),"height":str(int(h)),"as":"geometry"}
    if relative is not None: kw["relative"] = str(relative)
    ET.SubElement(cell, "mxGeometry", **kw)


# ─────────────────────────────────────────────────────────────────────────────
# draw.io generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_drawio(nodes, findings, title="Network Diagram"):
    """No connector lines — pure host inventory diagram."""
    node_pos, containers = layout(nodes)

    # Build finding set for quick lookup
    flagged_ips = set()
    for f in findings:
        if f["severity"] in ("HIGH","CRITICAL"):
            flagged_ips.add(f["src"])
            if f["dst"] != "N/A": flagged_ips.add(f["dst"])

    root = ET.Element("mxGraphModel",
        dx="1422", dy="762", grid="1", gridSize="10", guides="1",
        tooltips="1", connect="1", arrows="1", fold="1", page="1",
        pageScale="1", pageWidth="1654", pageHeight="1169",
        math="0", shadow="0")
    g = ET.SubElement(root, "root")
    ET.SubElement(g, "mxCell", id="0")
    ET.SubElement(g, "mxCell", id="1", parent="0")

    # Title
    tc = _cell(g, id="title",
               value=f"<b>{title}</b>",
               style="text;html=1;strokeColor=none;fillColor=none;"
                     "align=center;verticalAlign=middle;whiteSpace=wrap;"
                     "rounded=0;fontSize=20;",
               vertex="1", parent="1")
    _geo(tc, x=PAGE_X, y=22, w=900, h=42)

    _add_legend(g, findings)

    # Subnet containers
    cont_ids = {}
    for ci, cont in enumerate(containers):
        cid = f"cont_{ci}"
        cont_ids[cont["subnet"]] = cid
        if cont["subnet"] == "external":
            fill, stroke = "#fff3e0","#e65100"; fc="#bf360c"
            lbl = "&#x2601;  External / Internet"
        else:
            fill, stroke = SUBNET_PALETTES[cont["palette_idx"] % len(SUBNET_PALETTES)]
            fc = stroke
            lbl = f"Subnet: {cont['subnet']}"

        cc = _cell(g, id=cid, value=f"<b>{lbl}</b>",
                   style=(f"swimlane;startSize={CONT_TITLE};fillColor={fill};"
                          f"strokeColor={stroke};fontColor={fc};fontSize=11;"
                          "fontStyle=1;rounded=1;arcSize=3;swimlaneLine=1;"
                          "align=left;spacingLeft=8;html=1;"),
                   vertex="1", parent="1")
        _geo(cc, x=cont["x"], y=cont["y"], w=cont["w"], h=cont["h"])

    # Nodes — NO edges drawn at all
    for ni, (ip, info) in enumerate(nodes.items()):
        nid = f"n{ni}"
        ax, ay  = node_pos[ip]
        sub     = info["subnet"]
        cont    = next(c for c in containers if c["subnet"] == sub)
        rx, ry  = ax - cont["x"], ay - cont["y"]
        parent  = cont_ids[sub]

        shape = (SHAPE_CLOUD  if not info["is_private"] else
                 SHAPE_SERVER if info["role"] == "server" else SHAPE_PC)

        # Red fill if flagged
        if ip in flagged_ips:
            fill, stroke = FLAG_FILL_STROKE
        else:
            role_k = info["role"] if info["is_private"] else "external"
            fill, stroke = ROLE_FILL_STROKE.get(role_k, ("#fff","#999"))

        hostname = info.get("hostname","")
        macs     = sorted(info["macs"])
        mac_str  = " | ".join(macs) if macs else "MAC: unknown"
        os_str   = info.get("os_guess","Unknown")
        flags    = info.get("flags", set())
        flag_str = "  ".join(sorted(flags)) if flags else ""

        # Label: hostname (bold) / IP / MAC / OS guess
        if hostname:
            label = (f"<b>{hostname}</b><br/>"
                     f"<font style='font-size:9px;'>{ip}</font><br/>"
                     f"<font style='font-size:8px;color:#444;'>{mac_str}</font><br/>"
                     f"<font style='font-size:8px;color:#666;'>OS: {os_str}</font>")
        else:
            label = (f"<b>{ip}</b><br/>"
                     f"<font style='font-size:8px;color:#444;'>{mac_str}</font><br/>"
                     f"<font style='font-size:8px;color:#666;'>OS: {os_str}</font>")

        protos  = sorted(info["protocols"])
        ports   = sorted(info["open_ports"])
        tooltip = (f"Protocols: {', '.join(protos)}\n"
                   f"Open ports (passive): {', '.join(str(p) for p in ports) or 'none seen'}\n"
                   f"OS guess: {os_str}\n"
                   f"Pkts: {info['count']:,}  Bytes: {info['bytes']:,}\n"
                   + (f"⚠ FLAGS: {flag_str}" if flag_str else ""))

        nc = _cell(g, id=nid, value=label, tooltip=tooltip,
                   style=(f"{shape}fillColor={fill};strokeColor={stroke};"
                          "verticalLabelPosition=bottom;verticalAlign=top;"
                          "labelPosition=center;align=center;html=1;"),
                   vertex="1", parent=parent)
        _geo(nc, x=rx-NODE_W//2, y=ry-NODE_H//2, w=NODE_W, h=NODE_H)

    raw = ET.tostring(root, encoding="unicode")
    return minidom.parseString(raw).toprettyxml(indent="  ")


def _add_legend(g, findings):
    sev_counts = defaultdict(int)
    for f in findings: sev_counts[f["severity"]] += 1

    roles = [("server","Server"),("host","Host"),
             ("client","Client"),("external","External")]
    height = 30 + len(roles)*24 + 20 + (60 if findings else 0)

    bg = _cell(g, id="legend_bg", value="<b>Legend</b>",
               style=("rounded=1;html=1;fillColor=#f5f5f5;strokeColor=#666;"
                      "fontColor=#333;align=center;verticalAlign=top;"
                      "spacingTop=6;fontSize=11;"),
               vertex="1", parent="1")
    _geo(bg, x=20, y=100, w=LEGEND_W, h=height)

    for ri, (role, lbl) in enumerate(roles):
        y = 100 + 30 + ri*24
        fill, stroke = ROLE_FILL_STROKE[role]
        rs = _cell(g, id=f"rs{ri}", value="",
                   style=(f"shape=mxgraph.cisco.computers_and_peripherals.pc;"
                          f"fillColor={fill};strokeColor={stroke};"),
                   vertex="1", parent="1")
        _geo(rs, x=28, y=y, w=20, h=20)
        rll = _cell(g, id=f"rll{ri}", value=lbl,
                    style="text;html=1;strokeColor=none;fillColor=none;"
                          "align=left;verticalAlign=middle;fontSize=10;",
                    vertex="1", parent="1")
        _geo(rll, x=54, y=y, w=148, h=20)

    if findings:
        base = 100 + 30 + len(roles)*24 + 14
        # Red flag node indicator
        rs2 = _cell(g, id="rs_flag", value="",
                    style=(f"rounded=1;html=1;"
                           f"fillColor={FLAG_FILL_STROKE[0]};strokeColor={FLAG_FILL_STROKE[1]};"),
                    vertex="1", parent="1")
        _geo(rs2, x=28, y=base, w=20, h=14)
        total = len(findings)
        crit  = sev_counts.get("CRITICAL",0)
        high  = sev_counts.get("HIGH",0)
        rll2 = _cell(g, id="rll_flag",
                     value=f"⚠ Pentest finding ({total} total, {crit} CRIT, {high} HIGH)",
                     style="text;html=1;strokeColor=none;fillColor=none;"
                           "align=left;verticalAlign=middle;fontSize=10;fontColor=#b85450;",
                     vertex="1", parent="1")
        _geo(rll2, x=54, y=base, w=148, h=20)
        note = _cell(g, id="rll_note",
                     value="Hover nodes &amp; see Excel<br/>Pentest Findings sheet",
                     style="text;html=1;strokeColor=none;fillColor=none;"
                           "align=left;verticalAlign=middle;fontSize=9;fontColor=#888;",
                     vertex="1", parent="1")
        _geo(note, x=24, y=base+22, w=165, h=28)


# ─────────────────────────────────────────────────────────────────────────────
# Excel export
# ─────────────────────────────────────────────────────────────────────────────

def generate_xlsx(rows, nodes, edges, findings, cleartext_hits, output_path):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("[!] openpyxl not installed — skipping XLSX.  pip install openpyxl")
        return False

    wb = Workbook()

    # ── Common styles ──────────────────────────────────────────────────────────
    def hdr_style(fill_hex="1F4E79"):
        return dict(
            font  =Font(name="Arial", bold=True, color="FFFFFF", size=10),
            fill  =PatternFill("solid", fgColor=fill_hex),
            align =Alignment(horizontal="center", vertical="center", wrap_text=True),
        )

    thin = Side(style="thin", color="CCCCCC")
    bdr  = Border(left=thin, right=thin, top=thin, bottom=thin)
    bf   = Font(name="Arial", size=9)
    ALT_FILL = PatternFill("solid", fgColor="EBF3FB")
    WHT_FILL = PatternFill("solid", fgColor="FFFFFF")
    ctr  = Alignment(horizontal="center", vertical="center")
    lft  = Alignment(horizontal="left",   vertical="center")

    def apply_hdr(ws, headers, fill_hex="1F4E79"):
        ws.row_dimensions[1].height = 30
        hs = hdr_style(fill_hex)
        for ci, h in enumerate(headers, 1):
            c = ws.cell(row=1, column=ci, value=h)
            c.font = hs["font"]; c.fill = hs["fill"]
            c.alignment = hs["align"]; c.border = bdr

    def body_cell(ws, row, col, val, alt_row=False, centre=False):
        c = ws.cell(row=row, column=col, value=val)
        c.font = bf
        c.fill = ALT_FILL if alt_row else WHT_FILL
        c.border = bdr
        c.alignment = ctr if centre else lft
        return c

    def col_w(ws, widths):
        for ci, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(ci)].width = w

    # ── Sheet 1: Connections ──────────────────────────────────────────────────
    ws1 = wb.active; ws1.title = "Connections"
    HDR1 = ["Hostname (src)","MAC Address (src)","Source IP",
            "Hostname (dst)","MAC Address (dst)","Destination IP",
            "Protocol","Port","Resource (if HTTP/HTTPS)",
            "Assessed Server Role","Packets"]
    apply_hdr(ws1, HDR1)
    ws1.freeze_panes = "A2"

    def hn(ip):  return nodes.get(ip,{}).get("hostname","")
    def fm(ip):
        macs = sorted(nodes.get(ip,{}).get("macs",set()))
        return macs[0] if macs else ""
    def rl(ip):  return nodes.get(ip,{}).get("role","unknown")

    agg = defaultdict(lambda: dict(count=0, resources=set()))
    for r in rows:
        k = (r["src_ip"], r["dst_ip"], r["proto"], r["port"],
             r.get("src_mac",""), r.get("dst_mac",""))
        agg[k]["count"] += 1
        if r.get("resource"): agg[k]["resources"].add(r["resource"])

    for ri, ((src_ip,dst_ip,proto,port,smac,dmac), info) in \
            enumerate(sorted(agg.items()), 2):
        ws1.row_dimensions[ri].height = 15
        alt = (ri % 2 == 0)
        vals = [hn(src_ip), smac or fm(src_ip), src_ip,
                hn(dst_ip), dmac or fm(dst_ip), dst_ip,
                proto, port or "", "; ".join(sorted(info["resources"])),
                rl(dst_ip), info["count"]]
        for ci, v in enumerate(vals, 1):
            body_cell(ws1, ri, ci, v, alt, centre=(ci in (7,8,11)))

    col_w(ws1, [18,18,15,18,18,15,13,7,28,18,10])

    # ── Sheet 2: Node Summary ─────────────────────────────────────────────────
    ws2 = wb.create_sheet("Node Summary")
    HDR2 = ["IP Address","Hostname","MAC Address(es)","Subnet","Role",
            "OS Guess (TTL)","TTL Value","Is Private",
            "Protocols Observed","Passive Open Ports",
            "Pentest Flags","Packet Count","Bytes"]
    apply_hdr(ws2, HDR2, "1F4E79")
    ws2.freeze_panes = "A2"

    def node_sort(item):
        ip, info = item
        r = {"server":0,"host":1,"client":2,"external":3}.get(info["role"],4)
        try: return (r, int(ipaddress.ip_address(ip.split("/")[0])))
        except: return (r, ip)

    for ri, (ip, info) in enumerate(sorted(nodes.items(), key=node_sort), 2):
        ws2.row_dimensions[ri].height = 15
        alt = (ri%2==0)
        vals = [
            ip,
            info.get("hostname",""),
            ", ".join(sorted(info["macs"])),
            info["subnet"],
            info["role"],
            info.get("os_guess","Unknown"),
            info.get("ttl_val",""),
            "Yes" if info["is_private"] else "No",
            ", ".join(sorted(info["protocols"])),
            ", ".join(str(p) for p in sorted(info["open_ports"])),
            "; ".join(sorted(info.get("flags",set()))),
            info["count"],
            info["bytes"],
        ]
        for ci, v in enumerate(vals, 1):
            c = body_cell(ws2, ri, ci, v, alt, centre=(ci in (6,7,8,12,13)))
            # Highlight flagged rows
            if info.get("flags"):
                if ci == 11:
                    c.font = Font(name="Arial", size=9, color="B85450", bold=True)

    col_w(ws2, [15,18,30,18,10,15,9,10,45,22,28,12,12])

    # ── Sheet 3: Pentest Findings ─────────────────────────────────────────────
    ws3 = wb.create_sheet("Pentest Findings")
    HDR3 = ["Severity","Category","Source","Destination","Detail","Recommendation"]
    apply_hdr(ws3, HDR3, "8B0000")
    ws3.freeze_panes = "A2"

    SEV_COLOURS = {"CRITICAL":"FF0000","HIGH":"FF6600",
                   "MEDIUM":"FFB300","LOW":"00AA00","INFO":"888888"}

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f["severity"],5))

    for ri, f in enumerate(sorted_findings, 2):
        ws3.row_dimensions[ri].height = 28
        vals = [f["severity"], f["category"], f["src"], f["dst"],
                f["detail"], f["recommendation"]]
        for ci, v in enumerate(vals, 1):
            c = body_cell(ws3, ri, ci, v, False, centre=(ci==1))
            c.alignment = Alignment(horizontal="center" if ci==1 else "left",
                                    vertical="center", wrap_text=True)
            if ci == 1:
                clr = SEV_COLOURS.get(f["severity"],"888888")
                c.font  = Font(name="Arial", bold=True, color="FFFFFF", size=10)
                c.fill  = PatternFill("solid", fgColor=clr)
                c.border = bdr

    col_w(ws3, [12,28,16,16,50,42])

    # ── Sheet 4: Protocol Summary ─────────────────────────────────────────────
    ws4 = wb.create_sheet("Protocol Summary")
    HDR4 = ["Protocol","Connections","Unique Sources","Unique Destinations",
            "Cleartext?","Lateral Movement Risk?"]
    apply_hdr(ws4, HDR4, "1F4E79")
    ws4.freeze_panes = "A2"

    proto_stats = defaultdict(lambda: dict(count=0, srcs=set(), dsts=set()))
    for (src_ip,dst_ip,proto,port,smac,dmac), info in agg.items():
        proto_stats[proto]["count"] += info["count"]
        proto_stats[proto]["srcs"].add(src_ip)
        proto_stats[proto]["dsts"].add(dst_ip)

    for ri, (proto, ps) in enumerate(
            sorted(proto_stats.items(), key=lambda x: -x[1]["count"]), 2):
        alt = (ri%2==0)
        vals = [proto, ps["count"], len(ps["srcs"]), len(ps["dsts"]),
                "YES ⚠" if proto in CLEARTEXT_PROTOS else "No",
                "YES 🔴" if proto in LATERAL_PROTOS else "No"]
        for ci, v in enumerate(vals, 1):
            c = body_cell(ws4, ri, ci, v, alt, centre=True)
            if ci==5 and v.startswith("YES"):
                c.font = Font(name="Arial", size=9, bold=True, color="B85450")
            if ci==6 and v.startswith("YES"):
                c.font = Font(name="Arial", size=9, bold=True, color="CC0000")

    col_w(ws4, [16,14,16,20,14,22])

    # ── Sheet 5: Port Inventory ───────────────────────────────────────────────
    ws5 = wb.create_sheet("Port Inventory")
    HDR5 = ["IP","Hostname","Role","OS Guess","Subnet",
            "Passive Open Ports","Well-Known Service Names","Suspicious Ports"]
    apply_hdr(ws5, HDR5, "1F4E79")
    ws5.freeze_panes = "A2"

    for ri, (ip, info) in enumerate(sorted(nodes.items(), key=node_sort), 2):
        ports    = sorted(info["open_ports"])
        svc_names = [WELL_KNOWN.get(("TCP",p)) or WELL_KNOWN.get(("UDP",p)) or ""
                     for p in ports]
        sus_ports = [str(p) for p in ports if p in SUSPICIOUS_PORTS]
        alt = (ri%2==0)
        vals = [ip, info.get("hostname",""), info["role"],
                info.get("os_guess","Unknown"), info["subnet"],
                ", ".join(str(p) for p in ports),
                ", ".join(s for s in svc_names if s),
                ", ".join(sus_ports) or ""]
        for ci, v in enumerate(vals, 1):
            c = body_cell(ws5, ri, ci, v, alt, centre=(ci in (3,4)))
            if ci==8 and v:
                c.font = Font(name="Arial", size=9, bold=True, color="B85450")

    col_w(ws5, [15,18,10,14,18,28,30,20])


    # ── Sheet 6: Cleartext Intercepts ────────────────────────────────────────
    ws6 = wb.create_sheet("Cleartext Intercepts")
    HDR6 = ["Protocol","Data Type","Extracted Value","Context / Raw",
            "Source IP","Destination IP","Src Port","Dst Port"]
    apply_hdr(ws6, HDR6, "4A0000")
    ws6.freeze_panes = "A2"

    # De-duplicate: same (proto, type, value, src, dst) seen in multiple packets
    seen_ct = set()
    deduped = []
    for h in cleartext_hits:
        key = (h["protocol"], h["type"], h["value"], h["src_ip"], h["dst_ip"])
        if key not in seen_ct:
            seen_ct.add(key)
            deduped.append(h)

    TYPE_SEVERITY = {
        "FTP Password":"CRITICAL", "FTP Username":"HIGH",
        "HTTP Basic Auth (decoded)":"CRITICAL", "HTTP Basic Auth (raw b64)":"HIGH",
        "HTTP Bearer Token":"HIGH", "HTTP Cookie":"MEDIUM",
        "HTTP POST Credential":"CRITICAL", "HTTP JSON Credential":"CRITICAL",
        "Telnet Keystrokes/Data":"HIGH", "Telnet Data":"HIGH",
        "SMTP Auth Command":"HIGH", "SMTP Auth (b64 decoded)":"CRITICAL",
        "POP3 Password":"CRITICAL", "POP3 Username":"HIGH",
        "IMAP Login":"CRITICAL",
        "LDAP Bind Data":"HIGH",
        "SNMP Community String":"MEDIUM",
        "AWS Access Key":"CRITICAL", "Private Key":"CRITICAL",
        "API Key":"HIGH", "Auth Token":"HIGH", "Secret/Key":"HIGH",
    }

    SEV_CLR = {
        "CRITICAL": ("FF0000","FFFFFF"),
        "HIGH":     ("FF6600","FFFFFF"),
        "MEDIUM":   ("FFB300","000000"),
        "LOW":      ("00AA00","FFFFFF"),
    }

    # Sort: CRITICAL first, then by protocol
    def ct_sort(h):
        sev = TYPE_SEVERITY.get(h["type"],"LOW")
        return ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(sev,4), h["protocol"])

    deduped.sort(key=ct_sort)

    if not deduped:
        ws6.cell(row=2, column=1, value="No cleartext credentials or sensitive data detected.")
    else:
        for ri, h in enumerate(deduped, 2):
            ws6.row_dimensions[ri].height = 20
            sev  = TYPE_SEVERITY.get(h["type"], "LOW")
            bg, fg = SEV_CLR.get(sev, ("FFFFFF","000000"))
            alt_row = (ri % 2 == 0)

            vals = [h["protocol"], h["type"], h["value"], h["context"],
                    h["src_ip"], h["dst_ip"], h["src_port"] or "", h["dst_port"] or ""]
            for ci, v in enumerate(vals, 1):
                c = body_cell(ws6, ri, ci, v, alt_row, centre=(ci in (1,7,8)))
                # Colour the Data Type cell by severity
                if ci == 2:
                    c.font  = Font(name="Arial", size=9, bold=True, color=fg)
                    c.fill  = PatternFill("solid", fgColor=bg)
                    c.border = bdr
                # Highlight the value cell for critical items
                if ci == 3 and sev == "CRITICAL":
                    c.font = Font(name="Arial", size=9, bold=True, color="8B0000")

    col_w(ws6, [14, 28, 45, 45, 15, 15, 9, 9])

    # Add a summary note at the top
    ws6.insert_rows(1)
    ws6.row_dimensions[1].height = 40
    summary = ws6.cell(row=1, column=1,
        value=(f"CLEARTEXT INTERCEPTS — {len(deduped)} unique items captured  "
               f"| CRITICAL: {sum(1 for h in deduped if TYPE_SEVERITY.get(h['type'])=='CRITICAL')}  "
               f"HIGH: {sum(1 for h in deduped if TYPE_SEVERITY.get(h['type'])=='HIGH')}  "
               f"MEDIUM: {sum(1 for h in deduped if TYPE_SEVERITY.get(h['type'])=='MEDIUM')}"))
    summary.font  = Font(name="Arial", bold=True, size=11, color="FFFFFF")
    summary.fill  = PatternFill("solid", fgColor="4A0000")
    summary.alignment = Alignment(horizontal="left", vertical="center",
                                   indent=1, wrap_text=False)
    ws6.merge_cells(start_row=1, start_column=1, end_row=1, end_column=8)


    wb.save(output_path)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="PCAP → draw.io + Excel  (v4.0 Pentester Edition)")
    ap.add_argument("pcap")
    ap.add_argument("-o","--output",  help=".drawio output path")
    ap.add_argument("--xlsx",         help=".xlsx output path")
    ap.add_argument("--min-packets",  type=int, default=1)
    ap.add_argument("--collapse-external", action="store_true")
    ap.add_argument("--hostname-file", metavar="FILE")
    ap.add_argument("--title", default="Network Diagram")
    args = ap.parse_args()

    base    = args.pcap.rsplit(".",1)[0]
    out_dio = args.output or base+".drawio"
    out_xl  = args.xlsx   or base+".xlsx"

    print(f"[*] Parsing {args.pcap} ...")
    try:
        packets = list(parse_pcap(args.pcap))
    except FileNotFoundError:
        print(f"[!] Not found: {args.pcap}", file=sys.stderr); sys.exit(1)
    except ValueError as e:
        print(f"[!] {e}",              file=sys.stderr); sys.exit(1)

    print(f"[*] {len(packets):,} packets")
    if not packets:
        print("[!] No packets — valid PCAP?", file=sys.stderr); sys.exit(1)

    extra_hn = _load_hostname_file(args.hostname_file)
    nodes, edges, rows, findings, cleartext_hits = build_graph(
        packets, args.min_packets, args.collapse_external, extra_hn)

    unique_conn = len({tuple(sorted(p)) for p in edges})
    subnets     = len({n["subnet"] for n in nodes.values()})
    print(f"[*] {len(nodes)} nodes · {unique_conn} connections · {subnets} subnets")
    print(f"[*] {len(findings)} pentest findings  "
          f"({sum(1 for f in findings if f['severity']=='CRITICAL')} CRITICAL  "
          f"{sum(1 for f in findings if f['severity']=='HIGH')} HIGH  "
          f"{sum(1 for f in findings if f['severity']=='MEDIUM')} MEDIUM)")

    xml = generate_drawio(nodes, findings, title=args.title)
    with open(out_dio,"w",encoding="utf-8") as f:
        f.write(xml)
    print(f"[+] Diagram  → {out_dio}")

    ok = generate_xlsx(rows, nodes, edges, findings, cleartext_hits, out_xl)
    if ok:
        print(f"[+] Workbook → {out_xl}  (5 sheets: Connections, Node Summary, "
              f"Pentest Findings, Protocol Summary, Port Inventory, Cleartext Intercepts)")

    print()
    print("  draw.io: File → Import From → Device → .drawio file")
    print("  Excel:   Pentest Findings sheet has colour-coded severity rows")
    print("           Node Summary has OS guesses, open ports, and risk flags")


if __name__ == "__main__":
    main()
