"""
NetScope — Network Packet Analyzer v3.0
Telecom-grade PCAP deep inspection tool
Stack: Python · Streamlit · Scapy · Pandas · NumPy
Designed for Ericsson · Nokia · JIO network engineering workflows
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta
import tempfile
import os
import traceback
from collections import defaultdict

# ─── Page Config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetScope — Packet Analyzer",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600;700&family=Rajdhani:wght@400;600;700&display=swap');

:root {
    --bg0: #080c14;
    --bg1: #0c1120;
    --bg2: #10172a;
    --bg3: #162035;
    --bg4: #1c2a42;
    --cyan:    #00d4ff;
    --green:   #00e676;
    --amber:   #ffab40;
    --red:     #ff5252;
    --purple:  #ce93d8;
    --blue:    #82b1ff;
    --t1: #e8eaf6;
    --t2: #90a4ae;
    --t3: #546e7a;
    --t4: #2e4057;
    --border:  #1a2a40;
    --border2: #243650;
}

html, body, [class*="css"] {
    font-family: 'IBM Plex Mono', monospace !important;
    background-color: var(--bg0) !important;
    color: var(--t1) !important;
}
.stApp { background-color: var(--bg0) !important; }

/* ── Header ── */
.ns-header {
    background: linear-gradient(120deg, var(--bg1) 0%, var(--bg2) 60%, var(--bg0) 100%);
    border: 1px solid var(--border2);
    border-radius: 14px;
    padding: 26px 36px;
    margin-bottom: 22px;
    position: relative;
    overflow: hidden;
}
.ns-header::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at 20% 50%, rgba(0,212,255,.06) 0%, transparent 60%),
                radial-gradient(ellipse at 80% 50%, rgba(0,230,118,.04) 0%, transparent 60%);
    pointer-events: none;
}
.ns-header h1 {
    font-family: 'Rajdhani', sans-serif;
    font-size: 2.2rem;
    font-weight: 700;
    background: linear-gradient(90deg, var(--cyan), var(--green));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
    letter-spacing: 1px;
}
.ns-header p {
    color: var(--t3);
    font-size: 0.75rem;
    margin: 5px 0 0;
    letter-spacing: 2px;
    text-transform: uppercase;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background-color: var(--bg1) !important;
    border-right: 1px solid var(--border) !important;
}

/* ── Stat Cards ── */
.stat-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
}
.stat-card .sv {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--cyan);
    line-height: 1.1;
}
.stat-card .sl {
    font-size: 0.68rem;
    color: var(--t3);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 3px;
}

/* ── Section Headers ── */
.ns-sh {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 22px 0 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
}
.ns-sh .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--cyan);
    box-shadow: 0 0 6px var(--cyan);
    flex-shrink: 0;
}
.ns-sh .title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--t1);
    text-transform: uppercase;
    letter-spacing: 2px;
}
.ns-sh .badge {
    font-size: 0.7rem;
    color: var(--t3);
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 2px 10px;
    margin-left: 4px;
}

/* ── Proto Pill ── */
.pill {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.66rem;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin: 1px;
}

/* ── Flow Row ── */
.flow-row {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 10px 14px;
    margin-bottom: 6px;
    font-size: 0.74rem;
    line-height: 1.7;
}

/* ── Detail Box ── */
.detail-box {
    background: var(--bg0);
    border: 1px solid var(--border2);
    border-radius: 6px;
    padding: 14px 16px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    color: var(--t2);
    white-space: pre-wrap;
    line-height: 1.8;
    max-height: 360px;
    overflow-y: auto;
}

/* ── Diagnostic Boxes ── */
.diag-critical {
    background: rgba(255,82,82,.07);
    border: 1px solid rgba(255,82,82,.3);
    border-left: 4px solid var(--red);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.diag-warning {
    background: rgba(255,171,64,.07);
    border: 1px solid rgba(255,171,64,.3);
    border-left: 4px solid var(--amber);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.diag-info {
    background: rgba(0,212,255,.06);
    border: 1px solid rgba(0,212,255,.25);
    border-left: 4px solid var(--cyan);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.diag-ok {
    background: rgba(0,230,118,.07);
    border: 1px solid rgba(0,230,118,.25);
    border-left: 4px solid var(--green);
    border-radius: 8px;
    padding: 14px 18px;
}
.diag-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.85rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 8px;
}
.diag-item {
    font-size: 0.76rem;
    color: var(--t2);
    padding: 4px 0;
    border-bottom: 1px solid rgba(255,255,255,.05);
    display: flex;
    gap: 8px;
    align-items: flex-start;
}
.diag-item:last-child { border-bottom: none; }
.diag-item strong { color: var(--t1); }

/* ── Proto Bar Chart ── */
.proto-bar-row {
    margin-bottom: 6px;
    font-size: 0.72rem;
}
.proto-bar-label {
    display: flex;
    justify-content: space-between;
    margin-bottom: 2px;
    color: var(--t2);
}
.proto-bar-track {
    background: var(--bg4);
    border-radius: 3px;
    height: 6px;
    width: 100%;
}
.proto-bar-fill {
    height: 6px;
    border-radius: 3px;
}

/* ── Overrides ── */
div[data-testid="stFileUploader"] {
    border: 2px dashed var(--border2) !important;
    border-radius: 10px !important;
    background: var(--bg2) !important;
}
div[data-testid="stFileUploader"]:hover { border-color: var(--cyan) !important; }
.stSelectbox > div > div {
    background-color: var(--bg2) !important;
    border-color: var(--border2) !important;
    color: var(--t1) !important;
}
.stTextInput > div > div > input {
    background-color: var(--bg2) !important;
    border-color: var(--border2) !important;
    color: var(--t1) !important;
    font-family: 'IBM Plex Mono', monospace !important;
}
.stButton > button {
    background: linear-gradient(135deg, var(--cyan), #007bbd) !important;
    color: #000 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 0.78rem !important;
    letter-spacing: 1px !important;
    border: none !important;
    border-radius: 7px !important;
    padding: 10px 22px !important;
    text-transform: uppercase !important;
}
.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 18px rgba(0,212,255,.3) !important;
}
div[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }
.stTabs [data-baseweb="tab-list"] {
    background-color: var(--bg2) !important;
    border-radius: 8px 8px 0 0;
    gap: 4px; padding: 5px;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.73rem !important;
    color: var(--t3) !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
}
.stTabs [aria-selected="true"] {
    color: var(--cyan) !important;
    background-color: var(--bg3) !important;
}
div[data-testid="stExpander"] {
    background-color: var(--bg2) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg0); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--cyan); }
</style>
""", unsafe_allow_html=True)

# ─── Constants ────────────────────────────────────────────────────────────────
IST = timezone(timedelta(hours=5, minutes=30))

PROTOCOL_FILTERS = [
    "TCP", "UDP", "IPv4", "IPv6", "ARP", "ICMP",
    "HTTP", "HTTPS", "TLS", "DNS", "FTP", "SMTP",
    "SSH", "TELNET", "Ethernet", "PPP", "PPPoE",
    "MQTT", "SIP", "SDP",
]

PROTO_COLORS = {
    "TCP":      "#00d4ff", "UDP":     "#00e676", "IPv4":    "#ce93d8",
    "IPv6":     "#ff6d00", "ARP":     "#ffab40", "ICMP":    "#f48fb1",
    "HTTP":     "#69f0ae", "HTTPS":   "#00d4ff", "TLS":     "#4fc3f7",
    "DNS":      "#ffe082", "FTP":     "#ff5252", "SMTP":    "#ea80fc",
    "SSH":      "#b9f6ca", "TELNET":  "#ff6d00", "Ethernet":"#90a4ae",
    "PPP":      "#80deea", "PPPoE":   "#b39ddb", "MQTT":    "#a5d6a7",
    "SIP":      "#ffcc80", "SDP":     "#e040fb",
}

PORT_PROTO_MAP = {
    80: "HTTP",   443: "HTTPS",  8080: "HTTP",  8443: "HTTPS",
    53: "DNS",    21:  "FTP",    20:   "FTP",
    25: "SMTP",   587: "SMTP",   465:  "SMTP",
    22: "SSH",    23:  "TELNET",
    1883: "MQTT", 8883: "MQTT",
    5060: "SIP",  5061: "SIP",
}

PROTO_ORDER = [
    "Ethernet", "PPPoE", "PPP", "ARP",
    "IPv4", "IPv6", "ICMP",
    "TCP", "UDP",
    "TLS", "DNS", "HTTP", "HTTPS", "FTP", "SMTP",
    "SSH", "TELNET", "MQTT", "SIP", "SDP",
]

TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
    0x40: "ECE", 0x80: "CWR",
}

DNS_OPCODES  = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
DNS_RCODES   = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                4: "NOTIMP",  5: "REFUSED"}


# ─── Core Helpers ─────────────────────────────────────────────────────────────

def ts_to_ist(ts_float):
    try:
        dt = datetime.fromtimestamp(float(ts_float), tz=timezone.utc).astimezone(IST)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " IST"
    except Exception:
        return str(ts_float)


def get_mac(pkt):
    try:
        from scapy.all import Ether
        if Ether in pkt:
            return pkt[Ether].src.upper(), pkt[Ether].dst.upper()
    except Exception:
        pass
    return "N/A", "N/A"


def get_ip(pkt):
    try:
        from scapy.all import IP, IPv6
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
    except Exception:
        pass
    return "N/A", "N/A"


def decode_tcp_flags(flags_int):
    """Return a readable flag string like SYN|ACK."""
    if flags_int is None:
        return ""
    names = [name for bit, name in TCP_FLAGS.items() if int(flags_int) & bit]
    return "|".join(names) if names else str(flags_int)


def build_packet_detail(pkt) -> str:
    """Build a human-readable, layer-by-layer breakdown of a packet."""
    lines = []
    try:
        from scapy.all import Ether, ARP, IP, IPv6, ICMP, TCP, UDP, Raw
        try:
            from scapy.all import DNS
            has_dns = True
        except ImportError:
            has_dns = False

        if Ether in pkt:
            e = pkt[Ether]
            lines.append("[ Ethernet ]")
            lines.append(f"  src_mac  : {e.src.upper()}")
            lines.append(f"  dst_mac  : {e.dst.upper()}")
            lines.append(f"  type     : 0x{e.type:04X}")

        if ARP in pkt:
            a = pkt[ARP]
            op = {1: "REQUEST", 2: "REPLY"}.get(a.op, str(a.op))
            lines.append("[ ARP ]")
            lines.append(f"  op       : {op}")
            lines.append(f"  src_mac  : {a.hwsrc.upper()}")
            lines.append(f"  src_ip   : {a.psrc}")
            lines.append(f"  dst_mac  : {a.hwdst.upper()}")
            lines.append(f"  dst_ip   : {a.pdst}")

        if IP in pkt:
            ip = pkt[IP]
            lines.append("[ IPv4 ]")
            lines.append(f"  src      : {ip.src}")
            lines.append(f"  dst      : {ip.dst}")
            lines.append(f"  ttl      : {ip.ttl}")
            lines.append(f"  proto    : {ip.proto}")
            lines.append(f"  ihl      : {ip.ihl * 4} bytes")
            lines.append(f"  flags    : {str(ip.flags)}")
            lines.append(f"  chksum   : 0x{ip.chksum:04X}" if ip.chksum else "  chksum   : N/A")

        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            lines.append("[ IPv6 ]")
            lines.append(f"  src      : {ip6.src}")
            lines.append(f"  dst      : {ip6.dst}")
            lines.append(f"  hop_limit: {ip6.hlim}")
            lines.append(f"  next_hdr : {ip6.nh}")

        if ICMP in pkt:
            ic = pkt[ICMP]
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                          8: "Echo Request", 11: "Time Exceeded"}
            tname = icmp_types.get(ic.type, str(ic.type))
            lines.append("[ ICMP ]")
            lines.append(f"  type     : {ic.type} ({tname})")
            lines.append(f"  code     : {ic.code}")
            lines.append(f"  id       : {getattr(ic, 'id', 'N/A')}")
            lines.append(f"  seq      : {getattr(ic, 'seq', 'N/A')}")

        if TCP in pkt:
            tcp = pkt[TCP]
            flag_str = decode_tcp_flags(tcp.flags)
            lines.append("[ TCP ]")
            lines.append(f"  sport    : {tcp.sport}")
            lines.append(f"  dport    : {tcp.dport}")
            lines.append(f"  seq      : {tcp.seq}")
            lines.append(f"  ack      : {tcp.ack}")
            lines.append(f"  flags    : {flag_str}")
            lines.append(f"  window   : {tcp.window}")
            lines.append(f"  dataofs  : {tcp.dataofs * 4} bytes")

        if UDP in pkt:
            udp = pkt[UDP]
            lines.append("[ UDP ]")
            lines.append(f"  sport    : {udp.sport}")
            lines.append(f"  dport    : {udp.dport}")
            lines.append(f"  len      : {udp.len}")

        if has_dns and DNS in pkt:
            dns = pkt[DNS]
            opname  = DNS_OPCODES.get(dns.opcode, str(dns.opcode))
            rcname  = DNS_RCODES.get(dns.rcode,   str(dns.rcode))
            qr_str  = "RESPONSE" if dns.qr else "QUERY"
            lines.append("[ DNS ]")
            lines.append(f"  qr       : {qr_str}")
            lines.append(f"  opcode   : {opname}")
            lines.append(f"  rcode    : {rcname}")
            lines.append(f"  qdcount  : {dns.qdcount}")
            lines.append(f"  ancount  : {dns.ancount}")
            if dns.qdcount and dns.qd:
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    lines.append(f"  query    : {qname}")
                except Exception:
                    pass

        if Raw in pkt:
            raw = bytes(pkt[Raw])
            try:
                text = raw.decode("utf-8", errors="ignore")
                preview = text[:120].replace("\r", "").replace("\n", " ↵ ")
            except Exception:
                preview = raw[:60].hex()
            lines.append("[ Payload ]")
            lines.append(f"  length   : {len(raw)} bytes")
            lines.append(f"  preview  : {preview}")

    except Exception as ex:
        lines.append(f"[parse error: {ex}]")

    return "\n".join(lines) if lines else "No layer detail available"


def detect_protocols(pkt) -> set:
    """Return set of protocol name strings present in packet."""
    try:
        from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
        try:
            from scapy.all import PPPoE
            has_pppoe = True
        except ImportError:
            has_pppoe = False

        protos = set()

        if Ether in pkt:
            protos.add("Ethernet")
        if ARP in pkt:
            protos.add("ARP")
        if IP in pkt:
            protos.add("IPv4")
        if IPv6 in pkt:
            protos.add("IPv6")
        if ICMP in pkt:
            protos.add("ICMP")
        if has_pppoe and PPPoE in pkt:
            protos.add("PPPoE")

        if TCP in pkt:
            protos.add("TCP")
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            for p in (sport, dport):
                if p in PORT_PROTO_MAP:
                    protos.add(PORT_PROTO_MAP[p])
            if sport in (443, 8443) or dport in (443, 8443):
                protos.update(["TLS", "HTTPS"])
            if sport == 22 or dport == 22:
                protos.add("SSH")
            if sport == 23 or dport == 23:
                protos.add("TELNET")
            if sport in (25, 587, 465) or dport in (25, 587, 465):
                protos.add("SMTP")
            if sport in (20, 21) or dport in (20, 21):
                protos.add("FTP")
            if sport in (5060, 5061) or dport in (5060, 5061):
                protos.add("SIP")
            if Raw in pkt:
                try:
                    raw = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                    if raw.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                        protos.add("HTTP")
                    if "v=0" in raw and "m=" in raw:
                        protos.add("SDP")
                    if "Content-Type" in raw and "application/mqtt" in raw:
                        protos.add("MQTT")
                except Exception:
                    pass

        if UDP in pkt:
            protos.add("UDP")
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            for p in (sport, dport):
                if p in PORT_PROTO_MAP:
                    protos.add(PORT_PROTO_MAP[p])
            if sport == 53 or dport == 53:
                protos.add("DNS")
            if sport in (1883, 8883) or dport in (1883, 8883):
                protos.add("MQTT")
            if sport in (5060, 5061) or dport in (5060, 5061):
                protos.add("SIP")

        return protos
    except Exception:
        return set()


def protocol_display_name(protos: set) -> str:
    """Return ordered protocol stack string e.g. 'Ethernet / IPv4 / TCP / HTTPS'."""
    ordered = [p for p in PROTO_ORDER if p in protos]
    return " / ".join(ordered) if ordered else "Unknown"


def load_pcap_scapy(filepath):
    try:
        from scapy.all import rdpcap
        packets = rdpcap(filepath)
        return packets, "scapy"
    except Exception as e:
        return None, str(e)


def parse_pcap_to_df(filepath):
    """Parse PCAP → DataFrame with all columns including Protocol & Packet Detail."""
    packets, status = load_pcap_scapy(filepath)
    if packets is None:
        return None, f"Failed to load PCAP: {status}"

    rows = []
    skipped = 0
    try:
        from scapy.all import TCP, UDP
        for i, pkt in enumerate(packets):
            try:
                src_ip, dst_ip = get_ip(pkt)
                src_mac, dst_mac = get_mac(pkt)
                raw_ts  = float(pkt.time)
                ts_ist  = ts_to_ist(raw_ts)
                size    = len(pkt)
                protos  = detect_protocols(pkt)
                proto_name = protocol_display_name(protos)
                detail  = build_packet_detail(pkt)

                sport, dport, flags = None, None, None
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    flags = pkt[TCP].flags
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport

                rows.append({
                    "No.":             i + 1,
                    "Source IP":       src_ip,
                    "Destination IP":  dst_ip,
                    "Src MAC":         src_mac,
                    "Dst MAC":         dst_mac,
                    "Timestamp (IST)": ts_ist,
                    "Size (Bytes)":    size,
                    "Protocol":        proto_name,
                    "Packet Detail":   detail,
                    "_protocols":      protos,
                    "_sport":          sport,
                    "_dport":          dport,
                    "_raw_ts":         raw_ts,
                    "_flags":          flags,
                    "_summary":        pkt.summary(),
                })
            except Exception:
                skipped += 1
                continue
    except Exception:
        return None, f"Error parsing packets:\n{traceback.format_exc()}"

    if not rows:
        return None, "No packets could be parsed from this file."

    df = pd.DataFrame(rows)
    if skipped:
        st.warning(f"⚠ {skipped} malformed/unrecognised packet(s) skipped during parse.")
    return df, packets


# ─── Display Helpers ──────────────────────────────────────────────────────────

DISPLAY_COLS = [
    "No.", "Source IP", "Destination IP", "Src MAC", "Dst MAC",
    "Timestamp (IST)", "Size (Bytes)", "Protocol", "Packet Detail",
]


def render_display_df(df: pd.DataFrame) -> pd.DataFrame:
    cols = [c for c in DISPLAY_COLS if c in df.columns]
    return df[cols].reset_index(drop=True)


def filter_df_by_protocol(df: pd.DataFrame, proto: str) -> pd.DataFrame:
    mask = df["_protocols"].apply(lambda p: proto in p)
    return df[mask].copy()


def filter_df_by_endpoints(df, src_ip=None, dst_ip=None,
                            src_mac=None, dst_mac=None) -> pd.DataFrame:
    if src_ip and src_ip.strip() and dst_ip and dst_ip.strip():
        s, d = src_ip.strip(), dst_ip.strip()
        mask = (
            ((df["Source IP"] == s) & (df["Destination IP"] == d)) |
            ((df["Source IP"] == d) & (df["Destination IP"] == s))
        )
    elif src_mac and src_mac.strip() and dst_mac and dst_mac.strip():
        s, d = src_mac.strip().upper(), dst_mac.strip().upper()
        mask = (
            ((df["Src MAC"] == s) & (df["Dst MAC"] == d)) |
            ((df["Src MAC"] == d) & (df["Dst MAC"] == s))
        )
    else:
        mask = pd.Series([True] * len(df), index=df.index)
    return df[mask].copy()


# ─── Flow Analysis ────────────────────────────────────────────────────────────

def analyze_flow(flow_df: pd.DataFrame, proto: str) -> list:
    """
    Returns list of (severity, title, description) tuples.
    severity: 'CRITICAL' | 'WARNING' | 'INFO'
    """
    issues = []
    if flow_df.empty:
        return [("WARNING", "No Packets", "No packets found for this flow.")]

    flags_list = flow_df["_flags"].dropna().tolist()
    ts_list    = sorted(flow_df["_raw_ts"].dropna().tolist())
    sizes      = flow_df["Size (Bytes)"].tolist()

    # ── TCP analysis
    if proto in ("TCP", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP", "TELNET", "SIP"):
        syn = sum(1 for f in flags_list if hasattr(f, '__int__') and int(f) & 0x02)
        ack = sum(1 for f in flags_list if hasattr(f, '__int__') and int(f) & 0x10)
        rst = sum(1 for f in flags_list if hasattr(f, '__int__') and int(f) & 0x04)
        fin = sum(1 for f in flags_list if hasattr(f, '__int__') and int(f) & 0x01)
        psh = sum(1 for f in flags_list if hasattr(f, '__int__') and int(f) & 0x08)

        if rst > 0:
            issues.append(("CRITICAL", "TCP RST Detected",
                f"{rst} RST packet(s) found. Connection forcibly reset — "
                "possible firewall block, ACL rule, port rejection, or application crash."))

        if syn > 0 and ack == 0:
            issues.append(("CRITICAL", "Incomplete TCP Handshake",
                "SYN sent but no ACK received. Server may be unreachable, port filtered, "
                "or experiencing severe packet loss."))

        if syn > 3 and ack < syn // 2:
            issues.append(("WARNING", "Possible SYN Flood / Port Scan",
                f"{syn} SYN packets with only {ack} ACKs. "
                "Possible DDoS SYN flood or automated port scan in progress."))

        if fin == 0 and len(flow_df) > 5:
            issues.append(("WARNING", "No TCP FIN Observed",
                "Session may not have terminated gracefully. "
                "Possible half-open connection, abrupt session drop, or capture truncated."))

        if psh == 0 and len(flow_df) > 3 and proto not in ("TLS",):
            issues.append(("INFO", "No PSH Flag in Flow",
                "No PUSH packets found. Data may be buffered or flow is control-only "
                "(SYN/ACK/FIN only)."))

    # ── Inter-packet gaps
    if len(ts_list) > 1:
        gaps = np.diff(ts_list)
        lg = gaps[gaps > 1.0]
        vlg = gaps[gaps > 5.0]
        if len(vlg) > 0:
            issues.append(("CRITICAL", "Extreme Latency Gaps",
                f"{len(vlg)} gap(s) > 5 seconds detected. Max: {max(vlg):.2f}s. "
                "Severe network latency, link instability, or application stall."))
        elif len(lg) > 0:
            issues.append(("WARNING", "Inter-Packet Delays > 1s",
                f"{len(lg)} gap(s) > 1 second. Max: {max(lg):.2f}s. "
                "Possible congestion, retransmission timeout, or server processing delay."))

    # ── Retransmission heuristic (duplicate size+timestamp proximity)
    if len(sizes) > 2:
        size_arr = np.array(sizes)
        dupes = int(np.sum(np.diff(size_arr) == 0))
        if dupes > max(3, len(sizes) * 0.15):
            issues.append(("WARNING", "Possible Retransmissions",
                f"{dupes} consecutive packets with identical size. "
                "May indicate TCP retransmissions due to packet loss or ACK timeout."))

    # ── Packet size anomalies
    if sizes:
        sa = np.array(sizes)
        if np.any(sa > 9000):
            issues.append(("INFO", "Jumbo Frames Detected",
                f"{int(np.sum(sa > 9000))} packet(s) > 9000 bytes. "
                "Ensure all path devices support Jumbo MTU to avoid fragmentation."))
        if np.any(sa < 20):
            issues.append(("WARNING", "Undersized Packets",
                f"{int(np.sum(sa < 20))} packet(s) < 20 bytes. "
                "Possible malformed, fragmented, or crafted packets."))

    # ── DNS
    if proto == "DNS":
        if len(flow_df) > 50:
            issues.append(("WARNING", "High DNS Volume",
                f"{len(flow_df)} DNS packets in this flow. "
                "Possible DNS amplification attack, misconfigured resolver, or excessive lookups."))
        # NXDOMAIN check from detail column
        nxd = flow_df["Packet Detail"].str.contains("NXDOMAIN", na=False).sum()
        if nxd > 5:
            issues.append(("WARNING", "Multiple NXDOMAIN Responses",
                f"{nxd} NXDOMAIN responses. Possible DNS tunnelling, malware C2 beaconing, "
                "or misconfigured domain lookups."))

    # ── ARP storm
    if proto == "ARP":
        src_counts = flow_df["Source IP"].value_counts()
        for ip, count in src_counts.items():
            if count > 20 and ip != "N/A":
                issues.append(("CRITICAL", "ARP Storm / Spoofing",
                    f"IP {ip} sent {count} ARP packets. "
                    "Possible ARP poisoning, spoofing attack, or broadcast storm."))

    # ── ICMP flood
    if proto == "ICMP":
        if len(flow_df) > 100:
            issues.append(("WARNING", "ICMP Flood",
                f"{len(flow_df)} ICMP packets detected. "
                "Possible ping flood DoS or ICMP-based scanning."))

    # ── Endpoint diversity
    try:
        pairs = flow_df.groupby(["Source IP", "Destination IP"]).size()
        if len(pairs) > 20:
            issues.append(("INFO", "High Endpoint Diversity",
                f"{len(pairs)} unique src→dst IP pairs. "
                "Possible port scan, P2P traffic, or misconfigured routing."))
    except Exception:
        pass

    # ── SIP without SDP
    if proto == "SIP":
        has_sdp = flow_df["Packet Detail"].str.contains("v=0", na=False).any()
        if not has_sdp:
            issues.append(("INFO", "SIP without SDP",
                "No SDP session description detected in SIP flow. "
                "Media negotiation may be incomplete or flow may be signalling only."))

    return issues


def build_report(issues: list, flow_df: pd.DataFrame, proto: str,
                 label: str) -> str:
    now = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    duration = flow_df["_raw_ts"].max() - flow_df["_raw_ts"].min() \
               if not flow_df.empty else 0
    total_bytes = flow_df["Size (Bytes)"].sum() if not flow_df.empty else 0

    lines = [
        "=" * 70,
        "  NETSCOPE — FLOW DIAGNOSTIC REPORT",
        "=" * 70,
        f"  Protocol      : {proto}",
        f"  Flow          : {label}",
        f"  Packets       : {len(flow_df):,}",
        f"  Duration      : {duration:.3f} s",
        f"  Bytes         : {total_bytes:,} ({total_bytes/1024:.2f} KB)",
        f"  Generated     : {now}",
        "=" * 70,
        "",
    ]

    sev_order = ["CRITICAL", "WARNING", "INFO"]
    by_sev = defaultdict(list)
    for sev, title, desc in issues:
        by_sev[sev].append((title, desc))

    if not issues:
        lines += ["  ✔  No anomalies detected. Flow appears healthy.", ""]
    else:
        for sev in sev_order:
            if sev not in by_sev:
                continue
            lines.append(f"── {sev} ({len(by_sev[sev])}) " + "─" * (60 - len(sev)))
            for i, (title, desc) in enumerate(by_sev[sev], 1):
                lines.append(f"  [{i}] {title}")
                for chunk in [desc[j:j+68] for j in range(0, len(desc), 68)]:
                    lines.append(f"      {chunk}")
            lines.append("")

    lines += [
        "── RECOMMENDATIONS " + "─" * 51,
    ]
    all_titles = [t for _, t, _ in issues]
    if any("RST" in t for t in all_titles):
        lines += [
            "  • Check firewall/ACL rules on path between endpoints.",
            "  • Review application logs on destination server.",
            "  • Use 'nmap -p <port> <host>' to verify port availability.",
        ]
    if any("Handshake" in t for t in all_titles):
        lines += [
            "  • Verify server reachability: ping / traceroute.",
            "  • Confirm port is open: telnet <host> <port>.",
        ]
    if any("Delay" in t or "Gap" in t for t in all_titles):
        lines += [
            "  • Analyse network congestion and QoS policies.",
            "  • Review TCP window scaling and buffer sizes.",
        ]
    if any("ARP" in t for t in all_titles):
        lines += [
            "  • Enable Dynamic ARP Inspection (DAI) on switches.",
            "  • Audit static ARP entries and MAC address tables.",
        ]
    if any("DNS" in t for t in all_titles):
        lines += [
            "  • Inspect resolver configuration for loops / misconfigs.",
            "  • Check for DNS-based malware/C2 beaconing patterns.",
        ]
    if not any(t in str(all_titles) for t in ("RST","Handshake","Delay","Gap","ARP","DNS")):
        lines.append("  • Review packet captures with Wireshark for detailed inspection.")

    lines += ["", "=" * 70]
    return "\n".join(lines)


# ─── Session State ────────────────────────────────────────────────────────────
for key, default in [
    ("df_all",        None),
    ("packets",       None),
    ("file_name",     None),
    ("flow_submitted", False),
    ("flow_result",   None),
]:
    if key not in st.session_state:
        st.session_state[key] = default


# ─── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="ns-header">
  <h1>🔬 NetScope — Packet Analyzer</h1>
  <p>Deep Packet Inspection · Protocol Flow Analysis · Anomaly Detection
     &nbsp;·&nbsp; Ericsson · Nokia · JIO Grade</p>
</div>
""", unsafe_allow_html=True)


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:10px 0 18px;">
      <div style="font-family:'Rajdhani',sans-serif;font-size:1.05rem;font-weight:700;
                  color:#00d4ff;letter-spacing:2px;text-transform:uppercase;">⚙ Controls</div>
      <div style="font-size:0.68rem;color:#546e7a;margin-top:3px;">Upload PCAP → Select Protocol</div>
    </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        "📁 Upload PCAP / PCAPNG",
        type=["pcap", "pcapng", "cap"],
        help="Supports 10 KB – 1 GB",
    )

    st.markdown("---")
    st.markdown('<div style="font-size:0.68rem;color:#546e7a;text-transform:uppercase;'
                'letter-spacing:1px;margin-bottom:8px;">Protocol Filter</div>',
                unsafe_allow_html=True)
    selected_proto = st.selectbox(
        "Protocol",
        options=["— Select —"] + PROTOCOL_FILTERS,
        label_visibility="collapsed",
    )

    # File stats + protocol distribution
    if st.session_state.df_all is not None:
        df_all = st.session_state.df_all
        total  = len(df_all)
        total_kb = df_all["Size (Bytes)"].sum() / 1024
        unique_endpoints = df_all["Source IP"].nunique() + df_all["Destination IP"].nunique()

        st.markdown("---")
        st.markdown(f"""
        <div style="padding:4px 0 10px;">
          <div style="font-size:0.68rem;color:#546e7a;text-transform:uppercase;
                      letter-spacing:1px;margin-bottom:10px;">File Stats</div>
          <div style="margin-bottom:8px;">
            <div style="font-family:'Rajdhani',sans-serif;font-size:1.5rem;
                        font-weight:700;color:#00d4ff;">{total:,}</div>
            <div style="font-size:0.66rem;color:#546e7a;text-transform:uppercase;">Total Packets</div>
          </div>
          <div style="margin-bottom:8px;">
            <div style="font-family:'Rajdhani',sans-serif;font-size:1.5rem;
                        font-weight:700;color:#00e676;">{unique_endpoints:,}</div>
            <div style="font-size:0.66rem;color:#546e7a;text-transform:uppercase;">Unique Endpoints</div>
          </div>
          <div>
            <div style="font-family:'Rajdhani',sans-serif;font-size:1.5rem;
                        font-weight:700;color:#ce93d8;">{total_kb:.1f} KB</div>
            <div style="font-size:0.66rem;color:#546e7a;text-transform:uppercase;">Total Data</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Protocol distribution chart
        st.markdown("---")
        st.markdown('<div style="font-size:0.68rem;color:#546e7a;text-transform:uppercase;'
                    'letter-spacing:1px;margin-bottom:10px;">Protocol Distribution</div>',
                    unsafe_allow_html=True)
        proto_counts = {}
        for proto in PROTOCOL_FILTERS:
            n = df_all["_protocols"].apply(lambda p: proto in p).sum()
            if n > 0:
                proto_counts[proto] = n
        if proto_counts:
            top = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_max = top[0][1]
            for pname, cnt in top:
                pct = cnt / total * 100
                bar_w = cnt / top_max * 100
                col = PROTO_COLORS.get(pname, "#90a4ae")
                st.markdown(f"""
                <div class="proto-bar-row">
                  <div class="proto-bar-label">
                    <span style="color:{col};font-weight:700;">{pname}</span>
                    <span>{pct:.1f}%</span>
                  </div>
                  <div class="proto-bar-track">
                    <div class="proto-bar-fill" style="width:{bar_w:.1f}%;background:{col};"></div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div style="font-size:0.62rem;color:#2e4057;text-align:center;padding-top:6px;">'
                'NetScope v3.0 · Scapy · Pandas<br>Telecom Grade · IST Timestamps</div>',
                unsafe_allow_html=True)


# ─── File Loading ─────────────────────────────────────────────────────────────
if uploaded_file is not None:
    if st.session_state.file_name != uploaded_file.name:
        st.session_state.flow_submitted = False
        st.session_state.flow_result    = None

        with st.spinner("⚡ Parsing PCAP — extracting metadata and building protocol stack…"):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(uploaded_file.read())
                    tmp_path = tmp.name

                df_all, packets = parse_pcap_to_df(tmp_path)
                os.unlink(tmp_path)

                if df_all is None:
                    st.error(f"❌ Failed to parse PCAP: {packets}")
                else:
                    st.session_state.df_all    = df_all
                    st.session_state.packets   = packets
                    st.session_state.file_name = uploaded_file.name
                    st.success(
                        f"✅ Loaded **{uploaded_file.name}** — {len(df_all):,} packets parsed")
            except Exception as e:
                st.error(f"❌ Error: {e}")
                st.code(traceback.format_exc())
else:
    if st.session_state.df_all is None:
        c1, c2, c3 = st.columns([1, 2, 1])
        with c2:
            st.markdown("""
            <div style="text-align:center;padding:56px 20px;">
              <div style="font-size:3.5rem;margin-bottom:16px;">📡</div>
              <div style="font-family:'Rajdhani',sans-serif;font-size:1.3rem;font-weight:700;
                          color:#e8eaf6;margin-bottom:10px;">Upload a PCAP File to Begin</div>
              <div style="font-size:0.78rem;color:#546e7a;line-height:1.9;">
                Supports .pcap / .pcapng / .cap<br>
                File sizes from <strong style="color:#00d4ff">10 KB</strong>
                to <strong style="color:#00d4ff">1 GB</strong><br><br>
                <em>Use the sidebar to upload your capture file</em>
              </div>
              <div style="margin-top:24px;padding:14px 18px;background:#0c1120;
                          border:1px solid #1a2a40;border-radius:8px;
                          font-size:0.72rem;color:#546e7a;text-align:left;">
                <strong style="color:#90a4ae;">Supported Protocols:</strong><br>
                TCP · UDP · IPv4 · IPv6 · ARP · ICMP<br>
                HTTP · HTTPS · TLS · DNS · FTP · SMTP<br>
                SSH · TELNET · Ethernet · PPP · PPPoE<br>
                MQTT · SIP · SDP
              </div>
            </div>
            """, unsafe_allow_html=True)


# ─── Main Analysis ────────────────────────────────────────────────────────────
if st.session_state.df_all is not None and selected_proto != "— Select —":
    df_all = st.session_state.df_all
    proto_df = filter_df_by_protocol(df_all, selected_proto)
    pcolor   = PROTO_COLORS.get(selected_proto, "#90a4ae")

    # ── Section header
    st.markdown(f"""
    <div class="ns-sh">
      <div class="dot" style="background:{pcolor};box-shadow:0 0 6px {pcolor};"></div>
      <span class="title">{selected_proto} — Packet Table</span>
      <span class="badge">{len(proto_df):,} packets</span>
    </div>
    """, unsafe_allow_html=True)

    if proto_df.empty:
        st.markdown(f"""
        <div style="padding:22px;background:#0c1120;border:1px dashed #1a2a40;
                    border-radius:8px;text-align:center;color:#546e7a;font-size:0.8rem;">
          No <strong style="color:{pcolor}">{selected_proto}</strong>
          packets found in this capture file.
        </div>
        """, unsafe_allow_html=True)
    else:
        # ── Stats row (5 cols)
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.markdown(f'<div class="stat-card"><div class="sv" style="color:{pcolor};">'
                        f'{len(proto_df):,}</div><div class="sl">Packets</div></div>',
                        unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="stat-card"><div class="sv">'
                        f'{proto_df["Source IP"].nunique()}</div>'
                        f'<div class="sl">Unique Src IPs</div></div>',
                        unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="stat-card"><div class="sv">'
                        f'{proto_df["Destination IP"].nunique()}</div>'
                        f'<div class="sl">Unique Dst IPs</div></div>',
                        unsafe_allow_html=True)
        with c4:
            total_kb = proto_df["Size (Bytes)"].sum() / 1024
            st.markdown(f'<div class="stat-card"><div class="sv">{total_kb:.1f}</div>'
                        f'<div class="sl">Total KB</div></div>',
                        unsafe_allow_html=True)
        with c5:
            avg_sz = proto_df["Size (Bytes)"].mean()
            st.markdown(f'<div class="stat-card"><div class="sv">{avg_sz:.0f}</div>'
                        f'<div class="sl">Avg Pkt Bytes</div></div>',
                        unsafe_allow_html=True)

        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

        # ── Packet Table (all columns incl Protocol + Packet Detail)
        display_df = render_display_df(proto_df)
        st.dataframe(
            display_df,
            use_container_width=True,
            height=min(420, 55 + len(display_df) * 35),
            hide_index=True,
            column_config={
                "Packet Detail": st.column_config.TextColumn(width="large"),
                "Protocol":      st.column_config.TextColumn(width="medium"),
            },
        )

        # ── Per-Packet Detail Inspector
        with st.expander("🔎 Per-Packet Detail Inspector", expanded=False):
            pkt_nos = proto_df["No."].tolist()
            sel_no = st.selectbox(
                "Select packet No. to inspect",
                options=pkt_nos,
                key="pkt_inspector_sel",
            )
            sel_row = proto_df[proto_df["No."] == sel_no]
            if not sel_row.empty:
                row = sel_row.iloc[0]
                st.markdown(f"""
                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
                  <span class="pill" style="background:rgba(0,212,255,.15);color:#00d4ff;">
                    #{row['No.']}
                  </span>
                  <span class="pill" style="background:rgba(0,230,118,.12);color:#00e676;">
                    {row['Source IP']} → {row['Destination IP']}
                  </span>
                  <span class="pill" style="background:rgba(206,147,216,.12);color:#ce93d8;">
                    {row['Size (Bytes)']} bytes
                  </span>
                  <span class="pill" style="background:rgba(255,171,64,.12);color:#ffab40;">
                    {row['Timestamp (IST)']}
                  </span>
                </div>
                <div style="font-size:0.68rem;color:#546e7a;margin-bottom:6px;">
                  Protocol Stack: <strong style="color:#e8eaf6;">{row['Protocol']}</strong>
                </div>
                <div class="detail-box">{row['Packet Detail']}</div>
                """, unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # Section 2: Flow Drill-Down
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("""
        <div class="ns-sh" style="margin-top:28px;">
          <div class="dot" style="background:#ce93d8;box-shadow:0 0 6px #ce93d8;"></div>
          <span class="title">Flow Drill-Down</span>
          <span class="badge">Filter by endpoint pair</span>
        </div>
        <div style="font-size:0.75rem;color:#546e7a;margin-bottom:14px;">
          Enter <strong style="color:#90a4ae;">Source + Destination IP</strong>
          &nbsp;<em>or</em>&nbsp;
          <strong style="color:#90a4ae;">Source + Destination MAC</strong>
          to inspect the complete conversation flow.
        </div>
        """, unsafe_allow_html=True)

        tab_ip, tab_mac = st.tabs(["🌐  Filter by IP Address", "🔌  Filter by MAC Address"])

        with tab_ip:
            ci1, ci2 = st.columns(2)
            with ci1:
                fi_src = st.text_input("Source IP", placeholder="e.g. 192.168.1.10",
                                        key="fi_src_ip")
            with ci2:
                fi_dst = st.text_input("Destination IP", placeholder="e.g. 8.8.8.8",
                                        key="fi_dst_ip")
            btn_ip = st.button("🔍  Analyze IP Flow", key="btn_ip", use_container_width=False)

        with tab_mac:
            cm1, cm2 = st.columns(2)
            with cm1:
                fm_src = st.text_input("Source MAC", placeholder="e.g. AA:BB:CC:DD:EE:FF",
                                        key="fi_src_mac")
            with cm2:
                fm_dst = st.text_input("Destination MAC", placeholder="e.g. 11:22:33:44:55:66",
                                        key="fi_dst_mac")
            btn_mac = st.button("🔍  Analyze MAC Flow", key="btn_mac", use_container_width=False)

        # ── Process flow filter
        flow_df     = None
        filter_label = ""

        if btn_ip and fi_src.strip() and fi_dst.strip():
            flow_df = filter_df_by_endpoints(proto_df, src_ip=fi_src, dst_ip=fi_dst)
            filter_label = f"IP Flow: {fi_src.strip()} ⟷ {fi_dst.strip()}"
            st.session_state.flow_submitted = True
            st.session_state.flow_result    = (flow_df.copy(), filter_label, selected_proto)

        elif btn_mac and fm_src.strip() and fm_dst.strip():
            flow_df = filter_df_by_endpoints(proto_df, src_mac=fm_src, dst_mac=fm_dst)
            filter_label = f"MAC Flow: {fm_src.strip().upper()} ⟷ {fm_dst.strip().upper()}"
            st.session_state.flow_submitted = True
            st.session_state.flow_result    = (flow_df.copy(), filter_label, selected_proto)

        elif st.session_state.flow_submitted and st.session_state.flow_result:
            flow_df, filter_label, _ = st.session_state.flow_result

        # ── Display flow results
        if flow_df is not None and st.session_state.flow_submitted:

            st.markdown(f"""
            <div class="ns-sh" style="margin-top:26px;">
              <div class="dot" style="background:#00e676;box-shadow:0 0 6px #00e676;"></div>
              <span class="title">Communication Flow</span>
              <span class="badge" style="color:#00e676;border-color:rgba(0,230,118,.3);
                                         background:rgba(0,230,118,.08);">
                {filter_label}
              </span>
            </div>
            """, unsafe_allow_html=True)

            if flow_df.empty:
                st.markdown("""
                <div style="padding:18px;background:#0c1120;border:1px dashed #ff5252;
                            border-radius:8px;text-align:center;color:#ff5252;font-size:0.8rem;">
                  ⚠ No packets found for this endpoint pair in the selected protocol.<br>
                  <span style="color:#546e7a;font-size:0.72rem;">
                  Verify addresses match entries in the packet table above.
                  </span>
                </div>
                """, unsafe_allow_html=True)
            else:
                # Flow stats (5 cols)
                raw_ts_col = flow_df["_raw_ts"]
                duration   = raw_ts_col.max() - raw_ts_col.min()
                flow_bytes = flow_df["Size (Bytes)"].sum()
                throughput = flow_bytes / max(duration, 0.001) / 1024

                cf1, cf2, cf3, cf4, cf5 = st.columns(5)
                with cf1:
                    st.markdown(f'<div class="stat-card"><div class="sv" style="color:#00e676;">'
                                f'{len(flow_df):,}</div><div class="sl">Flow Packets</div></div>',
                                unsafe_allow_html=True)
                with cf2:
                    st.markdown(f'<div class="stat-card"><div class="sv" style="color:#ffab40;">'
                                f'{duration:.3f}s</div><div class="sl">Duration</div></div>',
                                unsafe_allow_html=True)
                with cf3:
                    st.markdown(f'<div class="stat-card"><div class="sv" style="color:#ce93d8;">'
                                f'{flow_bytes/1024:.2f}</div><div class="sl">KB Exchanged</div></div>',
                                unsafe_allow_html=True)
                with cf4:
                    st.markdown(f'<div class="stat-card"><div class="sv" style="color:#00d4ff;">'
                                f'{flow_df["Destination IP"].nunique()}</div>'
                                f'<div class="sl">Unique Dst IPs</div></div>',
                                unsafe_allow_html=True)
                with cf5:
                    st.markdown(f'<div class="stat-card"><div class="sv" style="color:#82b1ff;">'
                                f'{throughput:.1f}</div><div class="sl">KB/s Throughput</div></div>',
                                unsafe_allow_html=True)

                st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

                # ── Flow Table (all columns incl Protocol + Packet Detail)
                st.markdown('<div style="font-size:0.68rem;color:#546e7a;'
                            'text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">'
                            '📋 Packet-by-Packet Flow Table</div>',
                            unsafe_allow_html=True)
                flow_display = render_display_df(flow_df)
                st.dataframe(
                    flow_display,
                    use_container_width=True,
                    height=min(440, 55 + len(flow_display) * 35),
                    hide_index=True,
                    column_config={
                        "Packet Detail": st.column_config.TextColumn(width="large"),
                        "Protocol":      st.column_config.TextColumn(width="medium"),
                    },
                )

                # ── Visual Flow Timeline
                with st.expander("🔀 Visual Flow Timeline (first 40 packets)", expanded=True):
                    ref_src_ip  = flow_df.iloc[0]["Source IP"]
                    ref_src_mac = flow_df.iloc[0]["Src MAC"]
                    timeline_df = flow_df.head(40).reset_index(drop=True)

                    for _, row in timeline_df.iterrows():
                        is_fwd = (row["Source IP"] == ref_src_ip or
                                  row["Src MAC"]   == ref_src_mac)
                        arrow_color = "#00d4ff" if is_fwd else "#00e676"
                        margin_auto = "0" if is_fwd else "auto"

                        sport = row.get("_sport", "")
                        dport = row.get("_dport", "")
                        port_str = f" :{sport}→:{dport}" if sport and dport else ""

                        # First line of Packet Detail
                        detail_first = str(row.get("Packet Detail", "")).split("\n")[0]

                        st.markdown(f"""
                        <div style="margin:4px 0;max-width:88%;margin-left:{margin_auto};">
                          <div style="background:#0c1120;border:1px solid #1a2a40;
                                      border-left:3px solid {arrow_color};
                                      border-radius:6px;padding:9px 13px;font-size:0.73rem;">
                            <div style="display:flex;justify-content:space-between;
                                        align-items:center;flex-wrap:wrap;gap:4px;">
                              <span>
                                <span style="color:{arrow_color};font-weight:700;">
                                  {'→' if is_fwd else '←'} {row['Source IP']}
                                </span>
                                <span style="color:#546e7a;"> → </span>
                                <span style="color:#90a4ae;">{row['Destination IP']}</span>
                                <span style="color:#2e4057;">{port_str}</span>
                              </span>
                              <span style="display:flex;gap:6px;align-items:center;">
                                <span style="background:rgba(0,212,255,.1);color:#00d4ff;
                                             padding:1px 7px;border-radius:3px;font-size:0.64rem;">
                                  {row.get('Protocol','').split(' / ')[-1]}
                                </span>
                                <span style="color:#2e4057;font-size:0.66rem;">
                                  {row['Size (Bytes)']} B
                                </span>
                                <span style="color:#2e4057;font-size:0.66rem;">
                                  {str(row['Timestamp (IST)'])[-18:-4]}
                                </span>
                              </span>
                            </div>
                            <div style="color:#546e7a;font-size:0.65rem;margin-top:3px;
                                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                              {detail_first}
                            </div>
                          </div>
                        </div>
                        """, unsafe_allow_html=True)

                # ══════════════════════════════════════════════════════════════
                # Section 4: Diagnostics
                # ══════════════════════════════════════════════════════════════
                st.markdown("""
                <div class="ns-sh" style="margin-top:28px;">
                  <div class="dot" style="background:#ff5252;box-shadow:0 0 6px #ff5252;"></div>
                  <span class="title">Flow Diagnostics &amp; Anomaly Detection</span>
                </div>
                """, unsafe_allow_html=True)

                issues = analyze_flow(flow_df, selected_proto)

                if not issues:
                    st.markdown("""
                    <div class="diag-ok">
                      <div class="diag-title" style="color:#00e676;">✔ Flow Healthy</div>
                      <div style="font-size:0.76rem;color:#90a4ae;">
                        No anomalies detected. Handshake, data transfer and termination
                        sequences appear normal for the selected protocol.
                      </div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    by_sev = defaultdict(list)
                    for sev, title, desc in issues:
                        by_sev[sev].append((title, desc))

                    sev_meta = {
                        "CRITICAL": ("diag-critical", "#ff5252", "🔴 CRITICAL"),
                        "WARNING":  ("diag-warning",  "#ffab40", "🟠 WARNING"),
                        "INFO":     ("diag-info",     "#00d4ff", "ℹ INFO"),
                    }

                    for sev in ("CRITICAL", "WARNING", "INFO"):
                        if sev not in by_sev:
                            continue
                        cls, col, label = sev_meta[sev]
                        st.markdown(f"""
                        <div class="{cls}">
                          <div class="diag-title" style="color:{col};">
                            {label} — {len(by_sev[sev])} issue(s)
                          </div>
                        """, unsafe_allow_html=True)
                        for title, desc in by_sev[sev]:
                            st.markdown(f"""
                            <div class="diag-item">
                              <span>▸</span>
                              <span><strong>{title}:</strong> {desc}</span>
                            </div>
                            """, unsafe_allow_html=True)
                        st.markdown("</div>", unsafe_allow_html=True)

                # ── Exportable Report
                st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
                report_text = build_report(issues, flow_df, selected_proto, filter_label)
                st.text_area(
                    "📋 Full Diagnostic Report (copy / export)",
                    value=report_text,
                    height=340,
                    key="diag_report",
                )

elif st.session_state.df_all is not None and selected_proto == "— Select —":
    st.markdown("""
    <div style="padding:28px;background:#0c1120;border:1px dashed #1a2a40;
                border-radius:10px;text-align:center;margin-top:14px;">
      <div style="font-size:1.8rem;margin-bottom:10px;">🔽</div>
      <div style="font-family:'Rajdhani',sans-serif;font-size:0.95rem;font-weight:700;
                  color:#90a4ae;text-transform:uppercase;letter-spacing:2px;">
        Select a Protocol Filter
      </div>
      <div style="font-size:0.75rem;color:#546e7a;margin-top:6px;">
        Use the sidebar dropdown to choose a protocol and begin analysis
      </div>
    </div>
    """, unsafe_allow_html=True)
