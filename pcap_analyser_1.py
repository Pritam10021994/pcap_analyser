"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         NetScope  —  Deep Packet Inspection & Protocol Flow Analyzer        ║
║         Telecom Grade · Ericsson · Nokia · JIO                              ║
║         Stack: Python · Streamlit · Scapy · Pandas · NumPy                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta
import tempfile, os, traceback, textwrap
from collections import defaultdict

# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="NetScope — PCAP Analyser",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# CSS  —  dark terminal aesthetic
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=Rajdhani:wght@400;500;600;700&display=swap');

:root {
    --bg0: #080c14;
    --bg1: #0d1322;
    --bg2: #111828;
    --bg3: #172035;
    --border0: #1a2540;
    --border1: #243356;
    --border2: #2e4070;
    --cyan:   #00e5ff;
    --green:  #00e676;
    --amber:  #ffab00;
    --red:    #ff1744;
    --purple: #d500f9;
    --pink:   #ff4081;
    --blue:   #2979ff;
    --teal:   #1de9b6;
    --txt0:   #eceff4;
    --txt1:   #b0bec5;
    --txt2:   #607d8b;
    --txt3:   #37474f;
}

/* ── Reset & base ── */
html, body, [class*="css"] {
    font-family: 'IBM Plex Mono', monospace !important;
    background: var(--bg0) !important;
    color: var(--txt0) !important;
}
.stApp { background: var(--bg0) !important; }
.block-container { padding: 1.5rem 2rem !important; max-width: 100% !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: var(--bg1) !important;
    border-right: 1px solid var(--border1) !important;
}
section[data-testid="stSidebar"] * { color: var(--txt1) !important; }

/* ── Sidebar title ── */
.sb-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.3rem;
    font-weight: 700;
    color: var(--cyan) !important;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 16px 0 4px;
    border-bottom: 1px solid var(--border1);
    margin-bottom: 16px;
}
.sb-label {
    font-size: 0.65rem;
    color: var(--txt2) !important;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 6px;
}

/* ── Main header ── */
.ns-header {
    background: linear-gradient(135deg, var(--bg2) 0%, var(--bg3) 60%, var(--bg1) 100%);
    border: 1px solid var(--border2);
    border-radius: 12px;
    padding: 26px 36px 22px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.ns-header::after {
    content: '';
    position: absolute;
    inset: 0;
    background:
        radial-gradient(ellipse 60% 80% at 5% 50%, rgba(0,229,255,.06) 0%, transparent 70%),
        radial-gradient(ellipse 40% 60% at 95% 50%, rgba(0,230,118,.04) 0%, transparent 70%);
    pointer-events: none;
}
.ns-header h1 {
    font-family: 'Rajdhani', sans-serif;
    font-size: 2.6rem;
    font-weight: 700;
    margin: 0 0 4px;
    letter-spacing: 2px;
    background: linear-gradient(90deg, var(--cyan) 0%, var(--teal) 50%, var(--green) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.ns-header .sub {
    font-size: 0.72rem;
    color: var(--txt2);
    letter-spacing: 2px;
    text-transform: uppercase;
}
.ns-header .badge {
    display: inline-block;
    font-size: 0.62rem;
    padding: 2px 10px;
    border-radius: 20px;
    background: rgba(0,229,255,.1);
    border: 1px solid rgba(0,229,255,.25);
    color: var(--cyan);
    margin-right: 6px;
    letter-spacing: 1px;
}

/* ── Section headers ── */
.sec-hdr {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 28px 0 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border0);
}
.sec-hdr .dot {
    width: 9px; height: 9px;
    border-radius: 50%;
    flex-shrink: 0;
}
.sec-hdr .title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.05rem;
    font-weight: 700;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--txt0);
}
.sec-hdr .pill {
    font-size: 0.65rem;
    padding: 2px 10px;
    border-radius: 20px;
    border: 1px solid var(--border1);
    color: var(--txt2);
    background: var(--bg2);
    white-space: nowrap;
}

/* ── Stat cards ── */
.stat-grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; }
.stat-card {
    flex: 1; min-width: 120px;
    background: var(--bg2);
    border: 1px solid var(--border1);
    border-radius: 10px;
    padding: 16px 20px;
}
.stat-card .val {
    font-family: 'Rajdhani', sans-serif;
    font-size: 1.9rem;
    font-weight: 700;
    line-height: 1;
}
.stat-card .lbl {
    font-size: 0.62rem;
    color: var(--txt2);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 4px;
}

/* ── Protocol pill in table ── */
.proto-pill {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    border: 1px solid currentColor;
}

/* ── Detail box (packet info) ── */
.detail-box {
    background: var(--bg1);
    border: 1px solid var(--border0);
    border-left: 3px solid var(--cyan);
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.72rem;
    line-height: 1.7;
    color: var(--txt1);
    font-family: 'IBM Plex Mono', monospace;
    white-space: pre-wrap;
    word-break: break-all;
}

/* ── Flow timeline packet ── */
.flow-pkt {
    background: var(--bg2);
    border: 1px solid var(--border0);
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    font-size: 0.73rem;
    line-height: 1.7;
    position: relative;
}
.flow-pkt .fp-num {
    position: absolute;
    top: 10px; right: 14px;
    font-size: 0.65rem;
    color: var(--txt3);
}
.flow-pkt .fp-dir  { font-weight: 700; }
.flow-pkt .fp-meta { color: var(--txt2); font-size: 0.68rem; }

/* ── Problem / OK boxes ── */
.prob-box {
    background: linear-gradient(135deg, rgba(255,23,68,.07), rgba(255,23,68,.03));
    border: 1px solid rgba(255,23,68,.3);
    border-left: 4px solid var(--red);
    border-radius: 8px;
    padding: 18px 22px;
    margin-bottom: 10px;
}
.prob-box .ph {
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.85rem;
    font-weight: 700;
    color: var(--red);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 10px;
}
.prob-item {
    font-size: 0.76rem;
    color: var(--txt1);
    padding: 6px 0;
    border-bottom: 1px solid rgba(255,23,68,.08);
    display: flex;
    align-items: flex-start;
    gap: 8px;
}
.prob-item:last-child { border-bottom: none; }
.ok-box {
    background: linear-gradient(135deg, rgba(0,230,118,.07), rgba(0,230,118,.03));
    border: 1px solid rgba(0,230,118,.3);
    border-left: 4px solid var(--green);
    border-radius: 8px;
    padding: 16px 22px;
    font-size: 0.8rem;
    color: var(--green);
    font-weight: 500;
}

/* ── Info / empty boxes ── */
.info-box {
    background: var(--bg2);
    border: 1px dashed var(--border1);
    border-radius: 8px;
    padding: 22px;
    text-align: center;
    color: var(--txt2);
    font-size: 0.8rem;
}

/* ── Streamlit widget overrides ── */
div[data-testid="stFileUploader"] {
    border: 2px dashed var(--border1) !important;
    border-radius: 10px !important;
    background: var(--bg2) !important;
}
div[data-testid="stFileUploader"]:hover { border-color: var(--cyan) !important; }

.stSelectbox > div > div,
.stTextInput > div > div > input,
.stTextArea textarea {
    background: var(--bg2) !important;
    border-color: var(--border1) !important;
    color: var(--txt0) !important;
    font-family: 'IBM Plex Mono', monospace !important;
}
.stTextArea textarea { font-size: 0.75rem !important; }

.stButton > button {
    background: linear-gradient(135deg, #0099bb, var(--cyan)) !important;
    color: #000 !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    letter-spacing: 2px !important;
    border: none !important;
    border-radius: 7px !important;
    padding: 10px 28px !important;
    text-transform: uppercase !important;
    transition: all .2s !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 20px rgba(0,229,255,.35) !important;
}

.stTabs [data-baseweb="tab-list"] {
    background: var(--bg2) !important;
    border-radius: 8px 8px 0 0;
    padding: 5px;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.72rem !important;
    color: var(--txt2) !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
}
.stTabs [aria-selected="true"] {
    color: var(--cyan) !important;
    background: var(--bg1) !important;
}
div[data-testid="stExpander"] {
    background: var(--bg2) !important;
    border: 1px solid var(--border0) !important;
    border-radius: 8px !important;
}
div[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

/* scrollbar */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg0); }
::-webkit-scrollbar-thumb { background: var(--border1); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--cyan); }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
IST = timezone(timedelta(hours=5, minutes=30))

PROTOCOL_FILTERS = [
    "TCP", "UDP", "IPv4", "IPv6", "ARP", "ICMP",
    "HTTP", "HTTPS", "TLS", "DNS", "FTP", "SMTP",
    "SSH", "TELNET", "Ethernet", "PPPoE",
    "MQTT", "SIP", "SDP",
]

PROTO_COLOR = {
    "TCP":      "#00e5ff", "UDP":      "#00e676", "IPv4":   "#d500f9",
    "IPv6":     "#ff6d00", "ARP":      "#ffab00", "ICMP":   "#ff4081",
    "HTTP":     "#69f0ae", "HTTPS":    "#00e5ff", "TLS":    "#40c4ff",
    "DNS":      "#ffca28", "FTP":      "#ff1744", "SMTP":   "#ea80fc",
    "SSH":      "#64ffda", "TELNET":   "#ff6d00", "Ethernet":"#90a4ae",
    "PPPoE":    "#80d8ff", "MQTT":     "#b9f6ca",
    "SIP":      "#fb8c00", "SDP":      "#ce93d8",
}

PORT_PROTO = {
    80: "HTTP",  443: "HTTPS",  8080: "HTTP",  8443: "HTTPS",
    53: "DNS",   21: "FTP",     20: "FTP",
    25: "SMTP",  587: "SMTP",   465: "SMTP",
    22: "SSH",   23: "TELNET",
    1883: "MQTT",8883: "MQTT",
    5060: "SIP", 5061: "SIP",
}

# ══════════════════════════════════════════════════════════════════════════════
# PACKET PARSING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def ts_to_ist(ts: float) -> str:
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone(IST)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " IST"
    except Exception:
        return str(ts)


def get_mac(pkt) -> tuple:
    """Always returns (src_mac, dst_mac) strings."""
    try:
        from scapy.all import Ether
        if Ether in pkt:
            return pkt[Ether].src.upper(), pkt[Ether].dst.upper()
    except Exception:
        pass
    return "N/A", "N/A"


def get_ip(pkt) -> tuple:
    """Always returns (src_ip, dst_ip) strings."""
    try:
        from scapy.all import IP, IPv6
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
    except Exception:
        pass
    return "N/A", "N/A"


def detect_protocols(pkt) -> set:
    """Return set of protocol names present in the packet."""
    try:
        from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
        p = set()

        if Ether in pkt:  p.add("Ethernet")
        if ARP   in pkt:  p.add("ARP")
        if IP    in pkt:  p.add("IPv4")
        if IPv6  in pkt:  p.add("IPv6")
        if ICMP  in pkt:  p.add("ICMP")

        if TCP in pkt:
            p.add("TCP")
            sp, dp = pkt[TCP].sport, pkt[TCP].dport
            for port in (sp, dp):
                if port in PORT_PROTO:
                    p.add(PORT_PROTO[port])
            if sp in (443,8443) or dp in (443,8443): p.update({"TLS","HTTPS"})
            if sp == 22  or dp == 22:  p.add("SSH")
            if sp == 23  or dp == 23:  p.add("TELNET")
            if sp in (25,587,465) or dp in (25,587,465): p.add("SMTP")
            if sp in (20,21) or dp in (20,21): p.add("FTP")
            if sp in (5060,5061) or dp in (5060,5061): p.add("SIP")
            if Raw in pkt:
                try:
                    raw = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                    if raw.startswith(("GET ","POST ","PUT ","DELETE ","HTTP/")): p.add("HTTP")
                    if "v=0" in raw and "m=" in raw: p.add("SDP")
                except Exception:
                    pass

        if UDP in pkt:
            p.add("UDP")
            sp, dp = pkt[UDP].sport, pkt[UDP].dport
            for port in (sp, dp):
                if port in PORT_PROTO:
                    p.add(PORT_PROTO[port])
            if sp == 53  or dp == 53:  p.add("DNS")
            if sp in (1883,8883) or dp in (1883,8883): p.add("MQTT")
            if sp in (5060,5061) or dp in (5060,5061): p.add("SIP")

        # PPPoE
        try:
            from scapy.all import PPPoE
            if PPPoE in pkt: p.add("PPPoE")
        except Exception:
            pass

        return p
    except Exception:
        return set()


def build_packet_detail(pkt) -> str:
    """
    Build a human-readable detail string for the packet showing
    all layer fields in a structured way.
    """
    lines = []
    try:
        from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

        # ── Ethernet
        if Ether in pkt:
            e = pkt[Ether]
            lines.append(f"[Ethernet]  src={e.src}  dst={e.dst}  type=0x{e.type:04X}")

        # ── ARP
        if ARP in pkt:
            a = pkt[ARP]
            ops = {1:"who-has", 2:"is-at"}.get(a.op, str(a.op))
            lines.append(f"[ARP]  op={ops}  sender={a.psrc}({a.hwsrc})  target={a.pdst}({a.hwdst})")

        # ── IPv4
        if IP in pkt:
            ip = pkt[IP]
            lines.append(
                f"[IPv4]  src={ip.src}  dst={ip.dst}  ttl={ip.ttl}  "
                f"proto={ip.proto}  len={ip.len}  id=0x{ip.id:04X}  "
                f"flags={ip.flags}  tos={ip.tos}"
            )

        # ── IPv6
        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            lines.append(
                f"[IPv6]  src={ip6.src}  dst={ip6.dst}  "
                f"hlim={ip6.hlim}  nh={ip6.nh}  plen={ip6.plen}"
            )

        # ── ICMP
        if ICMP in pkt:
            ic = pkt[ICMP]
            type_names = {
                0:"Echo Reply", 3:"Dest Unreachable", 5:"Redirect",
                8:"Echo Request", 11:"Time Exceeded", 12:"Parameter Problem"
            }
            lines.append(
                f"[ICMP]  type={ic.type}({type_names.get(ic.type,'')})  "
                f"code={ic.code}  id={getattr(ic,'id','-')}  seq={getattr(ic,'seq','-')}"
            )

        # ── TCP
        if TCP in pkt:
            t = pkt[TCP]
            flag_map = {
                "F":"FIN","S":"SYN","R":"RST","P":"PSH",
                "A":"ACK","U":"URG","E":"ECE","C":"CWR"
            }
            flag_str = "|".join(v for k,v in flag_map.items() if k in str(t.flags)) or str(t.flags)
            lines.append(
                f"[TCP]  sport={t.sport}  dport={t.dport}  "
                f"flags=[{flag_str}]  seq={t.seq}  ack={t.ack}  "
                f"win={t.window}  len={len(t.payload)}"
            )

        # ── UDP
        if UDP in pkt:
            u = pkt[UDP]
            lines.append(
                f"[UDP]  sport={u.sport}  dport={u.dport}  "
                f"len={u.len}  chksum=0x{u.chksum:04X}"
            )

        # ── DNS
        if DNS in pkt:
            dns = pkt[DNS]
            qname = ""
            try:
                if dns.qd:
                    qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            except Exception:
                pass
            opcode_map = {0:"QUERY",1:"IQUERY",2:"STATUS",4:"NOTIFY",5:"UPDATE"}
            rcode_map  = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",5:"REFUSED"}
            lines.append(
                f"[DNS]  id={dns.id}  qr={'Response' if dns.qr else 'Query'}  "
                f"opcode={opcode_map.get(dns.opcode,dns.opcode)}  "
                f"rcode={rcode_map.get(dns.rcode,dns.rcode)}  "
                f"qname={qname}  qdcount={dns.qdcount}  ancount={dns.ancount}"
            )

        # ── Raw payload excerpt
        if Raw in pkt:
            raw_bytes = bytes(pkt[Raw])
            try:
                text = raw_bytes.decode("utf-8", errors="replace")
                excerpt = text[:120].replace("\r","\\r").replace("\n","\\n")
            except Exception:
                excerpt = raw_bytes[:60].hex()
            lines.append(f"[Payload]  {len(raw_bytes)}B  \"{excerpt}{'…' if len(raw_bytes)>120 else ''}\"")

        if not lines:
            lines.append(pkt.summary())

    except Exception as e:
        lines.append(f"(detail error: {e})")

    return "\n".join(lines)


def protocol_display_name(protos: set) -> str:
    """
    Return a compact protocol-stack string, e.g. 'Ethernet / IPv4 / TCP / HTTP'.
    """
    order = ["Ethernet","PPPoE","ARP","IPv4","IPv6","ICMP",
             "TCP","UDP","TLS","DNS","HTTP","HTTPS","FTP","SMTP",
             "SSH","TELNET","MQTT","SIP","SDP"]
    ordered = [p for p in order if p in protos]
    rest    = sorted(protos - set(ordered))
    return " / ".join(ordered + rest) if ordered + rest else "Unknown"


# ══════════════════════════════════════════════════════════════════════════════
# PCAP LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_pcap(filepath: str):
    try:
        from scapy.all import rdpcap
        return rdpcap(filepath), None
    except Exception as e:
        return None, str(e)


def parse_pcap_to_df(filepath: str):
    """
    Returns (DataFrame, raw_packet_list) or (None, error_string).

    DataFrame columns:
        No. | Source IP | Destination IP | Src MAC | Dst MAC |
        Timestamp (IST) | Size (Bytes) | Protocol | Packet Detail |
        _protocols | _sport | _dport | _raw_ts | _flags | _summary
    """
    packets, err = load_pcap(filepath)
    if packets is None:
        return None, f"Could not open PCAP: {err}"

    rows, skipped = [], 0
    try:
        from scapy.all import TCP, UDP
        for i, pkt in enumerate(packets):
            try:
                src_ip,  dst_ip  = get_ip(pkt)
                src_mac, dst_mac = get_mac(pkt)
                raw_ts           = float(pkt.time)
                protos           = detect_protocols(pkt)
                proto_name       = protocol_display_name(protos)
                detail           = build_packet_detail(pkt)

                sport = dport = flags = None
                if TCP in pkt:
                    sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
                elif UDP in pkt:
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport

                rows.append({
                    "No.":             i + 1,
                    "Source IP":       src_ip,
                    "Destination IP":  dst_ip,
                    "Src MAC":         src_mac,
                    "Dst MAC":         dst_mac,
                    "Timestamp (IST)": ts_to_ist(raw_ts),
                    "Size (Bytes)":    len(pkt),
                    "Protocol":        proto_name,
                    "Packet Detail":   detail,
                    # internal cols
                    "_protocols": protos,
                    "_sport":     sport,
                    "_dport":     dport,
                    "_raw_ts":    raw_ts,
                    "_flags":     flags,
                    "_summary":   pkt.summary(),
                })
            except Exception:
                skipped += 1

    except Exception:
        return None, f"Error during parsing:\n{traceback.format_exc()}"

    if not rows:
        return None, "No packets could be parsed. File may be empty or unsupported."

    df = pd.DataFrame(rows)
    if skipped:
        st.warning(f"⚠ {skipped} malformed packet(s) skipped during parsing.")
    return df, packets


# ══════════════════════════════════════════════════════════════════════════════
# FILTER HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def filter_by_proto(df: pd.DataFrame, proto: str) -> pd.DataFrame:
    return df[df["_protocols"].apply(lambda p: proto in p)].copy()


def filter_by_endpoints(df: pd.DataFrame,
                        src_ip=None, dst_ip=None,
                        src_mac=None, dst_mac=None) -> pd.DataFrame:
    if src_ip and src_ip.strip() and dst_ip and dst_ip.strip():
        s, d = src_ip.strip(), dst_ip.strip()
        mask = (
            ((df["Source IP"] == s) & (df["Destination IP"] == d)) |
            ((df["Source IP"] == d) & (df["Destination IP"] == s))
        )
        return df[mask].copy()

    if src_mac and src_mac.strip() and dst_mac and dst_mac.strip():
        s, d = src_mac.strip().upper(), dst_mac.strip().upper()
        mask = (
            ((df["Src MAC"] == s) & (df["Dst MAC"] == d)) |
            ((df["Src MAC"] == d) & (df["Dst MAC"] == s))
        )
        return df[mask].copy()

    return df.copy()


DISPLAY_COLS = [
    "No.", "Source IP", "Destination IP", "Src MAC", "Dst MAC",
    "Timestamp (IST)", "Size (Bytes)", "Protocol", "Packet Detail",
]

def display_df(df: pd.DataFrame) -> pd.DataFrame:
    cols = [c for c in DISPLAY_COLS if c in df.columns]
    return df[cols].reset_index(drop=True)


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY / DIAGNOSTICS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def analyze_flow(flow: pd.DataFrame, proto: str) -> list:
    """
    Returns list of (severity, title, description) tuples.
    severity: "CRITICAL" | "WARNING" | "INFO"
    """
    issues = []
    if flow.empty:
        return [("CRITICAL","No Packets","No packets matched this endpoint pair.")]

    n = len(flow)

    # ── TCP handshake & state analysis ────────────────────────────────────────
    if proto in ("TCP","HTTP","HTTPS","TLS","SSH","FTP","SMTP","TELNET","SIP"):
        flags = flow["_flags"].dropna().tolist()

        def count_flag(bit):
            return sum(1 for f in flags if hasattr(f,"__int__") and int(f) & bit)

        syn = count_flag(0x02); ack = count_flag(0x10)
        rst = count_flag(0x04); fin = count_flag(0x01)
        psh = count_flag(0x08)

        if rst > 0:
            issues.append(("CRITICAL","TCP RST Detected",
                f"{rst} RST packet(s) found. The connection was forcibly terminated. "
                f"Possible causes: server port closed/refused, firewall ACL drop, "
                f"application crash, or load-balancer timeout."))

        if syn > 0 and ack == 0:
            issues.append(("CRITICAL","Incomplete TCP Handshake",
                f"{syn} SYN(s) sent with 0 ACKs returned. 3-way handshake never completed. "
                f"Server may be unreachable, port filtered, or the network is dropping SYNs."))

        if syn > 4 and rst == 0 and ack < syn // 2:
            issues.append(("WARNING","Possible SYN Flood / Port Scan",
                f"{syn} SYN packets vs only {ack} ACKs. High SYN-to-ACK ratio "
                f"suggests a SYN flood attack, aggressive port scan, or misconfigured retry loop."))

        if fin == 0 and n > 4 and rst == 0:
            issues.append(("WARNING","No TCP FIN — Ungraceful Session End",
                f"Session has {n} packets but no FIN observed. Connection may have been "
                f"dropped abruptly (half-open), or FIN packets were lost in transit."))

        if psh == 0 and n > 10:
            issues.append(("INFO","No PSH Flags in Long Flow",
                f"A {n}-packet TCP flow contains no PSH flags. "
                f"Application may not be flushing the send buffer efficiently, "
                f"causing buffering delays (Nagle algorithm conflict)."))

    # ── Inter-packet timing ───────────────────────────────────────────────────
    ts = sorted(flow["_raw_ts"].dropna().tolist())
    if len(ts) > 1:
        gaps = np.diff(ts)
        g1 = gaps[gaps > 1.0]; g5 = gaps[gaps > 5.0]
        if len(g5) > 0:
            issues.append(("CRITICAL","Severe Packet Delay (>5s)",
                f"{len(g5)} gap(s) exceeding 5 seconds. Max gap: {max(gaps):.2f}s. "
                f"Indicates severe network congestion, TCP retransmission timeout, "
                f"or application-level blocking call."))
        elif len(g1) > 0:
            issues.append(("WARNING","Inter-Packet Gap >1s",
                f"{len(g1)} gap(s) exceeding 1 second detected. Max: {max(gaps):.3f}s. "
                f"Possible: network congestion, QoS shaping, server processing delay, "
                f"or TCP window stall."))

        # Retransmission heuristic — repeated sizes in same direction
        sizes = flow["Size (Bytes)"].tolist()
        from collections import Counter
        sz_count = Counter(sizes)
        repeat = sum(c - 1 for c in sz_count.values() if c > 1)
        if repeat > max(3, n * 0.1):
            issues.append(("WARNING","Possible Retransmissions",
                f"{repeat} packets share a size with another packet in this flow. "
                f"This heuristic suggests retransmissions or duplicate ACKs. "
                f"Check TCP sequence numbers for confirmation."))

    # ── Packet size anomalies ─────────────────────────────────────────────────
    sizes_arr = np.array(flow["Size (Bytes)"].tolist())
    if np.any(sizes_arr > 9000):
        issues.append(("INFO","Jumbo Frames Detected",
            f"{int(np.sum(sizes_arr > 9000))} packet(s) exceed 9000 bytes. "
            f"Ensure all hops in the path support Jumbo MTU to avoid fragmentation."))
    if np.any(sizes_arr < 20):
        issues.append(("WARNING","Undersized / Malformed Packets",
            f"{int(np.sum(sizes_arr < 20))} packet(s) are under 20 bytes. "
            f"These are likely malformed, truncated, or padding-only frames."))

    # ── DNS-specific ──────────────────────────────────────────────────────────
    if proto == "DNS":
        if n > 100:
            issues.append(("WARNING","High DNS Volume",
                f"{n} DNS packets in this flow. Possible DNS amplification attack, "
                f"broken resolver retry loop, or excessive hostnames being resolved."))
        # Check for NXDOMAIN (rcode=3) dominance — hard to do without deep parse,
        # but we can check detail field
        nx = flow["Packet Detail"].str.contains("NXDOMAIN", na=False).sum()
        if nx > 5:
            issues.append(("WARNING",f"High NXDOMAIN Count ({nx})",
                f"{nx} DNS responses contain NXDOMAIN. "
                f"Application may be querying non-existent domains repeatedly — "
                f"check for misconfigured search domains or DNS leak."))

    # ── ARP ───────────────────────────────────────────────────────────────────
    if proto == "ARP":
        arp_src = flow["Source IP"].value_counts()
        for ip, cnt in arp_src.items():
            if cnt > 20 and ip != "N/A":
                issues.append(("CRITICAL","ARP Storm / Spoofing",
                    f"IP {ip} sent {cnt} ARP packets in this capture. "
                    f"Possible ARP broadcast storm, ARP poisoning, or MITM attack. "
                    f"Enable Dynamic ARP Inspection on the switch."))

    # ── Endpoint diversity (scanning heuristic) ───────────────────────────────
    pairs = flow.groupby(["Source IP","Destination IP"]).size()
    if len(pairs) > 25:
        issues.append(("INFO","High Endpoint Diversity",
            f"{len(pairs)} unique src→dst IP pairs in this flow. "
            f"Possible port/network scan, P2P traffic, or misconfigured broadcast."))

    # ── ICMP flood ────────────────────────────────────────────────────────────
    if proto == "ICMP" and n > 500:
        issues.append(("WARNING","ICMP Flood",
            f"{n} ICMP packets in this flow. "
            f"Possible ping flood / ICMP DDoS. Check for Smurf attack patterns."))

    # ── SIP without SDP ──────────────────────────────────────────────────────
    if proto == "SIP":
        sdp_present = flow["Packet Detail"].str.contains("SDP|v=0", na=False).any()
        if not sdp_present:
            issues.append(("INFO","SIP Without SDP Body",
                "SIP messages found but no SDP session description detected. "
                "Call setup may be using out-of-band media negotiation "
                "or SDP is in a different flow."))

    return issues


def build_report(issues, flow, proto, label) -> str:
    """Generate a plain-text diagnostic report."""
    sev_icon = {"CRITICAL":"[!!!]","WARNING":"[!! ]","INFO":"[  i]"}
    lines = [
        "═" * 66,
        "  NETSCOPE — FLOW DIAGNOSTIC REPORT",
        "═" * 66,
        f"  Protocol      : {proto}",
        f"  Flow          : {label}",
        f"  Packets       : {len(flow)}",
    ]
    if len(flow) > 1:
        dur = flow["_raw_ts"].max() - flow["_raw_ts"].min()
        lines.append(f"  Duration      : {dur:.3f} s")
    lines += [
        f"  Total Bytes   : {flow['Size (Bytes)'].sum():,}",
        f"  Analysis Time : {datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S IST')}",
        "═" * 66,
        "",
        f"  ISSUES FOUND: {len(issues)}",
        "",
    ]
    for sev, title, desc in issues:
        lines.append(f"  {sev_icon.get(sev,'[ ]')} [{sev}] {title}")
        for chunk in textwrap.wrap(desc, 62):
            lines.append(f"       {chunk}")
        lines.append("")

    lines += [
        "─" * 66,
        "  RECOMMENDATIONS",
        "─" * 66,
    ]
    has = {s for s,_,_ in issues}
    titles = {t for _,t,_ in issues}
    recs = []
    if any("RST" in t for t in titles):
        recs += ["• Check server-side firewall / ACL rules.",
                 "• Verify app logs on destination for connection refusal."]
    if any("Handshake" in t for t in titles):
        recs += ["• Confirm reachability: ping/traceroute to destination.",
                 "• Verify port is open: nmap -p <port> <dst_ip>."]
    if any("Gap" in t or "Delay" in t for t in titles):
        recs += ["• Review QoS configuration and traffic shaping policies.",
                 "• Inspect TCP window scaling and buffer sizes (ss -ti)."]
    if any("Retransmission" in t for t in titles):
        recs += ["• Check for packet loss using continuous ping.",
                 "• Examine TCP socket stats: netstat -s | grep retransmit."]
    if any("ARP" in t for t in titles):
        recs += ["• Enable Dynamic ARP Inspection (DAI) on access switches.",
                 "• Add static ARP entries for critical hosts."]
    if any("DNS" in t for t in titles):
        recs += ["• Audit DNS resolver configuration.",
                 "• Rate-limit DNS traffic at perimeter."]
    if not recs:
        recs = ["• Flow appears normal. Monitor for recurring patterns."]
    lines += recs
    lines += ["", "═" * 66]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ══════════════════════════════════════════════════════════════════════════════
for k, v in {
    "df_all": None, "packets": None, "file_name": None,
    "flow_submitted": False, "flow_result": None,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="ns-header">
  <h1>📡 NetScope</h1>
  <div class="sub">Deep Packet Inspection &amp; Protocol Flow Analyzer</div>
  <div style="margin-top:10px;">
    <span class="badge">Ericsson</span>
    <span class="badge">Nokia</span>
    <span class="badge">JIO</span>
    <span class="badge">Scapy</span>
    <span class="badge">Telecom Grade</span>
  </div>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown('<div class="sb-title">⚙ Controls</div>', unsafe_allow_html=True)

    st.markdown('<div class="sb-label">PCAP File</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader(
        "Upload PCAP",
        type=["pcap","pcapng","cap"],
        label_visibility="collapsed",
        help="Supports .pcap / .pcapng / .cap — 10 KB to 1 GB",
    )

    st.markdown("---")
    st.markdown('<div class="sb-label">Protocol Filter</div>', unsafe_allow_html=True)
    selected_proto = st.selectbox(
        "Protocol",
        options=["— Select Protocol —"] + PROTOCOL_FILTERS,
        label_visibility="collapsed",
    )

    # ── File stats
    if st.session_state.df_all is not None:
        df_s = st.session_state.df_all
        st.markdown("---")
        st.markdown('<div class="sb-label">File Statistics</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div style="font-size:0.78rem;line-height:2.2;">
          <span style="color:#607d8b;">Total Packets:</span>
          <strong style="color:#00e5ff;">{len(df_s):,}</strong><br>
          <span style="color:#607d8b;">Unique Src IPs:</span>
          <strong style="color:#00e676;">{df_s['Source IP'].nunique()}</strong><br>
          <span style="color:#607d8b;">Unique Dst IPs:</span>
          <strong style="color:#00e676;">{df_s['Destination IP'].nunique()}</strong><br>
          <span style="color:#607d8b;">Total Data:</span>
          <strong style="color:#d500f9;">{df_s['Size (Bytes)'].sum()/1024:.1f} KB</strong><br>
          <span style="color:#607d8b;">Avg Pkt Size:</span>
          <strong style="color:#ffab00;">{df_s['Size (Bytes)'].mean():.0f} B</strong>
        </div>
        """, unsafe_allow_html=True)

        # Protocol distribution
        st.markdown("---")
        st.markdown('<div class="sb-label">Protocol Distribution</div>', unsafe_allow_html=True)
        proto_counts = {}
        for protos in df_s["_protocols"]:
            for p in protos:
                if p in PROTOCOL_FILTERS:
                    proto_counts[p] = proto_counts.get(p, 0) + 1
        if proto_counts:
            top = sorted(proto_counts.items(), key=lambda x: -x[1])[:10]
            total_pkts = len(df_s)
            for pname, cnt in top:
                pct = cnt / total_pkts * 100
                color = PROTO_COLOR.get(pname, "#90a4ae")
                st.markdown(f"""
                <div style="margin-bottom:5px;">
                  <div style="display:flex;justify-content:space-between;
                              font-size:0.68rem;margin-bottom:2px;">
                    <span style="color:{color};font-weight:600;">{pname}</span>
                    <span style="color:#37474f;">{cnt:,} ({pct:.1f}%)</span>
                  </div>
                  <div style="background:#172035;border-radius:3px;height:4px;">
                    <div style="background:{color};width:{min(pct,100):.0f}%;
                                height:4px;border-radius:3px;"></div>
                  </div>
                </div>
                """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style="font-size:0.6rem;color:#263238;text-align:center;">
        NetScope v3.0 · IBM Plex Mono · Rajdhani<br>
        Powered by Scapy + Pandas + NumPy
    </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# FILE LOADING
# ══════════════════════════════════════════════════════════════════════════════
if uploaded is not None:
    if st.session_state.file_name != uploaded.name:
        st.session_state.update({
            "flow_submitted": False, "flow_result": None,
            "df_all": None, "packets": None,
        })
        with st.spinner("⚡ Parsing PCAP — extracting layers and building detail index…"):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name

                df_all, packets = parse_pcap_to_df(tmp_path)
                os.unlink(tmp_path)

                if df_all is None:
                    st.error(f"❌ {packets}")
                else:
                    st.session_state.update({
                        "df_all": df_all, "packets": packets,
                        "file_name": uploaded.name,
                    })
                    st.success(
                        f"✅ **{uploaded.name}** loaded — "
                        f"{len(df_all):,} packets parsed successfully"
                    )
            except Exception:
                st.error("❌ Unexpected error during PCAP loading.")
                st.code(traceback.format_exc())
else:
    if st.session_state.df_all is None:
        st.markdown("""
        <div style="text-align:center;padding:70px 20px 50px;">
          <div style="font-size:5rem;margin-bottom:18px;">📡</div>
          <div style="font-family:'Rajdhani',sans-serif;font-size:1.6rem;font-weight:700;
                      color:#eceff4;letter-spacing:2px;margin-bottom:10px;">
            Upload a PCAP File to Begin
          </div>
          <div style="font-size:0.8rem;color:#37474f;line-height:1.9;">
            Supports <strong style="color:#00e5ff;">.pcap · .pcapng · .cap</strong>
            &nbsp;·&nbsp; 10 KB – 1 GB<br>
            Use the sidebar uploader ←
          </div>
          <div style="margin-top:32px;padding:18px 28px;background:#0d1322;
                      border:1px solid #1a2540;border-radius:10px;
                      display:inline-block;text-align:left;">
            <div style="font-size:0.65rem;color:#37474f;text-transform:uppercase;
                        letter-spacing:1.5px;margin-bottom:10px;">Detected Protocols</div>
            <div style="font-size:0.75rem;color:#546e7a;line-height:2;">
              TCP · UDP · IPv4 · IPv6 · ARP · ICMP<br>
              HTTP · HTTPS · TLS · DNS · FTP · SMTP<br>
              SSH · TELNET · Ethernet · PPPoE<br>
              MQTT · SIP · SDP
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS AREA
# ══════════════════════════════════════════════════════════════════════════════
if st.session_state.df_all is not None and selected_proto not in ("— Select Protocol —",):

    df_all = st.session_state.df_all
    proto  = selected_proto
    pcolor = PROTO_COLOR.get(proto, "#90a4ae")

    proto_df = filter_by_proto(df_all, proto)

    # ── Section 1: Protocol header ────────────────────────────────────────────
    st.markdown(f"""
    <div class="sec-hdr">
      <div class="dot" style="background:{pcolor};box-shadow:0 0 9px {pcolor};"></div>
      <div class="title">{proto} — Packet Table</div>
      <div class="pill">{len(proto_df):,} packets matched</div>
    </div>
    """, unsafe_allow_html=True)

    if proto_df.empty:
        st.markdown(f"""
        <div class="info-box">
          No <strong style="color:{pcolor};">{proto}</strong> packets found in this capture.
        </div>""", unsafe_allow_html=True)

    else:
        # ── Stats row ─────────────────────────────────────────────────────────
        c1, c2, c3, c4, c5 = st.columns(5)
        stats = [
            (c1, f"{len(proto_df):,}",                       "Packets",       pcolor),
            (c2, f"{proto_df['Source IP'].nunique()}",        "Unique Src IPs","#00e676"),
            (c3, f"{proto_df['Destination IP'].nunique()}",   "Unique Dst IPs","#d500f9"),
            (c4, f"{proto_df['Size (Bytes)'].sum()/1024:.1f}","Total KB",      "#ffab00"),
            (c5, f"{proto_df['Size (Bytes)'].mean():.0f}",   "Avg Size (B)",  "#40c4ff"),
        ]
        for col, val, lbl, clr in stats:
            with col:
                st.markdown(f"""
                <div class="stat-card">
                  <div class="val" style="color:{clr};">{val}</div>
                  <div class="lbl">{lbl}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

        # ── Packet table ──────────────────────────────────────────────────────
        tbl = display_df(proto_df)
        st.dataframe(
            tbl,
            use_container_width=True,
            height=min(460, 56 + len(tbl) * 36),
            hide_index=True,
            column_config={
                "Packet Detail": st.column_config.TextColumn(
                    "Packet Detail", width="large"
                ),
                "Protocol": st.column_config.TextColumn(
                    "Protocol Stack", width="medium"
                ),
            },
        )

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 2: Flow Drill-Down Filter
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("""
        <div class="sec-hdr" style="margin-top:32px;">
          <div class="dot" style="background:#d500f9;box-shadow:0 0 9px #d500f9;"></div>
          <div class="title">Flow Drill-Down</div>
          <div class="pill">Filter by endpoint pair → inspect full conversation</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="font-size:0.76rem;color:#546e7a;margin-bottom:14px;">
          Enter a <strong style="color:#b0bec5;">Source + Destination IP</strong>
          &nbsp;<em>or</em>&nbsp;
          <strong style="color:#b0bec5;">Source + Destination MAC</strong> pair
          to extract and analyse the complete conversation flow.
        </div>""", unsafe_allow_html=True)

        tab_ip, tab_mac = st.tabs(["🌐  IP Address Filter", "🔌  MAC Address Filter"])

        with tab_ip:
            col_a, col_b, col_c = st.columns([2, 2, 1])
            with col_a:
                fi_src = st.text_input(
                    "Source IP", placeholder="e.g. 192.168.1.10", key="fi_src_ip"
                )
            with col_b:
                fi_dst = st.text_input(
                    "Destination IP", placeholder="e.g. 8.8.8.8", key="fi_dst_ip"
                )
            with col_c:
                st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
                btn_ip = st.button("Analyse IP Flow", key="btn_ip", use_container_width=True)

        with tab_mac:
            col_c2, col_d2, col_e2 = st.columns([2, 2, 1])
            with col_c2:
                fm_src = st.text_input(
                    "Source MAC", placeholder="AA:BB:CC:DD:EE:FF", key="fm_src"
                )
            with col_d2:
                fm_dst = st.text_input(
                    "Destination MAC", placeholder="11:22:33:44:55:66", key="fm_dst"
                )
            with col_e2:
                st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
                btn_mac = st.button("Analyse MAC Flow", key="btn_mac", use_container_width=True)

        # ── Process button presses ────────────────────────────────────────────
        flow_df    = None
        flow_label = ""

        if btn_ip and fi_src.strip() and fi_dst.strip():
            flow_df    = filter_by_endpoints(proto_df, src_ip=fi_src, dst_ip=fi_dst)
            flow_label = f"IP: {fi_src.strip()} ⟷ {fi_dst.strip()}"
            st.session_state.flow_submitted = True
            st.session_state.flow_result    = (flow_df.copy(), flow_label, proto)

        elif btn_mac and fm_src.strip() and fm_dst.strip():
            flow_df    = filter_by_endpoints(proto_df, src_mac=fm_src, dst_mac=fm_dst)
            flow_label = f"MAC: {fm_src.strip().upper()} ⟷ {fm_dst.strip().upper()}"
            st.session_state.flow_submitted = True
            st.session_state.flow_result    = (flow_df.copy(), flow_label, proto)

        elif st.session_state.flow_submitted and st.session_state.flow_result:
            flow_df, flow_label, _ = st.session_state.flow_result

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 3: Full Communication Flow
        # ══════════════════════════════════════════════════════════════════════
        if flow_df is not None and st.session_state.flow_submitted:
            st.markdown(f"""
            <div class="sec-hdr" style="margin-top:32px;">
              <div class="dot" style="background:#00e676;box-shadow:0 0 9px #00e676;"></div>
              <div class="title">Communication Flow</div>
              <div class="pill" style="color:#00e676;border-color:#00e676;
                                       background:rgba(0,230,118,.08);">{flow_label}</div>
            </div>
            """, unsafe_allow_html=True)

            if flow_df.empty:
                st.markdown("""
                <div class="info-box" style="border-color:rgba(255,23,68,.3);color:#ff1744;">
                  ⚠ No packets found for this endpoint pair.<br>
                  <span style="color:#37474f;font-size:0.72rem;">
                    Verify the addresses appear in the table above.
                  </span>
                </div>""", unsafe_allow_html=True)

            else:
                # ── Flow stat row ─────────────────────────────────────────────
                dur    = flow_df["_raw_ts"].max() - flow_df["_raw_ts"].min()
                fb     = flow_df["Size (Bytes)"].sum()
                n_flow = len(flow_df)

                fc1, fc2, fc3, fc4 = st.columns(4)
                fstats = [
                    (fc1, f"{n_flow:,}",      "Flow Packets",  "#00e676"),
                    (fc2, f"{dur:.3f}s",       "Duration",      "#ffab00"),
                    (fc3, f"{fb/1024:.2f} KB", "Data Exchanged","#d500f9"),
                    (fc4, f"{fb/max(dur,0.001)/1024:.1f}",
                          "Throughput KB/s",   "#00e5ff"),
                ]
                for col, val, lbl, clr in fstats:
                    with col:
                        st.markdown(f"""
                        <div class="stat-card">
                          <div class="val" style="color:{clr};">{val}</div>
                          <div class="lbl">{lbl}</div>
                        </div>""", unsafe_allow_html=True)

                st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

                # ── Full flow table with ALL columns (same as spec) ───────────
                st.markdown("""
                <div style="font-size:0.68rem;color:#546e7a;text-transform:uppercase;
                            letter-spacing:1.5px;margin-bottom:8px;">
                  📋 Complete Protocol Flow — All Packets
                </div>""", unsafe_allow_html=True)

                flow_tbl = display_df(flow_df)
                st.dataframe(
                    flow_tbl,
                    use_container_width=True,
                    height=min(460, 56 + len(flow_tbl) * 36),
                    hide_index=True,
                    column_config={
                        "Packet Detail": st.column_config.TextColumn(
                            "Packet Detail", width="large"
                        ),
                        "Protocol": st.column_config.TextColumn(
                            "Protocol Stack", width="medium"
                        ),
                    },
                )

                # ── Visual flow timeline ──────────────────────────────────────
                with st.expander("🔀  Visual Flow Timeline  (first 40 packets)", expanded=True):
                    ref_ip  = flow_df.iloc[0]["Source IP"]
                    ref_mac = flow_df.iloc[0]["Src MAC"]
                    timeline = flow_df.head(40).reset_index(drop=True)

                    for _, row in timeline.iterrows():
                        is_fwd = (row["Source IP"] == ref_ip) or (row["Src MAC"] == ref_mac)
                        arrow  = "▶" if is_fwd else "◀"
                        acolor = "#00e5ff" if is_fwd else "#00e676"
                        side   = "0" if is_fwd else "auto"

                        sp = row.get("_sport",""); dp = row.get("_dport","")
                        port_str = f"  :{sp}→:{dp}" if sp and dp else ""
                        ts_short = row["Timestamp (IST)"][11:23]

                        # Proto pills
                        protos_set = row.get("_protocols", set())
                        pill_html  = " ".join(
                            f'<span style="font-size:0.58rem;padding:1px 5px;'
                            f'border-radius:3px;border:1px solid {PROTO_COLOR.get(p,"#607d8b")}80;'
                            f'color:{PROTO_COLOR.get(p,"#607d8b")};">{p}</span>'
                            for p in sorted(protos_set)
                            if p in PROTO_COLOR
                        )

                        # Trim detail for timeline
                        detail_lines = str(row.get("Packet Detail","")).split("\n")
                        short_detail = detail_lines[0] if detail_lines else ""
                        if len(short_detail) > 90:
                            short_detail = short_detail[:88] + "…"

                        st.markdown(f"""
                        <div class="flow-pkt" style="border-left:3px solid {acolor};
                                                     margin-left:{side};">
                          <div class="fp-num">#{row['No.']}  ·  {row['Size (Bytes)']} B</div>
                          <div class="fp-dir" style="color:{acolor};">
                            {arrow} {row['Source IP']}
                            <span style="color:#37474f;font-weight:400;"> → </span>
                            <span style="color:#b0bec5;font-weight:400;">{row['Destination IP']}</span>
                            <span style="color:#263238;">{port_str}</span>
                          </div>
                          <div class="fp-meta">
                            MAC {row['Src MAC']} → {row['Dst MAC']}
                            &nbsp;·&nbsp; {ts_short} IST
                            &nbsp;·&nbsp; {pill_html}
                          </div>
                          <div style="font-size:0.68rem;color:#546e7a;margin-top:3px;">
                            {short_detail}
                          </div>
                        </div>
                        """, unsafe_allow_html=True)

                # ── Expandable per-packet detail ──────────────────────────────
                with st.expander("🔍  Per-Packet Detail Inspector", expanded=False):
                    sel_pkt_no = st.selectbox(
                        "Select Packet No.",
                        options=flow_df["No."].tolist(),
                        key="detail_pkt_sel",
                    )
                    pkt_row = flow_df[flow_df["No."] == sel_pkt_no]
                    if not pkt_row.empty:
                        r = pkt_row.iloc[0]
                        st.markdown(f"""
                        <div class="detail-box">{r['Packet Detail']}</div>
                        """, unsafe_allow_html=True)

                # ══════════════════════════════════════════════════════════════
                # SECTION 4: Flow Diagnostics & Problem Description
                # ══════════════════════════════════════════════════════════════
                st.markdown("""
                <div class="sec-hdr" style="margin-top:36px;">
                  <div class="dot" style="background:#ff1744;box-shadow:0 0 9px #ff1744;"></div>
                  <div class="title">Flow Diagnostics &amp; Anomaly Detection</div>
                </div>
                """, unsafe_allow_html=True)

                issues = analyze_flow(flow_df, proto)

                if issues:
                    sev_color = {"CRITICAL":"#ff1744","WARNING":"#ffab00","INFO":"#00e5ff"}
                    sev_emoji = {"CRITICAL":"🔴","WARNING":"🟠","INFO":"🔵"}

                    # Group by severity
                    for sev in ("CRITICAL","WARNING","INFO"):
                        grp = [(t,d) for s,t,d in issues if s == sev]
                        if not grp:
                            continue
                        sc = sev_color[sev]
                        st.markdown(f"""
                        <div class="prob-box" style="border-color:rgba({
                            '255,23,68' if sev=='CRITICAL' else
                            '255,171,0' if sev=='WARNING' else
                            '0,229,255'},.3);
                            border-left-color:{sc};">
                          <div class="ph" style="color:{sc};">
                            {sev_emoji[sev]} {sev} — {len(grp)} Issue(s)
                          </div>
                        """, unsafe_allow_html=True)
                        for title, desc in grp:
                            st.markdown(f"""
                            <div class="prob-item">
                              <div>
                                <strong style="color:{sc};">{title}</strong><br>
                                {desc}
                              </div>
                            </div>""", unsafe_allow_html=True)
                        st.markdown("</div>", unsafe_allow_html=True)

                    # ── Full diagnostic report text area ──────────────────────
                    report_txt = build_report(issues, flow_df, proto, flow_label)
                    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
                    st.text_area(
                        "📋 Full Diagnostic Report  (copy / save / share)",
                        value=report_txt,
                        height=380,
                        key="diag_report",
                    )

                else:
                    st.markdown("""
                    <div class="ok-box">
                      ✅ No anomalies detected in this flow.<br>
                      <span style="font-size:0.76rem;color:#00c853;">
                        Handshake, data transfer, and timing patterns all appear normal
                        for the selected protocol. Continue monitoring for recurring patterns.
                      </span>
                    </div>""", unsafe_allow_html=True)

# ── Prompt to select protocol after file loaded ───────────────────────────────
elif st.session_state.df_all is not None:
    st.markdown("""
    <div class="info-box" style="padding:36px;margin-top:8px;">
      <div style="font-size:2.5rem;margin-bottom:14px;">🔽</div>
      <div style="font-family:'Rajdhani',sans-serif;font-size:1.1rem;font-weight:700;
                  color:#546e7a;letter-spacing:2px;text-transform:uppercase;">
        Select a Protocol Filter from the sidebar
      </div>
      <div style="font-size:0.74rem;color:#263238;margin-top:8px;">
        File loaded successfully. Choose a protocol to begin analysis.
      </div>
    </div>
    """, unsafe_allow_html=True)
