# 🔬 NetScope — Network Packet Analyzer

**Telecom-grade PCAP inspection tool built with Streamlit + Scapy**
*Designed for Ericsson · Nokia · JIO network engineering workflows*

---

## ⚡ Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note on PyShark:** PyShark requires `tshark` (Wireshark CLI) to be installed:
> - **Ubuntu/Debian:** `sudo apt install tshark`
> - **macOS:** `brew install wireshark`
> - **Windows:** Install Wireshark from https://www.wireshark.org/download.html

### 2. Run the App

```bash
streamlit run pcap_analyzer.py
```

App opens at `http://localhost:8501`

---

## 🧩 Features

### File Upload
- Accepts `.pcap`, `.pcapng`, `.cap` files
- Supports 10 KB → 1 GB file sizes
- Uses **Scapy** for parsing (with PyShark fallback)

### Protocol Filters (Sidebar)
| Layer 2 | Layer 3 | Layer 4 | Application |
|---------|---------|---------|-------------|
| Ethernet | IPv4 | TCP | HTTP / HTTPS |
| PPP | IPv6 | UDP | TLS / DNS |
| PPPoE | ARP | ICMP | FTP / SMTP |
| — | — | — | SSH / TELNET |
| — | — | — | MQTT / SIP / SDP |

### Packet Table
Each filtered protocol shows:
- Source IP · Destination IP
- Source MAC · Destination MAC
- Timestamp (converted to **IST — Indian Standard Time**)
- Packet Size (bytes)

### Flow Drill-Down
Filter by:
- **IP pair** (Source IP + Destination IP)
- **MAC pair** (Source MAC + Destination MAC)

Bidirectional matching — shows complete A↔B conversation.

### Visual Flow Timeline
Packet-by-packet directional view (first 30 packets shown inline, full table below).

### Anomaly Detection Engine
Automatically detects:
| Issue | Protocol |
|-------|----------|
| TCP RST / incomplete handshake | TCP/HTTP/HTTPS |
| SYN flood / port scan heuristic | TCP |
| Inter-packet gaps > 1s / > 5s | All |
| Jumbo frames / undersized packets | All |
| ARP storm / spoofing | ARP |
| High DNS volume (amplification) | DNS |
| High IP endpoint diversity | All |

Outputs a full **exportable diagnostic text report**.

---

## 🏗 Architecture

```
pcap_analyzer.py
├── load_pcap_scapy()          # Scapy PCAP reader
├── parse_pcap_to_df()         # Packet → DataFrame conversion
├── get_protocol_layer()       # Multi-protocol detection per packet
├── filter_df_by_protocol()    # Protocol-level filter
├── filter_df_by_endpoints()   # IP/MAC endpoint pair filter
├── analyze_flow_problems()    # Anomaly / diagnostic engine
└── Streamlit UI               # Dark-themed, responsive layout
```

---

## 🔧 Customization

### Add new port-to-protocol mappings
Edit `PORT_PROTO_MAP` in the source:
```python
PORT_PROTO_MAP = {
    80: "HTTP",
    443: "HTTPS",
    1883: "MQTT",
    # Add your custom ports here
    5000: "CUSTOM_PROTO",
}
```

### Extend anomaly detection
Add new conditions inside `analyze_flow_problems()`.

---

## 📋 Requirements

| Package | Version | Purpose |
|---------|---------|---------|
| streamlit | ≥1.32 | Web UI |
| scapy | ≥2.5 | Packet parsing |
| pyshark | ≥0.6 | Tshark wrapper (optional) |
| pandas | ≥2.0 | DataFrame operations |
| numpy | ≥1.24 | Numerical analysis |

---

## ⚠️ Notes

- **Large files (>500MB):** May take 30–90 seconds to parse. Progress shown via spinner.
- **Root privileges:** Scapy may require elevated permissions on some systems for live capture (not needed for PCAP file reading).
- **IST Timezone:** All timestamps are converted from UTC epoch to `UTC+5:30`.

---

*Built with ❤️ for Telecom Network Engineers*
"# pcap_analyser" 
