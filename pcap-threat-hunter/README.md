# 🕵️‍♂️ PCAP Network Packet Threat Hunter

A Python network forensics tool that parses binary `.pcap` and Next-Generation **`.pcapng`** packet captures at the **raw byte level** (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6, DNS) without requiring Wireshark or third-party libraries, and hunts for **six classes of network attacks**.

## ✨ Features
- **Zero-Dependency Binary `.pcap` & `.pcapng` Parser:** Unpacks classic `.pcap` (microsecond/nanosecond) and Next-Gen `.pcapng` blocks (`SHB`, `IDB`, `EPB`, `SPB`), Ethernet frames, ARP packets, **IPv4 and IPv6 (`0x86DD`) headers**, TCP sequence streams, UDP datagrams, ICMP/ICMPv6, and DNS wire labels using Python's `struct` module
- **6 Built-in Threat Detections:**
  1. **TCP SYN Port Scans (`MITRE T1046`):** Spots hosts sending `SYN`-only packets across many distinct ports on a target
  2. **ARP Spoofing / Cache Poisoning (`MITRE T1557.002`):** Alerts when multiple MAC addresses claim the same IPv4 address
  3. **DNS Tunneling / Exfiltration (`MITRE T1071.004`):** Calculates **Shannon entropy** on DNS query labels to flag long, base64/hex-encoded subdomains used for C2 or exfiltration
  4. **ICMP / ICMPv6 Covert Tunneling (`MITRE T1095`):** Flags oversized Echo Request/Reply payloads (`> 64 bytes`) and high-entropy covert data inside ping traffic
  5. **Cleartext Credentials via Multi-Packet TCP Stream Reassembly (`MITRE T1040`):** Reassembles fragmented and out-of-order TCP segments by sequence number (`seq`) to catch HTTP Basic Auth, HTTP `POST` logins, and FTP `USER`/`PASS` credentials split across multiple packets
  6. **Periodic C2 Beaconing Detection (`MITRE T1071.001`):** Analyzes inter-arrival intervals and jitter across flows to spot automated C2 heartbeats
- **JSON Threat Report Export (`-o`) & Built-in `--demo` Generator:** Exports machine-readable findings to JSON and can write the built-in simulated capture to disk (`--save-demo sample.pcap`) for inspection in Wireshark

## 🎯 MITRE ATT&CK Mapping
| Detection | Technique | ID |
|---|---|---|
| TCP SYN Port Scan | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| ARP Spoofing | Adversary-in-the-Middle: ARP Cache Poisoning | [T1557.002](https://attack.mitre.org/techniques/T1557/002/) |
| DNS Tunneling | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| ICMP Covert Tunneling | Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) |
| Cleartext Credentials | Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) |
| Periodic C2 Beaconing | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |

## 🚀 Usage
Requires **Python 3.10+**.

```bash
# Run against the built-in simulated attack capture
python pcap_hunter.py --demo

# Analyze a real Wireshark / tcpdump .pcap or .pcapng file and export JSON report
python pcap_hunter.py capture.pcapng -o report.json

# Custom port-scan threshold (default: 10 ports)
python pcap_hunter.py capture.pcap -t 20

# Export the built-in demo capture as a real .pcap file to open in Wireshark
python pcap_hunter.py --save-demo demo_traffic.pcap
```

| Option | Description |
|---|---|
| `pcap` | Path to a `.pcap` or `.pcapng` file to analyze |
| `-t`, `--threshold` | Distinct ports before flagging a SYN scan (default: `10`) |
| `-o`, `--output` | Export threat hunt findings to a JSON report file |
| `--demo` | Run against the built-in simulated capture |
| `--save-demo FILE` | Save the built-in demo capture to disk (compatible with Wireshark) |

## 📊 Example Output
![PCAP Network Packet Threat Hunter demo](demo.png)

```text
                   [ PCAP Network Packet Threat Hunter v2.0 ]

[*] Capture Source  : built-in demo capture (PCAP)
[*] Total Packets   : 25  |  Reassembled TCP Streams: 2
[*] Protocols       : IPv4: 22, TCP: 20, UDP: 2, DNS: 2, ARP: 2, IPv6: 1, ICMP: 1
[*] Top Talkers     : 203.0.113.50 (15), 192.168.1.10 (7), 2001:db8::10 (1)
==============================================================================

  [1] Port Scan Detection (MITRE T1046):
  [ALERT] SYN scan from 203.0.113.50 -> 192.168.1.10: 15 ports probed (21, 22, 23, 25, 53, 80, 110, 139, ... (+7 more))

  [2] ARP Spoofing Detection (MITRE T1557.002):
  [ALERT] IP 192.168.1.1 claimed by multiple MAC addresses: aa:bb:cc:00:00:01, de:ad:be:ef:13:37

  [3] DNS Tunneling / Exfiltration (MITRE T1071.004):
  [ALERT] 192.168.1.10 queried high-entropy subdomain (50 chars, 4.51 bits): aGVsbG8tdGhpcy1pcy1leGZpbHRyYXRlZC1zZWNyZXQtZGF0YQ.c2-t

  [4] ICMP / ICMPv6 Covert Tunneling (MITRE T1095):
  [ALERT] Oversized ICMP Echo tunnel 192.168.1.10 -> 198.51.100.77 (81 bytes payload, 5.47 bits entropy)

  [5] Cleartext Credentials via TCP Stream Reassembly (MITRE T1040):
  [ALERT] HTTP POST Login  192.168.1.10 -> 192.168.1.25:80  (user='admin' pass='Spring2026!Secret')
  [ALERT] FTP Cleartext    192.168.1.10 -> 192.168.1.30:21  (USER backup_svc)
  [ALERT] FTP Cleartext    192.168.1.10 -> 192.168.1.30:21  (PASS Backup#9921)

==============================================================================
  SUMMARY: 25 packets (PCAP)   |   VERDICT: 7 THREAT INDICATOR(S) DETECTED
==============================================================================
```

## 🧠 What I Learned
- How classic `.pcap` headers (`24 bytes` + `16-byte` packet records) differ from Next-Gen `.pcapng` block structures (`SHB`, `IDB`, `EPB`)
- Unpacking raw Ethernet (`14 bytes`), IPv4 (`IHL`), IPv6 (`40-byte` fixed header + `inet_ntop`), TCP sequence numbers, ARP, ICMP/ICMPv6, and DNS wire labels
- Why TCP sequence-number stream reassembly is essential in network forensics: credentials or HTTP payloads split across multiple TCP segments evade single-packet inspection

## 🔄 Version History & Changelog (v1.0 → v2.0)
- **v1.0 (Initial Release):** Classic `.pcap` & IPv4 byte-level parser with single-packet detection for TCP SYN port scans, ARP spoofing, DNS tunneling (Shannon entropy), and cleartext HTTP/FTP credentials.
- **v2.0:**
  - Added **Next-Generation `.pcapng` Format & IPv6 (`0x86DD`) Support** so modern Wireshark default captures and dual-stack IPv6 networks are parsed natively.
  - Added **ICMP / ICMPv6 Covert Tunneling Detection (`MITRE T1095`)** to flag oversized Echo Request/Reply payloads (`> 64 bytes`) and high-entropy exfiltration data inside ping packets.
  - Added **Multi-Packet TCP Stream Sequence Reassembly** (`seq`-ordered stream stitching per 4-tuple flow) to catch credentials and HTTP requests split or reordered across multiple TCP segments.
  - Added **Periodic C2 Beaconing / Heartbeat Detection (`MITRE T1071.001`)** and **JSON Threat Report Export (`-o`)**.
