#!/usr/bin/env python3
"""
PCAP Network Packet Threat Hunter - analyze .pcap captures for network attacks.

Parses raw binary .pcap files at the byte level (Ethernet, ARP, IPv4, TCP, UDP, DNS)
without external libraries and detects four classes of suspicious traffic:
  1. TCP SYN Port Scans (many destination ports probed with SYN-only packets)
  2. ARP Spoofing / Cache Poisoning (conflicting MAC addresses claiming the same IP)
  3. DNS Tunneling / Exfiltration (long or high-entropy encoded subdomain queries)
  4. Cleartext Credentials (HTTP Basic Auth, HTTP login POSTs, FTP USER/PASS)

MITRE ATT&CK: T1046 (Network Service Discovery), T1557.002 (ARP Cache Poisoning),
              T1071.004 (DNS Protocol Tunneling), T1040 (Network Sniffing)

Uses only the Python standard library.
"""
import argparse
import base64
import io
import math
import re
import socket
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

BANNER = r"""
                   :                                                           
           .      t#,      L.                      ,;                   :      
          ;W     ;##W.     EW:        ,ft        f#i              i     Ef     
         f#E    :#L:WE     E##;       t#E      .E#t              LE     E#t    
       .E#f    .KG  ,#D    E###t      t#E     i#W,              L#E     E#t    
      iWW;     EE    ;#f   E#fE#f     t#E    L#D.              G#W.     E#t    
     L##Lffi  f#.     t#i  E#t D#G    t#E  :K#Wfff;           D#K.      E#t fi 
    tLLG##L   :#G     GK   E#t  f#E.  t#E  i##WLLLLt         E#K.       E#t L#j
      ,W#i     ;#L   LW.   E#t   t#K: t#E   .E#L           .E#E.        E#t L#L
     j#E.       t#f f#:    E#t    ;#W,t#E     f#E:        .K#E          E#tf#E:
   .D#j          f#D#;     E#t     :K#D#E      ,WW;      .K#D           E###f  
  ,WK,            G#t      E#t      .E##E       .D#;    .W#G            E#K,   
  EG.              t       ..         G#E         tt   :W##########Wt   EL     
  ,                                    fE              :,,,,,,,,,,,,,.  :      
                                        ,                                      
                     [ PCAP Network Packet Threat Hunter ]
"""

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
PROTO_TCP = 6
PROTO_UDP = 17
SYN_FLAG = 0x02
ACK_FLAG = 0x10

HTTP_BASIC_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)
HTTP_FORM_RE = re.compile(r"(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)", re.I)
FTP_USER_RE = re.compile(r"^USER\s+(\S+)", re.I | re.M)
FTP_PASS_RE = re.compile(r"^PASS\s+(\S+)", re.I | re.M)


# ----------------------------------------------------------------- helpers
def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_dns_qname(payload: bytes, offset: int = 12) -> str | None:
    """Read the queried domain name from a raw DNS packet."""
    labels = []
    idx = offset
    while idx < len(payload):
        length = payload[idx]
        if length == 0:
            return ".".join(labels)
        if length & 0xC0:  # pointer compression
            break
        idx += 1
        if idx + length > len(payload):
            return None
        labels.append(payload[idx:idx + length].decode("ascii", errors="ignore"))
        idx += length
    return ".".join(labels) if labels else None


# ------------------------------------------------------------- pcap parser
def read_pcap(stream: io.BufferedReader):
    """Yield (timestamp, link_type, raw_frame_bytes) from a .pcap stream."""
    ghdr = stream.read(24)
    if len(ghdr) < 24:
        raise ValueError("File is too short to be a valid .pcap")
    magic = ghdr[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported file format (expected standard .pcap magic bytes)")

    link_type = struct.unpack(endian + "IHHIIII", ghdr)[-1]
    pkt_hdr_fmt = endian + "IIII"
    while True:
        phdr = stream.read(16)
        if len(phdr) < 16:
            break
        ts_sec, ts_usec, incl_len, _ = struct.unpack(pkt_hdr_fmt, phdr)
        frame = stream.read(incl_len)
        if len(frame) < incl_len:
            break
        yield ts_sec + ts_usec / 1_000_000, link_type, frame


# ----------------------------------------------------------- threat hunter
def analyze_pcap(stream: io.BufferedReader, source_name: str, port_scan_threshold: int = 10) -> int:
    total_packets = 0
    proto_counts = Counter()
    talkers = Counter()

    # Detection trackers
    syn_ports = defaultdict(set)          # (src_ip, dst_ip) -> {dst_port, ...}
    syn_ack_seen = Counter()              # (src_ip, dst_ip) -> count
    arp_table = defaultdict(set)          # ip -> {mac, ...}
    dns_suspects = []                     # (src_ip, qname, subdomain_len, entropy)
    cred_leaks = []                       # (proto, src_ip, dst_ip, dst_port, detail)

    for _, link_type, frame in read_pcap(stream):
        total_packets += 1
        if link_type == 1:  # Ethernet
            if len(frame) < 14:
                continue
            eth_type = struct.unpack("!H", frame[12:14])[0]
            l3 = frame[14:]
        elif link_type == 101:  # Raw IPv4
            eth_type, l3 = ETH_IPV4, frame
        else:
            continue

        # 1. ARP inspection (check for ARP cache poisoning)
        if eth_type == ETH_ARP and len(l3) >= 28:
            proto_counts["ARP"] += 1
            oper = struct.unpack("!H", l3[6:8])[0]
            sha, spa = mac_str(l3[8:14]), ip_str(l3[14:18])
            if oper in (1, 2) and spa != "0.0.0.0":
                arp_table[spa].add(sha)
            continue

        if eth_type != ETH_IPV4 or len(l3) < 20:
            continue

        ihl = (l3[0] & 0x0F) * 4
        proto = l3[9]
        src_ip, dst_ip = ip_str(l3[12:16]), ip_str(l3[16:20])
        talkers[src_ip] += 1
        l4 = l3[ihl:]

        # 2. TCP inspection (SYN scans + cleartext HTTP/FTP credentials)
        if proto == PROTO_TCP and len(l4) >= 20:
            proto_counts["TCP"] += 1
            src_port, dst_port = struct.unpack("!HH", l4[:4])
            data_offset = ((l4[12] >> 4) & 0x0F) * 4
            flags = l4[13]
            payload = l4[data_offset:]

            if (flags & SYN_FLAG) and not (flags & ACK_FLAG):
                syn_ports[(src_ip, dst_ip)].add(dst_port)
            elif (flags & SYN_FLAG) and (flags & ACK_FLAG):
                syn_ack_seen[(dst_ip, src_ip)] += 1

            if payload:
                text = payload.decode("utf-8", errors="ignore")
                if m := HTTP_BASIC_RE.search(text):
                    try:
                        decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                    except ValueError:
                        decoded = m.group(1)
                    cred_leaks.append(("HTTP Basic Auth", src_ip, dst_ip, dst_port, f"credentials '{decoded}'"))
                if m := HTTP_FORM_RE.search(text):
                    cred_leaks.append(("HTTP POST Login", src_ip, dst_ip, dst_port,
                                       f"user='{m.group(1)}' pass='{m.group(2)}'"))
                if dst_port == 21:
                    if m := FTP_USER_RE.search(text):
                        cred_leaks.append(("FTP Cleartext", src_ip, dst_ip, dst_port, f"USER {m.group(1)}"))
                    if m := FTP_PASS_RE.search(text):
                        cred_leaks.append(("FTP Cleartext", src_ip, dst_ip, dst_port, f"PASS {m.group(1)}"))

        # 3. UDP / DNS inspection (check for DNS tunneling / exfiltration)
        elif proto == PROTO_UDP and len(l4) >= 8:
            proto_counts["UDP"] += 1
            src_port, dst_port = struct.unpack("!HH", l4[:4])
            payload = l4[8:]
            if dst_port == 53 and len(payload) > 12:
                proto_counts["DNS"] += 1
                qname = parse_dns_qname(payload)
                if qname and "." in qname:
                    sub = qname.split(".", 1)[0]
                    ent = shannon_entropy(sub)
                    if len(sub) >= 28 and ent >= 3.5:
                        dns_suspects.append((src_ip, qname, len(sub), ent))

    # --------------------------------------------------------------- report
    print(f"=== PCAP Threat Hunt Report: {source_name} ===\n")
    print(f"  Total packets   : {total_packets}")
    proto_summary = ", ".join(f"{k}: {v}" for k, v in proto_counts.most_common()) or "none"
    print(f"  Protocols       : {proto_summary}")
    top_ips = ", ".join(f"{ip} ({n})" for ip, n in talkers.most_common(3)) or "none"
    print(f"  Top talkers     : {top_ips}")

    alerts = 0

    print("\n  [1] Port Scan Detection (MITRE T1046):")
    scans = [(pair, ports) for pair, ports in syn_ports.items() if len(ports) >= port_scan_threshold]
    if scans:
        for (src, dst), ports in sorted(scans, key=lambda x: -len(x[1])):
            alerts += 1
            sample = ", ".join(str(p) for p in sorted(ports)[:8])
            more = f", ... (+{len(ports) - 8} more)" if len(ports) > 8 else ""
            print(f"  [ALERT] SYN scan from {src} -> {dst}: {len(ports)} ports probed ({sample}{more})")
    else:
        print("  [PASS]  No port scans detected")

    print("\n  [2] ARP Spoofing Detection (MITRE T1557.002):")
    spoofed = {ip: macs for ip, macs in arp_table.items() if len(macs) > 1}
    if spoofed:
        for ip, macs in spoofed.items():
            alerts += 1
            print(f"  [ALERT] IP {ip} claimed by multiple MAC addresses: {', '.join(sorted(macs))}")
    else:
        print("  [PASS]  No conflicting ARP mappings found")

    print("\n  [3] DNS Tunneling / Exfiltration (MITRE T1071.004):")
    if dns_suspects:
        for src, qname, length, ent in dns_suspects:
            alerts += 1
            print(f"  [ALERT] {src} queried high-entropy subdomain ({length} chars, {ent:.2f} bits): {qname[:55]}")
    else:
        print("  [PASS]  No suspicious DNS queries found")

    print("\n  [4] Cleartext Credentials on the Wire (MITRE T1040):")
    if cred_leaks:
        for kind, src, dst, port, detail in cred_leaks:
            alerts += 1
            print(f"  [ALERT] {kind:<16} {src} -> {dst}:{port}  ({detail})")
    else:
        print("  [PASS]  No cleartext credentials detected")

    verdict = f"{alerts} THREAT INDICATOR(S) DETECTED" if alerts else "CLEAN CAPTURE"
    print(f"\n  SUMMARY: {total_packets} packets analyzed   VERDICT: {verdict}\n")
    return 0


# --------------------------------------------------------- demo pcap builder
def _eth_ipv4(src_ip: str, dst_ip: str, proto: int, l4: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", ETH_IPV4)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return eth + ip_hdr + l4


def _tcp_pkt(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 0x50, flags, 8192, 0, 0) + payload
    return _eth_ipv4(src_ip, dst_ip, PROTO_TCP, tcp)


def _dns_query_pkt(src_ip: str, dst_ip: str, domain: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.split(".")) + b"\x00"
    dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    return _eth_ipv4(src_ip, dst_ip, PROTO_UDP, udp)


def _arp_reply(mac: bytes, sender_ip: str, target_ip: str = "192.168.1.10") -> bytes:
    eth = b"\xff\xff\xff\xff\xff\xff" + mac + struct.pack("!H", ETH_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, ETH_IPV4, 6, 4, 2,
        mac, socket.inet_aton(sender_ip),
        b"\x00\x11\x22\x33\x44\x55", socket.inet_aton(target_ip),
    )
    return eth + arp


def build_demo_pcap() -> bytes:
    """Create a realistic in-memory .pcap containing normal traffic + 4 simulated attacks."""
    frames = [
        # Normal web & DNS traffic
        _dns_query_pkt("192.168.1.10", "8.8.8.8", "github.com"),
        _tcp_pkt("192.168.1.10", "93.184.216.34", 51200, 443, SYN_FLAG | ACK_FLAG),
    ]
    # 1. SYN port scan from 203.0.113.50 against 192.168.1.10 (15 ports)
    for port in (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080):
        frames.append(_tcp_pkt("203.0.113.50", "192.168.1.10", 44000 + port, port, SYN_FLAG))

    # 2. ARP spoofing: gateway 192.168.1.1 claimed by two different MAC addresses
    frames.append(_arp_reply(b"\xaa\xbb\xcc\x00\x00\x01", "192.168.1.1"))
    frames.append(_arp_reply(b"\xde\xad\xbe\xef\x13\x37", "192.168.1.1"))

    # 3. DNS tunneling / exfiltration query with high-entropy base64/hex subdomain
    frames.append(_dns_query_pkt("192.168.1.10", "8.8.8.8",
                                 "aGVsbG8tdGhpcy1pcy1leGZpbHRyYXRlZC1zZWNyZXQtZGF0YQ.c2-tunnel.example.net"))

    # 4. Cleartext HTTP POST login & FTP credentials
    http_post = (b"POST /login HTTP/1.1\r\nHost: intranet.local\r\n\r\n"
                 b"username=admin&password=Spring2026!Secret")
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.25", 52001, 80, ACK_FLAG, http_post))
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.30", 52002, 21, ACK_FLAG, b"USER backup_svc\r\n"))
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.30", 52002, 21, ACK_FLAG, b"PASS Backup#9921\r\n"))

    buf = io.BytesIO()
    buf.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for idx, frame in enumerate(frames):
        buf.write(struct.pack("<IIII", 1729850000 + idx, 0, len(frame), len(frame)))
        buf.write(frame)
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a .pcap packet capture for network attacks.")
    parser.add_argument("pcap", nargs="?", help="Path to a .pcap file")
    parser.add_argument("-t", "--threshold", type=int, default=10,
                        help="Distinct ports before flagging a SYN port scan (default: 10)")
    parser.add_argument("--demo", action="store_true", help="Analyze a built-in simulated .pcap capture")
    parser.add_argument("--save-demo", metavar="FILE", help="Save the built-in demo .pcap to a file (for Wireshark)")
    args = parser.parse_args()

    print(BANNER)
    if args.save_demo:
        Path(args.save_demo).write_bytes(build_demo_pcap())
        print(f"[+] Saved demo capture to {args.save_demo}\n")
        if not args.demo and not args.pcap:
            return 0

    if args.demo:
        return analyze_pcap(io.BytesIO(build_demo_pcap()), "built-in demo capture", args.threshold)
    if not args.pcap:
        parser.error("provide a .pcap file or use --demo")

    try:
        with open(args.pcap, "rb") as f:
            return analyze_pcap(f, args.pcap, args.threshold)
    except (OSError, ValueError) as e:
        print(f"[!] Could not analyze {args.pcap}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
