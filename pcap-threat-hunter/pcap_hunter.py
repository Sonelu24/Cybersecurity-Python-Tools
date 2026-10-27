#!/usr/bin/env python3
"""
PCAP Network Packet Threat Hunter v2.0 (Blue Team — Network Forensics & Hunting)

Parses binary .pcap and Next-Generation .pcapng packet captures at the raw byte level
(Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP/ICMPv6, DNS) without external libraries
and detects six classes of network attacks:
  1. TCP SYN Port Scans (MITRE T1046)
  2. ARP Spoofing / Cache Poisoning (MITRE T1557.002)
  3. DNS Tunneling / Exfiltration via Shannon Entropy (MITRE T1071.004)
  4. ICMP / ICMPv6 Covert Tunneling & Oversized Echo Payloads (MITRE T1095)
  5. Cleartext Credentials via Multi-Packet TCP Stream Reassembly (MITRE T1040)
  6. Periodic C2 Beaconing / Heartbeat Detection (MITRE T1071.001)

Uses only the Python standard library.
"""

import argparse
import base64
import io
import json
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
                   [ PCAP Network Packet Threat Hunter v2.0 ]
"""

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

SYN_FLAG = 0x02
ACK_FLAG = 0x10

HTTP_BASIC_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)
HTTP_FORM_RE = re.compile(r"(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)", re.I | re.S)
FTP_USER_RE = re.compile(r"USER\s+(\S+)", re.I)
FTP_PASS_RE = re.compile(r"PASS\s+(\S+)", re.I)


# ----------------------------------------------------------------- helpers
def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ipv4_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def ipv6_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return ":".join(f"{ int.from_bytes(raw[i:i+2], 'big'):x}" for i in range(0, 16, 2))


def shannon_entropy(data: str | bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_dns_qname(payload: bytes, offset: int = 12) -> str | None:
    """Read the queried domain name from a raw DNS packet."""
    labels = []
    idx = offset
    while idx < len(payload):
        length = payload[idx]
        if length == 0:
            return ".".join(labels)
        if length & 0xC0:
            break
        idx += 1
        if idx + length > len(payload):
            return None
        labels.append(payload[idx : idx + length].decode("ascii", errors="ignore"))
        idx += length
    return ".".join(labels) if labels else None


# ------------------------------------------------ .pcap & .pcapng parsers
def read_capture(stream: io.BufferedReader):
    """Yield (timestamp, link_type, raw_frame_bytes, fmt_name) from .pcap or .pcapng."""
    magic = stream.read(4)
    if len(magic) < 4:
        raise ValueError("File is too short to be a valid packet capture")

    # 1. Next-Generation .pcapng format (Section Header Block 0x0A0D0D0A)
    if magic == b"\x0a\x0d\x0d\x0a":
        rest_shb = stream.read(8)
        if len(rest_shb) < 8:
            raise ValueError("Truncated .pcapng Section Header Block")
        bom = rest_shb[4:8]
        if bom == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        elif bom == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("Invalid .pcapng Byte-Order Magic")
        shb_len = struct.unpack(endian + "I", rest_shb[:4])[0]
        if shb_len > 12:
            stream.read(shb_len - 12)

        if_link_types: list[int] = []
        while True:
            bhdr = stream.read(8)
            if len(bhdr) < 8:
                break
            btype, blen = struct.unpack(endian + "II", bhdr)
            if blen < 12:
                break
            body = stream.read(blen - 8)
            if len(body) < blen - 8:
                break

            if btype == 0x00000001 and len(body) >= 8:  # Interface Description Block (IDB)
                link_type = struct.unpack(endian + "H", body[:2])[0]
                if_link_types.append(link_type)
            elif btype == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block (EPB)
                if_id, ts_high, ts_low, cap_len, _ = struct.unpack(endian + "IIIII", body[:20])
                frame = body[20 : 20 + cap_len]
                ts = ((ts_high << 32) | ts_low) / 1_000_000.0
                ltype = if_link_types[if_id] if if_id < len(if_link_types) else 1
                yield ts, ltype, frame, "PCAPNG"
            elif btype == 0x00000003 and len(body) >= 4:  # Simple Packet Block (SPB)
                frame = body[4:-4]
                ltype = if_link_types[0] if if_link_types else 1
                yield 0.0, ltype, frame, "PCAPNG"
        return

    # 2. Classic .pcap format
    rem_ghdr = stream.read(20)
    if len(rem_ghdr) < 20:
        raise ValueError("File is too short to be a valid .pcap")
    ghdr = magic + rem_ghdr
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported file format (expected .pcap or .pcapng magic bytes)")

    ns_factor = 1_000_000_000.0 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1_000_000.0
    link_type = struct.unpack(endian + "IHHIIII", ghdr)[-1]
    pkt_hdr_fmt = endian + "IIII"
    while True:
        phdr = stream.read(16)
        if len(phdr) < 16:
            break
        ts_sec, ts_sub, incl_len, _ = struct.unpack(pkt_hdr_fmt, phdr)
        frame = stream.read(incl_len)
        if len(frame) < incl_len:
            break
        yield ts_sec + ts_sub / ns_factor, link_type, frame, "PCAP"


# ----------------------------------------------------------- threat hunter
def inspect_credentials_in_text(
    text: str, src_ip: str, dst_ip: str, dst_port: int, seen_Set: set, cred_leaks: list
) -> None:
    """Extracts HTTP Basic Auth, HTTP Form POST logins, and FTP USER/PASS from reassembled text."""
    for m in HTTP_BASIC_RE.finditer(text):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
        except ValueError:
            decoded = m.group(1)
        key = ("HTTP Basic Auth", src_ip, dst_ip, dst_port, f"credentials '{decoded}'")
        if key not in seen_Set:
            seen_Set.add(key)
            cred_leaks.append(key)

    for m in HTTP_FORM_RE.finditer(text):
        key = ("HTTP POST Login", src_ip, dst_ip, dst_port, f"user='{m.group(1)}' pass='{m.group(2)}'")
        if key not in seen_Set:
            seen_Set.add(key)
            cred_leaks.append(key)

    if dst_port == 21:
        for m in FTP_USER_RE.finditer(text):
            key = ("FTP Cleartext", src_ip, dst_ip, dst_port, f"USER {m.group(1)}")
            if key not in seen_Set:
                seen_Set.add(key)
                cred_leaks.append(key)
        for m in FTP_PASS_RE.finditer(text):
            key = ("FTP Cleartext", src_ip, dst_ip, dst_port, f"PASS {m.group(1)}")
            if key not in seen_Set:
                seen_Set.add(key)
                cred_leaks.append(key)


def analyze_pcap(
    stream: io.BufferedReader,
    source_name: str,
    port_scan_threshold: int = 10,
    output_path: str | None = None,
) -> int:
    total_packets = 0
    capture_fmt = "PCAP"
    proto_counts = Counter()
    talkers = Counter()

    # Detection trackers
    syn_ports = defaultdict(set)          # (src_ip, dst_ip) -> {dst_port, ...}
    arp_table = defaultdict(set)          # ip -> {mac, ...}
    dns_suspects = []                     # (src_ip, qname, subdomain_len, entropy)
    icmp_suspects = []                    # (src_ip, dst_ip, payload_len, entropy)
    tcp_streams: dict[tuple[str, int, str, int], dict[int, bytes]] = defaultdict(dict)
    flow_times: dict[tuple[str, str, int], list[float]] = defaultdict(list)

    for ts, link_type, frame, fmt_name in read_capture(stream):
        total_packets += 1
        capture_fmt = fmt_name
        if link_type == 1:  # Ethernet
            if len(frame) < 14:
                continue
            eth_type = struct.unpack("!H", frame[12:14])[0]
            l3 = frame[14:]
        elif link_type == 101:  # Raw IPv4 / IPv6
            ver = (frame[0] >> 4) if frame else 0
            eth_type = ETH_IPV6 if ver == 6 else ETH_IPV4
            l3 = frame
        else:
            continue

        # 1. ARP inspection (ARP cache poisoning)
        if eth_type == ETH_ARP and len(l3) >= 28:
            proto_counts["ARP"] += 1
            oper = struct.unpack("!H", l3[6:8])[0]
            sha, spa = mac_str(l3[8:14]), ipv4_str(l3[14:18])
            if oper in (1, 2) and spa != "0.0.0.0":
                arp_table[spa].add(sha)
            continue

        # 2. L3 Unpacking (IPv4 & IPv6)
        if eth_type == ETH_IPV4 and len(l3) >= 20:
            proto_counts["IPv4"] += 1
            ihl = (l3[0] & 0x0F) * 4
            proto = l3[9]
            src_ip, dst_ip = ipv4_str(l3[12:16]), ipv4_str(l3[16:20])
            l4 = l3[ihl:]
        elif eth_type == ETH_IPV6 and len(l3) >= 40:
            proto_counts["IPv6"] += 1
            proto = l3[6]
            src_ip, dst_ip = ipv6_str(l3[8:24]), ipv6_str(l3[24:40])
            l4 = l3[40:]
        else:
            continue

        talkers[src_ip] += 1

        # 3. ICMP / ICMPv6 Tunneling inspection (MITRE T1095)
        if proto in (PROTO_ICMP, PROTO_ICMPV6) and len(l4) >= 8:
            proto_counts["ICMPv6" if proto == PROTO_ICMPV6 else "ICMP"] += 1
            icmp_type = l4[0]
            icmp_data = l4[8:]
            if icmp_type in (0, 8, 128, 129) and len(icmp_data) > 64:
                ent = shannon_entropy(icmp_data)
                icmp_suspects.append((src_ip, dst_ip, len(icmp_data), round(ent, 2)))

        # 4. TCP inspection + Sequence Stream Reassembly
        elif proto == PROTO_TCP and len(l4) >= 20:
            proto_counts["TCP"] += 1
            src_port, dst_port, seq = struct.unpack("!HHI", l4[:8])
            data_offset = ((l4[12] >> 4) & 0x0F) * 4
            flags = l4[13]
            payload = l4[data_offset:]

            if (flags & SYN_FLAG) and not (flags & ACK_FLAG):
                syn_ports[(src_ip, dst_ip)].add(dst_port)
                if ts > 0:
                    flow_times[(src_ip, dst_ip, dst_port)].append(ts)

            if payload:
                tcp_streams[(src_ip, src_port, dst_ip, dst_port)][seq] = payload

        # 5. UDP / DNS inspection (DNS tunneling / exfiltration)
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
                        dns_suspects.append((src_ip, qname, len(sub), round(ent, 2)))

    # Reassemble TCP streams ordered by sequence number and scan for credentials
    cred_leaks = []
    seen_creds = set()
    for (src_ip, src_port, dst_ip, dst_port), seg_map in tcp_streams.items():
        reassembled = b"".join(seg_map[seq] for seq in sorted(seg_map))
        text = reassembled.decode("utf-8", errors="ignore")
        inspect_credentials_in_text(text, src_ip, dst_ip, dst_port, seen_creds, cred_leaks)

    # Periodic C2 Beaconing detection (flows with >= 4 intervals and low jitter)
    beacons = []
    for (src_ip, dst_ip, dst_port), times in flow_times.items():
        if len(times) >= 4:
            ordered = sorted(times)
            deltas = [ordered[i + 1] - ordered[i] for i in range(len(ordered) - 1)]
            mean_d = sum(deltas) / len(deltas)
            if mean_d >= 1.0:
                variance = sum((d - mean_d) ** 2 for d in deltas) / len(deltas)
                jitter_cv = math.sqrt(variance) / mean_d
                if jitter_cv <= 0.15:
                    beacons.append((src_ip, dst_ip, dst_port, len(times), round(mean_d, 1), round(jitter_cv * 100, 1)))

    # --------------------------------------------------------------- report
    print(f"[*] Capture Source  : {source_name} ({capture_fmt})")
    print(f"[*] Total Packets   : {total_packets}  |  Reassembled TCP Streams: {len(tcp_streams)}")
    proto_summary = ", ".join(f"{k}: {v}" for k, v in proto_counts.most_common()) or "none"
    print(f"[*] Protocols       : {proto_summary}")
    top_ips = ", ".join(f"{ip} ({n})" for ip, n in talkers.most_common(3)) or "none"
    print(f"[*] Top Talkers     : {top_ips}")
    print("=" * 78)

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

    print("\n  [4] ICMP / ICMPv6 Covert Tunneling (MITRE T1095):")
    if icmp_suspects:
        for src, dst, plen, ent in icmp_suspects:
            alerts += 1
            print(f"  [ALERT] Oversized ICMP Echo tunnel {src} -> {dst} ({plen} bytes payload, {ent:.2f} bits entropy)")
    else:
        print("  [PASS]  No oversized or covert ICMP payloads found")

    print("\n  [5] Cleartext Credentials via TCP Stream Reassembly (MITRE T1040):")
    if cred_leaks:
        for kind, src, dst, port, detail in cred_leaks:
            alerts += 1
            print(f"  [ALERT] {kind:<16} {src} -> {dst}:{port}  ({detail})")
    else:
        print("  [PASS]  No cleartext credentials detected")

    if beacons:
        print("\n  [6] Periodic C2 Beaconing Detected (MITRE T1071.001):")
        for src, dst, port, count, interval, jitter in beacons:
            alerts += 1
            print(f"  [ALERT] C2 Heartbeat {src} -> {dst}:{port} ({count} beacons, every ~{interval}s, jitter {jitter}%)")

    verdict = f"{alerts} THREAT INDICATOR(S) DETECTED" if alerts else "CLEAN CAPTURE"
    print("\n" + "=" * 78)
    print(f"  SUMMARY: {total_packets} packets ({capture_fmt})   |   VERDICT: {verdict}")
    print("=" * 78)

    if output_path:
        report = {
            "source": source_name,
            "format": capture_fmt,
            "total_packets": total_packets,
            "protocols": dict(proto_counts),
            "alerts_count": alerts,
            "verdict": verdict,
            "port_scans": [
                {"src_ip": s, "dst_ip": d, "ports": sorted(p)} for (s, d), p in scans
            ],
            "arp_spoofing": {ip: sorted(macs) for ip, macs in spoofed.items()},
            "dns_tunneling": [
                {"src_ip": s, "qname": q, "subdomain_len": l, "entropy": e}
                for s, q, l, e in dns_suspects
            ],
            "icmp_tunneling": [
                {"src_ip": s, "dst_ip": d, "payload_bytes": l, "entropy": e}
                for s, d, l, e in icmp_suspects
            ],
            "cleartext_credentials": [
                {"type": k, "src_ip": s, "dst_ip": d, "dst_port": p, "detail": dt}
                for k, s, d, p, dt in cred_leaks
            ],
            "c2_beacons": [
                {"src_ip": s, "dst_ip": d, "dst_port": p, "count": c, "interval_sec": iv, "jitter_pct": j}
                for s, d, p, c, iv, j in beacons
            ],
        }
        Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Exported JSON threat report to {output_path}")

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


def _eth_ipv6(src_ip6: str, dst_ip6: str, next_hdr: int, l4: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", ETH_IPV6)
    ip6_hdr = (
        struct.pack("!IHBB", 0x60000000, len(l4), next_hdr, 64)
        + socket.inet_pton(socket.AF_INET6, src_ip6)
        + socket.inet_pton(socket.AF_INET6, dst_ip6)
    )
    return eth + ip6_hdr + l4


def _tcp_pkt(
    src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 1000
) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 8192, 0, 0) + payload
    return _eth_ipv4(src_ip, dst_ip, PROTO_TCP, tcp)


def _icmp_echo_pkt(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1337, 1) + payload
    return _eth_ipv4(src_ip, dst_ip, PROTO_ICMP, icmp)


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
    """Create a realistic in-memory capture with IPv4/IPv6 + 5 simulated attacks."""
    frames = [
        _dns_query_pkt("192.168.1.10", "8.8.8.8", "github.com"),
        _eth_ipv6(
            "2001:db8::10",
            "2001:db8::1",
            PROTO_TCP,
            struct.pack("!HHIIBBHHH", 54100, 443, 1, 0, 0x50, SYN_FLAG | ACK_FLAG, 8192, 0, 0),
        ),
    ]
    # 1. SYN port scan from 203.0.113.50 against 192.168.1.10 (15 ports)
    for port in (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080):
        frames.append(_tcp_pkt("203.0.113.50", "192.168.1.10", 44000 + port, port, SYN_FLAG))

    # 2. ARP spoofing: gateway 192.168.1.1 claimed by two different MAC addresses
    frames.append(_arp_reply(b"\xaa\xbb\xcc\x00\x00\x01", "192.168.1.1"))
    frames.append(_arp_reply(b"\xde\xad\xbe\xef\x13\x37", "192.168.1.1"))

    # 3. DNS tunneling / exfiltration query with high-entropy base64/hex subdomain
    frames.append(_dns_query_pkt(
        "192.168.1.10", "8.8.8.8",
        "aGVsbG8tdGhpcy1pcy1leGZpbHRyYXRlZC1zZWNyZXQtZGF0YQ.c2-tunnel.example.net",
    ))

    # 4. ICMP covert tunnel (oversized 96-byte high-entropy ping payload)
    frames.append(_icmp_echo_pkt(
        "192.168.1.10", "198.51.100.77",
        b"EXFIL_CHUNK_01::a8f9c2d1e4b709123456789abcdef0123456789ABCDEF!@#$%^&*()_+=[];',./",
    ))

    # 5. Cleartext HTTP POST login split across TWO separate TCP packets (requires stream reassembly!)
    part1 = b"POST /login HTTP/1.1\r\nHost: intranet.local\r\n\r\nusername=admin&"
    part2 = b"password=Spring2026!Secret"
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.25", 52001, 80, ACK_FLAG, part1, seq=1000))
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.25", 52001, 80, ACK_FLAG, part2, seq=1000 + len(part1)))
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.30", 52002, 21, ACK_FLAG, b"USER backup_svc\r\n", seq=2000))
    frames.append(_tcp_pkt("192.168.1.10", "192.168.1.30", 52002, 21, ACK_FLAG, b"PASS Backup#9921\r\n", seq=2020))

    buf = io.BytesIO()
    buf.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for idx, frame in enumerate(frames):
        buf.write(struct.pack("<IIII", 1729850000 + idx, 0, len(frame), len(frame)))
        buf.write(frame)
    return buf.getvalue()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Analyze a .pcap or .pcapng packet capture for network attacks.")
    parser.add_argument("pcap", nargs="?", help="Path to a .pcap or .pcapng file")
    parser.add_argument(
        "-t", "--threshold", type=int, default=10,
        help="Distinct ports before flagging a SYN port scan (default: 10)",
    )
    parser.add_argument("-o", "--output", help="Export threat hunt findings to a JSON report file")
    parser.add_argument("--demo", action="store_true", help="Analyze a built-in simulated packet capture")
    parser.add_argument("--save-demo", metavar="FILE", help="Save the built-in demo .pcap to a file (for Wireshark)")
    args = parser.parse_args()

    print(BANNER)
    if args.save_demo:
        Path(args.save_demo).write_bytes(build_demo_pcap())
        print(f"[+] Saved demo capture to {args.save_demo}\n")
        if not args.demo and not args.pcap:
            return 0

    if args.demo:
        return analyze_pcap(io.BytesIO(build_demo_pcap()), "built-in demo capture", args.threshold, args.output)
    if not args.pcap:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to test against the built-in simulated packet capture!")
        return 0

    try:
        with open(args.pcap, "rb") as f:
            return analyze_pcap(f, args.pcap, args.threshold, args.output)
    except (OSError, ValueError) as e:
        print(f"[!] Could not analyze {args.pcap}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
