#!/usr/bin/env python3
"""
IOC Extractor & Defanger (Blue Team — SOC & Threat Intelligence)
Extracts, validates, classifies, and defangs/refangs Indicators of Compromise
(IPv4/IPv6, URLs, Domains, Emails, MD5/SHA1/SHA256 Hashes, CVEs, and MITRE ATT&CK IDs)
from raw logs, phishing emails, or threat advisories using only the Python standard library.
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
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
                        [ IOC Extractor & Defanger ]
"""

# Built-in simulated SOC Threat Advisory & Incident Log for --demo mode
DEMO_REPORT = """
=== SOC INCIDENT ADVISORY: INC-2026-0842 (Operation ShadowDrop) ===
Analyst Notes: Phishing email received by workstation 10.20.4.115 from spoofed sender
alerts[@]auth-example-portal[.]com and billing@cdn-example-verify.net.

The email exploited CVE-2024-21413 and CVE-2023-38831 (MITRE ATT&CK: T1566.002, T1059.001, T1071.001)
to reach external command-and-control (C2) servers at 198.51.100.42 and 203.0.113[.]195
(IPv6 fallback: 2001:db8:85a3::8a2e:370:7334).

Observed outbound HTTP/HTTPS requests:
  - hxxps://cdn-example-verify[.]net/api/v2/stage2.bin
  - http://203.0.113.195:8443/beacon/checkin.php

Dropped stage-2 payload hashes captured by EDR:
  - MD5:    d41d8cd98f00b204e9800998ecf8427e
  - SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
  - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

# Common file extensions that look like TLDs in logs (excluded from domain matches)
IGNORED_EXTENSIONS = {
    "exe", "dll", "sys", "bin", "dat", "log", "txt", "pdf", "doc", "docx",
    "xls", "xlsx", "zip", "rar", "tar", "gz", "py", "js", "php", "html",
    "css", "json", "xml", "yml", "yaml", "ini", "cfg", "bat", "ps1", "sh",
    "jpg", "jpeg", "png", "gif", "svg", "ico", "mp4", "mp3", "pcap", "eml",
}

# Known valid-looking TLDs for offline heuristic domain validation
VALID_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai",
    "app", "dev", "xyz", "top", "info", "biz", "me", "tv", "cc", "ru",
    "cn", "de", "uk", "fr", "nl", "ro", "eu", "us", "ca", "au", "br",
    "in", "jp", "kr", "it", "es", "ch", "se", "no", "pl", "UA", "cloud",
    "online", "site", "tech", "store", "security", "local", "onion",
}


def refang_text(text: str) -> str:
    """Normalizes defanged indicators in raw text back to canonical form before extraction."""
    normalized = text
    # Protocol normalization: hxxp / hxxps / fxp and [:]//
    normalized = re.sub(r"\bhxxps\b", "https", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bhxxp\b", "http", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\bfxp\b", "ftp", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\[://\]|\[:\]//|\(:\)//", "://", normalized)
    # Dot normalization: [.] (.) {.} [dot] (dot)
    normalized = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", normalized, flags=re.IGNORECASE)
    # At-sign normalization: [@] (@) [at] (at)
    normalized = re.sub(r"\[@\]|\(@\)|\[at\]|\(at\)", "@", normalized, flags=re.IGNORECASE)
    return normalized


def defang_ioc(value: str, category: str) -> str:
    """Converts a canonical IOC into safe defanged notation for SOC tickets & reports."""
    if category == "urls":
        out = re.sub(r"^https://", "hxxps://", value, flags=re.IGNORECASE)
        out = re.sub(r"^http://", "hxxp://", out, flags=re.IGNORECASE)
        out = re.sub(r"^ftp://", "fxp://", out, flags=re.IGNORECASE)
        # Defang dots only in the host portion of the URL
        m = re.match(r"^([a-zA-Z]+://)([^/]+)(.*)$", out)
        if m:
            scheme, host, rest = m.groups()
            return f"{scheme}{host.replace('.', '[.]')}{rest}"
        return out.replace(".", "[.]")
    if category in ("ipv4", "domains"):
        return value.replace(".", "[.]")
    if category == "emails":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


def extract_iocs(raw_text: str, include_private_ips: bool = True) -> dict:
    """Extracts, validates, and deduplicates 8 types of IOCs from raw text."""
    text = refang_text(raw_text)

    # 1. URLs (http, https, ftp)
    url_pattern = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]]+", re.IGNORECASE)
    urls = sorted({u.rstrip(".,;:!?)") for u in url_pattern.findall(text)})

    # 2. Email addresses
    email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,15}\b")
    emails = sorted(set(email_pattern.findall(text)))

    # 3. IPv4 addresses (strictly validated with ipaddress module)
    rfc1918_nets = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
        ipaddress.IPv4Network("127.0.0.0/8"),
        ipaddress.IPv4Network("169.254.0.0/16"),
    )
    ipv4_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    ipv4_list = []
    seen_ips = set()
    for candidate in ipv4_candidates:
        try:
            ip_obj = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        ip_str = str(ip_obj)
        if ip_str in seen_ips:
            continue
        is_internal = any(ip_obj in net for net in rfc1918_nets)
        if is_internal and not include_private_ips:
            continue
        seen_ips.add(ip_str)
        scope = "INTERNAL/RFC1918" if is_internal else "EXTERNAL"
        ipv4_list.append({"ip": ip_str, "scope": scope})

    # 4. IPv6 addresses (supports standard and :: compressed notation)
    ipv6_candidates = re.findall(
        r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,7}:?[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*(?![0-9a-fA-F:])",
        text,
    )
    ipv6_list = []
    for candidate in ipv6_candidates:
        try:
            ip6_str = str(ipaddress.IPv6Address(candidate))
            if ip6_str not in ipv6_list:
                ipv6_list.append(ip6_str)
        except ValueError:
            continue

    # 5. Domains / FQDNs (excluding file names and IPs)
    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,15})\b"
    )
    domains = set()
    for match in domain_pattern.finditer(text):
        full_domain = match.group(0).lower()
        tld = match.group(1).lower()
        if tld in IGNORED_EXTENSIONS:
            continue
        if tld in VALID_TLDS or len(tld) in (2, 3):
            domains.add(full_domain)

    # 6. Cryptographic Hashes (SHA-256, SHA-1, MD5) — match longest first to avoid substring collisions
    sha256_hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text.lower())))
    text_no_256 = re.sub(r"\b[a-fA-F0-9]{64}\b", " ", text.lower())
    sha1_hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{40}\b", text_no_256)))
    text_no_1 = re.sub(r"\b[a-fA-F0-9]{40}\b", " ", text_no_256)
    md5_hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b", text_no_1)))

    # 7. CVEs (CVE-YYYY-NNNN+)
    cves = sorted({c.upper() for c in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)})

    # 8. MITRE ATT&CK Technique IDs (Txxxx or Txxxx.xxx)
    mitre_ids = sorted({m.upper() for m in re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)})

    return {
        "ipv4": ipv4_list,
        "ipv6": ipv6_list,
        "urls": urls,
        "domains": sorted(domains),
        "emails": emails,
        "hashes": {
            "md5": md5_hashes,
            "sha1": sha1_hashes,
            "sha256": sha256_hashes,
        },
        "cves": cves,
        "mitre_attack": mitre_ids,
    }


def format_ioc(value: str, category: str, mode: str) -> str:
    """Applies either defang (safe) or refang (raw) formatting."""
    return defang_ioc(value, category) if mode == "defang" else value


def print_report(results: dict, mode: str, source_label: str) -> None:
    """Prints a compact, screenshot-friendly SOC IOC Triage Report."""
    total_hashes = sum(len(v) for v in results["hashes"].values())
    total_iocs = (
        len(results["ipv4"])
        + len(results["ipv6"])
        + len(results["urls"])
        + len(results["domains"])
        + len(results["emails"])
        + total_hashes
        + len(results["cves"])
        + len(results["mitre_attack"])
    )

    mode_badge = "DEFANGED (Safe for SOC Sharing)" if mode == "defang" else "REFANGED (Raw Blocklist Ready)"
    print(f"[*] Source       : {source_label}")
    print(f"[*] Output Mode  : {mode_badge}")
    print(f"[*] Total IOCs   : {total_iocs} unique indicators extracted")
    print("=" * 72)

    if results["ipv4"] or results["ipv6"]:
        print(f"\n[🌐 Network IP Addresses ({len(results['ipv4']) + len(results['ipv6'])})]")
        for item in results["ipv4"]:
            disp = format_ioc(item["ip"], "ipv4", mode)
            print(f"  • {disp:<22} [{item['scope']}]")
        for ip6 in results["ipv6"]:
            print(f"  • {ip6:<22} [IPv6]")

    if results["urls"]:
        print(f"\n[🔗 URLs ({len(results['urls'])})]")
        for u in results["urls"]:
            print(f"  • {format_ioc(u, 'urls', mode)}")

    if results["domains"]:
        print(f"\n[🏷️  Domains / FQDNs ({len(results['domains'])})]")
        for d in results["domains"]:
            print(f"  • {format_ioc(d, 'domains', mode)}")

    if results["emails"]:
        print(f"\n[✉️  Email Addresses ({len(results['emails'])})]")
        for e in results["emails"]:
            print(f"  • {format_ioc(e, 'emails', mode)}")

    if total_hashes > 0:
        print(f"\n[#️⃣  File Hashes ({total_hashes})]")
        for htype, hlist in results["hashes"].items():
            for h in hlist:
                print(f"  • [{htype.upper():<6}] {h}")

    if results["cves"] or results["mitre_attack"]:
        print(f"\n[🎯 Vulnerability & Threat Context ({len(results['cves']) + len(results['mitre_attack'])})]")
        if results["cves"]:
            print(f"  • CVEs         : {', '.join(results['cves'])}")
        if results["mitre_attack"]:
            print(f"  • MITRE ATT&CK : {', '.join(results['mitre_attack'])}")

    print("\n" + "=" * 72)


def export_results(results: dict, output_path: str, mode: str) -> None:
    """Exports extracted IOCs to JSON or CSV."""
    out_file = Path(output_path)
    rows = []
    for item in results["ipv4"]:
        rows.append({"type": f"IPv4 ({item['scope']})", "value": format_ioc(item["ip"], "ipv4", mode)})
    for ip6 in results["ipv6"]:
        rows.append({"type": "IPv6", "value": ip6})
    for u in results["urls"]:
        rows.append({"type": "URL", "value": format_ioc(u, "urls", mode)})
    for d in results["domains"]:
        rows.append({"type": "Domain", "value": format_ioc(d, "domains", mode)})
    for e in results["emails"]:
        rows.append({"type": "Email", "value": format_ioc(e, "emails", mode)})
    for htype, hlist in results["hashes"].items():
        for h in hlist:
            rows.append({"type": f"Hash-{htype.upper()}", "value": h})
    for c in results["cves"]:
        rows.append({"type": "CVE", "value": c})
    for m in results["mitre_attack"]:
        rows.append({"type": "MITRE-ATT&CK", "value": m})

    if out_file.suffix.lower() == ".csv":
        with out_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "value"])
            writer.writeheader()
            writer.writerows(rows)
    else:
        with out_file.open("w", encoding="utf-8") as f:
            json.dump({"mode": mode, "total": len(rows), "indicators": rows}, f, indent=2)

    print(f"[+] Exported {len(rows)} IOCs to {out_file}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Extract, classify, and defang/refang IOCs from logs, emails, or threat reports."
    )
    parser.add_argument("file", nargs="?", help="Path to input text/log/email file")
    parser.add_argument("--demo", action="store_true", help="Run built-in SOC incident advisory demo")
    parser.add_argument(
        "--refang",
        action="store_true",
        help="Output raw/active IOCs instead of defanged indicators (for firewall/SIEM blocklists)",
    )
    parser.add_argument(
        "--no-private",
        action="store_true",
        help="Exclude internal RFC 1918 / loopback IPv4 addresses",
    )
    parser.add_argument("-o", "--output", help="Export extracted IOCs to a .json or .csv file")
    args = parser.parse_args()

    print(BANNER)

    if args.demo:
        raw_text = DEMO_REPORT
        source_label = "Built-in SOC Incident Advisory (INC-2026-0842)"
    elif args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"[!] Error: File not found: {args.file}")
            sys.exit(1)
        raw_text = path.read_text(encoding="utf-8", errors="ignore")
        source_label = path.name
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
        source_label = "stdin"
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to test with a built-in SOC threat report!")
        sys.exit(0)

    mode = "refang" if args.refang else "defang"
    results = extract_iocs(raw_text, include_private_ips=not args.no_private)
    print_report(results, mode=mode, source_label=source_label)

    if args.output:
        export_results(results, args.output, mode=mode)


if __name__ == "__main__":
    main()
