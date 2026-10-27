#!/usr/bin/env python3
"""
SSH & Auth Log Analyzer v2.0 (Blue Team — SOC & Intrusion Detection)
Detects brute-force bursts (sliding time-window analysis), password spraying / username
enumeration, and post-brute-force account compromise across both Linux OpenSSH
(/var/log/auth.log) and Windows Security Event Logs (Event ID 4625 & 4624),
with GeoIP/ASN attribution and JSON/CSV export.

MITRE ATT&CK: T1110.001 (Password Guessing), T1110.003 (Password Spraying), T1078 (Valid Accounts)
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
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
                       [ SSH & Auth Log Analyzer v2.0 ]
"""

# Linux OpenSSH regexes
SSH_FAILED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})?.*?"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_SUCCESS_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})?.*?"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Windows Security Event Log (Event ID 4625 Failed Logon / 4624 Successful Logon)
WIN_EVENT_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})?.*?"
    r"EventID[=:\s]+(?P<eid>4625|4624).*?"
    r"(?:Account Name|TargetUserName)[=:\s\"']+(?P<user>[A-Za-z0-9_.\-$]+).*?"
    r"(?:Source Network Address|IpAddress)[=:\s\"']+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# Built-in hybrid Linux sshd + Windows Event ID 4625/4624 sample log for --demo
DEMO_LOG = """\
Oct 15 10:01:01 prod-web01 sshd[1001]: Failed password for root from 203.0.113.45 port 50122 ssh2
Oct 15 10:01:03 prod-web01 sshd[1001]: Failed password for root from 203.0.113.45 port 50123 ssh2
Oct 15 10:01:05 prod-web01 sshd[1001]: Failed password for invalid user admin from 203.0.113.45 port 50124 ssh2
Oct 15 10:01:07 prod-web01 sshd[1001]: Failed password for invalid user test from 203.0.113.45 port 50125 ssh2
Oct 15 10:01:09 prod-web01 sshd[1001]: Failed password for invalid user oracle from 203.0.113.45 port 50126 ssh2
Oct 15 10:01:11 prod-web01 sshd[1001]: Failed password for root from 203.0.113.45 port 50127 ssh2
Oct 15 10:02:00 prod-web01 sshd[1002]: Failed password for alice from 192.168.1.20 port 40000 ssh2
Oct 15 10:02:10 prod-web01 sshd[1002]: Accepted password for alice from 192.168.1.20 port 40001 ssh2
Oct 15 10:05:00 prod-web01 sshd[1003]: Failed password for invalid user ubuntu from 198.51.100.7 port 60001 ssh2
Oct 15 10:05:02 prod-web01 sshd[1003]: Failed password for invalid user pi from 198.51.100.7 port 60002 ssh2
Oct 15 10:05:04 prod-web01 sshd[1003]: Failed password for invalid user git from 198.51.100.7 port 60003 ssh2
Oct 15 10:05:06 prod-web01 sshd[1003]: Failed password for invalid user deploy from 198.51.100.7 port 60004 ssh2
Oct 15 10:05:08 prod-web01 sshd[1003]: Failed password for bob from 198.51.100.7 port 60005 ssh2
Oct 15 10:05:10 prod-web01 sshd[1003]: Failed password for bob from 198.51.100.7 port 60006 ssh2
Oct 15 10:05:30 prod-web01 sshd[1003]: Accepted password for bob from 198.51.100.7 port 60007 ssh2
2026-10-15 10:08:10 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 TargetUserName=Administrator IpAddress=192.0.2.88 LogonType=10
2026-10-15 10:08:12 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 TargetUserName=svc_sql IpAddress=192.0.2.88 LogonType=10
2026-10-15 10:08:14 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 TargetUserName=svc_backup IpAddress=192.0.2.88 LogonType=10
2026-10-15 10:08:16 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 TargetUserName=adm_domain IpAddress=192.0.2.88 LogonType=10
2026-10-15 10:08:18 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 TargetUserName=Administrator IpAddress=192.0.2.88 LogonType=10
2026-10-15 10:08:22 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4624 TargetUserName=svc_backup IpAddress=192.0.2.88 LogonType=10
"""

OFFLINE_GEO_MAP = {
    "203.0.113.": "TEST-NET-3 (APNIC Doc Block / Simulated Hosting ASN)",
    "198.51.100.": "TEST-NET-2 (ARIN Doc Block / Simulated VPS ASN)",
    "192.0.2.": "TEST-NET-1 (IANA Doc Block / Simulated Botnet Node)",
}


def parse_timestamp(ts_str: str | None) -> float | None:
    """Converts syslog ('Oct 15 10:01:01') or ISO timestamps into epoch seconds."""
    if not ts_str:
        return None
    ts_str = ts_str.strip()
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=2026)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def max_burst_in_window(timestamps: list[float], window_seconds: int = 60) -> int:
    """Calculates the maximum number of failed logins within any sliding N-second window."""
    if not timestamps:
        return 0
    ordered = sorted(timestamps)
    best = 1
    left = 0
    for right in range(len(ordered)):
        while ordered[right] - ordered[left] > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def resolve_geo_asn(ip: str, live_lookup: bool = False) -> str:
    """Returns network scope / GeoIP / ASN attribution for an IPv4 address."""
    for prefix, label in OFFLINE_GEO_MAP.items():
        if ip.startswith(prefix):
            return label
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "INTERNAL / RFC1918 LAN"
    except ValueError:
        return "Unknown"

    if live_lookup:
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,org,as"
            with urllib.request.urlopen(url, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    return f"{data.get('countryCode', '??')} — {data.get('as') or data.get('org', 'Unknown ASN')}"
        except Exception:
            pass
    return "External Public IP"


def parse_lines(lines: list[str]) -> dict:
    """Parses Linux sshd and Windows Event 4625/4624 lines into structured telemetry."""
    failed = Counter()
    failed_users: dict[str, set[str]] = defaultdict(set)
    failed_times: dict[str, list[float]] = defaultdict(list)
    sources_by_ip: dict[str, set[str]] = defaultdict(set)
    successes: list[tuple[str, str, str]] = []

    for line in lines:
        if m := WIN_EVENT_RE.search(line):
            ip, user, eid = m["ip"], m["user"], m["eid"]
            sources_by_ip[ip].add(f"WinEvent:{eid}")
            if eid == "4625":
                failed[ip] += 1
                failed_users[ip].add(user)
                if (epoch := parse_timestamp(m["ts"])) is not None:
                    failed_times[ip].append(epoch)
            else:
                successes.append((ip, user, "WinEvent:4624"))
        elif m := SSH_FAILED_RE.search(line):
            ip, user = m["ip"], m["user"]
            sources_by_ip[ip].add("Linux:sshd")
            failed[ip] += 1
            failed_users[ip].add(user)
            if (epoch := parse_timestamp(m["ts"])) is not None:
                failed_times[ip].append(epoch)
        elif m := SSH_SUCCESS_RE.search(line):
            ip, user = m["ip"], m["user"]
            sources_by_ip[ip].add("Linux:sshd")
            successes.append((ip, user, "Linux:sshd"))

    return {
        "failed": failed,
        "failed_users": failed_users,
        "failed_times": failed_times,
        "sources_by_ip": sources_by_ip,
        "successes": successes,
    }


def export_report(
    path: str,
    flagged_rows: list[dict],
    compromised: list[dict],
    total_fails: int,
    window_sec: int,
) -> None:
    """Exports findings to JSON or CSV depending on file extension."""
    out_path = Path(path)
    if out_path.suffix.lower() == ".json":
        payload = {
            "total_failed_attempts": total_fails,
            "window_seconds": window_sec,
            "flagged_ips": flagged_rows,
            "compromised_logins": compromised,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "ip",
                    "failed_attempts",
                    "max_burst_in_window",
                    "attack_pattern",
                    "log_source",
                    "geo_asn",
                    "usernames_tried",
                    "later_success",
                ],
            )
            writer.writeheader()
            writer.writerows(flagged_rows)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Detect SSH & Windows Event 4625 brute-force bursts, password spraying, and compromises."
    )
    parser.add_argument("logfile", nargs="?", help="Path to Linux auth.log or Windows Event log")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempts threshold (default: 5)")
    parser.add_argument(
        "-w", "--window", type=int, default=60, help="Sliding time-window in seconds for burst detection (default: 60)"
    )
    parser.add_argument("--geoip", action="store_true", help="Enable live GeoIP / ASN lookup for public IPs")
    parser.add_argument("-o", "--output", help="Export report to .json or .csv")
    parser.add_argument("--demo", action="store_true", help="Run built-in Linux sshd + Windows 4625/4624 demo")
    args = parser.parse_args()

    print(BANNER)

    if args.demo:
        source = "Built-in Hybrid Demo Log (Linux sshd + Windows Event ID 4625/4624)"
        lines = DEMO_LOG.splitlines()
    elif args.logfile:
        source = args.logfile
        try:
            with open(args.logfile, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError as e:
            print(f"[!] Could not read {args.logfile}: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to test with built-in Linux sshd & Windows 4625 logs!")
        return 0

    telemetry = parse_lines(lines)
    failed = telemetry["failed"]
    failed_users = telemetry["failed_users"]
    failed_times = telemetry["failed_times"]
    sources_by_ip = telemetry["sources_by_ip"]
    successes = telemetry["successes"]
    success_ips = {ip for ip, _, _ in successes}

    flagged_rows = []
    for ip, count in sorted(failed.items(), key=lambda x: -x[1]):
        burst = max_burst_in_window(failed_times[ip], args.window) or count
        if count >= args.threshold or burst >= args.threshold:
            users_sorted = sorted(failed_users[ip])
            tactic = "T1110.003 Password Spray" if len(users_sorted) >= 4 else "T1110.001 Brute Force"
            flagged_rows.append({
                "ip": ip,
                "failed_attempts": count,
                "max_burst_in_window": burst,
                "attack_pattern": tactic,
                "log_source": "/".join(sorted(sources_by_ip[ip])),
                "geo_asn": resolve_geo_asn(ip, live_lookup=args.geoip),
                "usernames_tried": ", ".join(users_sorted),
                "later_success": ip in success_ips,
            })

    flagged_ip_set = {r["ip"] for r in flagged_rows}
    compromised = [
        {"ip": ip, "user": user, "source": src}
        for ip, user, src in successes
        if ip in flagged_ip_set
    ]

    print(f"[*] Telemetry Source : {source}")
    print(f"[*] Detection Rules  : Threshold >= {args.threshold} fails  |  Burst Window: {args.window}s")
    print(
        f"[*] Summary          : {sum(failed.values())} failed logins across {len(failed)} IP(s) "
        f"-> {len(flagged_rows)} flagged"
    )
    print("=" * 78)

    if flagged_rows:
        print(f"\n[🚨 Flagged Brute-Force & Password-Spraying Sources ({len(flagged_rows)})]")
        for r in flagged_rows:
            print(
                f"  • {r['ip']:<15} | Fails: {r['failed_attempts']:>2} (Peak {r['max_burst_in_window']}/{args.window}s) "
                f"| [{r['log_source']}] | {r['attack_pattern']}"
            )
            print(f"      ├─ Attribution : {r['geo_asn']}")
            print(f"      └─ Accounts    : {r['usernames_tried']}")
    else:
        print("\n[+] No source IPs exceeded the failure or burst threshold.")

    if compromised:
        print(f"\n[🔥 CRITICAL ALERT: Post-Brute-Force Account Compromise ({len(compromised)}) — MITRE T1078]")
        for c in compromised:
            print(f"  • [COMPROMISED] Account '{c['user']}' logged in from flagged IP {c['ip']} ({c['source']})")

    print("\n" + "=" * 78)

    if args.output:
        export_report(args.output, flagged_rows, compromised, sum(failed.values()), args.window)
        print(f"[+] Report exported to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
