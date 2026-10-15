#!/usr/bin/env python3
"""
SSH Log Analyzer - detect brute-force attempts in Linux auth logs.

Parses /var/log/auth.log style files, counts failed logins per IP,
flags IPs over a threshold, and alerts when a flagged IP later logs in
successfully (possible account compromise).

MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)
Made By Sonelu
"""
import argparse
import csv
import re
import sys
from collections import Counter, defaultdict

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Built-in sample log (uses RFC 5737 documentation IPs) so the tool can be tried with --demo
DEMO_LOG = """\
Oct 15 10:01:01 server sshd[1001]: Failed password for root from 203.0.113.45 port 50122 ssh2
Oct 15 10:01:03 server sshd[1001]: Failed password for root from 203.0.113.45 port 50123 ssh2
Oct 15 10:01:05 server sshd[1001]: Failed password for invalid user admin from 203.0.113.45 port 50124 ssh2
Oct 15 10:01:07 server sshd[1001]: Failed password for invalid user test from 203.0.113.45 port 50125 ssh2
Oct 15 10:01:09 server sshd[1001]: Failed password for invalid user oracle from 203.0.113.45 port 50126 ssh2
Oct 15 10:01:11 server sshd[1001]: Failed password for root from 203.0.113.45 port 50127 ssh2
Oct 15 10:02:00 server sshd[1002]: Failed password for alice from 192.168.1.20 port 40000 ssh2
Oct 15 10:02:10 server sshd[1002]: Accepted password for alice from 192.168.1.20 port 40001 ssh2
Oct 15 10:05:00 server sshd[1003]: Failed password for invalid user ubuntu from 198.51.100.7 port 60001 ssh2
Oct 15 10:05:02 server sshd[1003]: Failed password for invalid user pi from 198.51.100.7 port 60002 ssh2
Oct 15 10:05:04 server sshd[1003]: Failed password for invalid user git from 198.51.100.7 port 60003 ssh2
Oct 15 10:05:06 server sshd[1003]: Failed password for invalid user deploy from 198.51.100.7 port 60004 ssh2
Oct 15 10:05:08 server sshd[1003]: Failed password for bob from 198.51.100.7 port 60005 ssh2
Oct 15 10:05:10 server sshd[1003]: Failed password for bob from 198.51.100.7 port 60006 ssh2
Oct 15 10:05:30 server sshd[1003]: Accepted password for bob from 198.51.100.7 port 60007 ssh2
"""


def parse_lines(lines):
    """Return failed-attempt counts, usernames tried per IP, and successful logins."""
    failed = Counter()
    failed_users = defaultdict(set)
    successes = []  # list of (ip, user)
    for line in lines:
        if m := FAILED_RE.search(line):
            failed[m["ip"]] += 1
            failed_users[m["ip"]].add(m["user"])
        elif m := SUCCESS_RE.search(line):
            successes.append((m["ip"], m["user"]))
    return failed, failed_users, successes


def write_csv(path, flagged, failed_users, successes):
    success_ips = {ip for ip, _ in successes}
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "failed_attempts", "usernames_tried", "later_success"])
        for ip, count in sorted(flagged.items(), key=lambda x: -x[1]):
            writer.writerow([ip, count, ";".join(sorted(failed_users[ip])), ip in success_ips])


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs.")
    parser.add_argument("logfile", nargs="?", help="Path to auth.log")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Failed attempts before an IP is flagged (default: 5)")
    parser.add_argument("-o", "--output", help="Optional path for a CSV report")
    parser.add_argument("--demo", action="store_true", help="Run against a built-in sample log")
    args = parser.parse_args()

    if args.demo:
        source = "built-in demo log"
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
        parser.error("provide a logfile or use --demo")

    failed, failed_users, successes = parse_lines(lines)
    flagged = {ip: n for ip, n in failed.items() if n >= args.threshold}

    print(f"\n=== SSH Log Analysis: {source} ===")
    print(f"Total failed attempts : {sum(failed.values())}")
    print(f"Unique source IPs     : {len(failed)}")
    print(f"Flagged IPs (>= {args.threshold})  : {len(flagged)}\n")

    if flagged:
        print(f"{'IP Address':<18}{'Fails':>6}  Usernames tried")
        print("-" * 60)
        for ip, n in sorted(flagged.items(), key=lambda x: -x[1]):
            users = ", ".join(sorted(failed_users[ip]))
            print(f"{ip:<18}{n:>6}  {users[:35]}")
    else:
        print("[+] No IPs exceeded the threshold.")

    compromised = [(ip, user) for ip, user in successes if ip in flagged]
    if compromised:
        print("\n[!!] ALERT: successful logins from flagged IPs (possible compromise):")
        for ip, user in compromised:
            print(f"     user '{user}' logged in from {ip}")

    if args.output:
        write_csv(args.output, flagged, failed_users, successes)
        print(f"\n[+] CSV report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
