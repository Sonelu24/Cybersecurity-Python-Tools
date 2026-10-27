#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) v2.0 (Blue Team — Host Intrusion Detection)
Creates SHA-256 + metadata (size/permissions) baselines optionally signed with
HMAC-SHA256 (to detect tampering with baseline.json itself), supports .fimignore /
--ignore exclusion patterns, and alerts on added, modified, permission-changed,
or deleted files with optional Slack/Discord/Teams webhook notifications.

MITRE ATT&CK: T1565.001 (Stored Data Manipulation), T1505.003 (Web Shell),
              T1070.004 (File Deletion), T1222 (File and Directory Permissions Modification)
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import sys
import tempfile
import time
import urllib.request
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
                    [ File Integrity Monitor (FIM) v2.0 ]
"""

DEFAULT_BASELINE = "baseline.json"
CHUNK_SIZE = 65536


def hash_file(path: Path) -> str:
    """SHA-256 a file in 64KB chunks so large files don't fill up memory."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_ignore_patterns(directory: Path, cli_ignore: str | None) -> list[str]:
    """Combines --ignore glob patterns with any .fimignore file in the target folder."""
    patterns = [".fimignore"]
    if cli_ignore:
        patterns.extend(p.strip() for p in cli_ignore.split(",") if p.strip())
    fimignore = directory / ".fimignore"
    if fimignore.is_file():
        for line in fimignore.read_text(encoding="utf-8", errors="ignore").splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                patterns.append(clean)
    return patterns


def is_ignored(rel_posix: str, patterns: list[str]) -> bool:
    """Checks whether a relative POSIX path matches any ignore glob pattern."""
    name = rel_posix.rsplit("/", 1)[-1]
    for pat in patterns:
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def scan(directory: Path, exclude: Path, ignore_patterns: list[str] | None = None) -> tuple[dict, int]:
    """Returns ({relative_path: {sha256, size, mode}}, skipped_ignored_count)."""
    records: dict[str, dict] = {}
    ignored_count = 0
    patterns = ignore_patterns or []
    excluded = exclude.resolve()

    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.resolve() == excluded:
            continue
        rel = path.relative_to(directory).as_posix()
        if is_ignored(rel, patterns):
            ignored_count += 1
            continue
        try:
            st = path.stat()
            records[rel] = {
                "sha256": hash_file(path),
                "size": st.st_size,
                "mode": oct(st.st_mode & 0o777),
            }
        except OSError as e:
            print(f"[!] Skipped {path}: {e}", file=sys.stderr)
    return records, ignored_count


def compute_baseline_hmac(files_dict: dict, directory_str: str, key: str) -> str:
    """Computes an HMAC-SHA256 signature over the canonical baseline contents."""
    canonical = json.dumps({"directory": directory_str, "files": files_dict}, sort_keys=True).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def save_baseline(
    directory: Path,
    baseline: Path,
    ignore_patterns: list[str] | None = None,
    hmac_key: str | None = None,
) -> tuple[int, int]:
    files, ignored_count = scan(directory, baseline, ignore_patterns)
    dir_str = str(directory.resolve())
    data = {
        "directory": dir_str,
        "created": datetime.now().isoformat(timespec="seconds"),
        "algorithm": "sha256",
        "ignore_patterns": ignore_patterns or [],
        "hmac_signed": bool(hmac_key),
        "hmac_sha256": compute_baseline_hmac(files, dir_str, hmac_key) if hmac_key else None,
        "files": files,
    }
    baseline.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(files), ignored_count


def verify_baseline_hmac(data: dict, hmac_key: str | None) -> tuple[bool, str]:
    """Verifies the HMAC-SHA256 signature of a loaded baseline."""
    stored_sig = data.get("hmac_sha256")
    if not stored_sig:
        return True, "UNSIGNED"
    if not hmac_key:
        return False, "MISSING_KEY (Baseline is HMAC-signed; pass --key to verify)"
    expected = compute_baseline_hmac(data["files"], data["directory"], hmac_key)
    if hmac.compare_digest(stored_sig, expected):
        return True, "VALID (HMAC-SHA256 Verified)"
    return False, "TAMPERED (HMAC-SHA256 Mismatch — baseline.json was modified!)"


def compare(old: dict, new: dict) -> tuple[list[str], list[str], list[str], list[str]]:
    """Compares old and new file dictionaries (backward-compatible with v1.0 string hashes)."""
    added = sorted(new.keys() - old.keys())
    deleted = sorted(old.keys() - new.keys())
    modified = []
    perm_changed = []

    for k in sorted(old.keys() & new.keys()):
        o_entry = old[k] if isinstance(old[k], dict) else {"sha256": old[k], "mode": None}
        n_entry = new[k] if isinstance(new[k], dict) else {"sha256": new[k], "mode": None}
        if o_entry["sha256"] != n_entry["sha256"]:
            modified.append(k)
        elif o_entry.get("mode") and n_entry.get("mode") and o_entry["mode"] != n_entry["mode"]:
            perm_changed.append(f"{k} ({o_entry['mode']} -> {n_entry['mode']})")

    return added, modified, perm_changed, deleted


def send_webhook(url: str, summary_text: str) -> None:
    """POSTs an integrity alert to a Slack/Discord/Teams webhook."""
    payload = json.dumps({"text": summary_text, "content": summary_text}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except Exception as exc:
        print(f"     [!] Webhook delivery failed: {exc}")


def report(
    added: list[str],
    modified: list[str],
    perm_changed: list[str],
    deleted: list[str],
    webhook: str | None = None,
) -> bool:
    """Prints detected integrity changes and returns True if any occurred."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not (added or modified or perm_changed or deleted):
        print(f"[{stamp}] [+] No changes detected — all files match the SHA-256 baseline.")
        return False

    print(f"[{stamp}] [!!] INTEGRITY CHANGES DETECTED")
    for f in added:
        print(f"     [ADDED]      {f}  (MITRE T1505.003)")
    for f in modified:
        print(f"     [MODIFIED]   {f}  (MITRE T1565.001)")
    for f in perm_changed:
        print(f"     [PERM-CHG]   {f}  (MITRE T1222)")
    for f in deleted:
        print(f"     [DELETED]    {f}  (MITRE T1070.004)")

    summary = (
        f"Summary: {len(added)} added, {len(modified)} modified, "
        f"{len(perm_changed)} perm-changed, {len(deleted)} deleted"
    )
    print(f"     {summary}")
    if webhook:
        send_webhook(webhook, f"[FIM Alert {stamp}] {summary}")
    return True


def cmd_baseline(args) -> int:
    directory, baseline = Path(args.directory), Path(args.baseline)
    if not directory.is_dir():
        print(f"[!] Not a directory: {directory}")
        return 1
    patterns = load_ignore_patterns(directory, args.ignore)
    count, ignored = save_baseline(directory, baseline, patterns, hmac_key=args.key)
    sig_status = "HMAC-SHA256 signed" if args.key else "unsigned"
    print(f"[+] Baseline saved to {baseline} ({count} files hashed, {ignored} ignored, {sig_status})")
    return 0


def cmd_check(args) -> int:
    baseline = Path(args.baseline)
    if not baseline.exists():
        print(f"[!] Baseline not found: {baseline}. Run the 'baseline' command first.")
        return 1
    data = json.loads(baseline.read_text(encoding="utf-8"))
    ok, hmac_status = verify_baseline_hmac(data, args.key)
    print(f"[*] Baseline HMAC Status : {hmac_status}")
    if not ok:
        print("[!!] CRITICAL: Baseline integrity verification failed! Refusing to trust tampered baseline.")
        return 3

    directory = Path(args.directory) if args.directory else Path(data["directory"])
    patterns = load_ignore_patterns(directory, args.ignore) or data.get("ignore_patterns", [])
    print(f"[*] Checking Directory   : {directory} (baseline from {data['created']})")
    current, _ = scan(directory, baseline, patterns)
    changes = compare(data["files"], current)
    changed = report(*changes, webhook=args.webhook)

    if args.output:
        Path(args.output).write_text(
            json.dumps(
                {
                    "hmac_status": hmac_status,
                    "added": changes[0],
                    "modified": changes[1],
                    "perm_changed": changes[2],
                    "deleted": changes[3],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"[+] Exported JSON report to {args.output}")
    return 2 if changed else 0


def cmd_watch(args) -> int:
    baseline = Path(args.baseline)
    if not baseline.exists():
        print(f"[!] Baseline not found: {baseline}. Run the 'baseline' command first.")
        return 1
    data = json.loads(baseline.read_text(encoding="utf-8"))
    ok, hmac_status = verify_baseline_hmac(data, args.key)
    if not ok:
        print(f"[!!] CRITICAL: {hmac_status}")
        return 3

    directory = Path(args.directory) if args.directory else Path(data["directory"])
    patterns = load_ignore_patterns(directory, args.ignore) or data.get("ignore_patterns", [])
    print(f"=== Watching {directory} every {args.interval}s ({hmac_status}, Ctrl+C to stop) ===")

    known = data["files"]
    current, _ = scan(directory, baseline, patterns)
    report(*compare(known, current), webhook=args.webhook)
    try:
        while True:
            time.sleep(args.interval)
            current, _ = scan(directory, baseline, patterns)
            changes = compare(known, current)
            if any(changes):
                report(*changes, webhook=args.webhook)
                known = current
    except KeyboardInterrupt:
        print("\n[+] Stopped watching.")
    return 0


def cmd_demo(_args) -> int:
    """Simulates a full FIM v2.0 lifecycle: HMAC-signed baseline, ignore rules, attack, and baseline tamper check."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "webserver"
        (root / "config").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "index.html").write_text("<h1>Welcome</h1>\n", encoding="utf-8")
        (root / "config" / "settings.conf").write_text("debug=false\nadmin_user=admin\n", encoding="utf-8")
        (root / "logs" / "access.log").write_text("GET /index.html 200\n", encoding="utf-8")
        (root / "session.tmp").write_text("temp_cache_data\n", encoding="utf-8")
        baseline = Path(tmp) / DEFAULT_BASELINE
        demo_key = "soc_fim_master_key_2026"
        ignore_pats = ["*.tmp", "cache/*"]

        print("[*] Target Folder   : /var/www/webserver (Simulated Temp Environment)")
        print(f"[*] Security Policy : HMAC-SHA256 Signed Baseline  |  Ignore Rules: {', '.join(ignore_pats)}")
        print("=" * 76)

        count, ignored = save_baseline(root, baseline, ignore_pats, hmac_key=demo_key)
        print(f"\n[1] Created HMAC-SHA256 Signed Baseline ({count} files hashed, {ignored} *.tmp file ignored)")

        print("\n[2] Simulating Intrusion & File Tampering...")
        (root / "config" / "settings.conf").write_text("debug=true\nadmin_user=attacker\n", encoding="utf-8")
        print("    • Modified config/settings.conf (privilege escalation)")
        (root / "shell.php").write_text("<?php /* simulated web shell (harmless) */ ?>\n", encoding="utf-8")
        print("    • Dropped shell.php in webroot (persistence)")
        (root / "logs" / "access.log").unlink()
        print("    • Deleted logs/access.log (defense evasion)")

        print("\n[3] Verifying Baseline Signature & Running Integrity Check...")
        data = json.loads(baseline.read_text(encoding="utf-8"))
        _, hmac_status = verify_baseline_hmac(data, demo_key)
        print(f"    • Baseline Signature : {hmac_status}")
        current, _ = scan(root, baseline, ignore_pats)
        report(*compare(data["files"], current))

        print("\n[4] Simulating Attacker Editing baseline.json Directly (Anti-Tamper Test)...")
        data["files"].pop("logs/access.log", None)
        baseline.write_text(json.dumps(data), encoding="utf-8")
        _, tamper_status = verify_baseline_hmac(json.loads(baseline.read_text(encoding="utf-8")), demo_key)
        print(f"    • [CRITICAL ALERT] {tamper_status}")
        print("=" * 76)
    return 0


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print(BANNER)

    if "--demo" in sys.argv:
        return cmd_demo(None)

    parser = argparse.ArgumentParser(description="Detect added, modified, permission-changed, and deleted files.")
    parser.add_argument("--demo", action="store_true", help="Run built-in HMAC-signed FIM attack simulation")
    sub = parser.add_subparsers(dest="command")

    for name, fn, help_txt in (
        ("baseline", cmd_baseline, "Create a SHA-256 (+ optional HMAC-SHA256) baseline of a folder"),
        ("check", cmd_check, "Verify baseline HMAC and compare a folder against its baseline"),
        ("watch", cmd_watch, "Continuously monitor a folder and alert on changes"),
    ):
        p = sub.add_parser(name, help=help_txt)
        p.add_argument("directory", nargs="?" if name != "baseline" else None, help="Target directory")
        p.add_argument("-b", "--baseline", default=DEFAULT_BASELINE, help="Baseline JSON path")
        p.add_argument("-k", "--key", help="Secret key for HMAC-SHA256 baseline signing/verification")
        p.add_argument("--ignore", help="Comma-separated glob patterns to ignore (e.g. '*.tmp,cache/*')")
        if name in ("check", "watch"):
            p.add_argument("--webhook", help="Slack/Discord/Teams webhook URL for alerts")
        if name == "check":
            p.add_argument("-o", "--output", help="Export check results to JSON")
        if name == "watch":
            p.add_argument("-i", "--interval", type=int, default=10, help="Seconds between scans (default: 10)")
        p.set_defaults(func=fn)

    p_demo = sub.add_parser("demo", help="Run a simulated attack on a temporary folder")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not getattr(args, "command", None):
        parser.print_help()
        print("\n💡 Tip: Run with --demo (or 'python fim.py demo') to see the full FIM v2.0 simulation!")
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
