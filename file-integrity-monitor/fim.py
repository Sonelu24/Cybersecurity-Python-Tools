#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) - detect added, modified and deleted files.

Creates a SHA-256 "baseline" of a folder, then compares the folder against
it later to spot tampering - the same idea behind tools like Tripwire,
OSSEC and Wazuh.

MITRE ATT&CK: T1565.001 (Stored Data Manipulation), T1505.003 (Web Shell),
              T1070.004 (File Deletion)

Uses only the Python standard library.
"""
import argparse
import hashlib
import json
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

DEFAULT_BASELINE = "baseline.json"
CHUNK_SIZE = 65536


def hash_file(path: Path) -> str:
    """SHA-256 a file in chunks so large files don't fill up memory."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha.update(chunk)
    return sha.hexdigest()


def scan(directory: Path, exclude: Path) -> dict:
    """Return {relative_path: sha256} for every file under directory."""
    hashes = {}
    excluded = exclude.resolve()
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.resolve() != excluded:
            try:
                hashes[path.relative_to(directory).as_posix()] = hash_file(path)
            except OSError as e:
                print(f"[!] Skipped {path}: {e}", file=sys.stderr)
    return hashes


def save_baseline(directory: Path, baseline: Path) -> int:
    files = scan(directory, baseline)
    data = {
        "directory": str(directory.resolve()),
        "created": datetime.now().isoformat(timespec="seconds"),
        "algorithm": "sha256",
        "files": files,
    }
    baseline.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(files)


def load_baseline(baseline: Path) -> dict:
    return json.loads(baseline.read_text(encoding="utf-8"))


def compare(old: dict, new: dict):
    added = sorted(new.keys() - old.keys())
    deleted = sorted(old.keys() - new.keys())
    modified = sorted(k for k in old.keys() & new.keys() if old[k] != new[k])
    return added, modified, deleted


def report(added, modified, deleted) -> bool:
    """Print the changes. Returns True if anything changed."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not (added or modified or deleted):
        print(f"[{stamp}] [+] No changes detected - all files match the baseline.")
        return False
    print(f"[{stamp}] [!!] INTEGRITY CHANGES DETECTED")
    for f in added:
        print(f"     [ADDED]    {f}")
    for f in modified:
        print(f"     [MODIFIED] {f}")
    for f in deleted:
        print(f"     [DELETED]  {f}")
    print(f"     Summary: {len(added)} added, {len(modified)} modified, {len(deleted)} deleted")
    return True


def resolve_directory(arg, baseline_data: dict) -> Path:
    """Use the folder given on the command line, or the one stored in the baseline."""
    return Path(arg) if arg else Path(baseline_data["directory"])


def cmd_baseline(args) -> int:
    directory, baseline = Path(args.directory), Path(args.baseline)
    if not directory.is_dir():
        print(f"[!] Not a directory: {directory}")
        return 1
    count = save_baseline(directory, baseline)
    print(f"[+] Baseline saved to {baseline} ({count} files hashed with SHA-256)")
    return 0


def cmd_check(args) -> int:
    baseline = Path(args.baseline)
    if not baseline.exists():
        print(f"[!] Baseline not found: {baseline}. Run the 'baseline' command first.")
        return 1
    data = load_baseline(baseline)
    directory = resolve_directory(args.directory, data)
    print(f"=== Integrity check: {directory} (baseline from {data['created']}) ===")
    changed = report(*compare(data["files"], scan(directory, baseline)))
    return 2 if changed else 0


def cmd_watch(args) -> int:
    baseline = Path(args.baseline)
    if not baseline.exists():
        print(f"[!] Baseline not found: {baseline}. Run the 'baseline' command first.")
        return 1
    data = load_baseline(baseline)
    directory = resolve_directory(args.directory, data)
    print(f"=== Watching {directory} every {args.interval}s (Ctrl+C to stop) ===")

    known = data["files"]
    report(*compare(known, scan(directory, baseline)))
    try:
        while True:
            time.sleep(args.interval)
            current = scan(directory, baseline)
            changes = compare(known, current)
            if any(changes):
                report(*changes)
                known = current  # only alert once per change
    except KeyboardInterrupt:
        print("\n[+] Stopped watching.")
    return 0


def cmd_demo(_args) -> int:
    """Simulate an attack on a throwaway folder to show what the tool detects."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "webserver"
        (root / "config").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "index.html").write_text("<h1>Welcome</h1>\n")
        (root / "config" / "settings.conf").write_text("debug=false\nadmin_user=admin\n")
        (root / "logs" / "access.log").write_text("GET /index.html 200\n")
        baseline = Path(tmp) / DEFAULT_BASELINE

        print("=== File Integrity Monitor: demo ===\n")
        count = save_baseline(root, baseline)
        print(f"[1] Baseline created for a sample web server folder ({count} files)\n")

        print("[2] Simulating an attacker...")
        (root / "config" / "settings.conf").write_text("debug=true\nadmin_user=attacker\n")
        print("    - modified config/settings.conf")
        (root / "shell.php").write_text("<?php /* simulated web shell (harmless) */ ?>\n")
        print("    - dropped shell.php")
        (root / "logs" / "access.log").unlink()
        print("    - deleted logs/access.log (covering tracks)\n")

        print("[3] Running integrity check...")
        report(*compare(load_baseline(baseline)["files"], scan(root, baseline)))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect added, modified and deleted files.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("baseline", help="Hash every file in a folder and save a baseline")
    p.add_argument("directory", help="Folder to protect")
    p.add_argument("-b", "--baseline", default=DEFAULT_BASELINE, help="Baseline file (default: baseline.json)")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("check", help="Compare a folder against its baseline once")
    p.add_argument("directory", nargs="?", help="Folder to check (default: the one in the baseline)")
    p.add_argument("-b", "--baseline", default=DEFAULT_BASELINE, help="Baseline file (default: baseline.json)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("watch", help="Keep checking a folder and alert on changes")
    p.add_argument("directory", nargs="?", help="Folder to watch (default: the one in the baseline)")
    p.add_argument("-b", "--baseline", default=DEFAULT_BASELINE, help="Baseline file (default: baseline.json)")
    p.add_argument("-i", "--interval", type=int, default=10, help="Seconds between checks (default: 10)")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("demo", help="Run a simulated attack on a temporary folder")
    p.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
