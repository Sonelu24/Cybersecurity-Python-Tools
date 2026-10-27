#!/usr/bin/env python3
"""
Password Breach & Entropy Auditor v2.0 (Red Team — Credential Hygiene & Auditing)

Privately audits passwords against 800M+ breached credentials via the Have I Been Pwned
k-anonymity API (only the 5-char SHA-1 prefix ever leaves your machine), combined with
an offline pattern & weakness analyzer (keyboard walks, leetspeak root words, years/seasons,
repeated runs) and a cryptographic CSRNG password/passphrase generator (--generate).

MITRE ATT&CK: T1110.004 (Credential Stuffing), T1552 (Unsecured Credentials)
OWASP Top 10: A07:2021 (Identification and Authentication Failures)

Uses only the Python standard library.
"""

import argparse
import csv
import getpass
import hashlib
import json
import math
import re
import secrets
import string
import sys
import urllib.error
import urllib.request
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
                 [ Password Breach & Entropy Auditor v2.0 ]
"""

API_URL = "https://api.pwnedpasswords.com/range/{}"
_PREFIX_CACHE: dict[str, dict[str, int]] = {}

KEYBOARD_WALKS = ("qwerty", "asdfgh", "zxcvbn", "123456", "654321", "qazwsx", "1q2w3e", "098765")
COMMON_ROOTS = (
    "password", "passwd", "admin", "welcome", "letmein", "monkey", "dragon",
    "shadow", "master", "qwerty", "company", "service", "football", "iloveyou",
)
SEASONS_RE = re.compile(r"(?:spring|summer|autumn|winter|fall)", re.I)
YEAR_RE = re.compile(r"(?:19[7-9]\d|20[0-2]\d)")
REPEAT_RE = re.compile(r"(.)\1{2,}")

LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
    "3": "e", "$": "s", "5": "s", "7": "t", "+": "t",
})

PASSPHRASE_WORDS = [
    "amber", "anchor", "arctic", "atlas", "badger", "basalt", "beacon", "bison",
    "breeze", "canyon", "carbon", "cedar", "cipher", "cobalt", "comet", "copper",
    "coral", "cosmos", "crater", "crimson", "crystal", "dagger", "delta", "dynamo",
    "eclipse", "ember", "emerald", "enigma", "falcon", "fjord", "flint", "forest",
    "fossil", "galaxy", "garnet", "glacier", "granite", "harbor", "helios", "horizon",
    "indigo", "iron", "jasper", "jungle", "krypton", "lagoon", "lantern", "legend",
    "magnet", "marble", "matrix", "meadow", "meteor", "mirage", "monolith", "nebula",
    "nickel", "nimbus", "obsidian", "onyx", "orbit", "osprey", "panther", "paradox",
    "pegasus", "phantom", "phoenix", "photon", "pioneer", "plasma", "prism", "pulsar",
    "quartz", "quasar", "raptor", "redwood", "ripple", "saffron", "sapphire", "Sektor",
    "seismic", "sentinel", "shadow", "sierra", "silver", "solstice", "spectrum", "sphinx",
    "summit", "tempest", "thunder", "titanium", "topaz", "tundra", "valkyrie", "vector",
    "velvet", "vertex", "Viper", "vortex", "voyager", "zenith", "zephyr", "zircon",
]


def mask_password(pw: str) -> str:
    """Partially masks a password for safe terminal & report display."""
    if len(pw) <= 4:
        return "*" * len(pw)
    return f"{pw[:2]}{'*' * min(len(pw) - 4, 6)}{pw[-2:]}"


def pwned_count(password: str) -> tuple[int, str]:
    """Returns (breach_count, sha1_prefix) via HIBP k-anonymity with prefix caching."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    if prefix not in _PREFIX_CACHE:
        request = urllib.request.Request(
            API_URL.format(prefix),
            headers={"User-Agent": "Password-Breach-Checker-v2.0", "Add-Padding": "true"},
        )
        with urllib.request.urlopen(request, timeout=10) as resp:
            body = resp.read().decode("utf-8")
        bucket = {}
        for line in body.splitlines():
            if ":" in line:
                h_suf, cnt = line.split(":", 1)
                try:
                    bucket[h_suf.strip()] = int(cnt.strip())
                except ValueError:
                    pass
        _PREFIX_CACHE[prefix] = bucket
    return _PREFIX_CACHE[prefix].get(suffix, 0), prefix


def detect_weak_patterns(password: str) -> list[str]:
    """Identifies human-predictable patterns (keyboard walks, leetspeak roots, years, seasons, repeats)."""
    warnings = []
    lower = password.lower()
    unleeted = lower.translate(LEET_MAP)

    for walk in KEYBOARD_WALKS:
        if walk in lower:
            warnings.append(f"Keyboard walk ('{walk}')")
            break

    for root in COMMON_ROOTS:
        if root in lower:
            warnings.append(f"Dictionary root ('{root}')")
            break
        if root in unleeted:
            warnings.append(f"Leetspeak substitution of '{root}'")
            break

    if m := SEASONS_RE.search(password):
        warnings.append(f"Predictable season ('{m.group(0)}')")
    if m := YEAR_RE.search(password):
        warnings.append(f"Predictable year ('{m.group(0)}')")
    if REPEAT_RE.search(password):
        warnings.append("Repeated character sequence")

    return warnings


def analyze_password(password: str) -> dict:
    """Computes raw & pattern-adjusted entropy, weak patterns, and live HIBP breach count."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c not in string.printable for c in password):
        pool += 100

    raw_entropy = len(password) * math.log2(pool) if pool else 0.0
    patterns = detect_weak_patterns(password)
    effective_entropy = max(10.0, raw_entropy - (14.0 * len(patterns))) if password else 0.0

    try:
        breaches, prefix = pwned_count(password)
    except (urllib.error.URLError, TimeoutError):
        breaches, prefix = -1, "OFFLINE"

    if breaches > 0 or effective_entropy < 42:
        label = "CRITICAL / COMPROMISED" if breaches > 0 else "WEAK"
    elif effective_entropy < 62:
        label = "MODERATE"
    elif effective_entropy < 82:
        label = "STRONG"
    else:
        label = "VERY STRONG"

    return {
        "masked": mask_password(password),
        "length": len(password),
        "sha1_prefix": prefix,
        "raw_entropy_bits": round(raw_entropy, 1),
        "effective_entropy_bits": round(effective_entropy, 1),
        "strength": label,
        "breach_count": breaches,
        "weak_patterns": patterns,
    }


def generate_credentials() -> tuple[str, str]:
    """Generates a 20-char CSRNG password and a 5-word Diceware passphrase using secrets."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(20))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*-_=+" for c in pw)
        ):
            break
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(5)]
    passphrase = "-".join(words) + f"-{secrets.randbelow(90) + 10}!"
    return pw, passphrase


def export_audit(results: list[dict], path: str) -> None:
    out = Path(path)
    if out.suffix.lower() == ".csv":
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "masked", "length", "sha1_prefix", "raw_entropy_bits",
                    "effective_entropy_bits", "strength", "breach_count", "weak_patterns",
                ],
            )
            writer.writeheader()
            for r in results:
                row = dict(r)
                row["weak_patterns"] = "; ".join(r["weak_patterns"])
                writer.writerow(row)
    else:
        out.write_text(json.dumps({"audited_count": len(results), "results": results}, indent=2), encoding="utf-8")
    print(f"[+] Exported credential audit report to {path}")


def print_audit_table(results: list[dict], source_label: str) -> None:
    pwned_total = sum(1 for r in results if r["breach_count"] > 0)
    print(f"[*] Audit Source    : {source_label}")
    print(f"[*] Privacy Mode    : HIBP k-Anonymity (5-char SHA-1 prefix + response padding)")
    print(f"[*] Summary         : {len(results)} audited -> {pwned_total} breached, {len(results) - pwned_total} unbreached")
    print("=" * 80)

    for r in results:
        b_str = (
            f"PWNED ({r['breach_count']:,} breaches)"
            if r["breach_count"] > 0
            else ("CLEAN (0 breaches)" if r["breach_count"] == 0 else "API Offline")
        )
        print(
            f"\n  • {r['masked']:<12} | Len: {r['length']:>2} | Prefix: {r['sha1_prefix']} | "
            f"Eff. Entropy: {r['effective_entropy_bits']:>5.1f} bits | {b_str}"
        )
        print(f"      ├─ Verdict  : {r['strength']}")
        if r["weak_patterns"]:
            print(f"      └─ Patterns : {', '.join(r['weak_patterns'])}")
        else:
            print("      └─ Patterns : None (no keyboard walks, leetspeak roots, or years detected)")

    print("\n" + "=" * 80)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Privately check passwords against 800M+ breaches via k-anonymity & score pattern entropy."
    )
    parser.add_argument("-p", "--password", help="Single password to check")
    parser.add_argument("-f", "--file", help="Batch file of passwords to audit (one per line)")
    parser.add_argument("--generate", action="store_true", help="Generate cryptographic CSRNG password & passphrase")
    parser.add_argument("-o", "--output", help="Export audit results to .json or .csv")
    parser.add_argument("--demo", action="store_true", help="Run built-in credential audit & generator demo")
    args = parser.parse_args()

    print(BANNER)

    if args.generate:
        pw, phrase = generate_credentials()
        print("[🔐 Cryptographic Credential Generator (Python secrets CSRNG)]")
        print(f"  • Random 20-char Password : {pw}  (~131.1 bits entropy)")
        print(f"  • 5-Word Passphrase       : {phrase}  (~72.5 bits entropy)")
        print("=" * 80)
        if not (args.demo or args.password or args.file):
            return 0

    if args.demo:
        gen_pw, _ = generate_credentials()
        candidates = ["Password123!", "P@ssw0rd2024", "qwerty123456", gen_pw]
        source_label = "Built-in Sample Credential Set (4 candidates)"
    elif args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"[!] File not found: {path}", file=sys.stderr)
            return 1
        candidates = [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]
        source_label = str(path)
    elif args.password:
        candidates = [args.password]
        source_label = "CLI Argument (-p)"
    else:
        pw = getpass.getpass("Enter password to check (input hidden): ")
        if not pw:
            print("[!] No password entered.")
            return 1
        candidates = [pw]
        source_label = "Interactive Hidden Prompt"

    results = [analyze_password(c) for c in candidates]
    print_audit_table(results, source_label)

    if args.output:
        export_audit(results, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
