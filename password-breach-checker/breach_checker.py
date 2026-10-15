#!/usr/bin/env python3
"""
Password Breach Checker - safely check if a password appears in known data breaches.

Uses the Have I Been Pwned "Pwned Passwords" API with k-anonymity:
only the first 5 characters of the password's SHA-1 hash are sent,
so the password (and its full hash) never leaves your machine.
Also estimates password strength based on entropy.

Uses only the Python standard library - no installs required.
Made By Sonelu
"""
import getpass
import hashlib
import math
import string
import sys
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/{}"


def pwned_count(password: str) -> int:
    """Return how many times the password appears in breaches (0 if never)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    request = urllib.request.Request(
        API_URL.format(prefix),
        headers={"User-Agent": "Password-Breach-Checker", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(request, timeout=10) as resp:
        body = resp.read().decode("utf-8")
    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def strength(password: str) -> tuple[float, str]:
    """Estimate entropy in bits and return a strength label."""
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
    entropy = len(password) * math.log2(pool) if pool else 0.0

    if entropy < 40:
        label = "WEAK"
    elif entropy < 60:
        label = "MODERATE"
    elif entropy < 80:
        label = "STRONG"
    else:
        label = "VERY STRONG"
    return entropy, label


def main() -> int:
    print("=== Password Breach Checker (k-anonymity, your password is never sent) ===")
    password = getpass.getpass("Enter password to check (input hidden): ")
    if not password:
        print("[!] No password entered.")
        return 1

    entropy, label = strength(password)
    print(f"\nLength            : {len(password)} characters")
    print(f"Estimated entropy : {entropy:.1f} bits ({label})")

    try:
        count = pwned_count(password)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[!] Could not reach the HIBP API: {e}")
        return 1

    if count:
        print(f"\n[!!] PWNED: this password was seen {count:,} times in data breaches.")
        print("     Do NOT use it. Pick a new, unique password (a password manager helps).")
    else:
        print("\n[+] Good news: not found in any known breach.")
        if label in ("WEAK", "MODERATE"):
            print("    But it's still not very strong - consider a longer passphrase.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
