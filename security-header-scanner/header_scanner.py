#!/usr/bin/env python3
"""
Web Security Header Scanner - grade a website's HTTP security headers.

Checks for protective headers (HSTS, CSP, X-Frame-Options, ...), flags
headers that leak the server's tech stack, inspects cookie flags, and
assigns a score and letter grade.

It sends a single normal GET request - the same as visiting the page
in a browser. Uses only the Python standard library.
"""
import argparse
import sys
import urllib.error
import urllib.request

# header name -> (points, why it matters)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (20, "forces HTTPS, protects against SSL stripping"),
    "Content-Security-Policy": (25, "mitigates XSS and data injection"),
    "X-Frame-Options": (15, "prevents clickjacking"),
    "X-Content-Type-Options": (10, "stops MIME-type sniffing"),
    "Referrer-Policy": (10, "limits referrer data leakage"),
    "Permissions-Policy": (10, "restricts browser features (camera, mic, ...)"),
}
HTTPS_POINTS = 10
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
PENALTY = 5


def fetch(url: str):
    """Return (final_url, status_code, headers). HTTP errors still return headers."""
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityHeaderScanner/1.0"})
    try:
        resp = urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as e:
        resp = e  # 4xx/5xx responses still carry headers worth checking
    with resp:
        return resp.geturl(), resp.getcode(), resp.headers


def grade(score: int) -> str:
    for cutoff, letter in [(90, "A"), (75, "B"), (60, "C"), (40, "D")]:
        if score >= cutoff:
            return letter
    return "F"


def check_cookies(set_cookie_values):
    """Return a list of (cookie_name, [missing flags])."""
    results = []
    for raw in set_cookie_values:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = [p.lower() for p in parts[1:]]
        missing = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            missing.append("SameSite")
        results.append((name, missing))
    return results


def scan(url: str) -> int:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        final_url, status, headers = fetch(url)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"[!] Could not connect to {url}: {e}")
        return 1

    score = 0
    print(f"\n=== Security Header Scan: {final_url} (HTTP {status}) ===\n")

    print("  Security headers:")
    for name, (points, why) in SECURITY_HEADERS.items():
        value = headers.get(name)
        if value:
            score += points
            print(f"  [PASS] {name:<26} {value[:55]}")
        else:
            print(f"  [FAIL] {name:<26} missing - {why}")

    csp = headers.get("Content-Security-Policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        score -= PENALTY
        print(f"  [WARN] {'CSP quality':<26} allows 'unsafe-inline'/'unsafe-eval' (weakens XSS protection)")

    if final_url.startswith("https://"):
        score += HTTPS_POINTS
        print(f"  [PASS] {'HTTPS':<26} enabled")
    else:
        print(f"  [FAIL] {'HTTPS':<26} site is served over plain HTTP")

    print("\n  Information disclosure:")
    leaks = 0
    for h in LEAKY_HEADERS:
        value = headers.get(h)
        if not value:
            continue
        # A bare "Server: nginx" is common; a version number (nginx/1.18.0) helps attackers find CVEs
        if h == "Server" and not any(ch.isdigit() for ch in value):
            print(f"  [INFO] {h}: {value}  (no version exposed)")
            continue
        leaks += 1
        print(f"  [WARN] {h}: {value}  (reveals tech stack/version)")
    if not leaks:
        print("  [PASS] No version-leaking headers found")
    score -= PENALTY * leaks

    print("\n  Cookies:")
    cookies = check_cookies(headers.get_all("Set-Cookie") or [])
    if not cookies:
        print("  [INFO] No cookies set on this page")
    for name, missing in cookies:
        if missing:
            print(f"  [WARN] {name}: missing {', '.join(missing)}")
        else:
            print(f"  [PASS] {name}: Secure, HttpOnly and SameSite all set")

    score = max(0, min(100, score))
    print(f"\n  SCORE: {score}/100   GRADE: {grade(score)}\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Grade a website's HTTP security headers.")
    parser.add_argument("urls", nargs="+", help="One or more URLs, e.g. https://example.com")
    args = parser.parse_args()

    exit_code = 0
    for url in args.urls:
        exit_code |= scan(url)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
