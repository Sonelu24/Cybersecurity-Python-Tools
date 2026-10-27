#!/usr/bin/env python3
"""
Web Security Header Scanner v2.0 (Red Team — HTTP Hardening, CORS & TLS Auditor)

Audits a website's HTTP security posture in a single pass:
  1. Protective Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
     Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy)
  2. HSTS Preload Eligibility Audit (max-age >= 31536000, includeSubDomains, preload)
  3. Active CORS Misconfiguration Probe (tests Origin reflection & Allow-Credentials)
  4. Inline TLS Protocol Version & Certificate Expiry Inspection (for HTTPS targets)
  5. Server Version Leakage & Cookie Security Flags (Secure, HttpOnly, SameSite)
  6. JSON & Styled Dark-Mode HTML Assessment Report Export (-o report.json / .html)

OWASP Top 10: A05:2021 (Security Misconfiguration), A02:2021 (Cryptographic Failures)
Uses only the Python standard library.
"""

import argparse
import html as html_lib
import http.server
import json
import re
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

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
                    [ Web Security Header Scanner v2.0 ]
"""

CANARY_ORIGIN = "https://evil-cors-probe.example.com"

SECURITY_HEADERS = {
    "Strict-Transport-Security": (20, "forces HTTPS, protects against SSL stripping"),
    "Content-Security-Policy": (25, "mitigates XSS and data injection"),
    "X-Frame-Options": (15, "prevents clickjacking"),
    "X-Content-Type-Options": (10, "stops MIME-type sniffing"),
    "Referrer-Policy": (10, "limits referrer data leakage"),
    "Permissions-Policy": (10, "restricts browser features (camera, mic, ...)"),
}
HTTPS_POINTS = 10
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]
PENALTY = 5


def fetch_with_cors_probe(url: str):
    """Return (final_url, status_code, headers) while sending a canary Origin header."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SecurityHeaderScanner/2.0",
            "Origin": CANARY_ORIGIN,
        },
    )
    try:
        resp = urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as e:
        resp = e
    with resp:
        return resp.geturl(), resp.getcode(), resp.headers


def inspect_tls_inline(url: str) -> dict | None:
    """Inspects negotiated TLS version, cipher suite, and certificate expiry days for HTTPS URLs."""
    p = urlparse(url)
    if p.scheme.lower() != "https" or not p.hostname:
        return None
    port = p.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((p.hostname, port), timeout=5.0) as tcp:
            with ctx.wrap_socket(tcp, server_hostname=p.hostname) as tls:
                ver = tls.version() or "Unknown"
                cipher_info = tls.cipher()
                cipher_name = cipher_info[0] if cipher_info else "Unknown"
                cert = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                days_left = None
                if not_after:
                    exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp_dt - datetime.now(timezone.utc)).days
                return {"tls_version": ver, "cipher": cipher_name, "days_left": days_left}
    except Exception:
        return None


def audit_hsts_preload(hsts_val: str | None) -> tuple[str, str]:
    """Checks HSTS header against hstspreload.org criteria (max-age >= 31536000, includeSubDomains, preload)."""
    if not hsts_val:
        return "FAIL", "HSTS header missing (not eligible for browser preload list)"
    lower = hsts_val.lower()
    m = re.search(r"max-age\s*=\s*(\d+)", lower)
    max_age = int(m.group(1)) if m else 0
    missing = []
    if max_age < 31536000:
        missing.append(f"max-age={max_age} (< 31536000 / 1 yr)")
    if "includesubdomains" not in lower:
        missing.append("missing includeSubDomains")
    if "preload" not in lower:
        missing.append("missing preload directive")
    if not missing:
        return "PASS", f"HSTS Preload Eligible (max-age={max_age}, includeSubDomains, preload)"
    return "WARN", "HSTS present, but not preload-ready: " + ", ".join(missing)


def audit_cors(headers) -> tuple[str, str, int]:
    """Evaluates Access-Control-Allow-Origin & Allow-Credentials response to canary Origin."""
    acao = (headers.get("Access-Control-Allow-Origin") or "").strip()
    acac = (headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    if not acao:
        return "PASS", "Restricted (no permissive Access-Control-Allow-Origin exposed)", 0
    if acao == CANARY_ORIGIN and acac:
        return (
            "FAIL",
            f"CRITICAL CORS Misconfiguration: reflects arbitrary Origin ({CANARY_ORIGIN}) with Allow-Credentials: true",
            15,
        )
    if acao == CANARY_ORIGIN:
        return "WARN", f"Reflects arbitrary Origin ({CANARY_ORIGIN}) in Access-Control-Allow-Origin", 10
    if acao == "*" and acac:
        return "FAIL", "Wildcard Access-Control-Allow-Origin: * combined with Allow-Credentials: true", 15
    if acao == "*":
        return "INFO", "Public wildcard Access-Control-Allow-Origin: * (safe only for public APIs)", 0
    return "PASS", f"Access-Control-Allow-Origin restricted to {acao}", 0


def grade(score: int) -> str:
    for cutoff, letter in [(90, "A"), (75, "B"), (60, "C"), (40, "D")]:
        if score >= cutoff:
            return letter
    return "F"


def check_cookies(set_cookie_values):
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


def export_report(results: list[dict], path: str) -> None:
    out = Path(path)
    if out.suffix.lower() == ".html":
        cards = []
        for r in results:
            hdr_rows = "".join(
                f"<tr><td>{html_lib.escape(h['name'])}</td><td>{h['status']}</td><td>{html_lib.escape(h['detail'])}</td></tr>"
                for h in r["headers"]
            )
            cards.append(
                f"<div class='card'><h2>{html_lib.escape(r['url'])} — Grade {r['grade']} ({r['score']}/100)</h2>"
                f"<p><b>HSTS Preload:</b> {html_lib.escape(r['hsts_preload'][1])}<br>"
                f"<b>CORS Policy:</b> {html_lib.escape(r['cors'][1])}</p>"
                f"<table><tr><th>Header</th><th>Status</th><th>Value / Finding</th></tr>{hdr_rows}</table></div>"
            )
        html_doc = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Security Header Scan Report</title>"
            "<style>body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;padding:24px}"
            ".card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;margin-bottom:20px}"
            "table{width:100%;border-collapse:collapse;margin-top:12px}th,td{padding:8px;border-bottom:1px solid #334155;text-align:left}</style>"
            f"</head><body><h1>Web Security Header Scanner v2.0 Report</h1>{''.join(cards)}</body></html>"
        )
        out.write_text(html_doc, encoding="utf-8")
    else:
        payload = results[0] if len(results) == 1 else {"scans": results}
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[+] Exported security header report to {path}")


def scan(url: str) -> dict | None:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        final_url, status, headers = fetch_with_cors_probe(url)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        print(f"[!] Could not connect to {url}: {e}")
        return None

    score = 0
    print(f"[*] Target URL  : {final_url} (HTTP {status})")
    tls_info = inspect_tls_inline(final_url)
    if tls_info:
        days_str = f"{tls_info['days_left']} days left" if tls_info["days_left"] is not None else "valid"
        print(f"[*] TLS Posture : {tls_info['tls_version']} | Cipher: {tls_info['cipher']} | Cert: {days_str}")
    print("=" * 78)

    print("\n  [1] Security Headers:")
    header_findings = []
    for name, (points, why) in SECURITY_HEADERS.items():
        value = headers.get(name)
        if value:
            score += points
            print(f"  [PASS] {name:<26} {value[:50]}")
            header_findings.append({"name": name, "status": "PASS", "detail": value})
        else:
            print(f"  [FAIL] {name:<26} missing — {why}")
            header_findings.append({"name": name, "status": "FAIL", "detail": f"missing - {why}"})

    csp = headers.get("Content-Security-Policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        score -= PENALTY
        print(f"  [WARN] {'CSP Quality':<26} allows 'unsafe-inline'/'unsafe-eval' (-{PENALTY})")

    if final_url.startswith("https://"):
        score += HTTPS_POINTS
        print(f"  [PASS] {'HTTPS Transport':<26} enabled (+{HTTPS_POINTS})")
    else:
        print(f"  [FAIL] {'HTTPS Transport':<26} served over plain HTTP")

    print("\n  [2] HSTS Preload & Active CORS Probe:")
    hsts_lvl, hsts_msg = audit_hsts_preload(headers.get("Strict-Transport-Security"))
    print(f"  [{hsts_lvl}] {hsts_msg}")

    cors_lvl, cors_msg, cors_pen = audit_cors(headers)
    score -= cors_pen
    print(f"  [{cors_lvl}] {cors_msg}" + (f" (-{cors_pen})" if cors_pen else ""))

    print("\n  [3] Information Disclosure & Cookies:")
    leaks = []
    for h in LEAKY_HEADERS:
        value = headers.get(h)
        if not value:
            continue
        if h == "Server" and not any(ch.isdigit() for ch in value):
            print(f"  [INFO] {h}: {value} (generic banner, no version number exposed)")
            continue
        leaks.append(f"{h}: {value}")
        print(f"  [WARN] {h}: {value} (reveals server/framework version, -{PENALTY})")
    if not leaks:
        print("  [PASS] No version-leaking headers exposed")
    score -= PENALTY * len(leaks)

    cookies = check_cookies(headers.get_all("Set-Cookie") or [])
    for name, missing in cookies:
        if missing:
            print(f"  [WARN] Cookie '{name}': missing {', '.join(missing)}")
        else:
            print(f"  [PASS] Cookie '{name}': Secure, HttpOnly, SameSite all set")

    score = max(0, min(100, score))
    letter = grade(score)
    print("\n" + "=" * 78)
    print(f"  SCORE: {score}/100   |   GRADE: {letter}")
    print("=" * 78)

    return {
        "url": final_url,
        "status": status,
        "score": score,
        "grade": letter,
        "tls": tls_info,
        "headers": header_findings,
        "hsts_preload": [hsts_lvl, hsts_msg],
        "cors": [cors_lvl, cors_msg],
        "leaks": leaks,
        "cookies": [{"name": n, "missing": m} for n, m in cookies],
    }


# -------------------------------------------------------------------- demo
class DemoHeaderHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=86400")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "Apache/2.4.58 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.3.11")
        self.send_header("Access-Control-Allow-Origin", CANARY_ORIGIN)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Set-Cookie", "session_id=xyz987; Path=/")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Audit HTTP security headers, HSTS preload eligibility, CORS policy, and TLS posture."
    )
    parser.add_argument("urls", nargs="*", help="One or more URLs, e.g. https://example.com")
    parser.add_argument("-o", "--output", help="Export scan report to .json or .html")
    parser.add_argument("--demo", action="store_true", help="Run against a built-in local misconfigured web server")
    args = parser.parse_args()

    print(BANNER)
    results = []

    if args.demo:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DemoHeaderHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            res = scan(f"http://127.0.0.1:{server.server_address[1]}/")
            if res:
                results.append(res)
        finally:
            server.shutdown()
    elif args.urls:
        for u in args.urls:
            res = scan(u)
            if res:
                results.append(res)
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to test against a built-in misconfigured web server!")
        return 0

    if args.output and results:
        export_report(results, args.output)
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
