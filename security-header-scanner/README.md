# 🌐 Web Security Header Scanner

A Python tool that audits a website's **HTTP security headers**, **HSTS preload eligibility**, **CORS configuration**, **TLS protocol & certificate expiry**, cookie flags, and server version leaks—then gives it a **score and letter grade (`A–F`)** and can export **JSON or styled HTML reports (`-o`)**.

## ✨ Features
- **Checks 6 Core Security Headers:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`
- **HSTS Preload Eligibility Audit:** Verifies whether `Strict-Transport-Security` meets all three **hstspreload.org** requirements (`max-age >= 31536000`, `includeSubDomains`, and `preload`)
- **Active CORS Misconfiguration Probe:** Sends a canary `Origin: https://evil-cors-probe.example.com` header to detect dangerous arbitrary Origin reflection combined with `Access-Control-Allow-Credentials: true`
- **Inline TLS Version & Certificate Expiry Inspection:** Checks the active `ssl` handshake on HTTPS targets to report negotiated TLS version (`TLSv1.3` / `TLSv1.2`), cipher suite, and days remaining until certificate expiration
- **Information Disclosure & Cookie Audit:** Flags weak CSP directives (`unsafe-inline`, `unsafe-eval`), version-leaking headers (`Server: Apache/2.4.58`, `X-Powered-By`), and missing `Secure`, `HttpOnly`, and `SameSite` cookie attributes
- **JSON & Dark-Mode HTML Report Export (`-o report.json` / `.html`) + Built-in `--demo` Server**

## 🛡️ Why These Checks Matter
| Check | Protects Against |
|---|---|
| `Strict-Transport-Security` + Preload | SSL stripping & first-visit HTTP downgrade attacks |
| `Content-Security-Policy` | Cross-site scripting (XSS) and unauthorized script injection |
| `Access-Control-Allow-Origin` (CORS) | Cross-origin credential/session theft (`OWASP A05:2021`) |
| `X-Frame-Options` | Clickjacking via hidden `<iframe>` overlays |
| `X-Content-Type-Options: nosniff` | MIME-type confusion attacks |
| `Referrer-Policy` & `Permissions-Policy` | URL token leakage & unauthorized browser API access |

## 🚀 Usage
Requires **Python 3.10+**.

```bash
# Run against the built-in local misconfigured web server (offline)
python header_scanner.py --demo

# Scan a live HTTPS target (includes TLS & HSTS Preload checks)
python header_scanner.py https://github.com

# Scan multiple targets and export a dark-mode HTML or JSON report
python header_scanner.py example.com github.com -o security_headers.html
```

| Option | Description |
|---|---|
| `urls` | One or more target URLs to audit |
| `-o`, `--output` | Export assessment report to `.json` or `.html` |
| `--demo` | Launch and scan a built-in misconfigured local test server |

## 📊 Example Output
![Web Security Header Scanner demo](demo.png)

```text
                    [ Web Security Header Scanner v2.0 ]

[*] Target URL  : https://github.com (HTTP 200)
[*] TLS Posture : TLSv1.3 | Cipher: TLS_AES_128_GCM_SHA256 | Cert: 33 days left
==============================================================================

  [1] Security Headers:
  [PASS] Strict-Transport-Security  max-age=31536000; includeSubdomains; preload
  [PASS] Content-Security-Policy    default-src 'none'; base-uri 'self'; child-src git
  [PASS] X-Frame-Options            deny
  [PASS] X-Content-Type-Options     nosniff
  [PASS] Referrer-Policy            origin-when-cross-origin, strict-origin-when-cross
  [FAIL] Permissions-Policy         missing — restricts browser features (camera, mic, ...)
  [WARN] CSP Quality                allows 'unsafe-inline'/'unsafe-eval' (-5)
  [PASS] HTTPS Transport            enabled (+10)

  [2] HSTS Preload & Active CORS Probe:
  [PASS] HSTS Preload Eligible (max-age=31536000, includeSubDomains, preload)
  [PASS] Restricted (no permissive Access-Control-Allow-Origin exposed)

  [3] Information Disclosure & Cookies:
  [INFO] Server: github.com (generic banner, no version number exposed)
  [PASS] No version-leaking headers exposed
  [PASS] Cookie '_gh_sess': Secure, HttpOnly, SameSite all set
  [WARN] Cookie '_octo': missing HttpOnly
  [PASS] Cookie 'logged_in': Secure, HttpOnly, SameSite all set

==============================================================================
  SCORE: 85/100   |   GRADE: B
==============================================================================
```

## 📐 Scoring
| Check | Points |
|---|---|
| Content-Security-Policy | +25 |
| Strict-Transport-Security | +20 |
| X-Frame-Options | +15 |
| X-Content-Type-Options, Referrer-Policy, Permissions-Policy | +10 each |
| HTTPS enabled | +10 |
| Critical CORS Reflection (`Origin` + `Allow-Credentials: true`) | −15 |
| Weak CSP / each version-leaking header | −5 each |

**Grades:** A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40

## 🧠 What I Learned
- Why simply setting `Strict-Transport-Security` with a short `max-age` isn't enough for browser preload protection (`max-age >= 31536000`, `includeSubDomains`, and `preload` are all required)
- How misconfigured CORS servers that reflect arbitrary `Origin` headers with `Access-Control-Allow-Credentials: true` allow cross-site attackers to read authenticated API responses
- Combining HTTP header auditing with `ssl.SSLSocket` inspection in a single pass

## 🔄 Version History & Changelog (v1.0 → v2.0)
- **v1.0 (Initial Release):** 6-header check, CSP `unsafe-inline` check, `Server` version leak check, and `Set-Cookie` flag inspection.
- **v2.0:**
  - Added **HSTS Preload Eligibility Audit** verifying `max-age >= 31536000`, `includeSubDomains`, and `preload` directives.
  - Added **Active CORS Misconfiguration Probe** using a canary `Origin` header to catch arbitrary origin reflection and wildcard credential leaks.
  - Added **Inline TLS Protocol & Certificate Expiry Inspection** (`TLSv1.3`/`1.2`, cipher suite, and days remaining).
  - Added **JSON & Dark-Mode HTML Assessment Report Export (`-o`)**, built-in `--demo` server mode, and the `Def Leppard` `Sonelu` ASCII banner.
