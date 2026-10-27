# 📧 Phishing Email Analyzer

A Python tool that triages a suspicious email (`.eml` file) the way a **SOC analyst** would. It checks sender spoofing using **Public Suffix List (PSL) registered-domain parsing**, SPF/DKIM/DMARC authentication, deceptive links, **HTML credential-harvesting traps** (`<form>`, `<iframe>`, `javascript:`/`data:` URIs, `1x1` tracking pixels), dangerous attachments, and social-engineering language—then gives a **risk score, verdict, and automated IOC export (`.json` / `.csv`)**.

## ✨ Features
- **Sender & PSL Registered-Domain Checks:** Brand impersonation in the display name, plus `Reply-To` and `Return-Path` domain comparison with full multi-part TLD support (`.co.uk`, `.com.ro`, `.org.uk`, `.gov.au`, `.co.jp`, etc.)
- **Email Authentication:** Parses `SPF`, `DKIM`, and `DMARC` results from `Authentication-Results` and `Received-SPF` headers
- **Link & HTML Phishing Heuristics:**
  - Deceptive links (the anchor text shows `paypal.co.uk` while `href` points to `attacker.co.uk`)
  - Raw IP addresses, lookalike brand domains, punycode (`xn--`), and URL shorteners
  - **Embedded HTML `<form>` credential harvesters**, hidden `<iframe>` traps, `data:`/`javascript:` URI links, and **`1x1` / hidden tracking pixel beacons**
- **Attachment Triage:** Flags dangerous file extensions and **double extensions** (`Invoice.pdf.exe`) and computes SHA-256 hashes without ever opening or executing files
- **Automated IOC Export (`-o`) & Optional Threat-Intel (`--ti-lookup` / `--vt-key`):** Exports all origin IPs, domains, raw/defanged URLs, and attachment SHA-256 hashes to JSON or CSV, and optionally checks URLhaus / VirusTotal v3
- **Safe by Design:** All URLs are printed **defanged** (`hxxp://evil[.]com`), built-in `--demo` included, and zero external dependencies

## 🎯 MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Phishing for Information: Spearphishing Link (Credential Harvesting) | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) |

## 🚀 Usage
Requires **Python 3.10+**.

```bash
# Try it with the built-in sample phishing email
python phishing_analyzer.py --demo

# Analyze a real .eml file and export extracted IOCs to JSON or CSV
python phishing_analyzer.py suspicious.eml -o iocs.json
python phishing_analyzer.py suspicious.eml -o iocs.csv

# Enable live URLhaus / VirusTotal threat-intelligence lookups
python phishing_analyzer.py suspicious.eml --ti-lookup --vt-key YOUR_VT_API_KEY
```

| Option | Description |
|---|---|
| `emlfile` | Path to a `.eml` file to triage |
| `-o`, `--output` | Export extracted IOCs (IPs, domains, URLs, SHA-256) to `.json` or `.csv` |
| `--ti-lookup` | Query URLhaus threat intelligence for extracted URLs |
| `--vt-key KEY` | VirusTotal v3 API key (or `VT_API_KEY` env var) for attachment hash lookups |
| `--demo` | Analyze the built-in sample phishing email |

## 📊 Example Output
![Phishing Email Analyzer demo](demo.png)

```text
                       [ Phishing Email Analyzer v2.0 ]

[*] Target Email : built-in demo email
  From           : PayPal Security UK <service@login.paypal.paypa1-security.co.uk>  (Registered: paypa1-security.co.uk)
  Reply-To       : billing-support@account-help.co.uk  (Registered: account-help.co.uk)
  Return-Path    : <bounce@mailer.example.net>
  Subject        : URGENT: Your account has been suspended
  Origin IP(s)   : 203.0.113.66
============================================================================

  Authentication (SPF / DKIM / DMARC):
  [FAIL] SPF    fail  (+15)
  [FAIL] DKIM   none  (+5)
  [FAIL] DMARC  fail  (+20)

  Sender & PSL Registered-Domain Checks:
  [FAIL] Display name 'PayPal Security UK' impersonates Paypal but registered sender domain is paypa1-security.co.uk  (+20)
  [FAIL] Reply-To registered domain (account-help.co.uk) differs from From (paypa1-security.co.uk)  (+15)
  [WARN] Return-Path registered domain (example.net) differs from From (paypa1-security.co.uk)  (+10)

  Links & HTML Heuristics (4 URLs):
  [FAIL] Deceptive link: shows 'hxxps://www[.]paypal[.]co[.]uk/signin' (paypal.co.uk) but goes to hxxp://paypal-verify[.]attacker[.]co[.]uk/signin (attacker.co.uk)  (+25)
  [FAIL] Lookalike Paypal domain (attacker.co.uk): hxxp://paypal-verify[.]attacker[.]co[.]uk/signin  (+20)
  [FAIL] Link points to a raw IP address: hxxp://198[.]51[.]100[.]42/paypal/login[.]php  (+20)
  [FAIL] Embedded HTML <form> credential harvester -> hxxp://198[.]51[.]100[.]42/harvest[.]php  (+25)
  [WARN] 1x1 / hidden tracking pixel beacon -> hxxp://203[.]0[.]113[.]66/pixel[.]gif  (+10)

  Attachments (1 found):
  [FAIL] Double extension (disguised executable): Invoice_Oct2026.pdf.exe  (+35)
  [INFO]   SHA-256: b0c18130090d636fd371d6e6f7d9f312c08d6df4584625f57860292fbe7f12fd

  Social Engineering:
  [WARN] Pressure / urgency language: urgent, suspended, verify your account, within 24 hours, unusual activity  (+20)

============================================================================
  RISK SCORE: 100/100   |   VERDICT: PHISHING (High Confidence — Block & Quarantine)
============================================================================
```

## 📐 Scoring
| Red flag | Points |
|---|---|
| Double-extension attachment (`Invoice.pdf.exe`) | 35 |
| Deceptive link text, embedded `<form>` harvester, dangerous attachment | 25 each |
| Brand impersonation, raw-IP link, lookalike domain, hidden `<iframe>`, `javascript:`/`data:` URI | 20 each |
| DMARC fail | 20 |
| SPF fail, Reply-To mismatch, punycode domain | 15 each |
| DKIM fail, Return-Path mismatch, URL shortener, `1x1` tracking pixel | 10 each |
| Urgency language | 5 per phrase (max 20) |

**Verdict:** 0–29 LIKELY CLEAN · 30–59 SUSPICIOUS · 60+ PHISHING

## 🧠 What I Learned
- Why naive `split(".")[-2:]` domain extraction fails on multi-label public suffixes like `.co.uk` or `.com.ro` (treating `co.uk` as the domain and letting `paypal.attacker.co.uk` match `paypal.co.uk`)
- How modern phishing kits embed `<form action="...">` credential harvesters and `1x1` tracking pixels directly inside HTML emails
- Structuring automated IOC extraction (`.json` / `.csv`) so email triage feeds directly into SIEM and SOAR playbooks

## 🔄 Version History & Changelog (v1.0 → v2.0)
- **v1.0 (Initial Release):** Basic `.eml` header parsing (`From`, `Reply-To`, `Return-Path`), `SPF`/`DKIM`/`DMARC` extraction, `<a href>` deceptive link checks, attachment SHA-256 hashing, and urgency keyword scoring.
- **v2.0:**
  - Added **Public Suffix List (PSL) Registered-Domain Engine** supporting multi-part TLDs (`.co.uk`, `.com.ro`, `.org.uk`, `.gov.au`, `.co.jp`, etc.) to prevent false negatives on international domains.
  - Added **HTML Phishing & Evasion Heuristics** to detect embedded `<form>` credential harvesters (`MITRE T1598.003`), hidden `<iframe>` traps, `javascript:`/`data:` URIs, and `1x1` tracking pixel beacons.
  - Added **Automated IOC Extraction & Export (`-o iocs.json` / `.csv`)** for origin IPs, domains, raw/defanged URLs, and attachment hashes.
  - Added **Optional Threat-Intelligence Lookups (`--ti-lookup` / `--vt-key`)** for URLhaus and VirusTotal v3, plus the `Def Leppard` `Sonelu` ASCII banner.
