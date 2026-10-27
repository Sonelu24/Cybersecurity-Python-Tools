# 👋 Hello, it's Sonelu!

I want to share with you some of the Python scripts I made. Feel free to contact me if you have any questions!

## 📂 Projects

| Project | Description |
|---|---|
| [🔍 SSH & Auth Log Analyzer](./ssh-log-analyzer) | Detects SSH & Windows (`4625`/`4624`) brute-force bursts, password spraying and post-attack account compromise |
| [🔐 Password Breach Checker](./password-breach-checker) | Checks whether a password has been leaked in data breaches, privately, using k-anonymity |
| [🌐 Web Security Header Scanner](./security-header-scanner) | Grades a website's HTTP security headers, cookie flags and information leaks (A–F) |
| [🗂️ File Integrity Monitor](./file-integrity-monitor) | Detects file & permission tampering using `HMAC-SHA256` signed baselines, ignore rules and webhook alerts |
| [📧 Phishing Email Analyzer](./phishing-email-analyzer) | Triages `.eml` emails with PSL domain checks, SPF/DKIM/DMARC, HTML `<form>`/pixel traps, attachment hashing and IOC export |
| [🗺️ Website Crawler & Site Mapper](./site-mapper) | Crawls a website to build a visual page tree and map forms, sensitive paths, files and broken links |
| [🕵️‍♂️ PCAP Network Packet Threat Hunter](./pcap-threat-hunter) | Parses `.pcap` & `.pcapng` (IPv4/IPv6) captures with TCP stream reassembly to detect SYN scans, ARP spoofing, DNS/ICMP tunneling, C2 beacons and cleartext credentials |
| [📦 CVE Dependency & Supply-Chain Scanner](./cve-dependency-scanner) | Audits `requirements.txt` and `package.json` against the live OSV.dev database for known CVEs, severities and fix versions |
| [🧬 Static Malware & File Triage Scanner](./malware-triage-scanner) | Inspects files & folders via magic bytes, PE section table (`RWX`/packer) entropy, API indicators, PDB/Registry IOCs and auto-YARA generation |
| [🔎 IOC Extractor & Defanger](./ioc-extractor) | Extracts 11 classes of IOCs (IPs, URLs, hashes, Registry keys, file paths, BTC/XMR wallets, CVEs, MITRE tags) and exports OASIS STIX 2.1 bundles |
| [🔑 JWT Security Auditor](./jwt-security-auditor) | Decodes JSON Web Tokens, flags `alg: none`, claim/lifetime flaws and leaked secrets, and audits weak HMAC signing keys |
| [🔒 TLS & Certificate Security Inspector](./tls-cert-inspector) | Audits HTTPS endpoints for certificate expiry, SAN subdomains, issuer chains, TLS protocol versions and weak cipher suites |
| [🐚 PHP2Shell Log & Web Shell Detector](./php2shell-detector) | Hunts for October 2026 **PHP2Shell** (`CVE-2026-109618` / `CVE-2026-109619`) exploitation in Apache/PHP logs and detects dropped PHP web shells |
| [🛡️ PHP2Shell Exposure & Config Auditor](./php2shell-exposure-auditor) | Passively audits HTTP endpoints, `Apache mod_php` SAPIs and `php.ini` files against the October 2026 **PHP2Shell** patch floors |

## 🛠️ Skills Shown
- Python (standard library, `argparse`, regex, hashing)
- Log analysis and threat detection (MITRE ATT&CK)
- Secure API use and privacy-preserving design
- Web security and HTTP hardening (OWASP Top 10)
- Host-based intrusion detection (file integrity monitoring)
- Email security and phishing triage (SPF, DKIM, DMARC, IOC handling)
- Web reconnaissance and attack-surface mapping (crawling, `robots.txt`, entry points)
- Network packet forensics (`.pcap` binary parsing, TCP/IP/DNS/ARP analysis, entropy detection)
- Vulnerability management and supply-chain security (CVE auditing via OSV.dev, OWASP A06)
- Static malware triage and incident response (magic bytes, Shannon entropy, PE/API indicators)
- Cyber threat intelligence (CTI) and IOC parsing/defanging for SOC workflows
- API authentication security and token auditing (JWT RFC 7519, HMAC verification, OWASP API2:2023)
- Transport layer cryptography and X.509 certificate auditing (TLS 1.2/1.3, Forward Secrecy, SAN recon)
- Rapid-response emerging threat detection & exposure auditing (PHP2Shell `CVE-2026-109618` / `CVE-2026-109619`, Sigma/Wazuh rules, SAPI & `php.ini` hardening)

## 📬 Contact
- LinkedIn: https://www.linkedin.com/in/alexandru-mocanu-ba831b234/
- Email: mocanu.alexandru.info@gmail.com

---
<sub>*Developed by me with the help of AI-assisted tooling, then reviewed and tested by me.*</sub>
