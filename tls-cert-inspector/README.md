# 🔒 TLS & SSL Certificate Security Inspector (v2.0)

A zero-dependency Python Red Team / Network Security CLI tool that connects to HTTPS endpoints to audit **X.509 certificate chains**, **expiration timelines**, **OCSP/CRL revocation endpoints**, **Subject Alternative Names (SANs)**, **Certificate Transparency (`crt.sh`) historical subdomains** (`--ct-logs`), **TLS protocol versions**, **active multi-cipher enumeration** (`--enum-ciphers`), and **batch domain scanning** (`-i`) (Grading `A+` to `F`).

---

## ✨ Features (v2.0)

- **Live TLS Handshake & Legacy Protocol Probing:**
  - Inspects the negotiated TLS version (`TLSv1.3` / `TLSv1.2`) and actively probes whether the target still accepts deprecated legacy protocols (`TLSv1.0`, `TLSv1.1`).
  - Automatically falls back to unverified certificate extraction (`ssl.CERT_NONE` + `getpeercert(binary_form=True)`) if a target uses a self-signed or expired certificate while flagging the broken trust chain as `CRITICAL`.
- **Active Multi-Cipher Suite Enumeration (`--enum-ciphers`):**
  - Actively probes TLS 1.3 AEAD and TLS 1.2 cipher families (`ECDHE-ECDSA-AESGCM`, `ECDHE-RSA-AESGCM`, `ECDHE-CHACHA20`, `ECDHE-CBC`, `Static RSA (No PFS)`, and `3DES`) to map which cipher suites the server accepts beyond the default negotiated cipher.
- **Certificate Transparency (`crt.sh`) Historical Subdomain Recon (`--ct-logs`):**
  - Queries the public `crt.sh` Certificate Transparency JSON API to uncover historical and forgotten subdomains issued to the target domain (`MITRE ATT&CK T1596.003`).
- **X.509 Revocation Hygiene (`OCSP` & `CRL Distribution Points`):**
  - Extracts `OCSP` and `crlDistributionPoints` URLs from the X.509 certificate and optionally checks their HTTP reachability (`--check-revocation`).
- **Concurrent Batch Domain Scanning (`-i domains.txt`):**
  - Audits lists of domains concurrently via `ThreadPoolExecutor` and outputs a consolidated grade/expiry summary table.
- **Automated Security Grading (`A+` to `F`) & JSON Export (`-o`)**

---

## 🎯 OWASP & NIST Mapping

| Check | Standard / Reference | Security Impact |
|---|---|---|
| **Deprecated `TLSv1.0` / `TLSv1.1` Support** | **RFC 8996 / OWASP A02:2021 (Cryptographic Failures)** | Exposes traffic to protocol downgrade, BEAST, and POODLE attacks |
| **Missing Perfect Forward Secrecy (Static RSA)** | **NIST SP 800-52r2** | If the server's private key is ever stolen, all previously recorded PCAP traffic can be decrypted |
| **Untrusted / Expired X.509 Chain** | **OWASP A05:2021 (Security Misconfiguration)** | Causes service outages or trains users to click through browser MITM warnings |
| **SAN & `crt.sh` CT Log Subdomain Recon** | **MITRE ATT&CK `T1596.003` (Search Open Technical Databases: Digital Certificates)** | Reveals internal, staging, and historical subdomains via public X.509 certificates |

---

## 🚀 Usage

### 1. Run Built-in TLS & Certificate Security Audit Demo
```bash
python tls_inspector.py --demo
```

### 2. Audit a Live HTTPS Domain with Cipher Enumeration & CT Log Recon
```bash
python tls_inspector.py github.com --enum-ciphers --ct-logs --check-revocation
```

### 3. Batch-Scan a List of Domains Concurrently
```bash
python tls_inspector.py -i domains.txt -o batch_tls_report.json
```

### CLI Options
| Flag | Description |
|---|---|
| `target` | Target hostname, `host:port`, or HTTPS URL (`example.com`, `https://example.com:8443`) |
| `--demo` | Run built-in audit against a simulated misconfigured staging HTTPS endpoint |
| `-i`, `--input-file` | Path to a newline-delimited list of domains/hosts for concurrent batch scanning |
| `-p`, `--port` | Custom TCP port (default: `443`) |
| `--enum-ciphers` | Actively enumerate accepted TLS 1.3 and TLS 1.2 cipher families |
| `--ct-logs` | Query Certificate Transparency (`crt.sh`) for historical subdomains |
| `--check-revocation` | Verify OCSP and CRL revocation endpoint reachability |
| `--timeout` | Connection timeout in seconds (default: `6.0`) |
| `-o`, `--output` | Export the full TLS & certificate report to `.json` |

---

## 📊 Example Output

![TLS & Certificate Security Inspector demo](demo.png)

```text
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
                    [ TLS & Certificate Security Inspector v2.0 ]

[*] Target Host  : staging-gateway.example.com:443 (Built-in Demo Target)
[*] Handshake    : TLSv1.2  |  Cipher: TLS_RSA_WITH_AES_128_CBC_SHA (128-bit)
============================================================================

[📜 X.509 Certificate Metadata]
  • Subject CN   : *.example.com (Example Corp Staging Infrastructure)
  • Issuer CA    : Example Internal Issuing CA G2 (Example Corp Trust Network)
  • Validity     : 2025-06-23 18:05 UTC  →  2026-11-05 18:05 UTC (9 days left)
  • Serial / FP  : 04:A9:8F:12:C4:77:0B:9E  |  SHA256: 9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15...
  • Revocation   : 2 OCSP/CRL endpoint(s) (http://ocsp.example.com/status)

[🌐 Subject Alternative Names (SANs) Discovered (5)]
  • *.example.com, staging-gateway.example.com, dev-api.example.com, vpn-admin.example.com, jenkins-internal.example.net

[🔎 Certificate Transparency (crt.sh) Subdomains (4)]
  • old-git.example.com, qa-Billing-2024.example.com, shadow-api.example.com, staging-gateway.example.com

[🔐 Enumerated Accepted Cipher Families (3)]
  • TLS 1.2 ECDHE-RSA-AESGCM     -> ECDHE-RSA-AES128-GCM-SHA256 (TLSv1.2, 128-bit)
  • TLS 1.2 ECDHE-CBC (Legacy)   -> ECDHE-RSA-AES128-SHA (TLSv1.2, 128-bit)
  • TLS 1.2 Static RSA (No PFS)  -> AES128-SHA (TLSv1.2, 128-bit)

[🚨 TLS & Certificate Security Findings (6)]
  • [HIGH]     Certificate Imminent Expiration (9 days remaining)
               └─ Expires on 2026-11-05 18:05 UTC; immediate renewal required to avoid outage.
  • [LOW]      Excessive Certificate Validity Period (500 days)
               └─ Exceeds the 398-day CA/Browser Forum maximum validity baseline.
  • [HIGH]     Deprecated Legacy Protocol Enabled (TLSv1.1)
               └─ Server still accepts TLSv1.1 connections; disable all protocols below TLSv1.2.
  • [HIGH]     Missing Perfect Forward Secrecy (TLS_RSA_WITH_AES_128_CBC_SHA)
               └─ Static RSA key exchange allows past traffic decryption if the private key is compromised.
  • [MEDIUM]   CBC-Mode Cipher Negotiated (TLS_RSA_WITH_AES_128_CBC_SHA)
               └─ Prefer AEAD cipher suites (AES-GCM or CHACHA20-POLY1305) over legacy CBC mode.
  • [LOW]      Wildcard Certificate Scope (*.example.com)
               └─ Single private key covers all subdomains + 5 SAN entries (increases blast radius).

============================================================================
[!] SECURITY GRADE : F (15/100)
============================================================================
```

---

## 🧠 What I Learned

- **Parsed vs. Binary DER Certificates in Python's `ssl` Module:** Calling `ssock.getpeercert()` returns a decoded dictionary of `subject`, `issuer`, `OCSP`, `crlDistributionPoints`, and `subjectAltName` fields when verification succeeds, whereas `ssock.getpeercert(binary_form=True)` always returns the raw ASN.1 DER bytes needed to compute the `SHA-256` certificate thumbprint.
- **Active Cipher Enumeration:** A server may negotiate a strong `TLSv1.3` AEAD cipher by default while still accepting static RSA (`AES128-GCM-SHA256` without `ECDHE`) or `CBC` ciphers from TLS 1.2 clients. Testing individual cipher families with `SSLContext.set_ciphers()` reveals the full accepted cipher posture.
- **SANs + Certificate Transparency (`crt.sh`) Recon:** Combining live X.509 SAN inspection with public CT logs uncovers both active multi-tenant hostnames and historical/forgotten staging subdomains.

---

## 🔄 Version History & Changelog (v1.0 → v2.0)

- **v1.0 (Baseline):** Single-target TLS handshake inspector, X.509 expiry & 398-day baseline check, SAN extraction, and `TLSv1.0`/`1.1` fallback probing.
- **v2.0:**
  - Added **Certificate Transparency (`crt.sh`) Historical Subdomain Recon (`--ct-logs`)**.
  - Added **Active Multi-Cipher Suite Enumeration (`--enum-ciphers`)** across TLS 1.3 and TLS 1.2 cipher families (catching accepted static RSA or 3DES suites even when TLS 1.3 is default).
  - Added **X.509 Revocation Hygiene (`OCSP` & `CRL Distribution Points`)** extraction and optional reachability probing (`--check-revocation`).
  - Added **Concurrent Batch Domain Scanning (`-i domains.txt`)** via `ThreadPoolExecutor`.
