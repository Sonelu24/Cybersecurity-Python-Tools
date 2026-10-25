# 🔎 IOC Extractor & Defanger

A zero-dependency Python Blue Team / Threat Intelligence CLI tool that automatically **normalizes**, **extracts**, **validates**, and **defangs/refangs** 8 categories of **Indicators of Compromise (IOCs)** from raw logs, phishing emails, malware sandbox reports, or threat advisories.

---

## ✨ Features

- **Pre-Extraction Normalization (`refang_text`):** Automatically detects and normalizes already-obfuscated indicators (`hxxps://`, `[:]//`, `[.]`, `(.)`, `[@]`) so mixed threat reports are parsed with 100% recall.
- **8 IOC Categories Extracted & Deduplicated:**
  1. **IPv4 Addresses:** Validated via Python's `ipaddress.IPv4Address` (eliminates version-string false positives) and tagged as `[EXTERNAL]` vs. `[INTERNAL/RFC1918]`.
  2. **IPv6 Addresses:** Supports both standard and `::` compressed notation via `ipaddress.IPv6Address`.
  3. **URLs (`http`, `https`, `ftp`):** Preserves paths, ports, and query parameters while stripping trailing sentence punctuation.
  4. **Domains / FQDNs:** Filters out common file extensions (`.exe`, `.dll`, `.bin`, `.php`, `.log`) so filenames in logs aren't misclassified as domains.
  5. **Email Addresses:** Extracts phishing senders and attacker contact addresses.
  6. **Cryptographic File Hashes:** Automatically separates **SHA-256** (64 hex), **SHA-1** (40 hex), and **MD5** (32 hex) without substring collisions.
  7. **CVE Vulnerability IDs:** Matches `CVE-YYYY-NNNN+` identifiers.
  8. **MITRE ATT&CK Technique IDs:** Extracts `Txxxx` and `Txxxx.xxx` sub-technique tags.
- **Safe SOC Sharing (`--defang` default) & Blocklist Export (`--refang`):**
  - Default mode converts live indicators into safe, non-clickable text (`hxxps://`, `198[.]51[.]100[.]42`, `alerts[@]auth-example-portal[.]com`) for Jira tickets, Slack, and incident reports.
  - `--refang` outputs raw indicators ready for firewall blocklists, EDR rules, or SIEM lookups.
- **JSON & CSV Export (`-o`):** One-command export to `.json` or `.csv` for automated SOAR/SIEM ingestion.

---

## 🎯 MITRE ATT&CK & Cyber Threat Intelligence (CTI) Mapping

| Capability | Framework / Use Case | Why It Matters |
|---|---|---|
| **Automated IOC Harvesting** | **NIST SP 800-61r2** (Incident Handling) | Speeds up containment by extracting all network & host indicators from raw unstructured logs in seconds |
| **Indicator Defanging (`[.]`, `hxxps://`)** | **FIRST.org Traffic Light Protocol / SOC Hygiene** | Prevents analysts or stakeholders from accidentally clicking live C2/phishing links in tickets |
| **RFC 1918 vs. Public IP Classification** | **MITRE ATT&CK `T1071` (Application Layer Protocol)** | Immediately separates internal victim workstations (`10.x.x.x`) from external C2 infrastructure |
| **MITRE & CVE Tag Extraction** | **MITRE ATT&CK / NVD Correlation** | Links extracted technical artifacts directly to adversary TTPs and exploited vulnerabilities |

---

## 🚀 Usage

### 1. Run Built-in SOC Threat Advisory Demo
```bash
python ioc_extractor.py --demo
```

### 2. Extract & Defang IOCs from a Threat Report, Log, or `.eml` File
```bash
python ioc_extractor.py incident_notes.txt
```

### 3. Output Raw (Refanged) IOCs & Exclude Internal RFC 1918 IPs (For Firewall Blocklists)
```bash
python ioc_extractor.py incident_notes.txt --refang --no-private
```

### 4. Export Extracted IOCs to JSON or CSV
```bash
python ioc_extractor.py --demo -o iocs.json
python ioc_extractor.py --demo -o iocs.csv
```

### CLI Options
| Flag | Description |
|---|---|
| `file` | Path to any text, log, markdown, or `.eml` file (or pipe via `stdin`) |
| `--demo` | Run against the built-in simulated SOC Incident Advisory (`INC-2026-0842`) |
| `--refang` | Output raw/active indicators instead of defanged indicators |
| `--no-private` | Exclude internal RFC 1918 (`10.x`, `172.16.x`, `192.168.x`) and loopback IPs |
| `-o`, `--output` | Export extracted IOCs to `.json` or `.csv` |

---

## 📊 Example Output

![IOC Extractor & Defanger demo](demo.png)

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
                        [ IOC Extractor & Defanger ]

[*] Source       : Built-in SOC Incident Advisory (INC-2026-0842)
[*] Output Mode  : DEFANGED (Safe for SOC Sharing)
[*] Total IOCs   : 18 unique indicators extracted
========================================================================

[🌐 Network IP Addresses (4)]
  • 10[.]20[.]4[.]115      [INTERNAL/RFC1918]
  • 198[.]51[.]100[.]42    [EXTERNAL]
  • 203[.]0[.]113[.]195    [EXTERNAL]
  • 2001:db8:85a3::8a2e:370:7334 [IPv6]

[🔗 URLs (2)]
  • hxxp://203[.]0[.]113[.]195:8443/beacon/checkin.php
  • hxxps://cdn-example-verify[.]net/api/v2/stage2.bin

[🏷️  Domains / FQDNs (2)]
  • auth-example-portal[.]com
  • cdn-example-verify[.]net

[✉️  Email Addresses (2)]
  • alerts[@]auth-example-portal[.]com
  • billing[@]cdn-example-verify[.]net

[#️⃣  File Hashes (3)]
  • [MD5   ] d41d8cd98f00b204e9800998ecf8427e
  • [SHA1  ] da39a3ee5e6b4b0d3255bfef95601890afd80709
  • [SHA256] e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

[🎯 Vulnerability & Threat Context (5)]
  • CVEs         : CVE-2023-38831, CVE-2024-21413
  • MITRE ATT&CK : T1059.001, T1071.001, T1566.002

========================================================================
```

---

## 🧠 What I Learned

- **Normalize Before Extracting:** Threat intelligence feeds frequently mix live links (`http://...`) and partially defanged indicators (`hxxps://domain[.]com`). Normalizing (`refang_text`) before running extraction regexes ensures every indicator is captured and deduplicated cleanly.
- **Eliminating Regex False Positives:** Naive regexes often mistake filenames (`stage2.bin`, `checkin.php`) for domains, or software version strings (`1.2.3.400`) for IPv4 addresses. Combining `ipaddress.IPv4Address` validation with an extension exclusion list and longest-first hash matching (`SHA-256` → `SHA-1` → `MD5`) prevents false positives.
- **Operational SOC Formatting:** Separating `[INTERNAL/RFC1918]` workstation IPs from `[EXTERNAL]` routable IPs saves analysts time when building firewall blocklists (`--no-private --refang`).

---

## 🛣️ Future Improvements

- **STIX 2.1 Bundle Export:** Generate standardized OASIS STIX 2.1 JSON indicator bundles for direct import into OpenCTI or MISP.
- **Windows Registry & File Path Extraction:** Detect persistence registry keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) and suspicious file paths.
- **Optional Reputation Enrichment:** Query AbuseIPDB, VirusTotal, or URLhaus APIs when an API key is configured.
