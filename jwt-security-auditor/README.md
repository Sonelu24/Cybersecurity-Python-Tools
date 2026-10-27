# 🔑 JWT Security Auditor (v2.0)

A zero-dependency Python Application Security / Red Team CLI tool that decodes **JSON Web Tokens (JWT, RFC 7519)**, audits headers and claims against **OWASP API2:2023 (Broken Authentication)** and **OWASP A07:2021** best practices, tests HMAC (`HS256`/`HS384`/`HS512`) signatures against weak secrets, inspects live **OpenID Connect / JWKS** endpoints (`--jwks`), checks **asymmetric-to-symmetric algorithm confusion** (`--public-key`), and extracts/audits tokens in batch from `.har` captures or HTTP proxy logs (`--extract-file`).

---

## ✨ Features (v2.0)

- **RFC 7515 Base64URL Decoder:** Automatically restores stripped `=` padding, strips optional `Bearer ` prefixes, and pretty-prints the decoded **Header** and **Payload** with human-readable UTC timestamps (`iat`, `nbf`, `exp`).
- **Live OpenID Connect & JWKS Key Discovery (`--jwks URL`):**
  - Fetches `/.well-known/openid-configuration` (automatically following `jwks_uri`) or `jwks.json`.
  - Audits every public key for exposed symmetric (`oct`) or private (`d`/`p`/`q`) parameters, checks whether `alg` and `use` (`sig`) are explicitly pinned, and verifies whether the token's `kid` exists in the active JWKS.
- **Public-Key Algorithm Confusion Audit (`--public-key FILE`):**
  - Checks whether an `HS256`/`HS384`/`HS512` token signature was computed using the server's PEM public key bytes as an HMAC secret (`CVE-2016-5431` / `CVE-2016-10555`).
- **Batch `.har` / HTTP Log JWT Extractor (`--extract-file FILE`):**
  - Scans `.har` captures, proxy logs, or raw files to extract, deduplicate, and batch-audit every `eyJ...` JWT automatically.
- **Cryptographic, Header & Claim Security Checks:**
  - **`alg: none` & Missing Signature Detection (`CRITICAL`)** (`CVE-2015-2951`).
  - **Weak HMAC Secret Auditing (`CRITICAL`):** Recomputes `HS256`/`HS384`/`HS512` signatures via constant-time `hmac.compare_digest()` against built-in or custom (`-w`) wordlists.
  - **Dynamic Key & `kid` Injection (`HIGH`):** Flags `jku`, `jwk`, `x5u`, and `kid` path traversal (`../`).
  - **Expiration (`exp`), Cleartext Secret Exposure & Replay Hygiene:** Flags missing/excessive `exp`, leaked API keys/passwords in claims, and missing `iss`/`aud`/`jti`.
- **Automated Risk Scoring (0–100) & JSON Export (`-o`)**

---

## 🎯 OWASP & CWE Mapping

| Check | OWASP / CWE Reference | Security Impact |
|---|---|---|
| **`alg: none` / Weak HMAC Secret / Key Confusion** | **OWASP API2:2023 (Broken Authentication)** / `CWE-347` | Allows attackers to forge arbitrary `role: admin` session tokens |
| **`kid` Path Traversal / `jku` Header / JWKS Misconfig** | **OWASP A07:2021 (Auth Failures)** / `CWE-22` | Tricks server into verifying signatures against untrusted or unpinned keys |
| **Sensitive Claims in Payload** | **OWASP A02:2021 (Cryptographic Failures)** / `CWE-312` | JWT payloads are Base64URL-encoded, not encrypted; any client or proxy can read them |
| **Missing `exp` / Excessive TTL** | **OWASP ASVS v4.0 (V3.5 Token-Based Session Mgmt)** / `CWE-613` | Stolen tokens remain valid indefinitely without a short expiration window |

---

## 🚀 Usage

### 1. Run Built-in Vulnerable JWT + JWKS Audit Demo
```bash
python jwt_auditor.py --demo
```

### 2. Audit a JWT & Inspect Live OpenID / JWKS Discovery
```bash
python jwt_auditor.py token.txt --jwks https://accounts.google.com/.well-known/openid-configuration
```

### 3. Check Public-Key Algorithm Confusion (`RS256` → `HS256`)
```bash
python jwt_auditor.py token.txt --public-key server_pub.pem
```

### 4. Batch-Extract & Audit All JWTs from a `.har` Capture or Proxy Log
```bash
python jwt_auditor.py --extract-file traffic_capture.har -o batch_jwt_audit.json
```

### CLI Options
| Flag | Description |
|---|---|
| `token` | Raw JWT string (`eyJ...`, with or without `Bearer `) or path to a file |
| `--demo` | Audit a built-in vulnerable sample JWT + JWKS |
| `-w`, `--wordlist` | Path to a custom newline-delimited wordlist for HMAC secret testing |
| `-s`, `--secret` | Test a specific candidate HMAC secret key |
| `--jwks` | URL to a live `jwks.json` or `/.well-known/openid-configuration` endpoint |
| `--public-key` | Path to PEM public key file to audit `RS256` → `HS256` algorithm confusion |
| `--extract-file` | Extract and batch-audit all JWTs from a `.har` capture or HTTP log file |
| `-o`, `--output` | Export the audit report to a `.json` file |

---

## 📊 Example Output

![JWT Security Auditor demo](demo.png)

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
                         [ JWT Security Auditor v2.0 ]

[*] Target Token : eyJhbGciOiJIUzI1NiIsInR5cCI6...7xuLSM8ARJ-Y (Built-in Demo JWT)
[*] Algorithm    : HS256  |  HMAC Secrets Tested: 22
============================================================================

[🧩 Decoded Header & Payload]
  Header  : {"alg": "HS256", "typ": "JWT", "kid": "../../keys/dev.key"}
  Payload :
    • sub               : usr_9042_admin
    • username          : svc_deploy
    • role              : superadmin
    • internal_api_key  : demo_internal_token_98a4f2c1e0b7
    • iat               : 1793120569  (2026-10-27 17:02:49 UTC)
    • exp               : 1824660169  (2027-10-27 18:02:49 UTC)

[🌐 OpenID / JWKS Key Discovery (2 keys from https://auth.example.com/.well-known/jwks.json (Built-in Demo JWKS))]
    • kid=prod-rsa-2026-01       kty=RSA   alg=RS256      use=sig
    • kid=legacy-unpinned-key    kty=RSA   alg=UNPINNED   use=UNSPECIFIED

[🚨 Security Audit Findings (7)]
  • [CRITICAL] Weak HMAC Signing Secret Discovered ('jwt_secret')
               └─ HS256 signature matched weak secret 'jwt_secret' (22 candidates tested). Attackers can forge admin tokens.
  • [HIGH]     Suspicious 'kid' Header Parameter ('../../keys/dev.key')
               └─ Key ID contains path traversal or injection characters that may trick key-lookup routines.
  • [MEDIUM]   Excessive Token Lifetime (365 days)
               └─ Access token is valid for 365 days (recommended: 15m–24h with refresh tokens).
  • [HIGH]     Sensitive Data in Payload (internal_api_key)
               └─ JWT payloads are Base64URL-encoded, NOT encrypted. Anyone with the token can read these secrets.
  • [LOW]      Missing Scope/Replay Claims (iss, aud, jti)
               └─ Omitting 'aud'/'iss'/'jti' increases risk of cross-service token replay attacks.
  • [LOW]      Unpinned JWK Metadata (kid: legacy-unpinned-key, alg: UNPINNED, use: UNSPECIFIED)
               └─ Pinning both 'alg' and 'use': 'sig' in every JWK helps prevent cross-algorithm key misuse.
  • [MEDIUM]   Token 'kid' ('../../keys/dev.key') Not Found in Active JWKS (2 keys)
               └─ Token references a rotated, retired, or injected key ID not present in the server's JWKS.

============================================================================
[!] RISK SCORE   : 100/100 — CRITICAL RISK (Immediate Remediation Required)
============================================================================
```

---

## 🧠 What I Learned

- **Base64 vs. Base64URL Padding:** JWTs use RFC 7515 Base64URL encoding (`-` and `_` instead of `+` and `/`, with trailing `=` padding stripped). Restoring `=` padding via `len(segment) % 4` is required before passing segments to Python's `base64.urlsafe_b64decode()`.
- **OpenID Connect JWKS Key Hygiene:** Public JWKS endpoints (`jwks_uri`) should explicitly pin `alg` and `use: "sig"` on every key and never expose symmetric (`oct`) or private RSA parameters.
- **Asymmetric-to-Symmetric Algorithm Confusion (`CVE-2016-5431`):** If a backend JWT verifier does not strictly enforce `algorithms=["RS256"]`, an attacker can sign an `HS256` token using the server's publicly available RSA public key bytes as the HMAC secret.

---

## 🔄 Version History & Changelog (v1.0 → v2.0)

- **v1.0 (Baseline):** Single-token RFC 7519 decoder, `alg: none` & `kid` injection checks, claim/TTL auditing, and weak HMAC secret dictionary testing.
- **v2.0:**
  - Added **Live OpenID Connect & JWKS Key Discovery (`--jwks URL`)** to inspect `/.well-known/openid-configuration` and `jwks.json` endpoints for unpinned keys, `kid` mismatches, and leaked key parameters.
  - Added **Public-Key Algorithm Confusion Auditing (`--public-key FILE`)** to detect tokens signed with PEM public key bytes as an HMAC secret (`CVE-2016-5431`).
  - Added **Batch `.har` / HTTP Log JWT Extraction (`--extract-file FILE`)** to automatically extract, deduplicate, and audit all JWTs across web traffic captures.
