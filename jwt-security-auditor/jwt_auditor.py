#!/usr/bin/env python3
"""
JWT Security Auditor v2.0 (Red Team / Application Security Assessment)
Decodes JSON Web Tokens (RFC 7519), audits headers and claims against OWASP API2:2023 /
A07:2021 best practices (alg:none, header injection, lifetime/exp issues, sensitive data exposure),
tests HMAC (HS256/HS384/HS512) signatures against weak development secrets, inspects live
OpenID Connect / JWKS endpoints (--jwks), checks public-key HMAC algorithm confusion (--public-key),
and extracts/audits tokens in batch from .har or HTTP logs (--extract-file).
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
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
                         [ JWT Security Auditor v2.0 ]
"""

DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "supersecret", "changeme",
    "admin", "development", "dev-secret", "mysecret", "secretkey", "jwtkey",
    "default", "test", "key", "private", "app_secret", "auth_secret",
    "qwerty", "letmein", "token_secret", "sonelu_demo_secret",
]

SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "internal_api_key",
    "private_key", "access_key", "ssn", "credit_card", "card_number", "cvv", "pin",
}

HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

ASYMMETRIC_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EDDSA"}

JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def b64url_decode(segment: str) -> bytes:
    """Decodes a Base64URL string, automatically restoring stripped '=' padding."""
    rem = len(segment) % 4
    if rem:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def b64url_encode(data: bytes) -> str:
    """Encodes raw bytes into unpadded Base64URL format (RFC 7515)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_demo_jwt() -> str:
    """Generates a realistic vulnerable sample JWT for --demo mode."""
    now = int(time.time())
    header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": "../../keys/dev.key",
    }
    payload = {
        "sub": "usr_9042_admin",
        "username": "svc_deploy",
        "role": "superadmin",
        "internal_api_key": "demo_internal_token_98a4f2c1e0b7",
        "iat": now - 3600,
        "exp": now + (365 * 86400),  # 365-day token lifetime
    }
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(b"jwt_secret", signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def build_demo_jwks() -> dict:
    """Returns a sample JWKS response with key-hygiene findings for --demo mode."""
    return {
        "source": "https://auth.example.com/.well-known/jwks.json (Built-in Demo JWKS)",
        "keys": [
            {
                "kty": "RSA",
                "kid": "prod-rsa-2026-01",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
            },
            {
                "kty": "RSA",
                "kid": "legacy-unpinned-key",
                # Missing 'alg' and 'use' fields!
                "n": "xvx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc",
                "e": "AQAB",
            },
        ],
    }


def parse_jwt(token: str) -> dict:
    """Splits and decodes a JWT into header, payload, and signature components."""
    clean = token.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()

    parts = clean.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 dot-separated segments, got {len(parts)}")

    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(b64url_decode(h_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to decode JWT header: {exc}") from exc

    try:
        payload = json.loads(b64url_decode(p_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to decode JWT payload: {exc}") from exc

    return {
        "raw": clean,
        "signing_input": f"{h_b64}.{p_b64}",
        "header": header,
        "payload": payload,
        "signature_b64": s_b64,
    }


def test_hmac_secrets(signing_input: str, signature_b64: str, alg: str, secrets: list[str]) -> str | None:
    """Tests a list of candidate secrets against an HS256/HS384/HS512 signature."""
    hash_fn = HMAC_ALGORITHMS.get(alg.upper())
    if not hash_fn or not signature_b64:
        return None

    msg = signing_input.encode("ascii")
    for candidate in secrets:
        digest = hmac.new(candidate.encode("utf-8"), msg, hash_fn).digest()
        expected_b64 = b64url_encode(digest)
        if hmac.compare_digest(expected_b64, signature_b64):
            return candidate
    return None


def check_public_key_confusion(parsed: dict, pubkey_bytes: bytes) -> dict:
    """
    Audits a token against RSA/ECDSA -> HMAC algorithm confusion (CVE-2016-5431 / CVE-2016-10555).
    Checks whether an HS256/384/512 signature was computed using the server's public key bytes
    (either raw or stripped of trailing newlines) as an HMAC secret, or evaluates confusion risk
    if the token uses an asymmetric algorithm.
    """
    alg = str(parsed["header"].get("alg", "")).upper()
    sig_b64 = parsed["signature_b64"]
    msg = parsed["signing_input"].encode("ascii")

    variants = [
        ("exact PEM bytes", pubkey_bytes),
        ("trimmed PEM bytes", pubkey_bytes.strip()),
        ("LF-normalized PEM bytes", pubkey_bytes.replace(b"\r\n", b"\n").strip()),
    ]

    matched_variant = None
    if alg in HMAC_ALGORITHMS and sig_b64:
        hash_fn = HMAC_ALGORITHMS[alg]
        for label, key_material in variants:
            digest = hmac.new(key_material, msg, hash_fn).digest()
            if hmac.compare_digest(b64url_encode(digest), sig_b64):
                matched_variant = label
                break

    return {
        "public_key_loaded": True,
        "public_key_sha256": hashlib.sha256(pubkey_bytes).hexdigest()[:16],
        "token_alg": alg,
        "signed_with_public_key_hmac": matched_variant is not None,
        "matched_variant": matched_variant,
        "asymmetric_downgrade_candidate": alg in ASYMMETRIC_ALGORITHMS,
    }


def fetch_and_audit_jwks(url: str, token_kid: str | None = None, demo_jwks: dict | None = None) -> dict:
    """
    Fetches either an OpenID Connect discovery document (/.well-known/openid-configuration)
    or a JWKS endpoint (jwks.json) and audits key rotation, algorithm pinning, and kid matching.
    """
    if demo_jwks is not None:
        jwks_data = demo_jwks
        source_url = demo_jwks.get("source", url)
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "Sonelu-JWT-Auditor/2.0"})
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        source_url = url
        # If OpenID discovery doc, follow jwks_uri
        if "jwks_uri" in data and "keys" not in data:
            jwks_uri = data["jwks_uri"]
            req2 = urllib.request.Request(jwks_uri, headers={"User-Agent": "Sonelu-JWT-Auditor/2.0"})
            with urllib.request.urlopen(req2, timeout=6.0) as resp2:
                jwks_data = json.loads(resp2.read().decode("utf-8"))
            source_url = f"{url} -> {jwks_uri}"
        else:
            jwks_data = data

    keys = jwks_data.get("keys", [])
    key_summaries = []
    jwks_findings = []
    matched_kid = False

    for idx, k in enumerate(keys):
        kty = k.get("kty", "UNKNOWN")
        kid = k.get("kid", f"<missing-kid-{idx}>")
        use = k.get("use", "UNSPECIFIED")
        alg = k.get("alg", "UNPINNED")
        key_summaries.append({"kid": kid, "kty": kty, "use": use, "alg": alg})

        if token_kid and kid == token_kid:
            matched_kid = True

        # Check for symmetric or private key material accidentally leaked in public JWKS
        if kty.upper() == "OCT" or "k" in k:
            jwks_findings.append({
                "severity": "CRITICAL",
                "title": f"Symmetric Key Material Exposed in Public JWKS (kid: {kid})",
                "detail": "JWKS contains a symmetric 'oct' key; anyone can fetch the key and forge tokens.",
            })
        if any(priv_param in k for priv_param in ("d", "p", "q", "dp", "dq", "qi")):
            jwks_findings.append({
                "severity": "CRITICAL",
                "title": f"Private Key Parameters Exposed in Public JWKS (kid: {kid})",
                "detail": "Public JWKS leaks private RSA/EC exponent parameters ('d'/'p'/'q')!",
            })
        if alg == "UNPINNED" or use == "UNSPECIFIED":
            jwks_findings.append({
                "severity": "LOW",
                "title": f"Unpinned JWK Metadata (kid: {kid}, alg: {alg}, use: {use})",
                "detail": "Pinning both 'alg' and 'use': 'sig' in every JWK helps prevent cross-algorithm key misuse.",
            })

    if token_kid and keys and not matched_kid:
        jwks_findings.append({
            "severity": "MEDIUM",
            "title": f"Token 'kid' ('{token_kid}') Not Found in Active JWKS ({len(keys)} keys)",
            "detail": "Token references a rotated, retired, or injected key ID not present in the server's JWKS.",
        })

    return {
        "source": source_url,
        "key_count": len(keys),
        "token_kid_matched": matched_kid,
        "keys": key_summaries,
        "findings": jwks_findings,
    }


def extract_jwts_from_file(path: Path) -> list[str]:
    """Extracts unique JWT strings from a .har capture, proxy log, or raw text file."""
    content = path.read_text(encoding="utf-8", errors="ignore")
    matches = JWT_REGEX.findall(content)
    unique = []
    seen = set()
    for m in matches:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


def fmt_ts(epoch_val: int | float) -> str:
    """Formats a Unix epoch timestamp into a readable UTC string."""
    try:
        return datetime.fromtimestamp(float(epoch_val), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(epoch_val)


def audit_jwt(
    parsed: dict,
    secrets: list[str],
    pubkey_bytes: bytes | None = None,
    jwks_report: dict | None = None,
) -> dict:
    """Evaluates header, claims, HMAC strength, public-key confusion, and JWKS posture."""
    header = parsed["header"]
    payload = parsed["payload"]
    sig_b64 = parsed["signature_b64"]
    alg = str(header.get("alg", "MISSING"))

    findings = []
    risk_score = 0
    matched_secret = None

    # 1. Algorithm checks
    if alg.lower() == "none" or not sig_b64:
        findings.append({
            "severity": "CRITICAL",
            "title": "Unverified Token ('alg: none' / Missing Signature)",
            "detail": "Token allows arbitrary claim tampering without a cryptographic signature (CVE-2015-2951).",
        })
        risk_score += 50
    elif alg.upper() in HMAC_ALGORITHMS:
        matched_secret = test_hmac_secrets(parsed["signing_input"], sig_b64, alg, secrets)
        if matched_secret is not None:
            findings.append({
                "severity": "CRITICAL",
                "title": f"Weak HMAC Signing Secret Discovered ('{matched_secret}')",
                "detail": f"{alg} signature matched weak secret '{matched_secret}' ({len(secrets)} candidates tested). Attackers can forge admin tokens.",
            })
            risk_score += 45

    # 2. Public-key algorithm confusion check (--public-key)
    pubkey_audit = None
    if pubkey_bytes:
        pubkey_audit = check_public_key_confusion(parsed, pubkey_bytes)
        if pubkey_audit["signed_with_public_key_hmac"]:
            findings.append({
                "severity": "CRITICAL",
                "title": f"Algorithm Confusion Confirmed ({alg} Signed with Public Key Bytes)",
                "detail": f"Signature matched HMAC computed using the server's public key ({pubkey_audit['matched_variant']}) (CVE-2016-5431).",
            })
            risk_score += 50
        elif pubkey_audit["asymmetric_downgrade_candidate"]:
            findings.append({
                "severity": "LOW",
                "title": f"Asymmetric Token Audited for Key Confusion ({alg})",
                "detail": "Ensure the backend verifier strictly pins algorithms=['RS256']/['ES256'] and rejects HS256 downgrades.",
            })

    # 3. Header injection / dangerous key parameters
    for hdr_param in ("jku", "jwk", "x5u"):
        if hdr_param in header:
            findings.append({
                "severity": "HIGH",
                "title": f"Dynamic Key Header Present ('{hdr_param}')",
                "detail": f"Header specifies '{hdr_param}', which can enable SSRF or rogue key injection if not strictly allowlisted.",
            })
            risk_score += 25

    kid = str(header.get("kid", ""))
    if kid and ("../" in kid or "..\\" in kid or "'" in kid or ";" in kid):
        findings.append({
            "severity": "HIGH",
            "title": f"Suspicious 'kid' Header Parameter ('{kid}')",
            "detail": "Key ID contains path traversal or injection characters that may trick key-lookup routines.",
        })
        risk_score += 20

    # 4. Expiration & lifetime checks
    now = int(time.time())
    if "exp" not in payload:
        findings.append({
            "severity": "HIGH",
            "title": "Missing Expiration Claim ('exp')",
            "detail": "Token never expires; a leaked token grants permanent access unless revoked server-side.",
        })
        risk_score += 25
    else:
        try:
            exp_val = int(payload["exp"])
            base_time = int(payload.get("iat", now))
            ttl_days = (exp_val - base_time) / 86400
            if exp_val < now:
                findings.append({
                    "severity": "LOW",
                    "title": f"Token Expired ({fmt_ts(exp_val)})",
                    "detail": "Verify the API rejects expired tokens and does not ignore 'exp' validation.",
                })
                risk_score += 5
            elif ttl_days > 7:
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Excessive Token Lifetime ({int(ttl_days)} days)",
                    "detail": f"Access token is valid for {int(ttl_days)} days (recommended: 15m–24h with refresh tokens).",
                })
                risk_score += 15
        except (ValueError, TypeError):
            pass

    # 5. Sensitive data exposure in unencrypted payload
    exposed_keys = [k for k in payload if k.lower() in SENSITIVE_CLAIM_KEYS]
    if exposed_keys:
        findings.append({
            "severity": "HIGH",
            "title": f"Sensitive Data in Payload ({', '.join(exposed_keys)})",
            "detail": "JWT payloads are Base64URL-encoded, NOT encrypted. Anyone with the token can read these secrets.",
        })
        risk_score += 20

    # 6. Missing standard replay/audience scope claims
    missing_std = [c for c in ("iss", "aud", "jti") if c not in payload]
    if missing_std:
        findings.append({
            "severity": "LOW",
            "title": f"Missing Scope/Replay Claims ({', '.join(missing_std)})",
            "detail": "Omitting 'aud'/'iss'/'jti' increases risk of cross-service token replay attacks.",
        })
        risk_score += 10

    # 7. Merge JWKS findings if present
    if jwks_report:
        for jf in jwks_report["findings"]:
            findings.append(jf)
            if jf["severity"] == "CRITICAL":
                risk_score += 40
            elif jf["severity"] == "MEDIUM":
                risk_score += 15
            else:
                risk_score += 5

    risk_score = min(100, risk_score)
    if risk_score >= 70:
        verdict = "CRITICAL RISK (Immediate Remediation Required)"
    elif risk_score >= 40:
        verdict = "HIGH RISK (Weak Configuration / Claims)"
    elif risk_score >= 15:
        verdict = "MEDIUM RISK (Hardening Recommended)"
    else:
        verdict = "LOW RISK (Follows JWT Security Best Practices)"

    return {
        "algorithm": alg,
        "header": header,
        "payload": payload,
        "signature_present": bool(sig_b64),
        "weak_secret_found": matched_secret if alg.upper() in HMAC_ALGORITHMS else None,
        "secrets_tested": len(secrets) if alg.upper() in HMAC_ALGORITHMS else 0,
        "public_key_audit": pubkey_audit,
        "jwks_audit": jwks_report,
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings,
    }


def print_report(report: dict, source_label: str) -> None:
    """Prints a clean, single-screen JWT Security Audit report."""
    print(f"[*] Target Token : {source_label}")
    print(f"[*] Algorithm    : {report['algorithm']}  |  HMAC Secrets Tested: {report['secrets_tested']}")
    print("=" * 76)

    print("\n[🧩 Decoded Header & Payload]")
    print(f"  Header  : {json.dumps(report['header'])}")
    print("  Payload :")
    for k, v in report["payload"].items():
        extra = f"  ({fmt_ts(v)})" if k in ("exp", "iat", "nbf") and isinstance(v, (int, float)) else ""
        print(f"    • {k:<18}: {v}{extra}")

    if report.get("jwks_audit"):
        ja = report["jwks_audit"]
        print(f"\n[🌐 OpenID / JWKS Key Discovery ({ja['key_count']} keys from {ja['source']})]")
        for k in ja["keys"][:5]:
            print(f"    • kid={k['kid']:<22} kty={k['kty']:<5} alg={k['alg']:<10} use={k['use']}")

    print(f"\n[🚨 Security Audit Findings ({len(report['findings'])})]")
    if not report["findings"]:
        print("  ✅ No cryptographic or claim vulnerabilities detected.")
    else:
        for f in report["findings"]:
            sev = f"[{f['severity']}]"
            print(f"  • {sev:<10} {f['title']}")
            print(f"               └─ {f['detail']}")

    print("\n" + "=" * 76)
    print(f"[!] RISK SCORE   : {report['risk_score']}/100 — {report['verdict']}")
    print("=" * 76)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Decode and audit JWT tokens for alg:none, claim flaws, weak HMAC secrets, JWKS hygiene, and key confusion."
    )
    parser.add_argument("token", nargs="?", help="JWT string (eyJ...) or path to file containing a token")
    parser.add_argument("--demo", action="store_true", help="Audit a built-in vulnerable sample JWT + JWKS")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file for HMAC secret auditing")
    parser.add_argument("-s", "--secret", help="Test a specific HMAC secret key against the token")
    parser.add_argument("--jwks", help="URL to a live jwks.json or /.well-known/openid-configuration endpoint")
    parser.add_argument("--public-key", help="Path to PEM public key file to audit RS256->HS256 algorithm confusion")
    parser.add_argument("--extract-file", help="Extract and batch-audit all JWTs from a .har capture or HTTP log file")
    parser.add_argument("-o", "--output", help="Export full audit report to a JSON file")
    args = parser.parse_args()

    print(BANNER)

    secrets = list(DEFAULT_WEAK_SECRETS)
    if args.secret:
        secrets.insert(0, args.secret)
    if args.wordlist:
        wl_path = Path(args.wordlist)
        if not wl_path.is_file():
            print(f"[!] Error: Wordlist file not found: {args.wordlist}")
            sys.exit(1)
        custom = [line.strip() for line in wl_path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
        secrets = list(dict.fromkeys(custom + secrets))

    pubkey_bytes = None
    if args.public_key:
        pk_path = Path(args.public_key)
        if not pk_path.is_file():
            print(f"[!] Error: Public key file not found: {args.public_key}")
            sys.exit(1)
        pubkey_bytes = pk_path.read_bytes()

    # Batch .har / HTTP log extraction mode
    if args.extract_file:
        ext_path = Path(args.extract_file)
        if not ext_path.is_file():
            print(f"[!] Error: Capture file not found: {args.extract_file}")
            sys.exit(1)
        tokens = extract_jwts_from_file(ext_path)
        if not tokens:
            print(f"[!] No JWT tokens (eyJ...) found in {ext_path}")
            sys.exit(1)
        print(f"[*] Batch Capture Source : {ext_path} ({len(tokens)} unique JWTs extracted)")
        print("=" * 76)
        batch_reports = []
        for idx, tok in enumerate(tokens, 1):
            try:
                parsed = parse_jwt(tok)
                rep = audit_jwt(parsed, secrets, pubkey_bytes=pubkey_bytes)
                batch_reports.append(rep)
                sub = rep["payload"].get("sub", "N/A")
                print(
                    f"  [#{idx}] alg={rep['algorithm']:<6} sub={str(sub):<18} "
                    f"score={rep['risk_score']:>3}/100  findings={len(rep['findings'])}  "
                    f"weak_secret={rep['weak_secret_found'] or 'None'}"
                )
            except ValueError as err:
                print(f"  [#{idx}] Skipped malformed token: {err}")
        print("=" * 76)
        if args.output:
            Path(args.output).write_text(json.dumps(batch_reports, indent=2), encoding="utf-8")
            print(f"[+] Saved batch JSON audit report to {args.output}")
        return

    if args.demo:
        raw_token = build_demo_jwt()
        source_label = f"{raw_token[:28]}...{raw_token[-12:]} (Built-in Demo JWT)"
    elif args.token:
        potential_file = Path(args.token)
        if potential_file.is_file():
            raw_token = potential_file.read_text(encoding="utf-8", errors="ignore").strip()
            source_label = f"File: {potential_file.name}"
        else:
            raw_token = args.token.strip()
            source_label = f"{raw_token[:28]}...{raw_token[-12:]}" if len(raw_token) > 45 else raw_token
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to audit a sample vulnerable JWT!")
        sys.exit(0)

    try:
        parsed = parse_jwt(raw_token)
    except ValueError as err:
        print(f"[!] Error: {err}")
        sys.exit(1)

    jwks_report = None
    token_kid = parsed["header"].get("kid")
    if args.demo and not args.jwks:
        jwks_report = fetch_and_audit_jwks("demo", token_kid=token_kid, demo_jwks=build_demo_jwks())
    elif args.jwks:
        try:
            jwks_report = fetch_and_audit_jwks(args.jwks, token_kid=token_kid)
        except Exception as exc:
            print(f"[!] Warning: Could not fetch JWKS from {args.jwks}: {exc}")

    report = audit_jwt(parsed, secrets, pubkey_bytes=pubkey_bytes, jwks_report=jwks_report)
    print_report(report, source_label)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Saved JSON audit report to {out_path}")


if __name__ == "__main__":
    main()
