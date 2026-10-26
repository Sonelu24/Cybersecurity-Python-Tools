#!/usr/bin/env python3
"""
JWT Security Auditor (Red Team / Application Security Assessment)
Decodes JSON Web Tokens (RFC 7519), audits headers and claims against OWASP API2:2023 /
A07:2021 best practices (alg:none, header injection, lifetime/exp issues, sensitive data exposure),
and tests HMAC (HS256/HS384/HS512) signatures against common weak development secrets.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
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
                           [ JWT Security Auditor ]
"""

# Built-in dictionary of common default/weak HMAC secrets used in development configs
DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "supersecret", "changeme",
    "admin", "development", "dev-secret", "mysecret", "secretkey", "jwtkey",
    "default", "test", "key", "private", "app_secret", "auth_secret",
    "qwerty", "letmein", "token_secret", "sonelu_demo_secret",
]

# Keywords indicating sensitive data accidentally stored in unencrypted JWT payloads
SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "internal_api_key",
    "private_key", "access_key", "ssn", "credit_card", "card_number", "cvv", "pin",
}

HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


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
        "internal_api_key": "sk-live-98a4f2c1e0b7",
        "iat": now - 3600,
        "exp": now + (365 * 86400),  # 365-day token lifetime
    }
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(b"jwt_secret", signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


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


def fmt_ts(epoch_val: int | float) -> str:
    """Formats a Unix epoch timestamp into a readable UTC string."""
    try:
        return datetime.fromtimestamp(float(epoch_val), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(epoch_val)


def audit_jwt(parsed: dict, secrets: list[str]) -> dict:
    """Evaluates header, claims, and HMAC signature strength; returns findings and risk score."""
    header = parsed["header"]
    payload = parsed["payload"]
    sig_b64 = parsed["signature_b64"]
    alg = str(header.get("alg", "MISSING"))

    findings = []
    risk_score = 0

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
    else:
        matched_secret = None

    # 2. Header injection / dangerous key parameters
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

    # 3. Expiration & lifetime checks
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

    # 4. Sensitive data exposure in unencrypted payload
    exposed_keys = [k for k in payload if k.lower() in SENSITIVE_CLAIM_KEYS]
    if exposed_keys:
        findings.append({
            "severity": "HIGH",
            "title": f"Sensitive Data in Payload ({', '.join(exposed_keys)})",
            "detail": "JWT payloads are Base64URL-encoded, NOT encrypted. Anyone with the token can read these secrets.",
        })
        risk_score += 20

    # 5. Missing standard replay/audience scope claims
    missing_std = [c for c in ("iss", "aud", "jti") if c not in payload]
    if missing_std:
        findings.append({
            "severity": "LOW",
            "title": f"Missing Scope/Replay Claims ({', '.join(missing_std)})",
            "detail": "Omitting 'aud'/'iss'/'jti' increases risk of cross-service token replay attacks.",
        })
        risk_score += 10

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
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings,
    }


def print_report(report: dict, source_label: str) -> None:
    """Prints a clean, single-screen JWT Security Audit report."""
    print(f"[*] Target Token : {source_label}")
    print(f"[*] Algorithm    : {report['algorithm']}  |  HMAC Secrets Tested: {report['secrets_tested']}")
    print("=" * 72)

    print("\n[🧩 Decoded Header & Payload]")
    print(f"  Header  : {json.dumps(report['header'])}")
    print("  Payload :")
    for k, v in report["payload"].items():
        extra = f"  ({fmt_ts(v)})" if k in ("exp", "iat", "nbf") and isinstance(v, (int, float)) else ""
        print(f"    • {k:<18}: {v}{extra}")

    print(f"\n[🚨 Security Audit Findings ({len(report['findings'])})]")
    if not report["findings"]:
        print("  ✅ No cryptographic or claim vulnerabilities detected.")
    else:
        for f in report["findings"]:
            sev = f"[{f['severity']}]"
            print(f"  • {sev:<10} {f['title']}")
            print(f"               └─ {f['detail']}")

    print("\n" + "=" * 72)
    print(f"[!] RISK SCORE   : {report['risk_score']}/100 — {report['verdict']}")
    print("=" * 72)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Decode and audit JWT tokens for alg:none, claim flaws, and weak HMAC secrets."
    )
    parser.add_argument("token", nargs="?", help="JWT string (eyJ...) or path to file containing a token")
    parser.add_argument("--demo", action="store_true", help="Audit a built-in vulnerable sample JWT")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file for HMAC secret auditing")
    parser.add_argument("-s", "--secret", help="Test a specific HMAC secret key against the token")
    parser.add_argument("-o", "--output", help="Export full audit report to a JSON file")
    args = parser.parse_args()

    print(BANNER)

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

    try:
        parsed = parse_jwt(raw_token)
    except ValueError as err:
        print(f"[!] Error: {err}")
        sys.exit(1)

    report = audit_jwt(parsed, secrets)
    print_report(report, source_label)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Saved JSON audit report to {out_path}")


if __name__ == "__main__":
    main()
