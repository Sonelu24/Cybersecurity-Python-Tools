#!/usr/bin/env python3
"""
TLS & SSL Certificate Security Inspector v2.0 (Red Team / Network & Web Security Assessment)
Connects to HTTPS endpoints to audit X.509 certificate validity/expiry, issuer chains,
OCSP/CRL revocation endpoints, Subject Alternative Names (SANs), Certificate Transparency
(crt.sh) historical subdomains (--ct-logs), active cipher suite enumeration (--enum-ciphers),
and concurrent batch domain scanning (-i) using only the Python standard library.
"""

import argparse
import hashlib
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
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
                    [ TLS & Certificate Security Inspector v2.0 ]
"""

WEAK_CIPHER_KEYWORDS = ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "ANON")

CIPHER_PROBE_FAMILIES = [
    ("TLS 1.2 ECDHE-ECDSA-AESGCM", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384"),
    ("TLS 1.2 ECDHE-RSA-AESGCM", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"),
    ("TLS 1.2 ECDHE-CHACHA20", "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"),
    ("TLS 1.2 ECDHE-CBC (Legacy)", "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA"),
    ("TLS 1.2 Static RSA (No PFS)", "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"),
    ("TLS 1.2 3DES (Weak)", "DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA"),
]


def parse_target(raw_target: str, default_port: int = 443) -> tuple[str, int]:
    """Normalizes a URL, host:port, or hostname into (hostname, port)."""
    target = raw_target.strip()
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else default_port)
        return host, port
    if ":" in target and not target.startswith("["):
        host_part, port_part = target.rsplit(":", 1)
        if port_part.isdigit():
            return host_part, int(port_part)
    return target.split("/")[0], default_port


def parse_rdn(rdn_tuple: tuple) -> dict[str, str]:
    """Flattens OpenSSL X.509 subject/issuer RDN tuples into a clean dictionary."""
    out: dict[str, str] = {}
    for item in rdn_tuple or ():
        for k, v in item:
            out[k] = v
    return out


def probe_legacy_tls(hostname: str, port: int, timeout: float) -> list[str]:
    """Checks if the server accepts deprecated TLSv1.0 or TLSv1.1 handshakes."""
    accepted_legacy = []
    if not hasattr(ssl, "TLSVersion"):
        return accepted_legacy

    for ver_name, ver_enum in (
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ):
        if ver_enum is None:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver_enum
                ctx.maximum_version = ver_enum
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        accepted_legacy.append(ver_name)
        except Exception:
            pass
    return accepted_legacy


def enumerate_accepted_ciphers(hostname: str, port: int, timeout: float = 3.0) -> list[dict]:
    """Actively probes TLS 1.3 and TLS 1.2 cipher families to see which suites the server accepts."""
    accepted = []
    # 1. Check TLS 1.3 default negotiation
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_3"):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    c_name, c_ver, c_bits = ssock.cipher() or ("UNKNOWN", "TLSv1.3", 0)
                    accepted.append({"family": "TLS 1.3 AEAD", "cipher": c_name, "protocol": c_ver, "bits": c_bits})
        except Exception:
            pass

    # 2. Probe TLS 1.2 cipher families
    for family_label, cipher_str in CIPHER_PROBE_FAMILIES:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(cipher_str)
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    c_name, c_ver, c_bits = ssock.cipher() or ("UNKNOWN", "TLSv1.2", 0)
                    accepted.append({"family": family_label, "cipher": c_name, "protocol": c_ver, "bits": c_bits})
        except Exception:
            pass
    return accepted


def query_crt_sh(hostname: str, timeout: float = 6.0) -> list[str]:
    """Queries Certificate Transparency logs (crt.sh) for historical subdomains of the target domain."""
    parts = hostname.lower().lstrip("*.").split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    url = f"https://crt.sh/?q=%25.{base_domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Sonelu-TLS-Inspector/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return []

    subdomains = set()
    for entry in data:
        for line in str(entry.get("name_value", "")).splitlines():
            clean = line.strip().lower()
            if clean and clean.endswith(base_domain) and not clean.startswith("*."):
                subdomains.add(clean)
    return sorted(subdomains)[:25]


def check_revocation_reachability(urls: list[str], timeout: float = 4.0) -> list[dict]:
    """Checks whether OCSP/CRL revocation URLs are reachable over HTTP."""
    results = []
    for u in urls[:4]:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Sonelu-TLS-Inspector/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                results.append({"url": u, "status": resp.status, "reachable": 200 <= resp.status < 400})
        except Exception as exc:
            results.append({"url": u, "status": str(exc)[:40], "reachable": False})
    return results


def inspect_live_tls(
    hostname: str,
    port: int,
    timeout: float = 6.0,
    enum_ciphers: bool = False,
    ct_logs: bool = False,
    check_revocation: bool = False,
) -> dict:
    """Connects to an HTTPS target, retrieves X.509 certificate metadata, and inspects TLS parameters."""
    verified_chain = True
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert() or {}
                der_bytes = ssock.getpeercert(binary_form=True) or b""
                tls_version = ssock.version() or "UNKNOWN"
                cipher_info = ssock.cipher() or ("UNKNOWN", "UNKNOWN", 0)
    except ssl.SSLCertVerificationError:
        verified_chain = False
        fallback_ctx = ssl.create_default_context()
        fallback_ctx.check_hostname = False
        fallback_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with fallback_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert() or {}
                der_bytes = ssock.getpeercert(binary_form=True) or b""
                tls_version = ssock.version() or "UNKNOWN"
                cipher_info = ssock.cipher() or ("UNKNOWN", "UNKNOWN", 0)

    sha256_fp = hashlib.sha256(der_bytes).hexdigest().upper() if der_bytes else "N/A"
    formatted_fp = ":".join(sha256_fp[i : i + 2] for i in range(0, min(len(sha256_fp), 32), 2)) + "..."

    subject = parse_rdn(cert_dict.get("subject", ()))
    issuer = parse_rdn(cert_dict.get("issuer", ()))
    sans = [val for kind, val in cert_dict.get("subjectAltName", ()) if kind == "DNS"]
    ocsp_urls = list(cert_dict.get("OCSP", ()))
    crl_urls = list(cert_dict.get("crlDistributionPoints", ()))

    not_before_str = cert_dict.get("notBefore", "")
    not_after_str = cert_dict.get("notAfter", "")
    now = datetime.now(timezone.utc)

    days_left = None
    total_validity_days = None
    not_before_iso = "Unknown"
    not_after_iso = "Unknown"

    if not_after_str:
        exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after_iso = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
        days_left = (exp_dt - now).days
        if not_before_str:
            start_dt = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_before_iso = start_dt.strftime("%Y-%m-%d %H:%M UTC")
            total_validity_days = (exp_dt - start_dt).days

    legacy_supported = probe_legacy_tls(hostname, port, timeout=min(timeout, 3.0))
    accepted_ciphers = enumerate_accepted_ciphers(hostname, port, timeout=min(timeout, 3.0)) if enum_ciphers else []
    ct_subdomains = query_crt_sh(hostname, timeout=min(timeout, 6.0)) if ct_logs else []
    revocation_checks = (
        check_revocation_reachability(ocsp_urls + crl_urls, timeout=min(timeout, 4.0)) if check_revocation else []
    )

    return {
        "target": f"{hostname}:{port}",
        "hostname": hostname,
        "port": port,
        "verified_chain": verified_chain,
        "tls_version": tls_version,
        "cipher_name": cipher_info[0],
        "cipher_bits": cipher_info[2] or 0,
        "subject_cn": subject.get("commonName", hostname),
        "subject_org": subject.get("organizationName", "N/A"),
        "issuer_cn": issuer.get("commonName", "Unknown Issuer"),
        "issuer_org": issuer.get("organizationName", "Unknown CA"),
        "serial_number": cert_dict.get("serialNumber", "N/A"),
        "sha256_fingerprint_short": formatted_fp,
        "not_before": not_before_iso,
        "not_after": not_after_iso,
        "days_remaining": days_left,
        "total_validity_days": total_validity_days,
        "sans": sans,
        "ocsp_urls": ocsp_urls,
        "crl_urls": crl_urls,
        "revocation_checks": revocation_checks,
        "legacy_protocols": legacy_supported,
        "accepted_ciphers": accepted_ciphers,
        "ct_subdomains": ct_subdomains,
    }


def build_demo_data() -> dict:
    """Builds a realistic misconfigured enterprise HTTPS target profile for --demo mode."""
    now = datetime.now(timezone.utc)
    start_dt = now - timedelta(days=491)
    exp_dt = now + timedelta(days=9)
    return {
        "target": "staging-gateway.example.com:443 (Built-in Demo Target)",
        "hostname": "staging-gateway.example.com",
        "port": 443,
        "verified_chain": True,
        "tls_version": "TLSv1.2",
        "cipher_name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "cipher_bits": 128,
        "subject_cn": "*.example.com",
        "subject_org": "Example Corp Staging Infrastructure",
        "issuer_cn": "Example Internal Issuing CA G2",
        "issuer_org": "Example Corp Trust Network",
        "serial_number": "04:A9:8F:12:C4:77:0B:9E",
        "sha256_fingerprint_short": "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15...",
        "not_before": start_dt.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after": exp_dt.strftime("%Y-%m-%d %H:%M UTC"),
        "days_remaining": 9,
        "total_validity_days": 500,
        "sans": [
            "*.example.com",
            "staging-gateway.example.com",
            "dev-api.example.com",
            "vpn-admin.example.com",
            "jenkins-internal.example.net",
        ],
        "ocsp_urls": ["http://ocsp.example.com/status"],
        "crl_urls": ["http://crl.example.com/issuing-g2.crl"],
        "revocation_checks": [
            {"url": "http://ocsp.example.com/status", "status": 200, "reachable": True},
            {"url": "http://crl.example.com/issuing-g2.crl", "status": 200, "reachable": True},
        ],
        "legacy_protocols": ["TLSv1.1"],
        "accepted_ciphers": [
            {"family": "TLS 1.2 ECDHE-RSA-AESGCM", "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "protocol": "TLSv1.2", "bits": 128},
            {"family": "TLS 1.2 ECDHE-CBC (Legacy)", "cipher": "ECDHE-RSA-AES128-SHA", "protocol": "TLSv1.2", "bits": 128},
            {"family": "TLS 1.2 Static RSA (No PFS)", "cipher": "AES128-SHA", "protocol": "TLSv1.2", "bits": 128},
        ],
        "ct_subdomains": [
            "old-git.example.com",
            "qa-Billing-2024.example.com",
            "shadow-api.example.com",
            "staging-gateway.example.com",
        ],
    }


def evaluate_tls_security(info: dict) -> dict:
    """Audits TLS handshake and X.509 parameters, producing findings, score (0-100), and grade."""
    findings = []
    score = 100

    # 1. Trust Chain & Self-Signed Check
    if not info["verified_chain"]:
        findings.append({
            "severity": "CRITICAL",
            "title": "Untrusted or Self-Signed Certificate Chain",
            "detail": "Certificate failed OS trust store validation (vulnerable to MITM interception).",
        })
        score -= 40

    # 2. Certificate Expiry & Lifetime Checks
    days = info["days_remaining"]
    if days is not None:
        if days < 0:
            findings.append({
                "severity": "CRITICAL",
                "title": f"Certificate Expired ({abs(days)} days ago)",
                "detail": f"Certificate expired on {info['not_after']}.",
            })
            score -= 50
        elif days <= 14:
            findings.append({
                "severity": "HIGH",
                "title": f"Certificate Imminent Expiration ({days} days remaining)",
                "detail": f"Expires on {info['not_after']}; immediate renewal required to avoid outage.",
            })
            score -= 20
        elif days <= 30:
            findings.append({
                "severity": "MEDIUM",
                "title": f"Certificate Expiring Soon ({days} days remaining)",
                "detail": f"Expires on {info['not_after']}; verify automated ACME/Let's Encrypt renewal.",
            })
            score -= 10

    if info["total_validity_days"] and info["total_validity_days"] > 398:
        findings.append({
            "severity": "LOW",
            "title": f"Excessive Certificate Validity Period ({info['total_validity_days']} days)",
            "detail": "Exceeds the 398-day CA/Browser Forum maximum validity baseline.",
        })
        score -= 5

    # 3. Protocol Version Checks
    tls_ver = info["tls_version"]
    if tls_ver in ("SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
        findings.append({
            "severity": "CRITICAL",
            "title": f"Deprecated Protocol Negotiated ({tls_ver})",
            "detail": "RFC 8996 deprecates TLS 1.0/1.1 due to BEAST/POODLE/downgrade weaknesses.",
        })
        score -= 40

    if info["legacy_protocols"]:
        protos = ", ".join(info["legacy_protocols"])
        findings.append({
            "severity": "HIGH",
            "title": f"Deprecated Legacy Protocol Enabled ({protos})",
            "detail": f"Server still accepts {protos} connections; disable all protocols below TLSv1.2.",
        })
        score -= 25

    # 4. Cipher Suite Strength & Forward Secrecy Checks
    cipher = info["cipher_name"].upper()
    bits = info["cipher_bits"]
    if any(w in cipher for w in WEAK_CIPHER_KEYWORDS) or (0 < bits < 128):
        findings.append({
            "severity": "CRITICAL",
            "title": f"Broken / Weak Cipher Suite ({info['cipher_name']})",
            "detail": "Uses broken cryptographic primitives or < 128-bit key length.",
        })
        score -= 40
    else:
        has_pfs = tls_ver == "TLSv1.3" or "ECDHE" in cipher or "DHE" in cipher
        is_cbc = "CBC" in cipher
        if not has_pfs:
            findings.append({
                "severity": "HIGH",
                "title": f"Missing Perfect Forward Secrecy ({info['cipher_name']})",
                "detail": "Static RSA key exchange allows past traffic decryption if the private key is compromised.",
            })
            score -= 20
        if is_cbc:
            findings.append({
                "severity": "MEDIUM",
                "title": f"CBC-Mode Cipher Negotiated ({info['cipher_name']})",
                "detail": "Prefer AEAD cipher suites (AES-GCM or CHACHA20-POLY1305) over legacy CBC mode.",
            })
            score -= 10

    # Check enumerated cipher families if probed
    for ac in info.get("accepted_ciphers", []):
        fam = ac["family"]
        if "No PFS" in fam and all("Forward Secrecy" not in f["title"] for f in findings):
            findings.append({
                "severity": "MEDIUM",
                "title": f"Server Accepts Static RSA Cipher Suite ({ac['cipher']})",
                "detail": "Clients without ECDHE support can negotiate static RSA without Forward Secrecy.",
            })
            score -= 10
        elif "3DES" in fam:
            findings.append({
                "severity": "HIGH",
                "title": f"Server Accepts Sweet32 3DES Cipher ({ac['cipher']})",
                "detail": "64-bit block cipher vulnerable to Sweet32 birthday attacks (CVE-2016-2183).",
            })
            score -= 20

    # 5. Revocation Hygiene (OCSP / CRL)
    if info["verified_chain"] and not info.get("ocsp_urls") and not info.get("crl_urls"):
        findings.append({
            "severity": "LOW",
            "title": "No OCSP or CRL Revocation Endpoints Listed in Certificate",
            "detail": "Certificate omits both AuthorityInfoAccess (OCSP) and CRL Distribution Points.",
        })

    # 6. Wildcard & Multi-Tenant SAN Recon Notice
    wildcards = [s for s in info["sans"] if s.startswith("*.")]
    if wildcards:
        findings.append({
            "severity": "LOW",
            "title": f"Wildcard Certificate Scope ({', '.join(wildcards)})",
            "detail": f"Single private key covers all subdomains + {len(info['sans'])} SAN entries (increases blast radius).",
        })
        score -= 5

    score = max(0, min(100, score))
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 45:
        grade = "D"
    else:
        grade = "F"

    info["score"] = score
    info["grade"] = grade
    info["findings"] = findings
    return info


def print_report(report: dict) -> None:
    """Prints a compact, single-screen TLS & Certificate Security Audit report."""
    print(f"[*] Target Host  : {report['target']}")
    print(f"[*] Handshake    : {report['tls_version']}  |  Cipher: {report['cipher_name']} ({report['cipher_bits']}-bit)")
    print("=" * 76)

    print("\n[📜 X.509 Certificate Metadata]")
    print(f"  • Subject CN   : {report['subject_cn']} ({report['subject_org']})")
    print(f"  • Issuer CA    : {report['issuer_cn']} ({report['issuer_org']})")
    print(f"  • Validity     : {report['not_before']}  →  {report['not_after']} ({report['days_remaining']} days left)")
    print(f"  • Serial / FP  : {report['serial_number']}  |  SHA256: {report['sha256_fingerprint_short']}")
    rev_count = len(report.get("ocsp_urls", [])) + len(report.get("crl_urls", []))
    if rev_count:
        sample_rev = (report.get("ocsp_urls", []) + report.get("crl_urls", []))[0]
        print(f"  • Revocation   : {rev_count} OCSP/CRL endpoint(s) ({sample_rev})")

    sans = report["sans"]
    if sans:
        preview = ", ".join(sans[:6]) + (f" (+{len(sans) - 6} more)" if len(sans) > 6 else "")
        print(f"\n[🌐 Subject Alternative Names (SANs) Discovered ({len(sans)})]")
        print(f"  • {preview}")

    ct_subs = report.get("ct_subdomains") or []
    if ct_subs:
        preview_ct = ", ".join(ct_subs[:6]) + (f" (+{len(ct_subs) - 6} more)" if len(ct_subs) > 6 else "")
        print(f"\n[🔎 Certificate Transparency (crt.sh) Subdomains ({len(ct_subs)})]")
        print(f"  • {preview_ct}")

    ciphers = report.get("accepted_ciphers") or []
    if ciphers:
        print(f"\n[🔐 Enumerated Accepted Cipher Families ({len(ciphers)})]")
        for c in ciphers:
            print(f"  • {c['family']:<28} -> {c['cipher']} ({c['protocol']}, {c['bits']}-bit)")

    print(f"\n[🚨 TLS & Certificate Security Findings ({len(report['findings'])})]")
    if not report["findings"]:
        print("  ✅ Strong TLS configuration (TLS 1.3 / AEAD cipher / valid trust chain).")
    else:
        for f in report["findings"]:
            sev = f"[{f['severity']}]"
            print(f"  • {sev:<10} {f['title']}")
            print(f"               └─ {f['detail']}")

    print("\n" + "=" * 76)
    print(f"[!] SECURITY GRADE : {report['grade']} ({report['score']}/100)")
    print("=" * 76)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Audit HTTPS targets for certificate expiry, SANs, crt.sh logs, TLS versions, and cipher suites."
    )
    parser.add_argument("target", nargs="?", help="Target hostname, host:port, or HTTPS URL (e.g. example.com)")
    parser.add_argument("--demo", action="store_true", help="Run built-in TLS & certificate security audit demo")
    parser.add_argument("-i", "--input-file", help="Path to file containing a list of domains/hosts for batch scanning")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--enum-ciphers", action="store_true", help="Actively enumerate accepted TLS 1.3/1.2 cipher families")
    parser.add_argument("--ct-logs", action="store_true", help="Query Certificate Transparency (crt.sh) for historical subdomains")
    parser.add_argument("--check-revocation", action="store_true", help="Verify OCSP/CRL revocation URL reachability")
    parser.add_argument("--timeout", type=float, default=6.0, help="Connection timeout in seconds (default: 6.0)")
    parser.add_argument("-o", "--output", help="Export full TLS audit report to a JSON file")
    args = parser.parse_args()

    print(BANNER)

    # Batch domain scanning mode (-i)
    if args.input_file:
        in_path = Path(args.input_file)
        if not in_path.is_file():
            print(f"[!] Input file not found: {in_path}", file=sys.stderr)
            sys.exit(1)
        raw_targets = [
            line.strip()
            for line in in_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        print(f"[*] Batch Domain Scan : {in_path} ({len(raw_targets)} targets)")
        print("=" * 76)

        def _audit_one(raw_t: str) -> dict:
            h, p = parse_target(raw_t, default_port=args.port)
            try:
                inf = inspect_live_tls(
                    h, p, timeout=args.timeout, enum_ciphers=args.enum_ciphers,
                    ct_logs=args.ct_logs, check_revocation=args.check_revocation
                )
                return evaluate_tls_security(inf)
            except Exception as exc:
                return {"target": f"{h}:{p}", "error": str(exc), "grade": "ERR", "score": 0}

        with ThreadPoolExecutor(max_workers=6) as pool:
            batch_results = list(pool.map(_audit_one, raw_targets))

        for res in batch_results:
            if "error" in res:
                print(f"  [ERR]  {res['target']:<28} — {res['error']}")
            else:
                print(
                    f"  [{res['grade']:<2}]   {res['target']:<28} score={res['score']:>3}/100  "
                    f"proto={res['tls_version']:<7} days_left={str(res['days_remaining']):<4} "
                    f"SANs={len(res['sans'])}"
                )
        print("=" * 76)
        if args.output:
            Path(args.output).write_text(json.dumps(batch_results, indent=2), encoding="utf-8")
            print(f"[+] Exported batch TLS audit report to {args.output}")
        return

    if args.demo:
        info = build_demo_data()
    elif args.target:
        hostname, port = parse_target(args.target, default_port=args.port)
        try:
            info = inspect_live_tls(
                hostname,
                port,
                timeout=args.timeout,
                enum_ciphers=args.enum_ciphers,
                ct_logs=args.ct_logs,
                check_revocation=args.check_revocation,
            )
        except Exception as exc:
            print(f"[!] Failed to complete TLS handshake with {hostname}:{port} — {exc}")
            sys.exit(1)
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo or pass a domain like: python tls_inspector.py example.com")
        sys.exit(0)

    report = evaluate_tls_security(info)
    print_report(report)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Exported TLS audit report to {out_path}")


if __name__ == "__main__":
    main()
