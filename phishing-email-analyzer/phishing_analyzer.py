#!/usr/bin/env python3
"""
Phishing Email Analyzer v2.0 (Blue Team — SOC Email Triage & Threat Intel)

Triages suspicious .eml files for sender spoofing (From / Reply-To / Return-Path),
email authentication (SPF, DKIM, DMARC), Public Suffix List (PSL) registered-domain
mismatches, deceptive links, HTML credential-harvesting forms (<form>, <iframe>,
data:/javascript: URIs, 1x1 tracking pixels), dangerous attachments, and urgency
language. Supports automated IOC export (.json / .csv) and optional URLhaus /
VirusTotal threat-intelligence lookups.

MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link),
              T1598.003 (Spearphishing Link for Credential Harvesting)

Uses only the Python standard library.
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser
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
                       [ Phishing Email Analyzer v2.0 ]
"""

BRANDS = [
    "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon",
    "google", "netflix", "dhl", "fedex", "ups", "linkedin", "facebook", "instagram",
    "docusign", "stripe", "coinbase", "binance",
]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy",
}
DANGEROUS_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".hta", ".ps1", ".com", ".pif",
    ".iso", ".img", ".lnk", ".jar", ".msi", ".docm", ".xlsm", ".vhd", ".wsf",
}
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|txt|jpe?g|png|zip)\.(exe|scr|js|vbs|bat|cmd|hta|com|pif|lnk|ps1)$", re.I
)
URGENCY_PHRASES = [
    "urgent", "immediately", "suspended", "verify your account", "within 24 hours",
    "unusual activity", "confirm your identity", "password will expire", "wire transfer",
    "gift card", "final notice", "action required", "account locked", "unauthorized",
]
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
DOMAIN_TEXT_RE = re.compile(r"^(https?://)?([\w-]+\.)+[a-z]{2,}(/\S*)?$", re.I)

# Multi-part Public Suffix List (PSL) second-level TLD registry
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk",
    "com.ro", "org.ro", "tm.ro", "nt.ro", "info.ro",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "co.in", "net.in", "org.in", "gov.in",
    "com.mx", "org.mx", "gob.mx",
    "com.sg", "edu.sg", "gov.sg",
    "com.tr", "org.tr", "gov.tr",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.kr", "or.kr", "go.kr",
    "co.il", "org.il", "gov.il",
    "com.ar", "com.co", "com.pe", "com.my", "com.ph", "com.tw", "com.hk", "com.ua", "eu.org",
}


# ----------------------------------------------------------------- helpers
def base_domain(host: str) -> str:
    """Extracts the registered domain using Public Suffix List (PSL) multi-label rules."""
    if not host:
        return ""
    clean = host.lower().strip(".")
    if is_ip(clean):
        return clean
    parts = clean.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else clean


def domain_of(header_value) -> str:
    _, addr = parseaddr(str(header_value or ""))
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def defang(url: str) -> str:
    return re.sub(r"^http", "hxxp", url, flags=re.I).replace(".", "[.]")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class PhishingHTMLParser(HTMLParser):
    """Collects links, visible text, and HTML phishing traps (<form>, <iframe>, tracking pixels)."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self.forms: list[str] = []
        self.iframes: list[str] = []
        self.tracking_pixels: list[str] = []
        self.suspicious_uris: list[str] = []
        self._href: str | None = None
        self._anchor: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a":
            href = attr_map.get("href", "").strip()
            self._href, self._anchor = href, []
            if href.lower().startswith(("data:", "javascript:")):
                self.suspicious_uris.append(href[:80])
        elif t == "form":
            action = attr_map.get("action", "").strip() or "(inline form)"
            self.forms.append(action)
        elif t == "iframe":
            src = attr_map.get("src", "").strip() or "(inline iframe)"
            self.iframes.append(src)
        elif t == "img":
            src = attr_map.get("src", "").strip()
            w = attr_map.get("width", "").strip().rstrip("px")
            h = attr_map.get("height", "").strip().rstrip("px")
            style = attr_map.get("style", "").lower().replace(" ", "")
            if src.lower().startswith(("http://", "https://")) and (
                w in ("0", "1")
                or h in ("0", "1")
                or "display:none" in style
                or "visibility:hidden" in style
                or "width:1px" in style
                or "height:1px" in style
            ):
                self.tracking_pixels.append(src)

    def handle_data(self, data: str):
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)

    def handle_endtag(self, tag: str):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None


def extract_parts(msg) -> tuple[str, str, list[tuple[str, bytes]]]:
    """Return (plain_text, html_text, attachments[(filename, bytes)])."""
    plain, html, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append((filename or "(unnamed)", part.get_payload(decode=True) or b""))
            continue
        if part.get_content_maintype() != "text":
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="ignore")
        (html if part.get_content_subtype() == "html" else plain).append(content)
    return "\n".join(plain), "\n".join(html), attachments


# ------------------------------------------------------------------ checks
def check_sender(msg) -> list[tuple[str, str, int]]:
    findings = []
    from_hdr = str(msg.get("From", ""))
    display, _ = parseaddr(from_hdr)
    from_dom = domain_of(from_hdr)
    from_reg = base_domain(from_dom)

    for brand in BRANDS:
        if brand in display.lower() and brand not in from_reg.split(".")[0]:
            findings.append((
                "FAIL",
                f"Display name '{display}' impersonates {brand.title()} "
                f"but registered sender domain is {from_reg or 'unknown'}",
                20,
            ))
            break

    reply_dom = domain_of(msg.get("Reply-To"))
    if reply_dom and base_domain(reply_dom) != from_reg:
        findings.append((
            "FAIL",
            f"Reply-To registered domain ({base_domain(reply_dom)}) differs from From ({from_reg})",
            15,
        ))

    return_dom = domain_of(msg.get("Return-Path"))
    if return_dom and base_domain(return_dom) != from_reg:
        findings.append((
            "WARN",
            f"Return-Path registered domain ({base_domain(return_dom)}) differs from From ({from_reg})",
            10,
        ))
    return findings


def check_auth(msg) -> list[tuple[str, str, int]]:
    text = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    results = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", text, re.I)
        results[mech] = m.group(1).lower() if m else None
    if results["spf"] is None and msg.get("Received-SPF"):
        results["spf"] = str(msg.get("Received-SPF")).split()[0].lower()

    points = {"spf": 15, "dkim": 10, "dmarc": 20}
    findings = []
    for mech, value in results.items():
        name = mech.upper()
        if value is None:
            findings.append(("INFO", f"{name:<6} not present in headers", 0))
        elif value == "pass":
            findings.append(("PASS", f"{name:<6} pass", 0))
        elif value in ("fail", "softfail", "none", "permerror", "temperror", "neutral"):
            pts = points[mech] if value in ("fail", "softfail") else points[mech] // 2
            findings.append(("FAIL", f"{name:<6} {value}", pts))
        else:
            findings.append(("INFO", f"{name:<6} {value}", 0))
    return findings


def check_links_and_html(plain: str, html: str) -> tuple[list[tuple[str, str, int]], list[str]]:
    parser = PhishingHTMLParser()
    parser.feed(html)
    links = list(parser.links)
    seen = {href for href, _ in links}
    links += [(u, "") for u in URL_RE.findall(plain) if u not in seen]

    findings: list[tuple[str, str, int]] = []
    checked_urls: list[str] = []
    checked_set: set[str] = set()

    for href, text in links:
        if not href or not href.lower().startswith(("http://", "https://")):
            continue
        host = (urlparse(href).hostname or "").lower()
        reg_dom = base_domain(host)
        shown = defang(href)

        if text and DOMAIN_TEXT_RE.match(text):
            text_url = text if text.lower().startswith("http") else "http://" + text
            text_host = (urlparse(text_url).hostname or "").lower()
            if text_host and base_domain(text_host) != reg_dom:
                findings.append((
                    "FAIL",
                    f"Deceptive link: shows '{defang(text)}' ({base_domain(text_host)}) "
                    f"but goes to {shown} ({reg_dom})",
                    25,
                ))

        if href in checked_set:
            continue
        checked_set.add(href)
        checked_urls.append(href)

        if is_ip(host):
            findings.append(("FAIL", f"Link points to a raw IP address: {shown}", 20))
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(("FAIL", f"Punycode IDN domain (homograph risk): {shown}", 15))
        if reg_dom in SHORTENERS or host in SHORTENERS:
            findings.append(("WARN", f"URL shortener hides real destination: {shown}", 10))
        for brand in BRANDS:
            if brand in host and reg_dom.split(".")[0] != brand:
                findings.append(("FAIL", f"Lookalike {brand.title()} domain ({reg_dom}): {shown}", 20))
                break

    # HTML Evasion & Credential Harvesting Heuristics
    for action in parser.forms:
        findings.append(("FAIL", f"Embedded HTML <form> credential harvester -> {defang(action)}", 25))
        if action.lower().startswith(("http://", "https://")) and action not in checked_set:
            checked_set.add(action)
            checked_urls.append(action)

    for src in parser.iframes:
        findings.append(("FAIL", f"Hidden/embedded HTML <iframe> trap -> {defang(src)}", 20))
        if src.lower().startswith(("http://", "https://")) and src not in checked_set:
            checked_set.add(src)
            checked_urls.append(src)

    for uri in parser.suspicious_uris:
        findings.append(("FAIL", f"Obfuscated {uri.split(':', 1)[0]}: URI link in anchor tag", 20))

    for px in parser.tracking_pixels:
        findings.append(("WARN", f"1x1 / hidden tracking pixel beacon -> {defang(px)}", 10))
        if px not in checked_set:
            checked_set.add(px)
            checked_urls.append(px)

    return findings, checked_urls


def check_attachments(attachments: list[tuple[str, bytes]]) -> tuple[list[tuple[str, str, int]], list[dict]]:
    findings = []
    att_iocs = []
    for name, data in attachments:
        sha = hashlib.sha256(data).hexdigest()
        lower = name.lower()
        att_iocs.append({"filename": name, "sha256": sha, "size_bytes": len(data)})
        if DOUBLE_EXT_RE.search(lower):
            findings.append(("FAIL", f"Double extension (disguised executable): {name}", 35))
        elif any(lower.endswith(ext) for ext in DANGEROUS_EXT):
            findings.append(("FAIL", f"Dangerous attachment extension: {name}", 25))
        else:
            findings.append(("INFO", f"Attachment: {name} ({len(data)} bytes)", 0))
        findings.append(("INFO", f"  SHA-256: {sha}", 0))
    return findings, att_iocs


def check_language(subject: str, plain: str, html: str) -> list[tuple[str, str, int]]:
    parser = PhishingHTMLParser()
    parser.feed(html)
    text = " ".join([subject, plain, " ".join(parser.text)]).lower()
    hits = [p for p in URGENCY_PHRASES if p in text]
    if not hits:
        return []
    return [("WARN", f"Pressure / urgency language: {', '.join(hits)}", min(5 * len(hits), 20))]


def check_threat_intel(
    urls: list[str], attachments: list[dict], vt_key: str | None = None
) -> list[tuple[str, str, int]]:
    """Queries URLhaus (free) and optionally VirusTotal v3 API for URLs and attachment hashes."""
    findings = []
    for u in urls[:5]:
        try:
            data = urllib.parse.urlencode({"url": u}).encode("utf-8")
            req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=data)
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                if res.get("query_status") == "ok":
                    threat = res.get("threat", "malware_download")
                    findings.append(("FAIL", f"URLhaus positive hit ({threat}): {defang(u)}", 35))
        except Exception:
            pass

    if vt_key:
        for att in attachments:
            sha = att["sha256"]
            try:
                req = urllib.request.Request(
                    f"https://www.virustotal.com/api/v3/files/{sha}",
                    headers={"x-apikey": vt_key},
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    stats = res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    if mal > 0:
                        findings.append(("FAIL", f"VirusTotal: {att['filename']} flagged by {mal} engines", 40))
                    else:
                        findings.append(("PASS", f"VirusTotal: {att['filename']} (0 detections)", 0))
            except Exception:
                pass

    if not findings:
        findings.append(("INFO", "No active URLhaus / VirusTotal hits for extracted IOCs", 0))
    return findings


def export_iocs(path: str, report_data: dict) -> None:
    """Exports extracted IOCs and triage verdict to JSON or CSV."""
    out = Path(path)
    if out.suffix.lower() == ".json":
        out.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        return

    rows = []
    for ip in report_data["iocs"]["origin_ips"]:
        rows.append({"type": "origin_ip", "value": ip, "defanged": ip.replace(".", "[.]")})
    for dom in report_data["iocs"]["domains"]:
        rows.append({"type": "domain", "value": dom, "defanged": dom.replace(".", "[.]")})
    for u, df in zip(report_data["iocs"]["urls"], report_data["iocs"]["defanged_urls"]):
        rows.append({"type": "url", "value": u, "defanged": df})
    for att in report_data["iocs"]["attachments"]:
        rows.append({"type": "attachment_sha256", "value": att["sha256"], "defanged": att["filename"]})

    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "value", "defanged"])
        writer.writeheader()
        writer.writerows(rows)


# ------------------------------------------------------------------ report
def print_section(title: str, findings: list[tuple[str, str, int]]) -> int:
    print(f"\n  {title}:")
    if not findings:
        print("  [PASS] Nothing suspicious found")
        return 0
    total = 0
    for level, text, pts in findings:
        print(f"  [{level}] {text}" + (f"  (+{pts})" if pts else ""))
        total += pts
    return total


def analyze(
    msg,
    source: str,
    output_path: str | None = None,
    ti_lookup: bool = False,
    vt_key: str | None = None,
) -> int:
    plain, html, attachments = extract_parts(msg)
    received = msg.get_all("Received") or []
    origin_ips = []
    for hdr in received:
        for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(hdr)):
            if ip not in origin_ips:
                origin_ips.append(ip)

    from_dom = domain_of(msg.get("From"))
    reply_dom = domain_of(msg.get("Reply-To"))
    return_dom = domain_of(msg.get("Return-Path"))

    print(f"[*] Target Email : {source}")
    print(f"  From           : {msg.get('From', '-')}  (Registered: {base_domain(from_dom) or '-'})")
    print(f"  Reply-To       : {msg.get('Reply-To', '-')}  (Registered: {base_domain(reply_dom) or '-'})")
    print(f"  Return-Path    : {msg.get('Return-Path', '-')}")
    print(f"  Subject        : {msg.get('Subject', '-')}")
    print(f"  Origin IP(s)   : {', '.join(origin_ips) if origin_ips else '-'}")
    print("=" * 76)

    link_findings, urls = check_links_and_html(plain, html)
    att_findings, att_iocs = check_attachments(attachments)

    score = 0
    score += print_section("Authentication (SPF / DKIM / DMARC)", check_auth(msg))
    score += print_section("Sender & PSL Registered-Domain Checks", check_sender(msg))
    score += print_section(f"Links & HTML Heuristics ({len(urls)} URLs)", link_findings)
    score += print_section(f"Attachments ({len(attachments)} found)", att_findings)
    score += print_section("Social Engineering", check_language(str(msg.get("Subject", "")), plain, html))

    if ti_lookup or vt_key:
        score += print_section("Threat Intelligence (URLhaus / VirusTotal)", check_threat_intel(urls, att_iocs, vt_key))

    score = min(score, 100)
    if score >= 60:
        verdict = "PHISHING (High Confidence — Block & Quarantine)"
    elif score >= 30:
        verdict = "SUSPICIOUS (Manual SOC Review Required)"
    else:
        verdict = "LIKELY CLEAN"

    print("\n" + "=" * 76)
    print(f"  RISK SCORE: {score}/100   |   VERDICT: {verdict}")
    print("=" * 76)

    if output_path:
        domains = sorted({
            d for d in [from_dom, reply_dom, return_dom] + [(urlparse(u).hostname or "").lower() for u in urls]
            if d and not is_ip(d)
        })
        report_data = {
            "source": source,
            "subject": str(msg.get("Subject", "")),
            "risk_score": score,
            "verdict": verdict,
            "iocs": {
                "origin_ips": origin_ips,
                "domains": domains,
                "urls": urls,
                "defanged_urls": [defang(u) for u in urls],
                "attachments": att_iocs,
            },
        }
        export_iocs(output_path, report_data)
        print(f"[+] Exported extracted IOCs to {output_path}")

    return 0


# -------------------------------------------------------------------- demo
def build_demo_email() -> bytes:
    """Builds a realistic phishing email with PSL .co.uk spoofing, HTML form & tracking pixel."""
    msg = EmailMessage()
    msg["Received"] = "from mail.paypa1-security.co.uk (unknown [203.0.113.66]) by mx.example.org"
    msg["Authentication-Results"] = (
        "mx.example.org; spf=fail smtp.mailfrom=bounce@mailer.example.net; "
        "dkim=none; dmarc=fail header.from=login.paypal.paypa1-security.co.uk"
    )
    msg["Return-Path"] = "<bounce@mailer.example.net>"
    msg["From"] = "PayPal Security UK <service@login.paypal.paypa1-security.co.uk>"
    msg["Reply-To"] = "billing-support@account-help.co.uk"
    msg["To"] = "you@example.org"
    msg["Subject"] = "URGENT: Your account has been suspended"
    msg["Date"] = "Tue, 27 Oct 2026 09:14:02 +0000"
    msg.set_content(
        "Dear customer,\n\nWe detected unusual activity and your account has been suspended.\n"
        "Please verify your account within 24 hours:\n"
        "http://198.51.100.42/paypal/login.php\n"
    )
    msg.add_alternative(
        "<html><body><p>We detected <b>unusual activity</b> and your account has been suspended.</p>"
        '<p>Verify within 24 hours: <a href="http://paypal-verify.attacker.co.uk/signin">'
        "https://www.paypal.co.uk/signin</a></p>"
        '<form action="http://198.51.100.42/harvest.php" method="POST"><input name="pw"/></form>'
        '<img src="http://203.0.113.66/pixel.gif" width="1" height="1"/>'
        "</body></html>",
        subtype="html",
    )
    msg.add_attachment(
        b"Harmless demo file - not real malware.",
        maintype="application",
        subtype="octet-stream",
        filename="Invoice_Oct2026.pdf.exe",
    )
    return msg.as_bytes()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Analyze a suspicious email (.eml) for phishing indicators.")
    parser.add_argument("emlfile", nargs="?", help="Path to a .eml file")
    parser.add_argument("-o", "--output", help="Export extracted IOCs (IPs, URLs, domains, SHA-256) to .json or .csv")
    parser.add_argument("--ti-lookup", action="store_true", help="Check URLs against URLhaus threat intelligence")
    parser.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"), help="VirusTotal v3 API key (or VT_API_KEY)")
    parser.add_argument("--demo", action="store_true", help="Analyze a built-in sample phishing email")
    args = parser.parse_args()

    print(BANNER)
    if args.demo:
        return analyze(
            message_from_bytes(build_demo_email(), policy=policy.default),
            "built-in demo email",
            output_path=args.output,
            ti_lookup=args.ti_lookup,
            vt_key=args.vt_key,
        )
    if not args.emlfile:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to test with the built-in sample phishing email!")
        return 0
    try:
        with open(args.emlfile, "rb") as f:
            raw = f.read()
        msg = message_from_bytes(raw.removeprefix(b"\xef\xbb\xbf"), policy=policy.default)
    except OSError as e:
        print(f"[!] Could not read {args.emlfile}: {e}", file=sys.stderr)
        return 1
    return analyze(msg, args.emlfile, output_path=args.output, ti_lookup=args.ti_lookup, vt_key=args.vt_key)


if __name__ == "__main__":
    sys.exit(main())
