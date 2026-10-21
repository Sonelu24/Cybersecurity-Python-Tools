#!/usr/bin/env python3
"""
Phishing Email Analyzer - triage a suspicious .eml file like a SOC analyst.

Checks sender spoofing (From / Reply-To / Return-Path), email authentication
(SPF, DKIM, DMARC), deceptive or suspicious links, dangerous attachments and
social-engineering language, then gives a risk score and verdict.

URLs are printed "defanged" (hxxp://evil[.]com) so they can't be clicked by accident.
Attachments are never opened or executed - only their name and hash are inspected.

MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)

Uses only the Python standard library.
"""
import argparse
import hashlib
import ipaddress
import re
import sys
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

BRANDS = ["paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon",
          "google", "netflix", "dhl", "fedex", "ups", "linkedin", "facebook", "instagram"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".hta", ".ps1", ".com", ".pif",
                 ".iso", ".img", ".lnk", ".jar", ".msi", ".docm", ".xlsm"}
DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|txt|jpe?g|png|zip)\.(exe|scr|js|vbs|bat|cmd|hta|com|pif|lnk)$", re.I)
URGENCY_PHRASES = ["urgent", "immediately", "suspended", "verify your account", "within 24 hours",
                   "unusual activity", "confirm your identity", "password will expire", "wire transfer",
                   "gift card", "final notice", "action required", "account locked", "unauthorized"]
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
DOMAIN_TEXT_RE = re.compile(r"^(https?://)?([\w-]+\.)+[a-z]{2,}(/\S*)?$", re.I)


# ----------------------------------------------------------------- helpers
def base_domain(host: str) -> str:
    """Rough registered domain: last two labels (good enough for triage)."""
    return ".".join(host.lower().strip(".").split(".")[-2:]) if host else ""


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


class LinkParser(HTMLParser):
    """Collect (href, visible text) pairs and all visible text from HTML."""

    def __init__(self):
        super().__init__()
        self.links, self.text = [], []
        self._href, self._anchor = None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._anchor = dict(attrs).get("href"), []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None


def extract_parts(msg):
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
def check_sender(msg):
    findings = []
    from_hdr = str(msg.get("From", ""))
    display, _ = parseaddr(from_hdr)
    from_dom = domain_of(from_hdr)

    for brand in BRANDS:
        if brand in display.lower() and brand not in from_dom:
            findings.append(("FAIL", f"Display name '{display}' impersonates {brand.title()} "
                                     f"but was sent from {from_dom or 'unknown domain'}", 20))
            break

    reply_dom = domain_of(msg.get("Reply-To"))
    if reply_dom and base_domain(reply_dom) != base_domain(from_dom):
        findings.append(("FAIL", f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom})", 15))

    return_dom = domain_of(msg.get("Return-Path"))
    if return_dom and base_domain(return_dom) != base_domain(from_dom):
        findings.append(("WARN", f"Return-Path domain ({return_dom}) differs from From domain ({from_dom})", 10))
    return findings


def check_auth(msg):
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


def check_links(plain, html):
    parser = LinkParser()
    parser.feed(html)
    links = list(parser.links)
    seen = {href for href, _ in links}
    links += [(u, "") for u in URL_RE.findall(plain) if u not in seen]

    findings, checked = [], set()
    for href, text in links:
        if not href or not href.lower().startswith(("http://", "https://")):
            continue
        host = (urlparse(href).hostname or "").lower()
        shown = defang(href)

        if text and DOMAIN_TEXT_RE.match(text):
            text_url = text if text.lower().startswith("http") else "http://" + text
            text_host = (urlparse(text_url).hostname or "").lower()
            if text_host and base_domain(text_host) != base_domain(host):
                findings.append(("FAIL", f"Deceptive link: shows '{defang(text)}' but goes to {shown}", 25))

        if href in checked:
            continue
        checked.add(href)
        if is_ip(host):
            findings.append(("FAIL", f"Link points to a raw IP address: {shown}", 20))
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(("FAIL", f"Punycode domain (possible lookalike letters): {shown}", 15))
        if host in SHORTENERS:
            findings.append(("WARN", f"URL shortener hides the real destination: {shown}", 10))
        for brand in BRANDS:
            if brand in host and base_domain(host).split(".")[0] != brand:
                findings.append(("FAIL", f"Lookalike {brand.title()} domain: {shown}", 20))
                break
    return findings, len(checked)


def check_attachments(attachments):
    findings = []
    for name, data in attachments:
        sha = hashlib.sha256(data).hexdigest()
        lower = name.lower()
        if DOUBLE_EXT_RE.search(lower):
            findings.append(("FAIL", f"Double extension (disguised executable): {name}", 35))
        elif any(lower.endswith(ext) for ext in DANGEROUS_EXT):
            findings.append(("FAIL", f"Dangerous file type: {name}", 25))
        else:
            findings.append(("INFO", f"Attachment: {name}", 0))
        findings.append(("INFO", f"  SHA-256: {sha}", 0))
    return findings


def check_language(subject, plain, html):
    parser = LinkParser()
    parser.feed(html)
    text = " ".join([subject, plain, " ".join(parser.text)]).lower()
    hits = [p for p in URGENCY_PHRASES if p in text]
    if not hits:
        return []
    return [("WARN", f"Pressure / urgency language: {', '.join(hits)}", min(5 * len(hits), 20))]


# ------------------------------------------------------------------ report
def print_section(title, findings) -> int:
    print(f"\n  {title}:")
    if not findings:
        print("  [PASS] Nothing suspicious found")
        return 0
    total = 0
    for level, text, pts in findings:
        print(f"  [{level}] {text}" + (f"  (+{pts})" if pts else ""))
        total += pts
    return total


def analyze(msg, source: str) -> int:
    plain, html, attachments = extract_parts(msg)
    received = msg.get_all("Received") or []
    origin_ips = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(received[-1])) if received else []

    print(f"\n=== Phishing Email Analysis: {source} ===\n")
    print(f"  From        : {msg.get('From', '-')}")
    print(f"  Reply-To    : {msg.get('Reply-To', '-')}")
    print(f"  Return-Path : {msg.get('Return-Path', '-')}")
    print(f"  Subject     : {msg.get('Subject', '-')}")
    print(f"  Date        : {msg.get('Date', '-')}")
    print(f"  Origin IP   : {origin_ips[0] if origin_ips else '-'}")

    link_findings, link_count = check_links(plain, html)
    score = 0
    score += print_section("Authentication (SPF / DKIM / DMARC)", check_auth(msg))
    score += print_section("Sender checks", check_sender(msg))
    score += print_section(f"Links ({link_count} found)", link_findings)
    score += print_section(f"Attachments ({len(attachments)} found)", check_attachments(attachments))
    score += print_section("Social engineering", check_language(str(msg.get("Subject", "")), plain, html))

    score = min(score, 100)
    if score >= 60:
        verdict = "PHISHING (high confidence)"
    elif score >= 30:
        verdict = "SUSPICIOUS - handle with care"
    else:
        verdict = "LIKELY CLEAN"
    print(f"\n  RISK SCORE: {score}/100   VERDICT: {verdict}\n")
    return 0


# -------------------------------------------------------------------- demo
def build_demo_email() -> bytes:
    """A realistic fake phishing email using reserved example domains/IPs (harmless)."""
    msg = EmailMessage()
    msg["Received"] = "from mail.paypa1-security.example.com (unknown [203.0.113.66]) by mx.example.org"
    msg["Authentication-Results"] = ("mx.example.org; spf=fail smtp.mailfrom=bounce@mailer.example.net; "
                                     "dkim=none; dmarc=fail header.from=paypa1-security.example.com")
    msg["Return-Path"] = "<bounce@mailer.example.net>"
    msg["From"] = "PayPal Security <service@paypa1-security.example.com>"
    msg["Reply-To"] = "billing-support@account-help.example.org"
    msg["To"] = "you@example.org"
    msg["Subject"] = "URGENT: Your account has been suspended"
    msg["Date"] = "Wed, 21 Oct 2026 09:14:02 +0000"
    msg.set_content(
        "Dear customer,\n\nWe detected unusual activity and your account has been suspended.\n"
        "Please verify your account within 24 hours or it will be permanently closed:\n"
        "http://198.51.100.42/paypal/login.php\n\nSee the attached invoice for details.\nPayPal Security Team\n"
    )
    msg.add_alternative(
        "<html><body><p>Dear customer,</p>"
        "<p>We detected <b>unusual activity</b> and your account has been suspended.</p>"
        "<p>Please verify your account within 24 hours: "
        '<a href="http://paypal-account-verify.example.net/signin">https://www.paypal.com/signin</a></p>'
        "<p>PayPal Security Team</p></body></html>",
        subtype="html",
    )
    msg.add_attachment(b"Harmless demo file - not real malware.", maintype="application",
                       subtype="octet-stream", filename="Invoice_Oct2026.pdf.exe")
    return msg.as_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze a suspicious email (.eml) for phishing indicators.")
    parser.add_argument("emlfile", nargs="?", help="Path to a .eml file")
    parser.add_argument("--demo", action="store_true", help="Analyze a built-in sample phishing email")
    args = parser.parse_args()

    if args.demo:
        return analyze(message_from_bytes(build_demo_email(), policy=policy.default), "built-in demo email")
    if not args.emlfile:
        parser.error("provide a .eml file or use --demo")
    try:
        with open(args.emlfile, "rb") as f:
            raw = f.read()
        # Strip a UTF-8 BOM (added by some editors) - otherwise the headers aren't recognized
        msg = message_from_bytes(raw.removeprefix(b"\xef\xbb\xbf"), policy=policy.default)
    except OSError as e:
        print(f"[!] Could not read {args.emlfile}: {e}", file=sys.stderr)
        return 1
    return analyze(msg, args.emlfile)


if __name__ == "__main__":
    sys.exit(main())
