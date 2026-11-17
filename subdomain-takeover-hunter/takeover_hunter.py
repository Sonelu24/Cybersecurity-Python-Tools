#!/usr/bin/env python3
# Copyright (c) 2026 Alexandru Iosif Mocanu (Sonelu). All rights reserved.
"""
Subdomain Takeover & Dangling DNS Hunter v2.0 (Red Team - External Attack-Surface & DNS Recon)

Combines five attack-surface reconnaissance & takeover verification engines in one tool:
  1. Raw RFC 1035 DNS Wire-Protocol Resolver (pure Python struct + socket):
     Queries CNAME, A, AAAA, NS, MX, and TXT records directly against DNS resolvers
     (1.1.1.1 / 8.8.8.8) and inspects exact DNS RCODEs (NOERROR, NXDOMAIN, SERVFAIL).
  2. Multi-Hop CNAME Chain & Dead NXDOMAIN Tracer:
     Follows CNAME chains up to 8 hops deep and flags orphaned CNAMEs pointing to
     unregistered or deleted cloud resources.
  3. 25+ Cloud & SaaS Provider Takeover Fingerprint Engine:
     Verifies dangling CNAMEs via HTTP/HTTPS banner fingerprinting across GitHub Pages,
     AWS S3/CloudFront, Azure App Service/TrafficManager/Blob, Heroku, Vercel, Netlify,
     Shopify, Fastly, Pantheon, Zendesk, Surge.sh, Ghost, Tumblr, WordPress, Fly.io, Render, etc.
  4. Automated Subdomain Discovery (--discover):
     Harvests subdomains from Certificate Transparency logs (crt.sh) + high-value CNAME prefixes.
  5. Deep DNS Zone & Email Hijack Audit (--deep-dns):
     Audits delegated NS, MX, and SPF TXT (v=spf1 include:...) records for expired/NXDOMAIN targets.

MITRE ATT&CK: T1584.001 (Compromise Infrastructure: Domains),
              T1584.004 (Server / Cloud Service Hijacking),
              T1590.002 (Gather Victim Network Information: DNS), T1566 (Phishing)
OWASP Top 10: A05:2021 (Security Misconfiguration)

For education and authorized security testing only. Uses only the Python standard library.
"""

import argparse
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
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
              [ Subdomain Takeover & Dangling DNS Hunter v2.0 ]
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Athena-Takeover-Hunter/2.0"

# DNS Record Type Constants (RFC 1035)
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

COMMON_SUBDOMAIN_PREFIXES = [
    "docs", "blog", "dev", "staging", "stage", "test", "beta", "help",
    "support", "shop", "store", "status", "cdn", "assets", "static", "media",
    "api", "app", "portal", "careers", "jobs", "mail", "marketing", "events",
]

# 25+ Cloud & SaaS Provider Takeover Fingerprints
PROVIDER_FINGERPRINTS = [
    {
        "provider": "GitHub Pages",
        "cnames": (".github.io", ".github.com"),
        "fingerprints": (
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ),
        "nxdomain_takeover": False,
        "severity": "CRITICAL",
        "remediation": "Remove the CNAME pointing to *.github.io or claim the repository & configure the CNAME file.",
    },
    {
        "provider": "AWS S3 Bucket",
        "cnames": (".s3.amazonaws.com", ".s3-website", ".s3.dualstack."),
        "fingerprints": (
            "NoSuchBucket",
            "The specified bucket does not exist",
        ),
        "nxdomain_takeover": False,
        "severity": "CRITICAL",
        "remediation": "Delete the dangling S3 CNAME record or recreate the S3 bucket in the matching AWS region.",
    },
    {
        "provider": "AWS CloudFront",
        "cnames": (".cloudfront.net",),
        "fingerprints": (
            "Bad request",
            "We can't connect to the server for this app or website",
            "The request could not be satisfied",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the orphaned *.cloudfront.net CNAME or register the alternate domain name (CNAME) in CloudFront.",
    },
    {
        "provider": "Microsoft Azure App Service",
        "cnames": (".azurewebsites.net", ".scm.azurewebsites.net"),
        "fingerprints": (
            "404 Web Site not found",
            "Error 404 - Web app not found",
        ),
        "nxdomain_takeover": True,
        "severity": "CRITICAL",
        "remediation": "Delete the *.azurewebsites.net CNAME or use Azure Custom Domain Verification (asuid TXT record).",
    },
    {
        "provider": "Microsoft Azure Traffic Manager",
        "cnames": (".trafficmanager.net",),
        "fingerprints": ("404 Web Site not found",),
        "nxdomain_takeover": True,
        "severity": "CRITICAL",
        "remediation": "Delete the dangling *.trafficmanager.net CNAME record from DNS immediately.",
    },
    {
        "provider": "Microsoft Azure Blob / CDN",
        "cnames": (".blob.core.windows.net", ".azureedge.net", ".cloudapp.azure.com", ".cloudapp.net"),
        "fingerprints": (
            "The specified container does not exist",
            "ResourceNotFound",
            "InvalidUri",
        ),
        "nxdomain_takeover": True,
        "severity": "CRITICAL",
        "remediation": "Remove the orphaned Azure storage/cloudapp CNAME record from your DNS zone.",
    },
    {
        "provider": "Heroku",
        "cnames": (".herokuapp.com", ".herokudns.com", ".herokussl.com"),
        "fingerprints": (
            "No such app",
            "no-such-app",
            "There's nothing here, yet.",
        ),
        "nxdomain_takeover": False,
        "severity": "CRITICAL",
        "remediation": "Remove the *.herokuapp.com / *.herokudns.com CNAME record or reclaim the Heroku application.",
    },
    {
        "provider": "Vercel",
        "cnames": (".vercel.app", ".now.sh", ".vercel-dns.com"),
        "fingerprints": (
            "DEPLOYMENT_NOT_FOUND",
            "The deployment could not be found on Vercel",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the CNAME pointing to Vercel or bind the domain to an active Vercel project.",
    },
    {
        "provider": "Netlify",
        "cnames": (".netlify.app", ".netlify.com"),
        "fingerprints": (
            "Not Found - Request ID:",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.netlify.app CNAME record from your DNS zone.",
    },
    {
        "provider": "Shopify",
        "cnames": (".myshopify.com",),
        "fingerprints": (
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.myshopify.com CNAME record or claim the custom domain in Shopify Admin.",
    },
    {
        "provider": "Fastly CDN",
        "cnames": (".fastly.net", ".fastlylb.net"),
        "fingerprints": (
            "Fastly error: unknown domain",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Delete the *.fastly.net CNAME record or add the host to an active Fastly service.",
    },
    {
        "provider": "Pantheon",
        "cnames": (".pantheonsite.io", ".gotpantheon.com"),
        "fingerprints": (
            "404 error unknown site!",
            "The gods are wise, but do not know of the site which you seek.",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.pantheonsite.io CNAME record from DNS.",
    },
    {
        "provider": "Zendesk",
        "cnames": (".zendesk.com",),
        "fingerprints": (
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.zendesk.com CNAME record from DNS.",
    },
    {
        "provider": "Surge.sh",
        "cnames": (".surge.sh",),
        "fingerprints": (
            "project not found",
        ),
        "nxdomain_takeover": False,
        "severity": "CRITICAL",
        "remediation": "Delete the *.surge.sh CNAME or redeploy the Surge project on that domain.",
    },
    {
        "provider": "Ghost.io",
        "cnames": (".ghost.io",),
        "fingerprints": (
            "The thing you were looking for is no longer here",
            "Domain error",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.ghost.io CNAME record from your DNS configuration.",
    },
    {
        "provider": "Tumblr",
        "cnames": (".tumblr.com",),
        "fingerprints": (
            "Whatever you were looking for doesn't currently exist at this address",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.tumblr.com CNAME record.",
    },
    {
        "provider": "WordPress.com",
        "cnames": (".wordpress.com",),
        "fingerprints": (
            "Do you want to register",
            "doesn't exist",
        ),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Delete the *.wordpress.com CNAME record.",
    },
    {
        "provider": "Fly.io",
        "cnames": (".fly.dev", ".edgeapp.net"),
        "fingerprints": ("404 Not Found",),
        "nxdomain_takeover": True,
        "severity": "HIGH",
        "remediation": "Remove the dangling *.fly.dev CNAME record.",
    },
    {
        "provider": "Render",
        "cnames": (".onrender.com",),
        "fingerprints": ("Not Found",),
        "nxdomain_takeover": True,
        "severity": "HIGH",
        "remediation": "Remove the orphaned *.onrender.com CNAME record.",
    },
    {
        "provider": "ReadTheDocs",
        "cnames": (".readthedocs.io", ".readthedocs.org"),
        "fingerprints": ("unknown to Read the Docs",),
        "nxdomain_takeover": False,
        "severity": "MEDIUM",
        "remediation": "Remove the *.readthedocs.io CNAME record.",
    },
    {
        "provider": "Bitbucket Cloud",
        "cnames": (".bitbucket.io",),
        "fingerprints": ("Repository not found",),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Delete the *.bitbucket.io CNAME record.",
    },
    {
        "provider": "HelpScout Docs",
        "cnames": (".helpscoutdocs.com",),
        "fingerprints": ("No settings were found for this company",),
        "nxdomain_takeover": False,
        "severity": "HIGH",
        "remediation": "Remove the *.helpscoutdocs.com CNAME record.",
    },
    {
        "provider": "Unbounce",
        "cnames": (".unbouncepages.com",),
        "fingerprints": ("The requested URL was not found on this server",),
        "nxdomain_takeover": False,
        "severity": "MEDIUM",
        "remediation": "Remove the *.unbouncepages.com CNAME record.",
    },
    {
        "provider": "DigitalOcean Spaces / App Platform",
        "cnames": (".digitaloceanspaces.com", ".ondigitalocean.app"),
        "fingerprints": ("NoSuchBucket", "Domain not configured"),
        "nxdomain_takeover": True,
        "severity": "CRITICAL",
        "remediation": "Delete the DigitalOcean CNAME record from your DNS zone.",
    },
    {
        "provider": "Google Cloud Storage",
        "cnames": ("c.storage.googleapis.com", ".storage.googleapis.com"),
        "fingerprints": ("NoSuchBucket", "The specified bucket does not exist"),
        "nxdomain_takeover": False,
        "severity": "CRITICAL",
        "remediation": "Delete the c.storage.googleapis.com CNAME record.",
    },
]


# ---------------------------------------------------------------------------
# 1. Raw RFC 1035 DNS Wire-Protocol Resolver (Pure Python struct + socket)
# ---------------------------------------------------------------------------
def encode_dns_name(domain: str) -> bytes:
    """Encodes a domain name into RFC 1035 length-prefixed labels."""
    clean = domain.strip().rstrip(".")
    parts = clean.split(".") if clean else []
    out = bytearray()
    for label in parts:
        enc = label.encode("idna")
        out.append(len(enc))
        out.extend(enc)
    out.append(0)
    return bytes(out)


def decode_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decodes an RFC 1035 compressed domain name from a DNS packet."""
    labels: list[str] = []
    jumped = False
    orig_offset = offset
    hops = 0

    while offset < len(packet) and hops < 32:
        hops += 1
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        # Pointer compression (top 2 bits == 11 -> 0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                break
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(packet[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length

    final_offset = orig_offset if jumped else offset
    return ".".join(labels), final_offset


def build_dns_query(domain: str, qtype: int, txid: int | None = None) -> tuple[int, bytes]:
    """Builds a standard recursive DNS query packet (RD=1)."""
    tid = txid if txid is not None else random.randint(1, 65534)
    # Header: ID, Flags (0x0100 = Standard query, Recursion Desired), QDCOUNT=1, AN=0, NS=0, AR=0
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(domain) + struct.pack("!HH", qtype, 1)  # QCLASS=1 (IN)
    return tid, header + question


def parse_dns_response(packet: bytes) -> dict:
    """Parses a raw DNS wire-protocol response into header flags and answer records."""
    if len(packet) < 12:
        return {"rcode": -1, "rcode_name": "SHORT_PKT", "answers": []}

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    rcode = flags & 0x000F
    rcode_name = RCODE_NAMES.get(rcode, f"RCODE_{rcode}")

    offset = 12
    # Skip question section
    for _ in range(qdcount):
        _, offset = decode_dns_name(packet, offset)
        offset += 4  # QTYPE + QCLASS

    answers: list[dict] = []
    # Parse Answer + Authority records
    for section_idx in range(ancount + nscount):
        if offset >= len(packet):
            break
        rname, offset = decode_dns_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata_start = offset
        rdata = packet[offset : offset + rdlength]
        offset += rdlength

        is_answer = section_idx < ancount
        if not is_answer:
            continue

        val = ""
        if rtype == QTYPE_A and len(rdata) == 4:
            val = socket.inet_ntoa(rdata)
        elif rtype == QTYPE_AAAA and len(rdata) == 16:
            try:
                val = socket.inet_ntop(socket.AF_INET6, rdata)
            except Exception:
                val = rdata.hex()
        elif rtype in (QTYPE_CNAME, QTYPE_NS):
            val, _ = decode_dns_name(packet, rdata_start)
        elif rtype == QTYPE_MX and len(rdata) >= 3:
            pref = struct.unpack("!H", rdata[:2])[0]
            exchange, _ = decode_dns_name(packet, rdata_start + 2)
            val = f"{pref} {exchange}"
        elif rtype == QTYPE_TXT:
            txt_parts: list[str] = []
            idx = 0
            while idx < len(rdata):
                tlen = rdata[idx]
                idx += 1
                txt_parts.append(rdata[idx : idx + tlen].decode("utf-8", errors="replace"))
                idx += tlen
            val = "".join(txt_parts)

        if val:
            answers.append({"name": rname, "type": rtype, "ttl": ttl, "value": val.rstrip(".")})

    return {"txid": tid, "rcode": rcode, "rcode_name": rcode_name, "answers": answers}


def query_dns(
    domain: str, qtype: int = QTYPE_CNAME, resolver: str = "1.1.1.1", timeout: float = 3.0
) -> dict:
    """Sends a UDP DNS query (with fallback to 8.8.8.8) and returns parsed results."""
    resolvers = [resolver] if resolver == "8.8.8.8" else [resolver, "8.8.8.8"]
    _, query_pkt = build_dns_query(domain, qtype)

    for srv in resolvers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(query_pkt, (srv, 53))
                resp_pkt, _ = sock.recvfrom(4096)
                return parse_dns_response(resp_pkt)
        except Exception:
            continue

    return {"rcode": -1, "rcode_name": "TIMEOUT", "answers": []}


def trace_cname_chain(
    subdomain: str, resolver: str = "1.1.1.1", timeout: float = 3.0
) -> dict:
    """
    Traces CNAME hops up to 8 levels deep and checks whether the final target
    resolves to an A/AAAA record or dies with NXDOMAIN/SERVFAIL.
    """
    chain: list[str] = []
    current = subdomain.strip().rstrip(".")
    visited = {current.lower()}

    for _ in range(8):
        res = query_dns(current, QTYPE_CNAME, resolver=resolver, timeout=timeout)
        cnames = [a["value"] for a in res.get("answers", []) if a["type"] == QTYPE_CNAME]
        if not cnames:
            break
        next_hop = cnames[0].rstrip(".")
        chain.append(next_hop)
        if next_hop.lower() in visited:
            break
        visited.add(next_hop.lower())
        current = next_hop

    final_target = chain[-1] if chain else subdomain.strip().rstrip(".")
    a_res = query_dns(final_target, QTYPE_A, resolver=resolver, timeout=timeout)
    ips = [a["value"] for a in a_res.get("answers", []) if a["type"] == QTYPE_A]

    if not ips and a_res.get("rcode") == 0:
        aaaa_res = query_dns(final_target, QTYPE_AAAA, resolver=resolver, timeout=timeout)
        ips = [a["value"] for a in aaaa_res.get("answers", []) if a["type"] == QTYPE_AAAA]

    return {
        "subdomain": subdomain,
        "cname_chain": chain,
        "final_cname": chain[-1] if chain else None,
        "resolved_ips": ips,
        "final_rcode": a_res.get("rcode", -1),
        "final_rcode_name": a_res.get("rcode_name", "UNKNOWN"),
    }


# ---------------------------------------------------------------------------
# 2. Cloud Provider Matching & HTTP Fingerprint Verification
# ---------------------------------------------------------------------------
def match_provider_by_cname(cname: str | None) -> dict | None:
    """Checks if a CNAME target matches any of the 25+ monitored cloud/SaaS providers."""
    if not cname:
        return None
    low = cname.lower().rstrip(".")
    for entry in PROVIDER_FINGERPRINTS:
        for suffix in entry["cnames"]:
            if low.endswith(suffix) or suffix in low:
                return entry
    return None


def probe_http_banner(subdomain: str, timeout: float = 4.0) -> tuple[int | None, str]:
    """Fetches HTTP/HTTPS response body from the subdomain to inspect provider error banners."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Host": subdomain,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme == "https" else None) as resp:
                body = resp.read(32768).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as he:
            try:
                body = he.read(32768).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return he.code, body
        except Exception:
            continue
    return None, ""


def audit_single_subdomain(
    subdomain: str, resolver: str = "1.1.1.1", timeout: float = 3.5
) -> dict:
    """Audits a single subdomain for CNAME takeover, NXDOMAIN dead targets, and HTTP fingerprints."""
    dns_info = trace_cname_chain(subdomain, resolver=resolver, timeout=timeout)
    final_cname = dns_info["final_cname"]
    provider_meta = match_provider_by_cname(final_cname)
    rcode_name = dns_info["final_rcode_name"]

    status = "SAFE"
    severity = "INFO"
    provider_name = provider_meta["provider"] if provider_meta else ("Custom CNAME" if final_cname else "Direct A/AAAA")
    evidence = "Active DNS resolution"
    remediation = "None required."
    http_status = None

    if final_cname:
        # Case 1: Final CNAME target returns NXDOMAIN
        if rcode_name == "NXDOMAIN":
            if provider_meta and provider_meta.get("nxdomain_takeover"):
                status = "VULNERABLE"
                severity = provider_meta["severity"]
                evidence = f"CNAME -> {final_cname} returns DNS NXDOMAIN (Unregistered {provider_name} resource)"
                remediation = provider_meta["remediation"]
            else:
                status = "DANGLING_NXDOMAIN"
                severity = "HIGH"
                evidence = f"CNAME -> {final_cname} returns DNS NXDOMAIN (Dead external target)"
                remediation = f"Remove dangling CNAME record for {subdomain} pointing to {final_cname}."
        elif rcode_name == "SERVFAIL":
            status = "DANGLING_SERVFAIL"
            severity = "HIGH"
            evidence = f"CNAME -> {final_cname} returns DNS SERVFAIL (Broken/abandoned authority)"
            remediation = f"Inspect or remove broken CNAME delegation for {subdomain}."
        elif provider_meta:
            # Case 2: CNAME resolves, probe HTTP/HTTPS for unclaimed provider fingerprint
            http_status, body = probe_http_banner(subdomain, timeout=timeout)
            matched_fp = None
            for fp in provider_meta["fingerprints"]:
                if fp.lower() in body.lower():
                    matched_fp = fp
                    break
            if matched_fp:
                status = "VULNERABLE"
                severity = provider_meta["severity"]
                evidence = f"HTTP {http_status or 404} fingerprint matched: \"{matched_fp}\""
                remediation = provider_meta["remediation"]
            else:
                status = "SAFE"
                severity = "INFO"
                evidence = f"Cloud CNAME active ({provider_name}, HTTP {http_status or 'OK'})"
        else:
            evidence = f"CNAME -> {final_cname} ({len(dns_info['resolved_ips'])} IP(s) resolved)"
    else:
        if rcode_name == "NXDOMAIN":
            evidence = "Subdomain does not exist (NXDOMAIN)"
        elif dns_info["resolved_ips"]:
            evidence = f"Direct A/AAAA -> {', '.join(dns_info['resolved_ips'][:2])}"

    return {
        "subdomain": subdomain,
        "cname_chain": dns_info["cname_chain"],
        "final_cname": final_cname,
        "resolved_ips": dns_info["resolved_ips"],
        "dns_rcode": rcode_name,
        "provider": provider_name,
        "http_status": http_status,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# 3. Auto-Discovery (crt.sh Certificate Transparency + Common Prefixes)
# ---------------------------------------------------------------------------
def discover_subdomains(root_domain: str, timeout: float = 6.0) -> list[str]:
    """Discovers candidate subdomains via crt.sh CT logs + built-in high-value prefixes."""
    discovered: set[str] = {f"{p}.{root_domain}" for p in COMMON_SUBDOMAIN_PREFIXES}
    url = f"https://crt.sh/?q=%.{root_domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            entries = json.loads(resp.read().decode("utf-8", errors="replace"))
            for item in entries:
                for raw_name in str(item.get("name_value", "")).splitlines():
                    clean = raw_name.strip().lower().lstrip("*.")
                    if clean.endswith(f".{root_domain.lower()}") and "/" not in clean:
                        discovered.add(clean)
    except Exception:
        pass
    return sorted(discovered)[:60]


# ---------------------------------------------------------------------------
# 4. Deep DNS Hijack Audit (NS, MX, and SPF Include Takeover)
# ---------------------------------------------------------------------------
def audit_deep_dns(domain: str, resolver: str = "1.1.1.1", timeout: float = 3.5) -> list[dict]:
    """Audits NS, MX, and SPF include: records for NXDOMAIN or SERVFAIL takeover risks."""
    deep_findings: list[dict] = []

    # 1. NS Delegation Check
    ns_res = query_dns(domain, QTYPE_NS, resolver=resolver, timeout=timeout)
    for ans in ns_res.get("answers", []):
        if ans["type"] == QTYPE_NS:
            ns_host = ans["value"]
            a_check = query_dns(ns_host, QTYPE_A, resolver=resolver, timeout=timeout)
            if a_check.get("rcode_name") in ("NXDOMAIN", "SERVFAIL"):
                deep_findings.append({
                    "record_type": "NS",
                    "host": domain,
                    "target": ns_host,
                    "status": "DANGLING_NS",
                    "severity": "CRITICAL",
                    "detail": f"Delegated nameserver '{ns_host}' returns {a_check.get('rcode_name')} (Full Zone Takeover Risk)",
                })

    # 2. MX Mail Server Check
    mx_res = query_dns(domain, QTYPE_MX, resolver=resolver, timeout=timeout)
    for ans in mx_res.get("answers", []):
        if ans["type"] == QTYPE_MX:
            parts = ans["value"].split()
            mx_host = parts[-1] if parts else ans["value"]
            a_check = query_dns(mx_host, QTYPE_A, resolver=resolver, timeout=timeout)
            if a_check.get("rcode_name") == "NXDOMAIN":
                deep_findings.append({
                    "record_type": "MX",
                    "host": domain,
                    "target": mx_host,
                    "status": "DANGLING_MX",
                    "severity": "HIGH",
                    "detail": f"Mail exchanger '{mx_host}' returns NXDOMAIN (Inbound Email Hijack Risk)",
                })

    # 3. SPF TXT Include Takeover Check
    txt_res = query_dns(domain, QTYPE_TXT, resolver=resolver, timeout=timeout)
    for ans in txt_res.get("answers", []):
        if ans["type"] == QTYPE_TXT and "v=spf1" in ans["value"].lower():
            includes = re.findall(r"include:([a-zA-Z0-9_.\-]+)", ans["value"], re.I)
            for inc_domain in includes:
                inc_check = query_dns(inc_domain, QTYPE_TXT, resolver=resolver, timeout=timeout)
                if inc_check.get("rcode_name") == "NXDOMAIN":
                    deep_findings.append({
                        "record_type": "SPF (TXT)",
                        "host": domain,
                        "target": inc_domain,
                        "status": "DANGLING_SPF",
                        "severity": "HIGH",
                        "detail": f"SPF include:{inc_domain} returns NXDOMAIN (Attackers can claim domain & spoof SPF-authenticated email)",
                    })

    return deep_findings


# ---------------------------------------------------------------------------
# 5. Built-In Deterministic --demo Mode
# ---------------------------------------------------------------------------
def build_demo_report() -> dict:
    """Returns a realistic, deterministic corporate subdomain takeover audit for --demo."""
    results = [
        {
            "subdomain": "docs.example.com",
            "cname_chain": ["example-dev-docs.github.io"],
            "final_cname": "example-dev-docs.github.io",
            "resolved_ips": ["185.199.108.153"],
            "dns_rcode": "NOERROR",
            "provider": "GitHub Pages",
            "http_status": 404,
            "status": "VULNERABLE",
            "severity": "CRITICAL",
            "evidence": 'HTTP 404 fingerprint matched: "There isn\'t a GitHub Pages site here."',
            "remediation": "Remove the CNAME pointing to *.github.io or claim the repository & configure the CNAME file.",
        },
        {
            "subdomain": "assets-cdn.example.com",
            "cname_chain": ["example-static-media-prod.s3.amazonaws.com"],
            "final_cname": "example-static-media-prod.s3.amazonaws.com",
            "resolved_ips": ["52.217.168.101"],
            "dns_rcode": "NOERROR",
            "provider": "AWS S3 Bucket",
            "http_status": 404,
            "status": "VULNERABLE",
            "severity": "CRITICAL",
            "evidence": 'HTTP 404 fingerprint matched: "NoSuchBucket"',
            "remediation": "Delete the dangling S3 CNAME record or recreate the S3 bucket in the matching AWS region.",
        },
        {
            "subdomain": "staging-api.example.com",
            "cname_chain": ["alias.example.com", "example-stage- microservice.azurewebsites.net".replace(" ", "")],
            "final_cname": "example-stage-microservice.azurewebsites.net",
            "resolved_ips": [],
            "dns_rcode": "NXDOMAIN",
            "provider": "Microsoft Azure App Service",
            "http_status": None,
            "status": "VULNERABLE",
            "severity": "CRITICAL",
            "evidence": "CNAME -> example-stage-microservice.azurewebsites.net returns DNS NXDOMAIN (Unregistered Microsoft Azure App Service resource)",
            "remediation": "Delete the *.azurewebsites.net CNAME or use Azure Custom Domain Verification (asuid TXT record).",
        },
        {
            "subdomain": "support.example.com",
            "cname_chain": ["example-helpcenter.zendesk.com"],
            "final_cname": "example-helpcenter.zendesk.com",
            "resolved_ips": ["104.16.53.111"],
            "dns_rcode": "NOERROR",
            "provider": "Zendesk",
            "http_status": 404,
            "status": "VULNERABLE",
            "severity": "HIGH",
            "evidence": 'HTTP 404 fingerprint matched: "Help Center Closed"',
            "remediation": "Remove the *.zendesk.com CNAME record from DNS.",
        },
        {
            "subdomain": "shop.example.com",
            "cname_chain": ["shops.myshopify.com"],
            "final_cname": "shops.myshopify.com",
            "resolved_ips": ["23.227.38.65"],
            "dns_rcode": "NOERROR",
            "provider": "Shopify",
            "http_status": 200,
            "status": "SAFE",
            "severity": "INFO",
            "evidence": "Cloud CNAME active (Shopify, HTTP 200)",
            "remediation": "None required.",
        },
        {
            "subdomain": "portal.example.com",
            "cname_chain": [],
            "final_cname": None,
            "resolved_ips": ["93.184.215.14"],
            "dns_rcode": "NOERROR",
            "provider": "Direct A/AAAA",
            "http_status": 200,
            "status": "SAFE",
            "severity": "INFO",
            "evidence": "Direct A/AAAA -> 93.184.215.14",
            "remediation": "None required.",
        },
    ]

    deep_dns = [
        {
            "record_type": "SPF (TXT)",
            "host": "example.com",
            "target": "_spf.legacy-mailer.example.net",
            "status": "DANGLING_SPF",
            "severity": "HIGH",
            "detail": "SPF include:_spf.legacy-mailer.example.net returns NXDOMAIN (Attackers can claim domain & spoof SPF-authenticated email)",
        }
    ]

    return {
        "target_scope": "example.com (Simulated Corporate Perimeter)",
        "resolver": "1.1.1.1 (RFC 1035 Wire-Protocol)",
        "scanned_count": len(results),
        "vulnerable_count": 4,
        "deep_dns_issues": deep_dns,
        "results": results,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# ---------------------------------------------------------------------------
# 6. Reporting & Output Formatting
# ---------------------------------------------------------------------------
def print_report(report: dict) -> None:
    """Prints a compact, single-screen Subdomain Takeover & Dangling DNS report."""
    print(BANNER)
    print(f"[*] Target Scope  : {report['target_scope']}")
    print(f"[*] DNS Engine    : {report['resolver']}  |  Fingerprints Loaded: {len(PROVIDER_FINGERPRINTS)} Providers")
    print("=" * 80)

    print(f"\n[🔎 Subdomain CNAME & Takeover Audit ({report['scanned_count']} Checked)]")
    for r in report["results"]:
        badge = f"[{r['severity']}]" if r["status"] != "SAFE" else "[SAFE]"
        cname_str = f"-> {r['final_cname']}" if r["final_cname"] else "(Direct A/AAAA)"
        print(f"  • {badge:<10} {r['subdomain']:<26} {cname_str}")
        if r["status"] != "SAFE":
            print(f"               ├─ Provider : {r['provider']}  |  DNS: {r['dns_rcode']}")
            print(f"               ├─ Evidence : {r['evidence']}")
            print(f"               └─ Fix      : {r['remediation']}")

    deep = report.get("deep_dns_issues") or []
    if deep:
        print(f"\n[🛡️ Deep DNS Zone & Email Spoofing Audit ({len(deep)} Issue(s))]")
        for d in deep:
            print(f"  • [{d['severity']}]     {d['record_type']:<10} {d['host']} -> {d['target']}")
            print(f"               └─ {d['detail']}")

    vuln_total = report["vulnerable_count"] + len(deep)
    verdict = "CRITICAL - TAKEOVER VECTORS FOUND" if vuln_total > 0 else "CLEAN - NO DANGLING DNS FOUND"
    print("\n" + "=" * 80)
    print(f"[!] SUMMARY : {report['vulnerable_count']} Subdomain Takeover(s) | {len(deep)} Deep DNS Issue(s) | Verdict: {verdict}")
    print("=" * 80)


def export_markdown(report: dict) -> str:
    """Generates a Markdown assessment report for bug bounty / pentest handoff."""
    lines = [
        "# 🔴 Subdomain Takeover & Dangling DNS Assessment Report",
        "",
        f"- **Target Scope:** `{report['target_scope']}`",
        f"- **DNS Resolver:** `{report['resolver']}`",
        f"- **Timestamp:** `{report['timestamp']}`",
        f"- **Subdomains Audited:** `{report['scanned_count']}`",
        f"- **Takeover Vulnerabilities:** `{report['vulnerable_count']}`",
        "",
        "## 1. Subdomain Audit Findings",
        "",
        "| Severity | Subdomain | CNAME Target | Provider | Status | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for r in report["results"]:
        lines.append(
            f"| **{r['severity']}** | `{r['subdomain']}` | `{r['final_cname'] or 'N/A'}` | "
            f"{r['provider']} | `{r['status']}` | {r['evidence']} |"
        )
    if report.get("deep_dns_issues"):
        lines.extend(["", "## 2. Deep DNS (NS / MX / SPF) Issues", ""])
        for d in report["deep_dns_issues"]:
            lines.append(f"- **[{d['severity']}] {d['record_type']} (`{d['host']}` -> `{d['target']}`):** {d['detail']}")
    return "\n".join(lines) + "\n"


def parse_clean_domain(raw: str) -> str:
    """Strips URL schemes and paths to return a clean hostname."""
    val = raw.strip()
    if "://" in val:
        val = urlparse(val).hostname or val
    return val.split("/")[0].split(":")[0].strip().rstrip(".")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Subdomain Takeover & Dangling DNS Hunter v2.0 (Pure Python Standard Library)"
    )
    parser.add_argument("target", nargs="?", help="Target subdomain, root domain (with --discover), or input file")
    parser.add_argument("-i", "--input", help="File containing a list of subdomains to scan (one per line)")
    parser.add_argument("--discover", action="store_true", help="Auto-discover subdomains via crt.sh CT logs + common prefixes")
    parser.add_argument("--deep-dns", action="store_true", help="Audit NS, MX, and SPF include: records for dangling NXDOMAINs")
    parser.add_argument("--resolver", default="1.1.1.1", help="DNS server IP to query (default: 1.1.1.1)")
    parser.add_argument("-t", "--threads", type=int, default=15, help="Concurrent worker threads (default: 15)")
    parser.add_argument("--timeout", type=float, default=3.5, help="Query timeout in seconds (default: 3.5)")
    parser.add_argument("-o", "--output", help="Export report to JSON (.json) or Markdown (.md)")
    parser.add_argument("--demo", action="store_true", help="Run built-in subdomain takeover demonstration")
    args = parser.parse_args()

    if args.demo:
        report = build_demo_report()
        print_report(report)
        if args.output:
            out_path = Path(args.output)
            if out_path.suffix.lower() == ".md":
                out_path.write_text(export_markdown(report), encoding="utf-8")
            else:
                out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"[+] Exported report to {out_path}")
        return

    targets: list[str] = []
    scope_label = ""

    if args.input:
        in_path = Path(args.input)
        if not in_path.is_file():
            print(f"[!] Input file not found: {in_path}", file=sys.stderr)
            sys.exit(1)
        targets = [
            parse_clean_domain(line)
            for line in in_path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        scope_label = f"{in_path.name} ({len(targets)} hosts)"
    elif args.target:
        maybe_file = Path(args.target)
        if maybe_file.is_file():
            targets = [
                parse_clean_domain(line)
                for line in maybe_file.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            scope_label = f"{maybe_file.name} ({len(targets)} hosts)"
        else:
            clean_host = parse_clean_domain(args.target)
            scope_label = clean_host
            if args.discover:
                targets = discover_subdomains(clean_host, timeout=args.timeout + 2.0)
            else:
                targets = [clean_host]
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo or scan a domain: python takeover_hunter.py example.com --discover --deep-dns")
        sys.exit(0)

    def _worker(sub: str) -> dict:
        return audit_single_subdomain(sub, resolver=args.resolver, timeout=args.timeout)

    with ThreadPoolExecutor(max_workers=max(1, min(args.threads, len(targets) or 1))) as pool:
        results = list(pool.map(_worker, targets))

    deep_issues: list[dict] = []
    if args.deep_dns and args.target and not Path(args.target).is_file():
        deep_issues = audit_deep_dns(parse_clean_domain(args.target), resolver=args.resolver, timeout=args.timeout)

    vuln_count = sum(1 for r in results if r["status"] != "SAFE")
    report = {
        "target_scope": scope_label,
        "resolver": f"{args.resolver} (RFC 1035 Wire-Protocol)",
        "scanned_count": len(results),
        "vulnerable_count": vuln_count,
        "deep_dns_issues": deep_issues,
        "results": results,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    print_report(report)

    if args.output:
        out_path = Path(args.output)
        if out_path.suffix.lower() == ".md":
            out_path.write_text(export_markdown(report), encoding="utf-8")
        else:
            out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Exported report to {out_path}")


if __name__ == "__main__":
    main()
