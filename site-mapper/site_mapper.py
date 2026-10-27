#!/usr/bin/env python3
"""
Site Mapper & Hidden Path Finder v2.0 (Red Team — Web Recon & Attack-Surface Mapping)

Combines five reconnaissance techniques in one tool:
  1. Link Crawler (BFS): follows internal links and builds a visual directory tree
  2. JavaScript Bundle Endpoint & Secret Extractor: parses <script src="...js"> bundles
     for hidden API routes (/api/v1/..., /graphql) and leaked client-side API keys/tokens
  3. robots.txt & sitemap.xml Parser: harvests unlinked paths and sitemaps
  4. Smart Soft-404 Fingerprinting + Hidden Path Probe: baselines custom "200 OK" SPA
     error pages so only genuine hidden endpoints (/admin, /.env, /backup.zip) are flagged
  5. Subdomain Discovery (--subdomains): queries Certificate Transparency (crt.sh) & DNS

MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning),
              T1592 (Gather Victim Host Information), OWASP A01/A05

Only use against websites you own or have explicit permission to test.
Uses only the Python standard library.
"""

import argparse
import functools
import json
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

USER_AGENT = "SiteMapper/2.0 (Security Portfolio Recon Auditor)"
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
                    [ Site Mapper & Hidden Path Finder v2.0 ]
"""
MAX_BYTES = 2_000_000
FILE_EXT = {
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".csv", ".txt", ".xml", ".json", ".sql", ".bak", ".old", ".log",
    ".env", ".conf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".mp4", ".mp3", ".exe",
}
SENSITIVE_EXT = {".sql", ".bak", ".old", ".log", ".env", ".conf", ".zip", ".tar", ".gz", ".7z", ".rar"}
INTERESTING_WORDS = [
    "admin", "login", "signin", "wp-admin", "dashboard", "register", "upload",
    "api", "config", "backup", "debug", "test", "dev", "account", "reset", "secret",
]

COMMON_PATHS = [
    "/admin/", "/admin/login.html", "/login", "/login.html", "/wp-admin/", "/wp-login.php",
    "/dashboard/", "/panel/", "/manager/", "/phpmyadmin/",
    "/api/", "/api/v1/", "/swagger.json", "/graphql",
    "/config/", "/.env", "/config.php.bak", "/web.config",
    "/backup/", "/backup.zip", "/backup.sql", "/db.sql",
    "/uploads/", "/debug/", "/test/", "/server-status", "/robots.txt", "/sitemap.xml",
]

JS_ENDPOINT_RE = re.compile(
    r"""["'`](\/(?:api|v1|v2|v3|graphql|internal|admin|auth|debug|webhook|config|users|tokens)[a-zA-Z0-9_.\-\/]*)["'`]"""
)
JS_SECRET_RE = re.compile(
    r"""(?:(?:api[_-]?key|secret|token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{12,})["'`]|(AIza[0-9A-Za-z_\-]{20,}|sk_live_[0-9a-zA-Z]{16,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}))""",
    re.I,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class PageParser(HTMLParser):
    """Collect link targets, forms, and JavaScript bundle URLs from an HTML page."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[tuple[str, str]] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        t = tag.lower()
        if t == "a" and a.get("href"):
            self.links.append(a["href"].strip())
        elif t == "form":
            self.forms.append(((a.get("method") or "GET").upper(), a.get("action") or ""))
        elif t == "script" and a.get("src"):
            self.scripts.append(a["src"].strip())


# ----------------------------------------------------------------- helpers
def normalize(url: str) -> str:
    url, _ = urldefrag(url)
    p = urlparse(url)
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", p.query, ""))


def same_site(host_a: str | None, host_b: str | None) -> bool:
    return (host_a or "").removeprefix("www.") == (host_b or "").removeprefix("www.")


def extension(url: str) -> str:
    name = urlparse(url).path.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def extract_title(html: str) -> str:
    m = TITLE_RE.search(html or "")
    return m.group(1).strip().lower() if m else ""


def fetch(url: str) -> tuple[int | None, str, str, str]:
    """Return (status, content_type, final_url, body_text). status=None on network error."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=8) as resp:
            ctype = resp.headers.get("Content-Type", "")
            readable = any(t in ctype.lower() for t in ("html", "text", "xml", "json", "javascript", "ecmascript")) or url.endswith((".js", ".env", ".bak"))
            body = resp.read(MAX_BYTES) if readable else b""
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.getcode(), ctype, resp.geturl(), body.decode(charset, errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, "", url, ""
    except (urllib.error.URLError, TimeoutError, ValueError, ConnectionError):
        return None, "", url, ""


# -------------------------------------------- Soft-404 & Hidden Path Probe
def fingerprint_soft_404(base_url: str) -> tuple[bool, str, int]:
    """
    Requests a random non-existent path to detect SPA 'Soft-404' servers that return HTTP 200
    for every URL. Returns (is_soft_404_enabled, baseline_title, baseline_length).
    """
    p = urlparse(base_url)
    canary_url = f"{p.scheme}://{p.netloc}/definitely-nonexistent-{uuid.uuid4().hex[:10]}"
    status, _, _, body = fetch(canary_url)
    if status == 200:
        return True, extract_title(body), len(body)
    return False, "", 0


def is_soft_404_match(body: str, soft404_sig: tuple[bool, str, int]) -> bool:
    enabled, base_title, base_len = soft404_sig
    if not enabled:
        return False
    title = extract_title(body)
    length_diff = abs(len(body) - base_len)
    if base_title and title == base_title and length_diff <= max(64, int(base_len * 0.08)):
        return True
    if not base_title and length_diff <= 16:
        return True
    return False


def probe_single_path(url: str, soft404_sig: tuple[bool, str, int]) -> tuple[int | None, str | None, bool]:
    """Probes a single URL, follows redirects, and checks against the soft-404 baseline."""
    status, _, final_url, body = fetch(url)
    if status is None:
        return None, None, False
    final_norm = normalize(final_url) if final_url else None
    redirected = final_norm if final_norm and final_norm != normalize(url) else None
    if status == 200 and is_soft_404_match(body, soft404_sig):
        return 404, redirected, True
    return status, redirected, False


def probe_hidden_paths(base_url: str, paths: list[str], already_known: set[str]):
    """Probes common unlinked paths concurrently with smart Soft-404 filtering."""
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    targets = []
    for raw_path in paths:
        path = raw_path if raw_path.startswith("/") else "/" + raw_path
        target = normalize(root + path)
        if target not in already_known and target not in targets:
            targets.append(target)

    soft404_sig = fingerprint_soft_404(base_url)
    soft_filtered = 0
    discovered = []

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda t: probe_single_path(t, soft404_sig), targets))

    for target, (status, redirected_to, was_soft404) in zip(targets, results):
        if was_soft404:
            soft_filtered += 1
            continue
        if status == 200:
            note = f"redirects to {redirected_to} (HTTP 200)" if redirected_to else "accessible without authentication"
            discovered.append(("OPEN", status, redirected_to or target, note))
        elif status in (401, 403):
            reason = "login required (HTTP 401)" if status == 401 else "forbidden - exists on server (HTTP 403)"
            discovered.append(("PROTECTED", status, redirected_to or target, reason))
    return discovered, soft_filtered, soft404_sig[0]


# ----------------------------------- JS Bundle Analyzer & Subdomain Recon
def analyze_js_bundle(js_url: str, js_text: str) -> tuple[list[str], list[str]]:
    """Extracts hidden API endpoints and leaked secrets/keys from a JavaScript file."""
    endpoints = sorted(set(JS_ENDPOINT_RE.findall(js_text)))
    secrets = []
    for m in JS_SECRET_RE.finditer(js_text):
        val = m.group(1) or m.group(2)
        if val and val not in secrets:
            secrets.append(f"{val[:22]}... (in {urlparse(js_url).path})")
    return endpoints, secrets


def discover_subdomains(domain: str) -> list[str]:
    """Discovers subdomains via Certificate Transparency (crt.sh) and common prefix DNS resolution."""
    if not domain or domain in ("127.0.0.1", "localhost"):
        return []
    clean_dom = domain.removeprefix("www.")
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{clean_dom}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            entries = json.loads(resp.read().decode("utf-8", errors="ignore"))
            for item in entries[:80]:
                for name in str(item.get("name_value", "")).splitlines():
                    name = name.strip().lower().removeprefix("*.")
                    if name.endswith(clean_dom):
                        found.add(name)
    except Exception:
        pass

    for prefix in ("www", "api", "dev", "staging", "admin", "mail", "portal"):
        cand = f"{prefix}.{clean_dom}"
        if cand not in found:
            try:
                socket.gethostbyname(cand)
                found.add(cand)
            except OSError:
                pass
    return sorted(found)[:15]


# ------------------------------------------------- robots.txt & sitemap.xml
def harvest_robots_and_sitemap(base_url: str) -> tuple[list[tuple[str, str]], list[str]]:
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    robots_entries, sitemap_urls = [], []

    status, _, _, text = fetch(f"{root}/robots.txt")
    if status == 200 and text:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, val = [s.strip() for s in line.split(":", 1)]
            if key.lower() == "disallow" and val.startswith("/") and val != "/":
                robots_entries.append(("Disallow", normalize(urljoin(root, val))))
            elif key.lower() == "sitemap" and val.startswith("http"):
                sitemap_urls.append(val)

    sitemaps_to_check = list(sitemap_urls) or [f"{root}/sitemap.xml"]
    discovered_pages = []
    for sm_url in sitemaps_to_check[:3]:
        status, _, _, xml = fetch(sm_url)
        if status == 200 and xml:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml, re.I):
                loc_norm = normalize(loc)
                if loc_norm.endswith(".xml") and len(sitemaps_to_check) < 5:
                    sitemaps_to_check.append(loc_norm)
                elif not loc_norm.endswith(".xml"):
                    discovered_pages.append(loc_norm)

    return robots_entries, list(dict.fromkeys(discovered_pages))


# ------------------------------------------------------------------- crawl
def crawl(
    start: str,
    max_pages: int,
    max_depth: int,
    delay: float,
    probe_paths: list[str],
    enum_subdomains: bool = False,
) -> dict:
    start = normalize(start)
    host = urlparse(start).hostname or "localhost"

    robots_entries, sitemap_pages = harvest_robots_and_sitemap(start)
    queue = deque([(start, 0)])
    seen = {start}

    pages, broken, forms = {}, [], []
    files, external, emails = set(), set(), set()
    js_bundles_seen = set()
    js_endpoints, js_secrets = set(), []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if pages and delay:
            time.sleep(delay)

        status, _, final_url, html = fetch(url)
        pages[url] = status
        if status is None or status >= 400:
            if status not in (401, 403):
                broken.append((url, status))
            continue
        if not html or not same_site(urlparse(final_url).hostname, host):
            continue

        parser = PageParser()
        parser.feed(html)
        for method, action in parser.forms:
            entry = (url, method, normalize(urljoin(final_url, action)) if action else url)
            if entry not in forms:
                forms.append(entry)

        # Inspect linked JavaScript bundles for hidden routes & secrets
        for src in parser.scripts:
            js_url = normalize(urljoin(final_url, src))
            if same_site(urlparse(js_url).hostname, host) and js_url not in js_bundles_seen:
                js_bundles_seen.add(js_url)
                j_status, _, _, js_body = fetch(js_url)
                if j_status == 200 and js_body:
                    eps, secs = analyze_js_bundle(js_url, js_body)
                    js_endpoints.update(eps)
                    for s in secs:
                        if s not in js_secrets:
                            js_secrets.append(s)

        for href in parser.links:
            if href.lower().startswith("mailto:"):
                emails.add(href[7:].split("?")[0])
                continue
            link = normalize(urljoin(final_url, href))
            p = urlparse(link)
            if p.scheme not in ("http", "https"):
                continue
            if not same_site(p.hostname, host):
                if p.hostname:
                    external.add(p.hostname)
                continue
            if extension(link) in FILE_EXT:
                files.add(link)
                continue
            if link not in seen and depth < max_depth:
                seen.add(link)
                queue.append((link, depth + 1))

        if not queue and len(pages) < max_pages and sitemap_pages:
            for sm_url in sitemap_pages:
                if same_site(urlparse(sm_url).hostname, host) and sm_url not in seen:
                    seen.add(sm_url)
                    queue.append((sm_url, 1))
            sitemap_pages = []

    robots_paths = [urlparse(u).path for _, u in robots_entries]
    combined_probes = list(dict.fromkeys(robots_paths + sorted(js_endpoints) + probe_paths))
    probed, soft404_filtered, soft404_active = (
        probe_hidden_paths(start, combined_probes, set(pages.keys()))
        if combined_probes
        else ([], 0, False)
    )
    for _, status, url, _ in probed:
        pages[url] = status

    subdomains = discover_subdomains(host) if enum_subdomains else []

    return {
        "start": start,
        "host": host,
        "pages": pages,
        "broken": broken,
        "robots": robots_entries,
        "sitemap": sitemap_pages,
        "probed": probed,
        "soft404_active": soft404_active,
        "soft404_filtered": soft404_filtered,
        "js_bundles": sorted(js_bundles_seen),
        "js_endpoints": sorted(js_endpoints),
        "js_secrets": js_secrets,
        "subdomains": subdomains,
        "forms": forms,
        "files": sorted(files),
        "external": sorted(external),
        "emails": sorted(emails),
        "unvisited": len(queue),
    }


# ------------------------------------------------------------------ report
def build_tree(pages: dict):
    tree = {}
    for url, status in pages.items():
        if status is None or status == 404:
            continue
        p = urlparse(url)
        parts = [s for s in p.path.split("/") if s]
        if not parts:
            continue
        if status in (401, 403):
            parts[-1] += f"  [{status} PROTECTED]"
        node = tree
        for part in parts:
            node = node.setdefault(part, {})
    return tree


def print_tree(node, prefix=""):
    items = sorted(node.items())
    for i, (name, child) in enumerate(items):
        last = i == len(items) - 1
        print(prefix + ("└── " if last else "├── ") + name)
        print_tree(child, prefix + ("    " if last else "│   "))


def report(r: dict):
    live_pages = {u: s for u, s in r["pages"].items() if s and s != 404}
    s404_badge = (
        f"Active ({r['soft404_filtered']} false-positive 200s filtered)"
        if r["soft404_active"]
        else "Standard HTTP 404"
    )
    print(f"[*] Target URL    : {r['start']}")
    print(f"[*] Soft-404 Mode : {s404_badge}  |  JS Bundles Analyzed: {len(r['js_bundles'])}")
    print("=" * 78)

    print(f"\n  [1] Site Directory Tree ({len(live_pages)} live endpoints):")
    print(f"  {r['host']}")
    print_tree(build_tree(live_pages), prefix="  ")

    print("\n  [2] Hidden, Admin & JS-Extracted Endpoints:")
    robots_urls = {u for _, u in r["robots"]}
    for directive, u in r["robots"]:
        status = r["pages"].get(u)
        state = f"HTTP {status} OPEN" if status == 200 else (f"HTTP {status}" if status else "HTTP 404")
        print(f"  [ROBOTS]     {urlparse(u).path:<32} ({directive} in robots.txt — {state})")
    seen_probed = set(robots_urls)
    for tag, status, u, note in r["probed"]:
        if u in seen_probed:
            continue
        seen_probed.add(u)
        print(f"  [{tag:<9}]  {urlparse(u).path:<32} ({note})")
    for ep in r["js_endpoints"]:
        print(f"  [JS-ROUTE]   {ep:<32} (extracted from JavaScript bundle)")
    for sec in r["js_secrets"]:
        print(f"  [JS-SECRET]  {sec}")

    print("\n  [3] Attack Surface (Forms, Sensitive Files & OSINT):")
    for page, method, action in r["forms"]:
        print(f"  [FORM]       {method:<4} -> {urlparse(action).path:<24} (on {urlparse(page).path})")
    for f in r["files"]:
        tag = "SENSITIVE" if extension(f) in SENSITIVE_EXT else "FILE"
        print(f"  [{tag:<9}]  {urlparse(f).path}")
    for e in r["emails"]:
        print(f"  [EMAIL]      {e}")
    for sub in r["subdomains"]:
        print(f"  [SUBDOMAIN]  {sub}")

    hidden_count = len(r["robots"]) + len(r["probed"]) + len(r["js_endpoints"])
    print("\n" + "=" * 78)
    print(
        f"  SUMMARY: {len(live_pages)} endpoints | {hidden_count} hidden/JS routes | "
        f"{len(r['js_secrets'])} JS secrets | {len(r['forms'])} forms"
    )
    print("=" * 78)


def save_report(r: dict, path: str):
    out = Path(path)
    ext = out.suffix.lower()
    if ext == ".json":
        out.write_text(json.dumps(r, indent=2), encoding="utf-8")
    elif ext in (".md", ".markdown"):
        lines = [
            f"# Attack-Surface Recon Report: `{r['start']}`",
            "",
            f"- **Live Endpoints:** `{len(r['pages'])}`",
            f"- **Soft-404 Filtering:** `{r['soft404_active']}` (`{r['soft404_filtered']}` filtered)",
            f"- **JS Bundles Analyzed:** `{len(r['js_bundles'])}`",
            "",
            "## Hidden & Probed Endpoints",
        ]
        for tag, status, u, note in r["probed"]:
            lines.append(f"- **[{tag} {status}]** `{u}` — {note}")
        lines.append("\n## JavaScript Bundle Routes & Secrets")
        for ep in r["js_endpoints"]:
            lines.append(f"- **Route:** `{ep}`")
        for sec in r["js_secrets"]:
            lines.append(f"- **Leaked Secret:** `{sec}`")
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        out.write_text("\n".join(sorted(r["pages"])) + "\n", encoding="utf-8")
    print(f"[+] Report saved to {path}")


# -------------------------------------------------------------------- demo
DEMO_SITE = {
    "index.html": (
        '<h1>Demo Shop</h1><script src="/static/app.bundle.js"></script>'
        '<a href="/about.html">About</a> <a href="/shop/products.html">Shop</a> '
        '<a href="/docs/report.pdf">Annual report</a> '
        '<a href="mailto:security@example.com">Security contact</a>'
    ),
    "static/app.bundle.js": (
        'const API_BASE = "/api/v2/internal/users";\n'
        'const GRAPHQL_URI = "/graphql";\n'
        'const api_key = "demo_secret_key_998877665544";\n'
        'fetch("/api/v1/admin/export");\n'
    ),
    "about.html": '<a href="/">Home</a>',
    "shop/products.html": '<a href="/login.html">Log in</a> <a href="/backup/db-dump.sql">DB</a>',
    "login.html": '<form method="post" action="/auth"><input name="user"><input name="pass" type="password"></form>',
    "secret-portal/index.html": '<h1>Internal Portal</h1><form method="post" action="/secret-portal/login"></form>',
    "admin/index.html": "<h1>Admin Panel</h1>",
    "api/v1/index.html": '{"status": "ok", "version": "2.0"}',
    ".env": "APP_ENV=staging\nDB_HOST=10.0.0.15\n",
    "robots.txt": "User-agent: *\nDisallow: /secret-portal/\n",
}


class DemoHandler(SimpleHTTPRequestHandler):
    """Serve the demo site; return HTTP 403 for /admin/ and simulate SPA soft-404 on unknown .html."""

    def do_GET(self):
        if self.path.rstrip("/") == "/admin":
            self.send_response(403)
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, *args):
        pass


def run_demo(args, probe_paths: list[str]) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        for name, content in DEMO_SITE.items():
            path = Path(tmp) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        handler = functools.partial(DemoHandler, directory=tmp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/"
            result = crawl(url, args.max_pages, args.depth, 0, probe_paths, args.subdomains)
            report(result)
            if args.output:
                save_report(result, args.output)
        finally:
            server.shutdown()
    return 0


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Crawl a website, extract JS bundle routes/secrets, and probe hidden paths."
    )
    parser.add_argument("url", nargs="?", help="Start URL, e.g. https://example.com")
    parser.add_argument("-m", "--max-pages", type=int, default=100, help="Maximum pages to crawl (default: 100)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum link depth (default: 3)")
    parser.add_argument("--delay", type=float, default=0.2, help="Seconds between requests (default: 0.2)")
    parser.add_argument("-w", "--wordlist", help="Optional custom wordlist file of paths to probe")
    parser.add_argument("--no-probe", action="store_true", help="Skip probing for unlinked hidden paths")
    parser.add_argument("--subdomains", action="store_true", help="Discover subdomains via crt.sh & DNS")
    parser.add_argument("-o", "--output", help="Save results (.json, .md, or .txt URL list)")
    parser.add_argument("--demo", action="store_true", help="Scan a built-in simulated website on localhost")
    args = parser.parse_args()
    print(BANNER)

    if args.no_probe:
        probe_paths = []
    elif args.wordlist:
        probe_paths = [
            line.strip()
            for line in Path(args.wordlist).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        probe_paths = COMMON_PATHS

    if args.demo:
        return run_demo(args, probe_paths)
    if not args.url:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to scan the built-in simulated web target!")
        return 0
    url = args.url if args.url.startswith(("http://", "https://")) else "https://" + args.url
    try:
        result = crawl(url, args.max_pages, args.depth, max(args.delay, 0.05), probe_paths, args.subdomains)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        return 1
    report(result)
    if args.output:
        save_report(result, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
