#!/usr/bin/env python3
"""
Site Mapper & Hidden Path Finder - web reconnaissance tool for pentesting & attack-surface mapping.

Combines three reconnaissance techniques in one tool:
  1. Link Crawler (BFS): follows internal links and builds a visual directory tree
  2. robots.txt & sitemap.xml Parser: extracts paths that aren't linked in the HTML
  3. Hidden Path Probe: checks common unlinked endpoints (/admin, /wp-admin, /.env, /backup.zip, ...)
     and flags whether they are OPEN (200), PROTECTED (401/403) or REDIRECTED (301/302)

Only use against websites you own or have explicit permission to test.
Uses only the Python standard library.
"""
import argparse
import functools
import json
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

USER_AGENT = "SiteMapper/1.0 (security portfolio project)"
BANNER = r"""
  #####    #####   #     #  #######  #        #     #
 #     #  #     #  ##    #  #        #        #     #
 #        #     #  # #   #  #        #        #     #
  #####   #     #  #  #  #  #####    #        #     #
       #  #     #  #   # #  #        #        #     #
 #     #  #     #  #    ##  #        #        #     #
  #####    #####   #     #  #######  #######   #####
           [ Site Mapper & Hidden Path Finder ]
"""
MAX_BYTES = 2_000_000
FILE_EXT = {".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".doc", ".docx", ".xls", ".xlsx",
            ".ppt", ".pptx", ".csv", ".txt", ".xml", ".json", ".sql", ".bak", ".old", ".log",
            ".env", ".conf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".mp4", ".mp3", ".exe"}
SENSITIVE_EXT = {".sql", ".bak", ".old", ".log", ".env", ".conf", ".zip", ".tar", ".gz", ".7z", ".rar"}
INTERESTING_WORDS = ["admin", "login", "signin", "wp-admin", "dashboard", "register", "upload",
                     "api", "config", "backup", "debug", "test", "dev", "account", "reset", "secret"]

# Common unlinked paths probed during recon (similar to a lightweight gobuster/dirb check)
COMMON_PATHS = [
    "/admin/", "/admin/login.html", "/login", "/login.html", "/wp-admin/", "/wp-login.php",
    "/dashboard/", "/panel/", "/manager/", "/phpmyadmin/",
    "/api/", "/api/v1/", "/swagger.json", "/graphql",
    "/config/", "/.env", "/config.php.bak", "/web.config",
    "/backup/", "/backup.zip", "/backup.sql", "/db.sql",
    "/uploads/", "/debug/", "/test/", "/server-status", "/robots.txt", "/sitemap.xml",
]


class PageParser(HTMLParser):
    """Collect link targets and forms from an HTML page."""

    def __init__(self):
        super().__init__()
        self.links, self.forms = [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"].strip())
        elif tag == "form":
            self.forms.append(((a.get("method") or "GET").upper(), a.get("action") or ""))


# ----------------------------------------------------------------- helpers
def normalize(url: str) -> str:
    url, _ = urldefrag(url)
    p = urlparse(url)
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", p.query, ""))


def same_site(host_a: str, host_b: str) -> bool:
    return (host_a or "").removeprefix("www.") == (host_b or "").removeprefix("www.")


def extension(url: str) -> str:
    name = urlparse(url).path.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str):
    """Return (status, content_type, final_url, body_text). status=None on network error."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            ctype = resp.headers.get("Content-Type", "")
            readable = any(t in ctype for t in ("html", "text", "xml", "json"))
            body = resp.read(MAX_BYTES) if readable else b""
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.getcode(), ctype, resp.geturl(), body.decode(charset, errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, "", url, ""
    except (urllib.error.URLError, TimeoutError, ValueError, ConnectionError):
        return None, "", url, ""


def probe_status(url: str) -> tuple[int | None, str | None]:
    """
    Check a URL and follow redirects to verify the destination actually exists
    (avoids false positives on sites like Next.js that redirect every trailing slash before 404ing).
    Returns (final_status, redirected_to_or_None).
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            final_url = normalize(resp.geturl())
            redirected = final_url if final_url != normalize(url) else None
            return resp.getcode(), redirected
    except urllib.error.HTTPError as e:
        final_url = normalize(e.geturl()) if e.geturl() else None
        redirected = final_url if final_url and final_url != normalize(url) else None
        return e.code, redirected
    except (urllib.error.URLError, TimeoutError, ValueError, ConnectionError):
        return None, None


# ------------------------------------------------- robots.txt & sitemap.xml
def harvest_robots_and_sitemap(base_url: str) -> tuple[list[tuple[str, str]], list[str]]:
    """
    Parse robots.txt and sitemap.xml for hidden or unlinked paths.
    Returns (robots_entries[(directive, url)], sitemap_urls[url]).
    """
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


# -------------------------------------------------------- hidden path probe
def probe_hidden_paths(base_url: str, paths: list[str], already_known: set[str], delay: float):
    """Probe common unlinked paths (/admin, /.env, /backup, ...) concurrently and return findings."""
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    targets = []
    for raw_path in paths:
        path = raw_path if raw_path.startswith("/") else "/" + raw_path
        target = normalize(root + path)
        if target not in already_known and target not in targets:
            targets.append(target)

    print(f"\n  Probing {len(targets)} common hidden paths...")
    discovered = []  # list of (tag, status, url, note)
    with ThreadPoolExecutor(max_workers=5) as pool:
        for target, (status, redirected_to) in zip(targets, pool.map(probe_status, targets)):
            if status == 200:
                note = f"redirects to {redirected_to} (HTTP 200)" if redirected_to else "accessible without authentication"
                discovered.append(("OPEN", status, redirected_to or target, note))
                print(f"  [200 OPEN]      {target}" + (f" -> {redirected_to}" if redirected_to else ""))
            elif status in (401, 403):
                reason = "login required (HTTP 401)" if status == 401 else "forbidden - exists on server (HTTP 403)"
                discovered.append(("PROTECTED", status, redirected_to or target, reason))
                print(f"  [{status} PROTECTED] {target}")
    return discovered


# ------------------------------------------------------------------- crawl
def crawl(start: str, max_pages: int, max_depth: int, delay: float, probe_paths: list[str]) -> dict:
    start = normalize(start)
    host = urlparse(start).hostname

    print(f"\n=== Site Mapper: scanning {start} (max {max_pages} pages, depth {max_depth}) ===\n")

    robots_entries, sitemap_pages = harvest_robots_and_sitemap(start)
    queue = deque([(start, 0)])
    seen = {start}

    pages, broken, forms = {}, [], []
    files, external, emails = set(), set(), set()

    print("  Crawling linked pages:")
    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if pages and delay:
            time.sleep(delay)

        status, ctype, final_url, html = fetch(url)
        pages[url] = status
        print(f"  [{status or 'ERR'}] {url}")
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

        for href in parser.links:
            if href.lower().startswith("mailto:"):
                emails.add(href[7:].split("?")[0])
                continue
            link = normalize(urljoin(final_url, href))
            p = urlparse(link)
            if p.scheme not in ("http", "https"):
                continue
            if not same_site(p.hostname, host):
                external.add(p.hostname)
                continue
            if extension(link) in FILE_EXT:
                files.add(link)
                continue
            if link not in seen and depth < max_depth:
                seen.add(link)
                queue.append((link, depth + 1))

        # If the page had few HTML links (e.g. JS-heavy site), fall back to sitemap.xml URLs
        if not queue and len(pages) < max_pages and sitemap_pages:
            for sm_url in sitemap_pages:
                if same_site(urlparse(sm_url).hostname, host) and sm_url not in seen:
                    seen.add(sm_url)
                    queue.append((sm_url, 1))
            sitemap_pages = []

    # Combine robots.txt Disallow paths with the hidden-path wordlist
    robots_paths = [urlparse(u).path for _, u in robots_entries]
    combined_probes = list(dict.fromkeys(robots_paths + probe_paths))
    probed = probe_hidden_paths(start, combined_probes, set(pages.keys()), delay) if combined_probes else []
    for _, status, url, _ in probed:
        pages[url] = status

    return {
        "start": start, "host": host, "pages": pages, "broken": broken,
        "robots": robots_entries, "sitemap": sitemap_pages, "probed": probed,
        "forms": forms, "files": sorted(files), "external": sorted(external),
        "emails": sorted(emails), "unvisited": len(queue),
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
    print(f"\n  Site tree ({len(live_pages)} endpoints):")
    print(f"  {r['host']}")
    print_tree(build_tree(live_pages), prefix="  ")

    print("\n  Hidden & admin endpoints discovered:")
    robots_urls = {u for _, u in r["robots"]}
    for directive, u in r["robots"]:
        status = r["pages"].get(u)
        state = f"HTTP {status} OPEN" if status == 200 else (f"HTTP {status}" if status else "HTTP 404")
        print(f"  [ROBOTS]    {u:<45} ({directive} in robots.txt - {state})")
    seen_probed = set(robots_urls)
    for tag, status, u, note in r["probed"]:
        if u in seen_probed:
            continue
        seen_probed.add(u)
        print(f"  [{tag:<9}] {u:<45} ({note})")
    interesting_linked = [
        u for u, s in r["pages"].items()
        if s and s < 400 and u not in robots_urls and all(u != pu for _, _, pu, _ in r["probed"])
        and any(w in urlparse(u).path.lower() for w in INTERESTING_WORDS)
    ]
    for u in interesting_linked:
        print(f"  [LINKED]    {u:<45} (interesting path found in HTML)")
    if not (r["robots"] or r["probed"] or interesting_linked):
        print("  [INFO] No hidden or admin endpoints found")

    print("\n  Attack surface (forms & files):")
    for page, method, action in r["forms"]:
        print(f"  [FORM] {method:<4} -> {action}  (on {urlparse(page).path})")
    for f in r["files"]:
        tag = "WARN" if extension(f) in SENSITIVE_EXT else "FILE"
        print(f"  [{tag}] {f}")
    if not (r["forms"] or r["files"]):
        print("  [INFO] No forms or downloadable files found")

    print("\n  OSINT & broken links:")
    for e in r["emails"]:
        print(f"  [EMAIL]    {e}")
    for d in r["external"]:
        print(f"  [EXTERNAL] {d}")
    for u, s in r["broken"]:
        print(f"  [BROKEN]   {u}  ({s or 'connection error'})")
    if not (r["emails"] or r["external"] or r["broken"]):
        print("  [INFO] Nothing else to report")

    hidden_count = len(r["robots"]) + len(r["probed"])
    print(f"\n  SUMMARY: {len(live_pages)} endpoints, {hidden_count} hidden/admin paths, "
          f"{len(r['forms'])} forms, {len(r['files'])} files, {len(r['broken'])} broken links")
    if r["unvisited"]:
        print(f"  [INFO] {r['unvisited']} more links queued - raise --max-pages to crawl further")
    print()


def save(r: dict, path: str):
    if path.lower().endswith(".json"):
        Path(path).write_text(json.dumps(r, indent=2), encoding="utf-8")
    else:
        Path(path).write_text("\n".join(sorted(r["pages"])) + "\n", encoding="utf-8")
    print(f"[+] Results saved to {path}")


# -------------------------------------------------------------------- demo
DEMO_SITE = {
    "index.html": '<h1>Demo Shop</h1><a href="/about.html">About</a> <a href="/blog/">Blog</a> '
                  '<a href="/shop/products.html">Shop</a> <a href="/contact.html">Contact</a> '
                  '<a href="/docs/report.pdf">Annual report</a> <a href="/old-page.html">Old page</a> '
                  '<a href="https://github.com/Sonelu24">GitHub</a> '
                  '<a href="mailto:security@example.com">Security contact</a>',
    "about.html": '<a href="/">Home</a> <a href="/about/team.html">Our team</a>',
    "about/team.html": '<a href="/about.html">Back</a> <a href="https://www.linkedin.com/">LinkedIn</a>',
    "blog/index.html": '<a href="/blog/post-1.html">Post 1</a> <a href="/blog/post-2.html">Post 2</a>',
    "blog/post-1.html": '<a href="/blog/">Back to blog</a>',
    "blog/post-2.html": '<a href="/blog/">Back</a> <a href="/backup/site-backup.zip">Download backup</a>',
    "shop/products.html": '<a href="/shop/cart.html">Cart</a> <a href="/login.html">Log in</a>',
    "shop/cart.html": '<a href="/login.html">Log in to checkout</a>',
    "login.html": '<form method="post" action="/auth"><input name="user"><input name="pass" type="password"></form>',
    "contact.html": '<form method="post" action="/send-message"><textarea name="msg"></textarea></form>',
    # Unlinked hidden endpoints (only discoverable via robots.txt or path probing!)
    "secret-portal/index.html": '<h1>Internal Portal</h1><form method="post" action="/secret-portal/login"></form>',
    "admin/index.html": "<h1>Admin Panel</h1>",
    "api/v1/index.html": '{"status": "ok", "version": "1.0"}',
    ".env": "APP_ENV=staging\nDB_HOST=10.0.0.15\n",
    "robots.txt": "User-agent: *\nDisallow: /secret-portal/\n",
}


class DemoHandler(SimpleHTTPRequestHandler):
    """Serve the demo site; return HTTP 403 for /admin/ to simulate a protected admin panel."""

    def do_GET(self):
        if self.path.rstrip("/") == "/admin":
            self.send_response(403)
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, *args):
        pass


def run_demo(args, probe_paths: list[str]) -> int:
    """Serve a fake website on localhost and scan it - no internet needed."""
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
            result = crawl(url, args.max_pages, args.depth, 0, probe_paths)
            report(result)
            if args.output:
                save(result, args.output)
        finally:
            server.shutdown()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Crawl a website, build a site tree and probe for hidden admin paths.")
    parser.add_argument("url", nargs="?", help="Start URL, e.g. https://example.com")
    parser.add_argument("-m", "--max-pages", type=int, default=100, help="Maximum pages to crawl (default: 100)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum link depth (default: 3)")
    parser.add_argument("--delay", type=float, default=0.3, help="Seconds between requests (default: 0.3)")
    parser.add_argument("-w", "--wordlist", help="Optional custom wordlist file of paths to probe")
    parser.add_argument("--no-probe", action="store_true", help="Skip probing for unlinked hidden paths")
    parser.add_argument("-o", "--output", help="Save results (.json for full data, otherwise a URL list)")
    parser.add_argument("--demo", action="store_true", help="Scan a built-in fake website on localhost")
    args = parser.parse_args()
    print(BANNER)

    if args.no_probe:
        probe_paths = []
    elif args.wordlist:
        probe_paths = [line.strip() for line in Path(args.wordlist).read_text(encoding="utf-8").splitlines()
                       if line.strip() and not line.startswith("#")]
    else:
        probe_paths = COMMON_PATHS

    if args.demo:
        return run_demo(args, probe_paths)
    if not args.url:
        parser.error("provide a URL or use --demo")
    url = args.url if args.url.startswith(("http://", "https://")) else "https://" + args.url
    try:
        result = crawl(url, args.max_pages, args.depth, max(args.delay, 0.1), probe_paths)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        return 1
    report(result)
    if args.output:
        save(result, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
