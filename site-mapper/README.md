# 🗺️ Website Crawler & Hidden Path Finder

A Python web reconnaissance tool for **pentesting and attack-surface mapping**. Starting from a single URL, it crawls linked pages to build a **visual directory tree**, harvests paths from `robots.txt` and `sitemap.xml`, and **probes for unlinked hidden endpoints** (`/admin/`, `/wp-admin/`, `/.env`, `/api/v1/`, `/backup.zip`, etc. — like a built-in mini `gobuster`/`dirb`).

## ✨ Features
- **3-in-1 Web Recon:**
  1. **BFS Link Crawler:** follows internal links and maps every page into a visual folder/file tree
  2. **`robots.txt` & `sitemap.xml` Harvester:** extracts `Disallow:` and `<loc>` entries that aren't linked anywhere in the HTML and feeds them into the crawler
  3. **Hidden Path Probe:** tests 28 common unlinked paths (or your own `-w wordlist.txt`) and classifies responses as `OPEN` (`200`), `PROTECTED` (`401`/`403`), or `REDIRECT` (`301`/`302`)
- **Attack-Surface Mapping:**
  - Collects `<form>` endpoints (`POST` / `GET` actions)
  - Flags exposed backups and config files (`.zip`, `.sql`, `.bak`, `.env`, `.log`)
  - Extracts `mailto:` email addresses, external domains, and broken links (`404`)
- **Built-in `--demo` server:** spins up a local test website on `127.0.0.1` with hidden `/admin/`, `/secret-portal/`, and `/.env` endpoints so you can test it safely offline
- Pure Python standard library, nothing to install

## 🎯 MITRE ATT&CK & OWASP Mapping
| Framework | Category |
|---|---|
| MITRE ATT&CK | [T1594 — Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594/) |
| OWASP WSTG | [WSTG-CONFIG-04 — Review Old Backup and Unreferenced Files](https://owasp.org/www-project-web-security-testing-guide/) |
| OWASP WSTG | [WSTG-INFO-03 — Review Webserver Metafiles for Information Leakage (`robots.txt`)](https://owasp.org/www-project-web-security-testing-guide/) |
| OWASP WSTG | [WSTG-INFO-06 — Identify Application Entry Points](https://owasp.org/www-project-web-security-testing-guide/) |

## 🚀 Usage
Requires **Python 3.10+**. Only scan websites you own or have explicit permission to test.

```bash
# Try it safely against the built-in local demo site
python site_mapper.py --demo

# Scan a site (crawls links + checks robots.txt + probes common hidden paths)
python site_mapper.py https://example.com

# Use a custom wordlist of paths to probe
python site_mapper.py https://example.com -w my_wordlist.txt

# Crawl links only (skip hidden-path probing) and save JSON report
python site_mapper.py https://example.com --no-probe -o report.json
```

| Option | Description |
|---|---|
| `url` | Starting URL to scan |
| `-m`, `--max-pages` | Maximum number of pages to crawl (default: 100) |
| `-d`, `--depth` | Maximum link depth from the start page (default: 3) |
| `--delay` | Seconds between requests (default: 0.3) |
| `-w`, `--wordlist` | Custom file of paths to probe (one path per line) |
| `--no-probe` | Only crawl HTML links (disable hidden-path probing) |
| `-o`, `--output` | Save output (`.json` for full report, `.txt` for URL list) |
| `--demo` | Launch and scan the built-in local test website |

## 📊 Example Output
![Website Crawler & Hidden Path Finder demo](demo.png)

```
  #####    #####   #     #  #######  #        #     #
 #     #  #     #  ##    #  #        #        #     #
 #        #     #  # #   #  #        #        #     #
  #####   #     #  #  #  #  #####    #        #     #
       #  #     #  #   # #  #        #        #     #
 #     #  #     #  #    ##  #        #        #     #
  #####    #####   #     #  #######  #######   #####
           [ Site Mapper & Hidden Path Finder ]


=== Site Mapper: scanning http://127.0.0.1:63818/ (max 100 pages, depth 3) ===

  Crawling linked pages:
  [200] http://127.0.0.1:64024/
  [200] http://127.0.0.1:64024/secret-portal/
  [200] http://127.0.0.1:64024/about.html
  [200] http://127.0.0.1:64024/blog/
  [200] http://127.0.0.1:64024/shop/products.html
  [200] http://127.0.0.1:64024/contact.html
  [404] http://127.0.0.1:64024/old-page.html
  [200] http://127.0.0.1:64024/about/team.html
  [200] http://127.0.0.1:64024/blog/post-1.html
  [200] http://127.0.0.1:64024/blog/post-2.html
  [200] http://127.0.0.1:64024/shop/cart.html
  [200] http://127.0.0.1:64024/login.html

  Probing 28 common hidden paths...
  [403 PROTECTED] http://127.0.0.1:64024/admin/
  [200 OPEN]      http://127.0.0.1:64024/api/
  [200 OPEN]      http://127.0.0.1:64024/api/v1/
  [200 OPEN]      http://127.0.0.1:64024/.env
  [200 OPEN]      http://127.0.0.1:64024/robots.txt

  Site tree (16 endpoints):
  127.0.0.1
  ├── .env
  ├── about
  │   └── team.html
  ├── about.html
  ├── admin  [403 PROTECTED]
  ├── api
  │   └── v1
  ├── blog
  │   ├── post-1.html
  │   └── post-2.html
  ├── contact.html
  ├── login.html
  ├── robots.txt
  ├── secret-portal
  └── shop
      ├── cart.html
      └── products.html

  Hidden & admin endpoints discovered:
  [ROBOTS]    http://127.0.0.1:64024/secret-portal/         (Disallow in robots.txt - HTTP 200)
  [PROTECTED] http://127.0.0.1:64024/admin/                 (forbidden - exists on server (HTTP 403))
  [OPEN     ] http://127.0.0.1:64024/api/                   (accessible without authentication)
  [OPEN     ] http://127.0.0.1:64024/api/v1/                (accessible without authentication)
  [OPEN     ] http://127.0.0.1:64024/.env                   (accessible without authentication)
  [OPEN     ] http://127.0.0.1:64024/robots.txt             (accessible without authentication)
  [LINKED]    http://127.0.0.1:64024/login.html             (interesting path found in HTML)

  Attack surface (forms & files):
  [FORM] POST -> http://127.0.0.1:64024/secret-portal/login  (on /secret-portal/)
  [FORM] POST -> http://127.0.0.1:64024/send-message  (on /contact.html)
  [FORM] POST -> http://127.0.0.1:64024/auth  (on /login.html)
  [WARN] http://127.0.0.1:64024/backup/site-backup.zip
  [FILE] http://127.0.0.1:64024/docs/report.pdf

  OSINT & broken links:
  [EMAIL]    security@example.com
  [EXTERNAL] github.com
  [EXTERNAL] www.linkedin.com
  [BROKEN]   http://127.0.0.1:64024/old-page.html  (404)

  SUMMARY: 16 endpoints, 6 hidden/admin paths, 3 forms, 2 files, 1 broken links
```

## 🛠️ Real-World Debugging & Refinements
After testing the first version on the local demo server, I ran it (with permission) against a friend's live production website — and it immediately froze and produced false positives. Debugging that real target led to three key improvements:

1. **The `sitemap.xml` infinite-loop trap:** The site's `robots.txt` pointed to a `sitemap.xml` with 180+ `<loc>` entries. My original loop appended every discovered `<loc>` URL back into the same `sitemap_urls` list it was iterating over, causing it to fetch every single page on the site as if it were another sitemap before printing anything. Separating sitemap URLs from discovered page URLs fixed the hang.
2. **False-positive redirects (`307`/`308`) on modern frameworks:** When probing hidden paths like `/phpmyadmin/` or `/wp-admin/`, the site's Next.js router automatically returned `308 Redirect` (to strip the trailing slash or add a language prefix like `/fr/`) *before* checking whether the page existed — and the destination then returned `404`. I updated the path prober to follow redirects and verify the final HTTP status code before flagging a path as `OPEN` or `PROTECTED`.
3. **Crawl priority & speed:** Seeding `robots.txt` entries ahead of normal links caused small scans (`-m 10`) to spend their entire budget on `robots.txt` URLs instead of crawling the homepage's links. Moving `robots.txt` `Disallow:` checks into a multi-threaded `ThreadPoolExecutor` probe phase made the scanner both faster and much more accurate.

## 🧠 What I Learned
- Why pentesters combine **passive crawling** (following HTML links) with **active path discovery** (probing unlinked directories and `robots.txt` entries)
- What HTTP status codes reveal during recon: `200` (open), `401`/`403` (endpoint exists on the server even though access is restricted), and why redirects must be followed to avoid false positives
- How `Disallow:` lines in `robots.txt` accidentally expose sensitive directories like `/admin` and `/dashboard`

## 🛣️ Future Improvements
- Parse JavaScript bundles for hidden API routes
- Detect custom "soft 404" error pages that return HTTP `200`
- Subdomain enumeration mode
