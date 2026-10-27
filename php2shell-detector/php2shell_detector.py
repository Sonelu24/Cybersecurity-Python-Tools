#!/usr/bin/env python3
"""
PHP2Shell Log & Web Shell Detector (Blue Team — SOC / DFIR & Rapid-Response Threat Hunting)
Detects exploitation indicators for the October 2026 "PHP2Shell" core PHP engine RCE vulnerabilities
(CVE-2026-109618 OOM longjmp heap corruption, CVE-2026-109619 persistent worker Use-After-Free,
CVE-2026-115560 session.upload_progress abuse, and CVE-2024-4577 PHP-CGI RCE) across Apache/Nginx/PHP
logs and scans webroots for dropped post-exploitation PHP web shells.
"""

import argparse
import base64
import codecs
import json
import re
import sys
import time
import urllib.request
import uuid
import zlib
from collections import defaultdict
from datetime import datetime
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
                    [ PHP2Shell Log & Web Shell Detector ]
"""

# Built-in simulated Apache mod_php & PHP Engine incident telemetry for --demo mode
DEMO_LOGS = """
198.51.100.77 - - [27/Oct/2026:08:14:02 +0000] "POST /index.php HTTP/1.1" 500 0 "-" "Mozilla/5.0"
198.51.100.77 - - [27/Oct/2026:08:14:03 +0000] "POST /index.php HTTP/1.1" 500 0 "-" "Mozilla/5.0"
[Tue Oct 27 08:14:03.412091 2026] [php:error] [pid 14820] [client 198.51.100.77:51922] PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0
[Tue Oct 27 08:14:03.418902 2026] [core:notice] [pid 14820] zend_mm_heap corrupted during longjmp request teardown
203.0.113.210 - - [27/Oct/2026:08:16:19 +0000] "POST /login.php?PHP_SESSION_UPLOAD_PROGRESS=ovr_uaf_state HTTP/1.1" 500 182 "-" "curl/8.7.1"
[Tue Oct 27 08:16:19.882104 2026] [core:notice] [pid 14825] [client 203.0.113.210:44801] AH00052: child pid 14825 exit signal Segmentation fault (11), possible stale worker state reuse (fatal_error_backtraces)
203.0.113.210 - - [27/Oct/2026:08:16:20 +0000] "POST /uploads/cache_sync.php?cmd=id HTTP/1.1" 200 1420 "-" "curl/8.7.1"
192.0.2.99 - - [27/Oct/2026:08:19:44 +0000] "POST /cgi-bin/php-cgi.exe?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input HTTP/1.1" 404 209 "-" "Scanner/1.0"
"""

# Inert, non-functional test fixture: it only mimics the *layering* of real obfuscated shells
# (str_rot13 -> gzinflate/base64 -> base64) so the static deobfuscator can be demonstrated.
_DEMO_INNER_FIXTURE = (
    "/* INERT DEMO FIXTURE - not functional */ "
    '$auth_key = "demo_k3y_2026"; $beacon = "http://203.0.113.66/c2/gate.php"; '
    'echo "test fixture only";'
)


def _build_demo_encoded_fixture() -> str:
    """Wraps the inert fixture in 3 static encoding layers (no executable payload)."""
    layer1 = f"eval(str_rot13('{codecs.encode(_DEMO_INNER_FIXTURE, 'rot13')}'));"
    deflater = zlib.compressobj(9, zlib.DEFLATED, -15)  # raw DEFLATE == PHP gzinflate()
    raw = deflater.compress(layer1.encode()) + deflater.flush()
    layer2 = f"eval(gzinflate(base64_decode('{base64.b64encode(raw).decode()}')));"
    return f"<?php @error_reporting(0); eval(base64_decode('{base64.b64encode(layer2.encode()).decode()}')); ?>"


DEMO_WEBROOT_FILES = {
    "/var/www/html/index.php": "<?php require_once 'config.php'; render_home(); ?>",
    "/var/www/html/uploads/cache_sync.php": _build_demo_encoded_fixture(),
}

# Static decoding chain: nested decoder calls wrapped around a quoted string literal
DECODER_CHAIN_RE = re.compile(
    r"((?:(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(\s*)+)(['\"])((?:(?!\2).){8,})\2\s*\)",
    re.I | re.S,
)
SECRET_ASSIGN_RE = re.compile(r"\$(?:\w*(?:key|pass|pwd|secret|token|auth)\w*)\s*=\s*['\"]([^'\"]{4,})['\"]", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>)]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Static PHP web shell indicators (MITRE ATT&CK T1505.003)
WEBSHELL_PATTERNS = [
    (re.compile(r"\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(", re.I), "Obfuscated eval(base64/gzinflate) payload execution"),
    (re.compile(r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I), "Direct OS command execution from HTTP superglobal"),
    (re.compile(r"\bassert\s*\(\s*\$_(?:POST|REQUEST|GET)", re.I), "Dynamic assert() code execution backdoor"),
    (re.compile(r"create_function\s*\(.*\$_(?:POST|REQUEST|GET)", re.I), "Legacy create_function() web shell construct"),
]


def defang_ip(ip: str) -> str:
    """Defangs an IPv4 address for safe SOC reporting."""
    return ip.replace(".", "[.]")


def analyze_logs(raw_log_text: str) -> list[dict]:
    """Correlates HTTP access and PHP/Apache error log lines for PHP2Shell exploitation."""
    ip_stats: dict[str, dict] = defaultdict(lambda: {
        "post_500s": 0,
        "oom_errors": 0,
        "heap_corrupt": 0,
        "upload_progress": 0,
        "segfaults": 0,
        "cgi_rce": 0,
        "webshell_hits": [],
    })

    access_re = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+\"(POST|GET|PUT)\s+([^\s\"]+)[^\"]*\"\s+(\d{3})"
    )
    client_ip_re = re.compile(r"\[client\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\]")

    last_ip = "UNKNOWN"
    for line in raw_log_text.splitlines():
        line = line.strip()
        if not line:
            continue

        m_acc = access_re.match(line)
        if m_acc:
            ip, method, uri, status = m_acc.groups()
            last_ip = ip
            stats = ip_stats[ip]
            if method == "POST" and status == "500":
                stats["post_500s"] += 1
            if "PHP_SESSION_UPLOAD_PROGRESS" in uri or "session.upload_progress" in uri:
                stats["upload_progress"] += 1
            if re.search(r"allow_url_include|auto_prepend_file|%ADd", uri, re.I):
                stats["cgi_rce"] += 1
            if re.search(r"(?:uploads|tmp|cache|images)/[^\s?]+\.php\?(?:cmd|c|exec|sh)=", uri, re.I):
                stats["webshell_hits"].append(uri)
            continue

        m_cli = client_ip_re.search(line)
        err_ip = m_cli.group(1) if m_cli else last_ip

        if "Allowed memory size of" in line and "bytes exhausted" in line:
            ip_stats[err_ip]["oom_errors"] += 1
        if "zend_mm_heap corrupted" in line or "longjmp" in line:
            ip_stats[err_ip]["heap_corrupt"] += 1
        if "Segmentation fault (11)" in line or "fatal_error_backtraces" in line:
            ip_stats[err_ip]["segfaults"] += 1

    alerts = []
    for ip, st in ip_stats.items():
        if st["oom_errors"] > 0 and (st["post_500s"] > 0 or st["heap_corrupt"] > 0):
            alerts.append({
                "severity": "CRITICAL",
                "cve": "CVE-2026-109618 (PHP2Shell OOM longjmp RCE)",
                "mitre": "T1190 (Exploit Public-Facing Application)",
                "source_ip": ip,
                "detail": (
                    f"{st['post_500s']} HTTP 500 POSTs + {st['oom_errors']} PHP OOM exhaustion event(s) "
                    f"({'heap corruption detected' if st['heap_corrupt'] else 'teardown anomaly'})."
                ),
            })
        if st["upload_progress"] > 0 or st["segfaults"] > 0:
            alerts.append({
                "severity": "CRITICAL",
                "cve": "CVE-2026-109619 / CVE-2026-115560 (PHP2Shell Worker UAF)",
                "mitre": "T1190 / T1068 (Worker State Use-After-Free)",
                "source_ip": ip,
                "detail": (
                    f"Upload-progress state poisoning ({st['upload_progress']} reqs) + "
                    f"Apache/mod_php worker segfaults ({st['segfaults']}) followed by worker reuse."
                ),
            })
        if st["webshell_hits"]:
            alerts.append({
                "severity": "CRITICAL",
                "cve": "Post-Exploitation Command Execution",
                "mitre": "T1505.003 (Server Software Component: Web Shell)",
                "source_ip": ip,
                "detail": f"Active command execution against dropped script: {st['webshell_hits'][0]}",
            })
        if st["cgi_rce"] > 0:
            alerts.append({
                "severity": "HIGH",
                "cve": "CVE-2024-4577 (PHP-CGI Argument Injection Probe)",
                "mitre": "T1190 (Exploit Public-Facing Application)",
                "source_ip": ip,
                "detail": f"{st['cgi_rce']} PHP-CGI allow_url_include / auto_prepend_file RCE probe(s) blocked/404.",
            })

    return alerts


def _apply_decoder(func: str, data: bytes) -> bytes:
    """Applies one PHP decoder function statically (pure data transform, never executes code)."""
    func = func.lower()
    if func == "base64_decode":
        return base64.b64decode(re.sub(rb"\s+", b"", data) + b"===", validate=False)
    if func == "gzinflate":
        return zlib.decompress(data, -15)
    if func == "gzuncompress":
        return zlib.decompress(data)
    if func == "gzdecode":
        return zlib.decompress(data, 16 + zlib.MAX_WBITS)
    if func == "str_rot13":
        return codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")
    if func == "strrev":
        return data[::-1]
    raise ValueError(func)


def deobfuscate_php(content: str, max_layers: int = 10) -> dict:
    """Statically peels nested decoder layers (base64/gzinflate/rot13/strrev) and extracts IOCs."""
    current = content
    layers = 0
    for _ in range(max_layers):
        match = DECODER_CHAIN_RE.search(current)
        if not match:
            break
        funcs = re.findall(r"(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)", match.group(1), re.I)
        data = match.group(3).encode("latin-1", errors="ignore")
        try:
            for fn in reversed(funcs):  # innermost call is applied first
                data = _apply_decoder(fn, data)
        except Exception:
            break
        current = data.decode("utf-8", errors="ignore")
        layers += 1

    urls = sorted(set(URL_RE.findall(current))) if layers else []
    url_hosts = {u.split("/")[2].split(":")[0] for u in urls}
    ips = sorted({ip for ip in IP_RE.findall(current) if ip not in url_hosts}) if layers else []
    secrets = sorted(set(SECRET_ASSIGN_RE.findall(current))) if layers else []
    return {
        "layers": layers,
        "decoded_preview": current[:160],
        "decoded": current,
        "iocs": {"urls": urls, "ips": ips, "secrets": secrets},
    }


def defang_url(url: str) -> str:
    """Defangs a URL for safe reporting."""
    return re.sub(r"^http", "hxxp", url, flags=re.I).replace(".", "[.]")


def scan_webroot_map(file_map: dict[str, str]) -> list[dict]:
    """Scans a mapping of {filepath: content} for PHP web shell indicators (+ static deobfuscation)."""
    findings = []
    for fpath, content in file_map.items():
        matched_reasons = []
        for regex, desc in WEBSHELL_PATTERNS:
            if regex.search(content):
                matched_reasons.append(desc)
        if matched_reasons:
            deob = deobfuscate_php(content)
            # Re-scan the fully decoded layer for indicators hidden by the obfuscation
            if deob["layers"]:
                for regex, desc in WEBSHELL_PATTERNS:
                    if regex.search(deob["decoded"]) and desc not in matched_reasons:
                        matched_reasons.append(f"{desc} (hidden in decoded layer)")
            findings.append({
                "severity": "CRITICAL",
                "file": fpath,
                "mitre": "T1505.003 (Web Shell)",
                "indicators": matched_reasons,
                "deobfuscation": {k: v for k, v in deob.items() if k != "decoded"},
            })
    return findings


def scan_webroot_dir(webroot: Path) -> list[dict]:
    """Recursively reads .php/.phtml/.inc files in a directory and scans for web shells."""
    file_map: dict[str, str] = {}
    for ext in ("*.php", "*.phtml", "*.php5", "*.inc"):
        for p in webroot.rglob(ext):
            if p.is_file() and p.stat().st_size <= 2_000_000:
                file_map[str(p)] = p.read_text(encoding="utf-8", errors="ignore")
    return scan_webroot_map(file_map)


def print_report(log_alerts: list[dict], webshell_findings: list[dict], source_label: str) -> None:
    """Prints a compact, single-screen PHP2Shell SOC Detection Report."""
    print(f"[*] Telemetry Source : {source_label}")
    print("[*] Target Threats   : PHP2Shell (CVE-2026-109618, CVE-2026-109619, CVE-2026-115560) + Web Shells")
    print("=" * 76)

    print(f"\n[🚨 Log Exploitation Alerts ({len(log_alerts)})]")
    if not log_alerts:
        print("  ✅ No PHP2Shell OOM/UAF exploitation patterns found in logs.")
    else:
        for alert in log_alerts:
            sev = f"[{alert['severity']}]"
            ip_disp = defang_ip(alert["source_ip"])
            print(f"  • {sev:<10} {alert['cve']}  |  Src: {ip_disp}")
            print(f"               ├─ MITRE : {alert['mitre']}")
            print(f"               └─ Trace : {alert['detail']}")

    print(f"\n[🐚 Webroot Post-Exploitation Triage ({len(webshell_findings)} Suspicious File(s))]")
    if not webshell_findings:
        print("  ✅ No PHP web shell signatures detected in scanned webroot.")
    else:
        for wf in webshell_findings:
            print(f"  • [{wf['severity']}] {wf['file']}  [{wf['mitre']}]")
            for ind in wf["indicators"]:
                print(f"               └─ Indicator: {ind}")
            deob = wf.get("deobfuscation") or {}
            if deob.get("layers"):
                iocs = deob["iocs"]
                print(f"               🔓 Static Deobfuscation : {deob['layers']} layer(s) peeled (code never executed)")
                for u in iocs["urls"]:
                    print(f"                  ├─ C2 URL   : {defang_url(u)}")
                for ip in iocs["ips"]:
                    print(f"                  ├─ IP       : {defang_ip(ip)}")
                for s in iocs["secrets"]:
                    print(f"                  └─ Hardcoded Key: {s}")

    has_crit = any(a["severity"] == "CRITICAL" for a in log_alerts) or bool(webshell_findings)
    verdict = (
        "CRITICAL — Active PHP2Shell Exploitation & Web Shell Drop Detected!"
        if has_crit
        else ("HIGH — RCE Probing Detected (Verify Patch Floor)" if log_alerts else "CLEAN — No Active Exploitation")
    )
    print("\n" + "=" * 76)
    print(f"[!] INCIDENT VERDICT : {verdict}")
    print("=" * 76)


# --- Sigma & Wazuh detection rule export ------------------------------------
_RULE_NS = uuid.UUID("6f1c2a52-5a0e-4c39-9b8e-50e1e7a2d026")

SIGMA_RULES = [
    {
        "file": "php2shell_cve-2026-109618.yml",
        "title": "PHP2Shell CVE-2026-109618 Memory Exhaustion During Request Teardown",
        "logsource": "category: webserver\n  product: apache",
        "keywords": ["Allowed memory size of", "zend_mm_heap corrupted"],
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1190", "cve.2026-109618"],
    },
    {
        "file": "php2shell_cve-2026-109619.yml",
        "title": "PHP2Shell CVE-2026-109619 Worker Crash After Upload Progress Request",
        "logsource": "category: webserver\n  product: apache",
        "keywords": ["PHP_SESSION_UPLOAD_PROGRESS", "exit signal Segmentation fault (11)"],
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1190", "cve.2026-109619"],
    },
    {
        "file": "php_webshell_access.yml",
        "title": "Suspicious PHP Script Access in Upload or Cache Directory",
        "logsource": "category: webserver",
        "keywords": ["/uploads/*.php?cmd=", "/cache/*.php?cmd=", "/tmp/*.php?cmd="],
        "level": "high",
        "tags": ["attack.persistence", "attack.t1505.003"],
    },
]

WAZUH_RULES = [
    (100901, 14, "Allowed memory size of|zend_mm_heap corrupted", "PHP2Shell CVE-2026-109618 memory exhaustion indicator", "T1190"),
    (100902, 14, "PHP_SESSION_UPLOAD_PROGRESS|exit signal Segmentation fault", "PHP2Shell CVE-2026-109619 worker crash indicator", "T1190"),
    (100903, 12, "uploads/.+php.cmd=|cache/.+php.cmd=", "Suspicious PHP script access in upload/cache directory", "T1505.003"),
]

def build_sigma_rule(rule: dict) -> str:
    """Renders one Sigma rule as YAML text (no external YAML library needed)."""
    rule_id = uuid.uuid5(_RULE_NS, rule["file"])
    keywords = "\n".join(f"    - '{k}'" for k in rule["keywords"])
    tags = "\n".join(f"  - {t}" for t in rule["tags"])
    return (
        f"title: {rule['title']}\n"
        f"id: {rule_id}\n"
        "status: experimental\n"
        "description: Generated by php2shell_detector.py for SOC detection engineering.\n"
        "author: Sonelu\n"
        f"date: {datetime.now().strftime('%Y-%m-%d')}\n"
        f"tags:\n{tags}\n"
        f"logsource:\n  {rule['logsource']}\n"
        f"detection:\n  keywords:\n{keywords}\n  condition: keywords\n"
        "falsepositives:\n  - Legitimate memory-heavy uploads or unrelated worker crashes\n"
        f"level: {rule['level']}\n"
    )


def build_wazuh_rules() -> str:
    """Renders Wazuh local rules XML for the PHP2Shell indicators."""
    body = []
    for rid, level, regex, desc, mitre in WAZUH_RULES:
        body.append(
            f'  <rule id="{rid}" level="{level}">\n'
            f'    <regex type="pcre2">{regex}</regex>\n'
            f"    <description>{desc}</description>\n"
            f"    <mitre><id>{mitre}</id></mitre>\n"
            "  </rule>"
        )
    return '<group name="php2shell,web,">\n' + "\n".join(body) + "\n</group>\n"


def export_rules(out_dir: Path) -> list[Path]:
    """Writes all Sigma + Wazuh rules to a directory and returns the file paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for rule in SIGMA_RULES:
        path = out_dir / rule["file"]
        path.write_text(build_sigma_rule(rule), encoding="utf-8")
        written.append(path)
    wazuh_path = out_dir / "php2shell_wazuh_rules.xml"
    wazuh_path.write_text(build_wazuh_rules(), encoding="utf-8")
    written.append(wazuh_path)
    return written


def send_webhook(url: str, alert: dict) -> None:
    """POSTs an alert as JSON to a Slack/Discord/Teams-style webhook (failures never crash the monitor)."""
    text = f"[{alert['severity']}] {alert['cve']} | Src: {defang_ip(alert['source_ip'])} | {alert['detail']}"
    payload = json.dumps({"text": text, "content": text}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except Exception as exc:
        print(f"    [!] Webhook delivery failed: {exc}")


def follow_log(log_path: Path, interval: float = 1.0, webhook: str | None = None, window: int = 500) -> None:
    """Tails a growing log (like `tail -f`), re-correlating a sliding window and printing new alerts once."""
    print(f"[*] Live monitoring : {log_path}  (poll {interval}s, window {window} lines) | Ctrl+C to stop")
    if webhook:
        print("[*] Webhook alerts  : enabled")
    print("=" * 76)

    recent: list[str] = []
    seen: set[tuple[str, str]] = set()
    total_alerts = 0
    position = log_path.stat().st_size  # start at end of file, like tail -f

    try:
        while True:
            size = log_path.stat().st_size
            if size < position:  # log rotated or truncated
                print(f"[{datetime.now():%H:%M:%S}] [i] Log rotation detected, re-reading from start")
                position = 0
            if size > position:
                with log_path.open("r", encoding="utf-8", errors="ignore") as fh:
                    fh.seek(position)
                    new_lines = fh.read().splitlines()
                    position = fh.tell()
                recent = (recent + new_lines)[-window:]
                for alert in analyze_logs("\n".join(recent)):
                    key = (alert["cve"], alert["source_ip"])
                    if key in seen:
                        continue
                    seen.add(key)
                    total_alerts += 1
                    print(f"[{datetime.now():%H:%M:%S}] [{alert['severity']}] {alert['cve']} | Src: {defang_ip(alert['source_ip'])}")
                    print(f"           └─ {alert['detail']}")
                    if webhook:
                        send_webhook(webhook, alert)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n" + "=" * 76)
        print(f"[*] Monitoring stopped. {total_alerts} unique alert(s) raised this session.")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Hunt for October 2026 PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exploitation & PHP web shells."
    )
    parser.add_argument("log_file", nargs="?", help="Path to Apache/Nginx/PHP log file")
    parser.add_argument("--webroot", help="Optional path to webroot directory to scan for dropped PHP web shells")
    parser.add_argument("--demo", action="store_true", help="Run built-in October 2026 PHP2Shell SOC incident demo")
    parser.add_argument("-o", "--output", help="Export detection report to a JSON file")
    parser.add_argument("--export-rules", metavar="DIR", help="Write Sigma (.yml) + Wazuh (.xml) detection rules to DIR")
    parser.add_argument("--follow", metavar="LOGFILE", help="Real-time monitoring of a growing Apache/PHP log file")
    parser.add_argument("--webhook", metavar="URL", help="Send --follow alerts to a Slack/Discord/Teams webhook")
    parser.add_argument("--interval", type=float, default=1.0, help="Poll interval in seconds for --follow (default 1.0)")
    args = parser.parse_args()

    print(BANNER)

    if args.follow:
        fp = Path(args.follow)
        if not fp.is_file():
            print(f"[!] Error: Log file not found: {args.follow}")
            sys.exit(1)
        follow_log(fp, interval=args.interval, webhook=args.webhook)
        return

    if args.export_rules and not (args.demo or args.log_file or args.webroot):
        for p in export_rules(Path(args.export_rules)):
            print(f"[+] Wrote rule: {p}")
        return

    if args.demo:
        log_alerts = analyze_logs(DEMO_LOGS)
        webshell_findings = scan_webroot_map(DEMO_WEBROOT_FILES)
        source_label = "Simulated Apache mod_php Telemetry + /var/www/html (Demo)"
    elif args.log_file or args.webroot:
        log_alerts = []
        webshell_findings = []
        labels = []
        if args.log_file:
            lp = Path(args.log_file)
            if not lp.is_file():
                print(f"[!] Error: Log file not found: {args.log_file}")
                sys.exit(1)
            log_alerts = analyze_logs(lp.read_text(encoding="utf-8", errors="ignore"))
            labels.append(lp.name)
        if args.webroot:
            wp = Path(args.webroot)
            if not wp.is_dir():
                print(f"[!] Error: Webroot directory not found: {args.webroot}")
                sys.exit(1)
            webshell_findings = scan_webroot_dir(wp)
            labels.append(f"webroot:{wp.name}")
        source_label = " + ".join(labels)
    else:
        parser.print_help()
        print("\n💡 Tip: Run with --demo to test against simulated PHP2Shell incident logs!")
        sys.exit(0)

    print_report(log_alerts, webshell_findings, source_label)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps({"source": source_label, "log_alerts": log_alerts, "webshells": webshell_findings}, indent=2),
            encoding="utf-8",
        )
        print(f"[+] Saved JSON detection report to {out_path}")

    if args.export_rules:
        written = export_rules(Path(args.export_rules))
        print(f"[+] Exported {len(written)} Sigma/Wazuh rule file(s) to {args.export_rules}")


if __name__ == "__main__":
    main()
