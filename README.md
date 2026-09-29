8#!/usr/bin/env python3
"""
Website Security Toolkit v2
Passive / low-impact defensive auditing. Use ONLY on sites you own or are
explicitly authorized to test. No exploitation, brute force, or fuzzing.
"""

import argparse
import base64
import importlib.util
import os
import subprocess
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import html
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

REQUIRED_PACKAGES = {"requests": "requests"}  # import name -> pip name


def ensure_dependencies():
    """Install missing third-party packages automatically (opt out: --no-auto-install or WST_NO_AUTO_INSTALL=1)."""
    missing = [pkg for mod, pkg in REQUIRED_PACKAGES.items() if importlib.util.find_spec(mod) is None]
    if not missing:
        return
    if "--no-auto-install" in sys.argv or os.environ.get("WST_NO_AUTO_INSTALL"):
        sys.exit(f"Missing dependencies: {', '.join(missing)}\nInstall with: pip install {' '.join(missing)}")
    print(f"[setup] Installing missing dependencies: {', '.join(missing)}", file=sys.stderr)

    def pip_install(python, *extra):
        return subprocess.run([python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                               "--retries", "2", "--timeout", "15", *extra, *missing], capture_output=True, text=True)

    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    res = pip_install(sys.executable, *([] if in_venv else ["--user"]))
    importlib.invalidate_caches()
    if res.returncode == 0 and all(importlib.util.find_spec(m) for m in REQUIRED_PACKAGES):
        return
    if os.environ.get("WST_REEXEC"):
        sys.exit("Automatic install failed:\n" + (res.stdout + res.stderr)[-800:])
    # e.g. PEP 668 "externally-managed-environment": fall back to a private virtualenv and re-run inside it.
    try:
        import venv
        vdir = Path.home() / ".website_security_toolkit_venv"
        if not vdir.exists():
            venv.create(vdir, with_pip=True)
        exe = "python.exe" if os.name == "nt" else "python"
        py = str(vdir / ("Scripts" if os.name == "nt" else "bin") / exe)
        res2 = pip_install(py)
        if res2.returncode != 0:
            sys.exit("Automatic install failed:\n" + (res2.stdout + res2.stderr)[-800:])
        print(f"[setup] Re-running inside {vdir}", file=sys.stderr)
        sys.exit(subprocess.call([py, *sys.argv], env=dict(os.environ, WST_REEXEC="1")))
    except (ImportError, OSError, subprocess.SubprocessError) as e:
        sys.exit(f"Automatic install failed ({e}). Install manually: pip install {' '.join(missing)}")


ensure_dependencies()
import requests  # noqa: E402

VERSION = "2.3.0"
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
WEIGHTS = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}

DEFAULT_CONFIG = {
    "timeout": 12, "max_pages": 20, "workers": 4, "rate_limit": 0.2,
    "max_js": 15, "allowed_hosts": [],
    "user_agent": f"WebSecurityToolkit/{VERSION} (authorized defensive scanner)",
}

SECURITY_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", "medium"),
    "content-security-policy": ("Content-Security-Policy", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "low"),
    "x-frame-options": ("X-Frame-Options", "low"),
    "referrer-policy": ("Referrer-Policy", "low"),
    "permissions-policy": ("Permissions-Policy", "low"),
    "cross-origin-opener-policy": ("Cross-Origin-Opener-Policy", "info"),
    "cross-origin-resource-policy": ("Cross-Origin-Resource-Policy", "info"),
}

WEBSHELL_PATTERN = r"(?i)c99shell|r57shell|filesman|b374k|wso shell|web shell by|priv8|weevely|indoxploit|alfa team"
WEBSHELL_PATHS = {"c99.php", "r57.php", "wso.php", "shell.php", "b374k.php", "alfa.php", "indoxploit.php"}

# path -> (signature regex, severity, may_be_html)
# A hit needs BOTH HTTP 200 and matching content, which removes soft-404 false positives.
SENSITIVE_FILES = {
    ".env": (r"(?m)^[A-Za-z][A-Za-z0-9_]*\s*=", "high", False),
    ".git/config": (r"\[core\]", "high", False),
    ".git/HEAD": (r"^ref:\s*refs/", "high", False),
    ".svn/entries": (r"(?m)^\d+\s*$", "medium", False),
    ".DS_Store": (r"Bud1", "low", False),
    "wp-config.php.bak": (r"DB_PASSWORD|DB_NAME", "critical", False),
    "config.php.bak": (r"(?i)password|db_", "high", False),
    "phpinfo.php": (r"PHP Version|phpinfo\(\)", "medium", True),
    "server-status": (r"Apache Server Status", "medium", True),
    "debug.log": (r"(?i)\b(error|exception|warning|traceback)\b", "medium", False),
    "error.log": (r"(?i)\b(error|exception|warning|traceback)\b", "medium", False),
    "backup.sql": (r"(?i)CREATE TABLE|INSERT INTO", "high", False),
    "dump.sql": (r"(?i)CREATE TABLE|INSERT INTO", "high", False),
    "actuator/env": (r"propertySources", "high", False),
    "actuator/health": (r'"status"\s*:', "info", False),
    "swagger.json": (r'"swagger"|"openapi"', "info", False),
    "openapi.json": (r'"swagger"|"openapi"', "info", False),
    "v3/api-docs": (r'"openapi"', "info", False),
    "uploads/": (r"(?i)<title>\s*Index of /|Directory listing for /", "medium", True),
    "backup/": (r"(?i)<title>\s*Index of /|Directory listing for /", "medium", True),
    "backups/": (r"(?i)<title>\s*Index of /|Directory listing for /", "medium", True),
    "logs/": (r"(?i)<title>\s*Index of /|Directory listing for /", "medium", True),
    ".git/": (r"(?i)<title>\s*Index of /|Directory listing for /", "high", True),
    **{p: (WEBSHELL_PATTERN, "critical", True) for p in sorted(WEBSHELL_PATHS)},
    "phpmyadmin/": (r"(?i)phpMyAdmin", "medium", True),
    "pma/": (r"(?i)phpMyAdmin", "medium", True),
    "adminer.php": (r"(?i)Adminer", "medium", True),
    "administrator/": (r"(?i)Joomla|com_login", "low", True),
    "jenkins/": (r"(?i)Jenkins", "medium", True),
    "solr/": (r"(?i)Solr Admin", "medium", True),
    "console": (r"(?i)Werkzeug Console|Interactive Console|H2 Console|WebLogic Server Administration", "high", True),
    "server-info": (r"Apache Server Information", "medium", True),
    "info.php": (r"PHP Version|phpinfo\(\)", "medium", True),
    "_profiler/": (r"(?i)Symfony Profiler", "high", True),
    "telescope": (r"(?i)Laravel Telescope", "high", True),
    "elmah.axd": (r"(?i)Error Log for", "high", True),
    "trace.axd": (r"(?i)Application Trace", "high", True),
    "web.config": (r"(?i)<configuration", "high", False),
    "WEB-INF/web.xml": (r"(?i)<web-app", "high", False),
    ".htaccess": (r"(?i)RewriteEngine|AuthUserFile|AuthType", "medium", False),
    ".htpasswd": (r"(?m)^[\w.\-]+:[^\s:]{8,}$", "critical", False),
    "id_rsa": (r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY", "critical", False),
    ".npmrc": (r"_authToken|//registry", "high", False),
    ".aws/credentials": (r"aws_access_key_id", "critical", False),
    "docker-compose.yml": (r"(?m)^services:", "medium", False),
    "Dockerfile": (r"(?im)^FROM\s+\S+", "medium", False),
    "composer.lock": (r'"packages"\s*:', "low", False),
    "package.json": (r'"(?:dependencies|devDependencies|scripts)"\s*:', "low", False),
    "crossdomain.xml": (r'allow-access-from\s+domain\s*=\s*"\*"', "medium", False),
}

TECH_PATTERNS = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r'content="WordPress'],
    "Joomla": [r"/media/system/js/", r'content="Joomla'],
    "Drupal": [r"Drupal\.settings", r"/sites/default/files/", r'content="Drupal'],
    "React": [r"data-reactroot", r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js"],
    "Next.js": [r"/_next/static/", r"__NEXT_DATA__"],
    "Nuxt": [r"/_nuxt/", r"__NUXT__"],
    "Vue.js": [r"vue(?:\.runtime)?(?:\.min)?\.js", r"data-v-[0-9a-f]{6,}"],
    "Angular": [r"ng-version=", r"angular(?:\.min)?\.js"],
    "Bootstrap": [r"bootstrap(?:\.min)?\.(?:css|js)"],
    "jQuery": [r"jquery[\w.\-]*\.js"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrfmiddlewaretoken", r"csrftoken"],
    "PHP": [r"PHPSESSID", r"x-powered-by:\s*php"],
    "ASP.NET": [r"x-aspnet-version", r"__VIEWSTATE", r"x-powered-by:\s*asp\.net"],
    "Shopify": [r"cdn\.shopify\.com"],
    "Cloudflare": [r"cf-ray:", r"server:\s*cloudflare"],
    "nginx": [r"server:\s*nginx"], "Apache": [r"server:\s*apache"],
    "IIS": [r"server:\s*microsoft-iis"], "Vercel": [r"x-vercel-id"],
    "Netlify": [r"server:\s*netlify"], "CloudFront": [r"x-amz-cf-id"],
}

SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    ("Stripe Live Secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "critical"),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical"),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"), "high"),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "high"),
    ("Bearer Token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{30,}"), "medium"),
    ("Generic Secret", re.compile(
        r"(?i)\b(?:client[_-]?secret|app[_-]?secret|secret[_-]?key|api[_-]?key)\b['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]"), "medium"),
]
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

DISCLOSURE_PATTERNS = [
    ("stack-trace", re.compile(r"Traceback \(most recent call last\)|java\.lang\.\w+Exception|Fatal error:|Unhandled exception|at [\w.$]+\([\w.]+:\d+\)")),
    ("database-error", re.compile(r"SQL syntax.*MySQL|ORA-\d{4,}|PostgreSQL.*ERROR|SQLSTATE\[[0-9A-Z]+\]|SQLite.*(?:error|exception)", re.I)),
    ("debug-output", re.compile(r"Xdebug|werkzeug.*debugger|django\.debug", re.I)),
    ("absolute-path", re.compile(r"(?:/home/|/var/www/|/srv/www/|C:\\+Users|C:\\+inetpub)[^\s<]{4,}")),
    ("debug-page", re.compile(r"You're seeing this error because you have DEBUG = True|Whoops! There was an error|Whitelabel Error Page|Server Error in '/' Application|Werkzeug Debugger|Symfony Exception|Action Controller: Exception caught")),
]

SKIP_EXT = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".zip",
            ".gz", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".css", ".js", ".xml"}
REDIRECT_PARAMS = {"redirect", "redirect_url", "return", "return_url", "next", "next_url",
                   "continue", "dest", "destination", "url", "target", "callback"}
CSRF_HINTS = ("csrf", "xsrf", "token", "authenticity", "nonce")

# ---- vulnerability indicators (passive) ----
OSV_URL = "https://api.osv.dev/v1/query"
OSV_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}

# (product, min_inclusive, max_exclusive, severity, summary)
KNOWN_VULNS = [
    ("jquery", (0, 0, 0), (3, 5, 0), "medium", "CVE-2020-11022/11023: XSS when untrusted HTML reaches DOM manipulation methods"),
    ("jquery", (0, 0, 0), (3, 4, 0), "medium", "CVE-2019-11358: prototype pollution in jQuery.extend"),
    ("bootstrap", (3, 0, 0), (3, 4, 1), "medium", "CVE-2019-8331: XSS in tooltip/popover data-template"),
    ("bootstrap", (4, 0, 0), (4, 3, 1), "medium", "CVE-2019-8331: XSS in tooltip/popover data-template"),
    ("lodash", (0, 0, 0), (4, 17, 21), "high", "CVE-2021-23337 (template command injection), CVE-2020-8203 (prototype pollution)"),
    ("moment", (0, 0, 0), (2, 29, 4), "medium", "CVE-2022-31129: ReDoS in date parsing"),
    ("underscore", (1, 3, 2), (1, 12, 1), "medium", "CVE-2021-23358: template code injection"),
    ("handlebars", (0, 0, 0), (4, 7, 7), "high", "CVE-2021-23369: remote code execution via templates"),
    ("axios", (0, 0, 0), (0, 21, 2), "medium", "CVE-2020-28168: SSRF via redirect handling"),
    ("axios", (1, 0, 0), (1, 6, 0), "medium", "CVE-2023-45857: CSRF token leak to third parties"),
    ("angular", (1, 0, 0), (2, 0, 0), "medium", "AngularJS 1.x is end-of-life (Dec 2021) with unpatched sandbox-escape/XSS issues"),
    ("vue", (2, 0, 0), (3, 0, 0), "low", "Vue 2 reached end of life on 2023-12-31"),
    ("jquery-ui", (0, 0, 0), (1, 13, 0), "medium", "CVE-2021-41182/41183/41184: XSS via datepicker/position/of options"),
    ("chart.js", (0, 0, 0), (2, 9, 4), "medium", "CVE-2020-7746: prototype pollution"),
    ("dompurify", (0, 0, 0), (2, 0, 17), "high", "CVE-2020-26870: mutation-XSS sanitizer bypass"),
    ("marked", (0, 0, 0), (4, 0, 10), "medium", "CVE-2022-21680/21681: ReDoS"),
]
# Banner rules: (product, regex, unsupported_below, severity, reason). Banners can be spoofed/backported => low confidence.
BANNER_RULES = [
    ("Apache httpd", r"apache/(\d+\.\d+(?:\.\d+)?)", (2, 4, 0), "medium", "Apache httpd 2.2 and older are end-of-life"),
    ("PHP", r"php/(\d+\.\d+(?:\.\d+)?)", (8, 2, 0), "medium", "PHP below 8.2 no longer receives upstream security fixes (verify at php.net/supported-versions)"),
    ("OpenSSL", r"openssl/(\d+\.\d+\.\d+)", (1, 1, 1), "medium", "OpenSSL below 1.1.1 is end-of-life"),
    ("Microsoft IIS", r"microsoft-iis/(\d+\.\d+)", (10, 0, 0), "low", "IIS below 10.0 implies an out-of-support Windows Server"),
]
JS_BANNERS = [
    ("jquery", r"jQuery(?: JavaScript Library)? v?(\d+\.\d+\.\d+)"),
    ("bootstrap", r"Bootstrap v?(\d+\.\d+\.\d+)"),
    ("moment", r"moment\.js[\s\S]{0,80}?version\s*:\s*(\d+\.\d+\.\d+)"),
    ("vue", r"Vue\.js v?(\d+\.\d+\.\d+)"),
    ("angular", r"AngularJS v?(\d+\.\d+\.\d+)"),
    ("underscore", r"Underscore\.js (\d+\.\d+\.\d+)"),
    ("jquery-ui", r"jQuery UI(?: Core)? - v(\d+\.\d+\.\d+)"),
]
LIB_RX = re.compile(r"(?<![a-z0-9])(jquery-ui|jquery|bootstrap|lodash|moment|underscore|angularjs|angular|vue|react-dom|react|axios|handlebars|chart\.js|dompurify|marked)"
                    r"(?![a-z])(?:\.js)?(?:[.\-@/]min)?(?:[.\-@/]v?(\d+\.\d+(?:\.\d+)?))?")

# id -> (label, parameter names, advice). Names only; nothing is sent to the target.
PARAM_CLASSES = {
    "SQLI": ("SQL-injection-prone", {"id", "uid", "user_id", "userid", "pid", "cid", "cat", "category", "item", "product", "order",
             "orderby", "sort", "q", "search", "query", "keyword", "filter", "page_id", "post", "article", "limit", "offset"},
             "Confirm these values reach the database only through parameterized queries."),
    "PATH": ("File-path-prone", {"file", "filename", "path", "dir", "folder", "template", "include", "inc", "doc", "document",
             "download", "load", "view", "lang", "locale", "module", "conf"},
             "Confirm paths are resolved against an allow-list (path traversal / file inclusion)."),
    "CMD": ("Command/eval-prone", {"cmd", "command", "exec", "run", "eval", "code", "shell", "ping"},
            "Confirm user input never reaches a shell or eval-like function."),
    "SSRF": ("Redirect/SSRF-prone", REDIRECT_PARAMS | {"uri", "link", "src", "domain", "proxy", "fetch", "feed", "webhook"},
             "Allow-list redirect targets and outbound fetch destinations server-side."),
}
SENSITIVE_KEY_RE = re.compile(r"(?i)pass(word)?|secret|token|email|phone|ssn|address|card|iban|birth|api[_-]?key")

# ---- compromise / malware indicators (read-only signature heuristics) ----
MAL_ADVICE = ("Treat as a possible compromise: compare against a known-clean backup, review recent file changes and admin "
              "accounts, rotate credentials, and run a dedicated malware scanner. Signature heuristics can give false positives.")
MINER_RX = re.compile(r"(?i)coin-?hive|cryptoloot|crypto-loot|webminepool|minero\.cc|jsecoin|authedmine|coinimp|deepminer|browsermine")
OBFUSC_RX = re.compile(r"(?i)(?:\beval|\bFunction)\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(|document\.write\s*\(\s*unescape\s*\(|"
                       r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){25,}|(?:\\x[0-9a-f]{2}){40,}")
IFRAME_RX = re.compile(r"(?is)<iframe\b[^>]*>")
HIDDEN_BLOCK_RX = re.compile(r"""(?is)<(?:div|span|p|ul)\b[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|left\s*:\s*-\d{3,}|text-indent\s*:\s*-\d{3,})[^"']*["'][^>]*>(.{0,3000}?)</(?:div|span|p|ul)>""")
SPAM_RX = re.compile(r"(?i)viagra|cialis|casino|payday loan|replica (?:watches|handbags)|escort|porn|essay writing")
META_REFRESH_RX = re.compile(r"""(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*(https?://[^"'\s>]+)""")
CARD_RX = re.compile(r"(?i)card[-_ ]?num|cc[-_]?num|cardnumber|\bcvv\b|\bcvc\b|cc-exp")
EXFIL_RX = re.compile(r"""(?i)sendBeacon\s*\(|new\s+Image\s*\(\s*\)\s*\.src|XMLHttpRequest|fetch\s*\(\s*["']https?://""")
WEBSHELL_RX = re.compile(WEBSHELL_PATTERN)
DEFACE_RX = re.compile(r"(?i)<title>[^<]*(?:hacked|defaced|owned|pwned)\s+by|<h1[^>]*>[^<]*(?:hacked|defaced|owned|pwned)\s+by")
INLINE_SCRIPT_RX = re.compile(r"(?is)<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>")
SUSPICIOUS_TLDS = {"top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "icu", "zip", "mov"}

# ---- categories / coverage ----
CATEGORY_MAP = [
    ("XXE-", "XML External Entity (XXE)"), ("JWT-", "JWT vulnerabilities"), ("CRLF-", "CRLF / header injection"),
    ("IDOR-", "IDOR / broken access control"), ("BAC-", "IDOR / broken access control"),
    ("AUTH-", "Broken authentication"), ("SESSION-", "Session management"), ("COOKIE-", "Session management"),
    ("CSRF-", "CSRF"), ("FORM-NO-CSRF", "CSRF"), ("OAUTH-", "OAuth / SSO"),
    ("UPLOAD-", "File upload"), ("ENTRY-FILE-UPLOAD", "File upload"),
    ("SSRF-", "SSRF"), ("ENTRY-PARAM-SSRF", "SSRF"), ("ENTRY-PARAM-SQLI", "SQL injection (indicator)"),
    ("ENTRY-PARAM-CMD", "Command injection (indicator)"), ("ENTRY-PARAM-PATH", "Path traversal / file inclusion (indicator)"),
    ("DESER-", "Insecure deserialization"), ("LOGIC-", "Business logic"),
    ("CRYPTO-", "Cryptographic failures"), ("TLS-", "Cryptographic failures"), ("SECRET-", "Cryptographic failures"),
    ("HSTS-", "Cryptographic failures"), ("API-", "API-specific flaws"), ("ENTRY-API", "API-specific flaws"),
    ("CLIENT-", "Client-side vulnerabilities"), ("CACHE-", "Cache poisoning / caching"),
    ("VULN-", "Vulnerable & outdated components"), ("LIB-", "Vulnerable & outdated components"),
    ("MAL-", "Compromise indicators"), ("EXPOSED-", "Security misconfiguration"), ("MISCONF-", "Security misconfiguration"),
    ("HDR-", "Security misconfiguration"), ("CSP-", "Security misconfiguration"), ("CORS-", "Security misconfiguration"),
    ("DISC-", "Security misconfiguration"), ("HTTP-", "Security misconfiguration"), ("DNS-", "Security misconfiguration"),
]


def category_for(rule):
    return next((c for pre, c in CATEGORY_MAP if rule.startswith(pre)), "")


# (name, status, note) - status: detected | indicators | not_tested
COVERAGE = [
    ("Template Injection (SSTI/CSTI)", "not_tested", "Needs payloads. Only flags AngularJS 1.x (client-side template risk)."),
    ("XPath Injection", "not_tested", "Needs payloads."),
    ("LDAP Injection", "not_tested", "Needs payloads."),
    ("XML External Entity (XXE)", "indicators", "XML-RPC/WSDL/XML endpoints, DTD-with-ENTITY responses, XML upload formats."),
    ("Code Injection / RCE", "indicators", "Vulnerable/EOL components, exposed debug consoles, webshells. No exploitation."),
    ("Cross-Site Scripting (XSS)", "indicators", "DOM source->sink patterns, weak CSP. No reflected/stored probing."),
    ("Command / OS Command Injection", "indicators", "Parameter names only."),
    ("SQL Injection", "indicators", "Parameter names and DB error strings only."),
    ("CRLF / Response Splitting", "indicators", "Parameter values reflected in response headers / Location."),
    ("Header Injection", "indicators", "Same as CRLF."),
    ("Broken Access Control", "indicators", "Exposed admin panels, unauthenticated API responses."),
    ("IDOR", "indicators", "Numeric object references in URLs/APIs. Needs manual multi-account testing."),
    ("Privilege Escalation", "indicators", "Client-controlled role fields, privilege claims in JWTs."),
    ("Broken Authentication", "indicators", "Basic auth over HTTP, password forms over HTTP/GET. No login attempts."),
    ("Session Management", "detected", "Cookie flags, lifetimes, session IDs in URLs, JWT cookies."),
    ("CSRF", "indicators", "Forms without tokens, SameSite gaps, state-changing GET links."),
    ("OAuth / SSO flaws", "indicators", "Visible authorize URLs and OIDC discovery only; flows are not manipulated."),
    ("JWT vulnerabilities", "detected", "Passive analysis of tokens exposed in pages/JS/cookies."),
    ("Security Misconfiguration", "detected", "Headers, admin panels, config/backup files, debug pages, default pages."),
    ("Business Logic Flaws", "indicators", "Client-controlled price/role/ID hidden fields only."),
    ("SSRF", "indicators", "URL-taking parameters and inputs only."),
    ("File Upload", "indicators", "Upload form analysis. Nothing is uploaded."),
    ("Insecure Deserialization", "indicators", "Serialized objects in cookies/params/hidden fields."),
    ("Cryptographic Failures", "detected", "TLS version/cipher/cert, HSTS, cookies, secrets, weak crypto in client code."),
    ("API-specific flaws (OWASP API Top 10)", "indicators", "Unauthenticated data, rate-limit headers, versions, GraphQL presence."),
    ("Client-side vulnerabilities", "indicators", "DOM sinks, postMessage without origin check, tokens in Web Storage."),
    ("Race Conditions", "not_tested", "Needs concurrent state-changing requests."),
    ("DoS / ReDoS", "not_tested", "Needs load or crafted input."),
    ("Vulnerable & Outdated Components", "detected", "Local CVE table, banners, optional OSV.dev lookup."),
    ("Cache Poisoning", "indicators", "Cacheable responses that set cookies; login pages without no-store."),
]

SERIALIZED_RX = [
    (re.compile(r"^rO0AB"), "Java serialized object (base64)", "medium"),
    (re.compile(r"(?i)^aced0005"), "Java serialized object (hex)", "medium"),
    (re.compile(r'^(?:O:\d+:"|a:\d+:\{)'), "PHP serialized data", "medium"),
    (re.compile(r"^(?:gASV|gAJ)"), "Python pickle (base64)", "medium"),
    (re.compile(r"^/wE[A-Za-z0-9+/]"), "ASP.NET ViewState", "info"),
]
IDOR_PATH_RX = re.compile(r"/(users?|accounts?|orders?|invoices?|profiles?|customers?|documents?|files?|tickets?|messages?|payments?|receipts?|reports?)/(\d{1,12})(?:[/?#.]|$)", re.I)
IDOR_PARAMS = {"id", "uid", "user_id", "userid", "account", "account_id", "order_id", "invoice", "invoice_id", "doc", "doc_id", "file_id", "customer_id", "ticket"}
SENSITIVE_PARAMS = {"password", "passwd", "pwd", "pass", "token", "access_token", "secret", "apikey", "api_key", "auth", "ssn", "card", "cardnumber", "cvv", "otp"}
SESSION_PARAMS = {"jsessionid", "phpsessid", "sessionid", "session_id", "sid", "aspsessionid"}
STATE_CHANGE_RX = re.compile(r"/(delete|remove|destroy|cancel|approve|activate|deactivate|reset|transfer|unsubscribe|revoke)(?:[/?#.\-_]|$)", re.I)
LOGIC_FIELDS = {"price", "amount", "total", "cost", "discount", "coupon", "role", "isadmin", "is_admin", "admin", "balance", "quantity", "qty", "user_id", "userid", "points", "credit"}
DOM_FLOW_RX = re.compile(r"""(?:innerHTML|outerHTML)\s*=[^;\n]{0,120}(?:location\.(?:hash|search|href)|document\.(?:URL|referrer)|window\.name)|(?:location\.(?:hash|search)|document\.(?:URL|referrer)|window\.name)[^;\n]{0,120}(?:innerHTML|document\.write|\beval\s*\()|\$\(\s*(?:window\.)?location\.(?:hash|search)""")
POSTMSG_RX = re.compile(r"""addEventListener\(\s*["']message["']""")
CLIENT_PATTERNS = [
    (re.compile(r"(?i)\b(?:md5|sha-?1)\s*\(\s*[^)]{0,40}pass"), "CRYPTO-WEAK-HASH", "low", "Weak hash applied to a password-like value in client code",
     "Use a slow salted hash (Argon2/bcrypt/scrypt) on the server."),
    (re.compile(r"""(?i)AES\.(?:encrypt|decrypt)\([^,()]+,\s*["'][^"']{4,}["']"""), "CRYPTO-HARDCODED-KEY", "medium",
     "Hard-coded encryption key/passphrase in client code", "Client-side keys are public; do sensitive crypto server-side."),
    (re.compile(r"""(?i)(?:token|password|secret|nonce|session)\w*\s*[=:][^;\n]{0,60}Math\.random\(\)"""), "CRYPTO-WEAK-RANDOM", "low",
     "Math.random() used for a security-sensitive value", "Use crypto.getRandomValues() / a CSPRNG."),
    (re.compile(r"""(?i)(?:localStorage|sessionStorage)\.setItem\(\s*["'][^"']*(?:token|jwt|auth|session)"""), "CLIENT-TOKEN-IN-STORAGE", "low",
     "Auth token kept in Web Storage", "Any XSS can read Web Storage; prefer HttpOnly cookies."),
]


def vtuple(v):
    n = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return tuple(n + [0] * (3 - len(n)))


def libs_from_url(url):
    p = urlparse(url)
    path, q = p.path.lower(), dict(parse_qsl(p.query))
    out = []
    for m in LIB_RX.finditer(path):
        ver = m.group(2)
        if not ver:
            cand = q.get("ver") or q.get("v") or ""
            ver = cand if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", cand) else None
        if ver:
            out.append(({"angularjs": "angular"}.get(m.group(1), m.group(1)), ver))
    return out


def json_keys(obj, depth=2):
    if isinstance(obj, list):
        return json_keys(obj[0], depth) if obj else []
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            out.append(str(k))
            if depth > 1 and isinstance(v, (dict, list)):
                out += [f"{k}.{x}" for x in json_keys(v, depth - 1)]
        return out
    return []


# --------------------------------------------------------------------------- utils

# ==== Colorful banner ("snake scale" rainbow) ====
_BANNER_RESET = "\033[0m"
_BANNER_PALETTE = [196, 202, 208, 214, 220, 226, 190, 154, 118, 82, 46, 47, 48, 49, 50,
                   51, 45, 39, 33, 27, 21, 57, 93, 129, 165, 201, 200, 199, 198, 197]
_BANNER_FONT = {
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    " ": ["  ", "  ", "  ", "  ", "  "],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "X": ["#   #", " # # ", "  #  ", " # # ", "#   #"],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "C": [" ### ", "#    ", "#    ", "#    ", " ### "],
    "U": ["#   #", "#   #", "#   #", "#   #", " ### "],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "Y": ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
    "W": ["#   #", "#   #", "# # #", "## ##", "#   #"],
    "B": ["#### ", "#   #", "#### ", "#   #", "#### "],
}


def _banner_render(word):
    rows = ["", "", "", "", ""]
    for ch in word:
        glyph = _BANNER_FONT.get(ch, _BANNER_FONT[" "])
        for i in range(5):
            rows[i] += glyph[i] + " "
    return rows


def _banner_colorize(word, row_offset=0):
    lines = []
    for r, row in enumerate(_banner_render(word)):
        line, col = "", 0
        for ch in row:
            if ch == "#":
                code = _BANNER_PALETTE[(col + r + row_offset) % len(_BANNER_PALETTE)]
                line += f"\033[38;5;{code}m█"
            else:
                line += " "
            col += 1
        lines.append(line + _BANNER_RESET)
    return lines


def print_banner():
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        print("=" * 60 + "\n  TOOL AXEL SECURITY WEB\n" + "=" * 60)
        return
    print("""
""")
    for line in _banner_colorize("TOOL AXEL", 0):
        print(line)
    for line in _banner_colorize("SECURITY WEB", 5):
        print(line)
    print()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def mask(value):
    value = value.strip()
    return value[:6] + "..." + value[-4:] if len(value) > 18 else value[:3] + "..."


def b64url(value):
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
    except Exception:
        return None


def set_cookie_headers(resp):
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:
        v = resp.headers.get("Set-Cookie")
        return [v] if v else []


class RateLimiter:
    def __init__(self, interval):
        self.interval, self.lock, self.last = interval, threading.Lock(), 0.0

    def wait(self):
        if self.interval <= 0:
            return
        with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                time.sleep(delay)
            self.last = time.monotonic()


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    recommendation: str = ""
    evidence: str = ""
    url: str = ""
    confidence: str = "medium"
    category: str = ""


class PageParser(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.title, self._in_title = base, "", False
        self.links, self.scripts, self.styles = set(), [], []
        self.forms, self.resources, self.meta = [], [], {}
        self.images, self._form = 0, None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        u = lambda key: urljoin(self.base, a[key])
        if tag == "a" and a.get("href"):
            if not a["href"].startswith(("#", "mailto:", "tel:", "javascript:")):
                full = u("href")
                if urlparse(full).scheme in ("http", "https"):
                    self.links.add(full.split("#", 1)[0])
        elif tag == "script" and a.get("src"):
            self.scripts.append({"url": u("src"), "integrity": bool(a.get("integrity"))})
            self.resources.append(("script", u("src")))
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.styles.append({"url": u("href"), "integrity": bool(a.get("integrity"))})
            self.resources.append(("style", u("href")))
        elif tag == "img" and a.get("src"):
            self.images += 1
            self.resources.append(("img", u("src")))
        elif tag == "iframe" and a.get("src"):
            self.resources.append(("iframe", u("src")))
        elif tag == "form":
            self._form = {"action": urljoin(self.base, a.get("action", "")), "enctype": a.get("enctype", ""),
                          "method": a.get("method", "GET").upper(), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            t = a.get("type", "text").lower()
            self._form["inputs"].append({"name": a.get("name", ""), "type": t, "accept": a.get("accept", ""),
                                         "value": a.get("value", "")[:300] if t == "hidden" else ""})
        elif tag == "meta" and a.get("name") and a.get("content"):
            self.meta[a["name"].lower()] = a["content"]
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data


# --------------------------------------------------------------------------- scanner
class Scanner:
    def __init__(self, target, cfg, crawl=False, skip=(), osv=False):
        self.cfg, self.do_crawl, self.skip, self.osv = cfg, crawl, set(skip), osv
        raw = target.strip()
        self.defaulted = not raw.lower().startswith(("http://", "https://"))
        self.target = urlparse(("https://" + raw) if self.defaulted else raw)._replace(fragment="").geturl()
        self.host = (urlparse(self.target).hostname or "").lower()
        self.scope = {self.host} | {h.lower().strip() for h in cfg.get("allowed_hosts", [])}
        self.session = requests.Session()
        self.session.headers["User-Agent"] = cfg["user_agent"]
        self.limiter = RateLimiter(cfg["rate_limit"])
        self.lock = threading.Lock()
        self.findings, self._keys = [], set()
        self.checks, self.tech, self.pages = {}, set(), {}
        self.scripts = {}
        self.components, self.script_urls, self.urls_seen = {}, set(), set()
        self.forms_seen, self.js_endpoints = [], set()
        self.wp_plugins, self.wp_themes = {}, {}

    # -- core helpers
    def add(self, sev, rule, title, detail, rec="", evidence="", url="", conf="medium"):
        key = (rule, url, detail)
        with self.lock:
            if key in self._keys:
                return
            self._keys.add(key)
            self.findings.append(Finding(rule, sev, title, detail, rec, evidence, url, conf, category_for(rule)))

    def in_scope(self, url):
        return (urlparse(url).hostname or "").lower() in self.scope

    def fetch(self, url, method="GET", allow_redirects=True, retries=2, **kw):
        if not self.in_scope(url):
            raise ValueError(f"out of scope: {url}")
        last = None
        for i in range(retries + 1):
            self.limiter.wait()
            try:
                return self.session.request(method, url, timeout=self.cfg["timeout"],
                                            allow_redirects=allow_redirects, **kw)
            except (requests.Timeout, requests.ConnectionError) as e:
                last = e
                time.sleep(0.5 * (i + 1))
        raise last

    def safe(self, name, fn, *a):
        if name in self.skip:
            return None
        try:
            return fn(*a)
        except Exception as e:
            self.checks.setdefault("_errors", {})[name] = str(e)
            self.add("info", "SCAN-MODULE-ERROR", f"Module '{name}' failed", str(e))
            return None

    def doh(self, name, rtype):
        r = requests.get("https://dns.google/resolve", params={"name": name, "type": rtype},
                         headers={"User-Agent": self.cfg["user_agent"]}, timeout=self.cfg["timeout"])
        return [x.get("data", "") for x in r.json().get("Answer", [])] if r.ok else []

    # -- modules
    def check_headers(self, r):
        h = {k.lower(): v for k, v in r.headers.items()}
        https = r.url.startswith("https://")
        csp = h.get("content-security-policy", "")
        for key, (name, sev) in SECURITY_HEADERS.items():
            if key in h:
                continue
            if key == "strict-transport-security" and not https:
                continue
            if key == "x-frame-options" and "frame-ancestors" in csp.lower():
                continue
            self.add(sev, f"HDR-MISSING-{key.upper()}", f"Missing {name}",
                     f"The response did not include {name}.", f"Add {name} where appropriate.", url=r.url)
        if "'unsafe-inline'" in csp:
            self.add("medium", "CSP-UNSAFE-INLINE", "CSP allows unsafe-inline", csp[:200],
                     "Use nonces or hashes instead.", url=r.url)
        if "'unsafe-eval'" in csp:
            self.add("medium", "CSP-UNSAFE-EVAL", "CSP allows unsafe-eval", csp[:200], url=r.url)
        if re.search(r"(?:default-src|script-src)[^;]*(?:\s\*|\shttps?:(?:\s|;|$))", csp):
            self.add("medium", "CSP-WILDCARD", "CSP script source is overly broad", csp[:200], url=r.url)
        m = re.search(r"max-age\s*=\s*(\d+)", h.get("strict-transport-security", ""), re.I)
        if m and int(m.group(1)) < 15552000:
            self.add("low", "HSTS-SHORT", "Short HSTS max-age", f"max-age={m.group(1)}", url=r.url)
        if h.get("x-content-type-options") and h["x-content-type-options"].lower() != "nosniff":
            self.add("low", "XCTO-INVALID", "Invalid X-Content-Type-Options", h["x-content-type-options"], url=r.url)
        if h.get("referrer-policy", "").lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            self.add("low", "REFERRER-PERMISSIVE", "Permissive Referrer-Policy", h["referrer-policy"], url=r.url)
        if re.search(r"\d", h.get("server", "")):
            self.add("low", "HDR-SERVER-VERSION", "Server header discloses version", h["server"], url=r.url)
        if h.get("x-powered-by"):
            self.add("low", "HDR-POWERED-BY", "X-Powered-By exposed", h["x-powered-by"], url=r.url)
        acao, acac = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            self.add("high", "CORS-WILDCARD-CREDS", "Wildcard CORS with credentials", "ACAO=* and ACAC=true", url=r.url)
        elif acao == "*":
            self.add("info", "CORS-WILDCARD", "Wildcard CORS policy", "Verify this is intentional.", url=r.url)
        cc = h.get("cache-control", "").lower()
        if r.status_code < 400 and ("public" in cc or "s-maxage" in cc) and set_cookie_headers(r):
            self.add("medium", "CACHE-PUBLIC-SETCOOKIE", "Cacheable response sets a cookie", f"Cache-Control: {h.get('cache-control')}",
                     "Mark responses that set cookies private/no-store so shared caches cannot store or replay them.", url=r.url)
        if h.get("access-control-allow-origin", "").lower() == "null":
            self.add("medium", "CORS-NULL-ORIGIN", "CORS allows the 'null' origin", "ACAO: null",
                     "Do not trust the null origin (sandboxed iframes/local files can send it).", url=r.url)
        for hn in ("x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-debug-token", "x-debug-token-link"):
            if h.get(hn):
                dbg = hn.startswith("x-debug")
                self.add("medium" if dbg else "low", "MISCONF-DEBUG-HEADER" if dbg else "HDR-VERSION-DISCLOSURE",
                         "Debug/profiler header exposed" if dbg else "Technology/version header exposed", f"{hn}: {h[hn][:80]}",
                         "Disable debug tooling in production and strip version headers.", url=r.url)
        wa = h.get("www-authenticate", "")
        if wa.lower().startswith("basic") and not https:
            self.add("high", "AUTH-BASIC-HTTP", "HTTP Basic authentication over plaintext HTTP", wa[:80],
                     "Serve authenticated resources over HTTPS only.", url=r.url)
        path = urlparse(r.url).path.lower()
        if any(x in path for x in ("/login", "/account", "/admin", "/dashboard")) and "public" in h.get("cache-control", "").lower():
            self.add("medium", "CACHE-PUBLIC-SENSITIVE", "Public caching on sensitive-looking URL", h["cache-control"], url=r.url)
        return {k: v for k, v in r.headers.items()}

    def check_cookies(self, r):
        raws = []
        for x in list(r.history) + [r]:
            raws += set_cookie_headers(x)
        out = []
        for raw in raws:
            name = raw.split("=", 1)[0].strip()
            attrs = [a.strip().lower() for a in raw.split(";")[1:]]
            secure, httponly = "secure" in attrs, "httponly" in attrs
            samesite = next((a.split("=", 1)[1] for a in attrs if a.startswith("samesite=")), "")
            out.append({"name": name, "secure": secure, "httponly": httponly, "samesite": samesite})
            sessionish = bool(re.search(r"sess|token|auth|sid|jwt|login", name, re.I))
            if r.url.startswith("https://") and not secure:
                self.add("medium" if sessionish else "low", "COOKIE-NO-SECURE", "Cookie missing Secure",
                         f"{name!r} has no Secure attribute.", url=r.url)
            if not httponly:
                self.add("medium" if sessionish else "low", "COOKIE-NO-HTTPONLY", "Cookie missing HttpOnly",
                         f"{name!r} has no HttpOnly attribute.", url=r.url)
            if not samesite:
                self.add("low", "COOKIE-NO-SAMESITE", "Cookie missing SameSite", f"{name!r} has no SameSite.", url=r.url)
            elif samesite == "none" and not secure:
                self.add("medium", "COOKIE-SAMESITE-NONE-INSECURE", "SameSite=None without Secure", name, url=r.url)
            first = raw.split(";", 1)[0]
            value = first.split("=", 1)[1] if "=" in first else ""
            if sessionish:
                ma = next((a.split("=", 1)[1] for a in attrs if a.startswith("max-age=")), "")
                if ma.isdigit() and int(ma) > 30 * 86400:
                    self.add("low", "SESSION-LONG-LIVED", "Long-lived session-like cookie", f"{name!r} Max-Age={ma}s",
                             "Use short session lifetimes and server-side revocation.", url=r.url)
            if JWT_RE.fullmatch(value):
                self.analyze_jwt(value, r.url, f"cookie {name}", httponly)
            self.check_serialized(value, r.url, f"cookie {name}")
        return out

    def check_tls(self):
        u = urlparse(self.target)
        host, port = u.hostname, u.port or 443
        res = {"host": host, "port": port}
        try:
            with socket.create_connection((host, port), timeout=self.cfg["timeout"]) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as s:
                    cert, res["tls_version"], res["cipher"] = s.getpeercert(), s.version(), s.cipher()[0]
        except ssl.SSLCertVerificationError as e:
            self.add("high", "TLS-CERT-INVALID", "Certificate validation failed", str(e), "Fix the certificate chain/hostname.")
            return res
        except Exception as e:
            self.add("medium", "TLS-CONNECT-FAILED", "TLS connection failed", str(e))
            return res
        if re.search(r"RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon", res["cipher"], re.I):
            self.add("high", "CRYPTO-WEAK-CIPHER", "Weak TLS cipher negotiated", res["cipher"], "Disable weak ciphers.")
        if res["tls_version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
            self.add("high", "TLS-OUTDATED", "Outdated TLS negotiated", res["tls_version"])
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        res["expires_in_days"] = int((exp - time.time()) / 86400)
        res["issuer"] = " ".join(v for rdn in cert.get("issuer", []) for _, v in rdn)
        if res["expires_in_days"] < 0:
            self.add("critical", "TLS-CERT-EXPIRED", "Certificate expired", cert["notAfter"])
        elif res["expires_in_days"] < 21:
            self.add("medium", "TLS-CERT-EXPIRING", "Certificate expires soon", f"{res['expires_in_days']} days left")
        return res

    def check_http_redirect(self):
        r = self.fetch(f"http://{self.host}/", allow_redirects=False, retries=0)
        loc = r.headers.get("Location", "")
        res = {"status": r.status_code, "location": loc}
        if not (300 <= r.status_code < 400 and loc.lower().startswith("https://")):
            self.add("medium", "HTTP-NO-REDIRECT", "HTTP does not redirect to HTTPS",
                     f"http:// returned {r.status_code}.", "Redirect all HTTP traffic to HTTPS.")
        return res

    def check_dns(self):
        host = self.host
        try:
            ipaddress.ip_address(host)
            return {"skipped": "IP address"}
        except ValueError:
            pass
        res = {"addresses": sorted({x[4][0] for x in socket.getaddrinfo(host, None)})}
        txt = self.doh(host, "TXT")
        res["mx"], res["ns"] = self.doh(host, "MX"), self.doh(host, "NS")
        spf = [t for t in txt if "v=spf1" in t.lower()]
        if not spf:
            self.add("low", "DNS-NO-SPF", "SPF record not observed", host)
        elif re.search(r"[+?]all\b", spf[0]):
            self.add("medium", "DNS-SPF-PERMISSIVE", "SPF policy is permissive", spf[0])
        dmarc = [t for t in self.doh("_dmarc." + host, "TXT") if "v=dmarc1" in t.lower()]
        if not dmarc:
            self.add("low", "DNS-NO-DMARC", "DMARC record not observed", host)
        elif re.search(r"p\s*=\s*none", dmarc[0], re.I):
            self.add("info", "DNS-DMARC-MONITOR", "DMARC policy is p=none", dmarc[0])
        res["spf"], res["dmarc"] = spf, dmarc
        res["caa"] = self.doh(host, "CAA")
        if not res["caa"]:
            self.add("info", "DNS-NO-CAA", "No CAA record observed", host)
        res["dnssec_ds"] = bool(self.doh(host, "DS"))
        return res

    def check_exposure(self, base):
        base_url = base.rstrip("/") + "/"
        baseline = None
        try:
            bl = self.fetch(urljoin(base_url, secrets.token_hex(8) + ".txt"), allow_redirects=False, retries=1)
            baseline = hashlib.sha256(bl.content[:50000]).hexdigest()
            self.scan_text(bl.text, bl.url, "error page")
        except Exception:
            pass

        def probe(item):
            path, (pattern, sev, html_ok) = item
            url = urljoin(base_url, path)
            try:
                r = self.fetch(url, allow_redirects=False, retries=1)
            except Exception as e:
                return {"path": path, "error": str(e)}
            rec = {"path": path, "status": r.status_code, "length": len(r.content)}
            if r.status_code != 200 or not r.content:
                return rec
            if baseline and hashlib.sha256(r.content[:50000]).hexdigest() == baseline:
                rec["soft404"] = True
                return rec
            if "text/html" in r.headers.get("Content-Type", "").lower() and not html_ok:
                return rec
            body = r.content[:20000].decode("latin-1")
            if re.search(pattern, body):
                snippet = re.sub(r"\s+", " ", body[:160])
                if path == ".env":
                    snippet = re.sub(r"=[^\s]*", "=***", snippet)
                self.add(sev, "MAL-WEBSHELL-FILE" if path in WEBSHELL_PATHS else "EXPOSED-" + re.sub(r"\W+", "-", path).upper().strip("-"),
                         ("Possible webshell present: " if path in WEBSHELL_PATHS else "Exposed resource: ") + path, f"HTTP 200 with matching content ({len(r.content)} bytes).",
                         "Remove it from the web root or block access; rotate any exposed secrets.",
                         snippet, url, "high")
                rec["confirmed"] = True
            return rec

        with cf.ThreadPoolExecutor(self.cfg["workers"]) as ex:
            return list(ex.map(probe, SENSITIVE_FILES.items()))

    def check_methods(self, url):
        res = {}
        o = self.fetch(url, "OPTIONS", allow_redirects=False, retries=0)
        allow = o.headers.get("Allow", "")
        res["OPTIONS"] = {"status": o.status_code, "allow": allow}
        if re.search(r"\b(PUT|DELETE|PATCH)\b", allow):
            self.add("low", "METHODS-WRITE", "Write methods advertised", allow, "Restrict unneeded HTTP methods.", url=url)
        t = self.fetch(url, "TRACE", allow_redirects=False, retries=0)
        res["TRACE"] = {"status": t.status_code}
        if t.status_code == 200 and "TRACE" in t.text[:500]:
            self.add("medium", "METHODS-TRACE", "TRACE method enabled", "Server echoed the request.", "Disable TRACE.", url=url)
        return res

    def check_meta_files(self, base):
        res = {}
        for path in (".well-known/security.txt", "robots.txt", "sitemap.xml"):
            url = urljoin(base.rstrip("/") + "/", path)
            try:
                r = self.fetch(url, retries=1)
            except Exception as e:
                res[path] = {"error": str(e)}
                continue
            res[path] = {"status": r.status_code, "length": len(r.content)}
            if path.endswith("security.txt"):
                if r.status_code == 200 and "text/html" not in r.headers.get("Content-Type", ""):
                    fields = {k.strip().lower(): v.strip() for k, _, v in
                              (l.partition(":") for l in r.text.splitlines() if ":" in l and not l.startswith("#"))}
                    if "contact" not in fields:
                        self.add("low", "SECTXT-NO-CONTACT", "security.txt lacks Contact", url, url=url)
                    if "expires" not in fields:
                        self.add("low", "SECTXT-NO-EXPIRES", "security.txt lacks Expires", "Required by RFC 9116.", url=url)
                else:
                    self.add("info", "SECTXT-MISSING", "No security.txt found", "Publish /.well-known/security.txt.", url=url)
            elif path == "robots.txt" and r.status_code == 200:
                hits = [l.split(":", 1)[1].strip() for l in r.text.splitlines()
                        if l.lower().startswith("disallow:") and re.search(r"admin|backup|private|internal|secret|staging|\.sql", l, re.I)]
                if hits:
                    self.add("info", "ROBOTS-SENSITIVE", "robots.txt lists sensitive-looking paths",
                             ", ".join(hits[:10]), "robots.txt is public; do not rely on it for secrecy.", url=url)
        return res

    # -- page / asset analysis
    def detect_tech(self, text, headers, cookies):
        hay = (text[:200000] + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
               + "\n" + " ".join(c["name"] for c in cookies))
        for tech, pats in TECH_PATTERNS.items():
            if any(re.search(p, hay, re.I) for p in pats):
                self.tech.add(tech)

    def scan_text(self, text, url, kind):
        text = text[:1_500_000]
        for name, rx, sev in SECRET_PATTERNS:
            for m in list(rx.finditer(text))[:3]:
                self.add(sev, "SECRET-" + re.sub(r"\W+", "_", name.upper()), f"Possible exposed secret: {name}",
                         f"Pattern found in {kind}.", "Remove it from public assets and rotate the credential.",
                         mask(m.group(0)), url, "low" if name == "Generic Secret" else "medium")
        for tok in list(set(JWT_RE.findall(text)))[:5]:
            self.analyze_jwt(tok, url, kind)
        for name, rx in DISCLOSURE_PATTERNS:
            m = rx.search(text)
            if m:
                ex = re.sub(r"\s+", " ", text[max(0, m.start() - 60):m.end() + 100])[:220]
                self.add("medium", "DISC-" + name.upper(), f"Possible information disclosure: {name}", f"Found in {kind}.",
                         "Disable verbose errors/debug output in production.", ex, url)

    def analyze_page(self, url, text, parser, headers=None):
        https = url.startswith("https://")
        host = urlparse(url).hostname
        for kind, ru in parser.resources:
            if https and ru.startswith("http://"):
                self.add("low" if kind == "img" else "medium", "MIXED-CONTENT", "Mixed content reference",
                         f"{kind} loaded over HTTP: {ru}", "Load all resources over HTTPS.", url=url)
        nosri = [x["url"] for x in parser.scripts + parser.styles
                 if urlparse(x["url"]).hostname not in (host, None) and not x["integrity"]]
        if nosri:
            self.add("low", "SRI-MISSING", "Third-party resources without SRI", f"{len(nosri)} resource(s), e.g. {nosri[0]}",
                     "Add integrity= and crossorigin= to third-party scripts/styles.", url=url)
        for f in parser.forms:
            pw = any(i["type"] == "password" for i in f["inputs"])
            same = urlparse(f["action"]).hostname == host
            if pw and (not https or f["action"].startswith("http://")):
                self.add("high", "FORM-PASSWORD-HTTP", "Password form not protected by HTTPS", f["action"], url=url)
            if pw and f["method"] == "GET":
                self.add("high", "FORM-PASSWORD-GET", "Password submitted via GET", f["action"], url=url)
            if https and f["action"].startswith("http://"):
                self.add("high", "FORM-HTTP-ACTION", "HTTPS page posts to HTTP", f["action"], url=url)
            if f["method"] == "POST" and same and not any(h in (i["name"] or "").lower() for i in f["inputs"] for h in CSRF_HINTS):
                self.add("info", "FORM-NO-CSRF-TOKEN", "POST form without visible CSRF token",
                         f["action"], "Heuristic only; header- or cookie-based CSRF defenses are not visible here.", url=url, conf="low")
        for s_ in parser.scripts:
            if self.in_scope(s_["url"]):
                self.scripts[s_["url"]] = True
        with self.lock:
            self.script_urls.update(x["url"] for x in parser.scripts + parser.styles)
            self.urls_seen.update(parser.links)
            self.forms_seen.extend((url, f) for f in parser.forms)
        if re.search(r"<title>\s*Index of /|Directory listing for /", text, re.I):
            self.add("medium", "VULN-DIR-LISTING", "Directory listing enabled", "The page looks like an auto-generated directory index.",
                     "Disable directory indexing (Options -Indexes / autoindex off).", url=url, conf="high")
        for m in re.finditer(r"""/wp-content/(plugins|themes)/([\w\-]+)/[^"'\s>]*?[?&](?:amp;|\#038;)?ver=(\d+(?:\.\d+)+)""", text):
            (self.wp_plugins if m.group(1) == "plugins" else self.wp_themes).setdefault(m.group(2), m.group(3))
        self.scan_text(text, url, "HTML")
        self.scan_malicious(text, url, "HTML", parser)
        for b in INLINE_SCRIPT_RX.findall(text)[:50]:
            self.scan_client_side(b, url)
        if re.search(r"(?is)<!DOCTYPE[^>]*\[[^\]]*<!ENTITY", text):
            self.add("info", "XXE-DTD-ENTITY-SERVED", "Document with DTD ENTITY declarations served", "Page contains <!ENTITY ...>.",
                     "Confirm XML parsers on the server disable DTDs/external entities.", url=url, conf="low")
        if re.search(r"Welcome to nginx!|Apache2 (?:Ubuntu |Debian )?Default Page|IIS Windows Server|Test Page for the (?:Apache|Nginx)", text):
            self.add("low", "MISCONF-DEFAULT-PAGE", "Default web-server page exposed", "Stock server welcome page.",
                     "Remove default content and confirm the intended site is served.", url=url)
        if headers and any(i["type"] == "password" for f in parser.forms for i in f["inputs"]) and "no-store" not in headers.get("Cache-Control", "").lower():
            self.add("low", "CACHE-LOGIN-CACHEABLE", "Login page without Cache-Control: no-store", headers.get("Cache-Control", "(none)"),
                     "Send no-store on pages with credentials or personal data.", url=url)

    def analyze_js(self, url):
        r = self.fetch(url, retries=1)
        if r.status_code != 200:
            return None
        text = r.text[:1_500_000]
        self.scan_text(text, url, "JavaScript")
        self.detect_js_banner(text, url)
        self.scan_malicious(text, url, "JavaScript")
        if not LIB_RX.search(urlparse(url).path.lower()):
            self.scan_client_side(text, url)
        eps = sorted({m for m in re.findall(r"""["']((?:https?:)?//[^"' ]+|/[^"' ]{2,160})["']""", text)
                      if re.search(r"/(?:api|graphql|auth|oauth|token|admin|upload)", m, re.I)})[:50]
        res = {"url": url, "size": len(r.content), "endpoints": eps,
               "uses_document_cookie": "document.cookie" in text, "uses_postMessage": "postMessage(" in text}
        with self.lock:
            self.js_endpoints.update(urljoin(url, e) for e in eps)
        m = re.search(r"//[#@]\s*sourceMappingURL=([^\s]+)", text)
        if m and not m.group(1).startswith("data:"):
            mu = urljoin(url, m.group(1))
            res["source_map"] = mu
            try:
                if self.in_scope(mu) and self.fetch(mu, "HEAD", retries=0).status_code == 200:
                    self.add("low", "JS-SOURCEMAP-PUBLIC", "Public source map", mu,
                             "Do not publish source maps in production unless intended.", url=url)
            except Exception:
                pass
        return res

    def crawl(self, first_resp, first_parser):
        cap, host = self.cfg["max_pages"], self.host
        visited = {first_resp.url.split("#")[0]}
        frontier, broken = list(first_parser.links), []
        params = Counter()

        def fetch_page(u):
            try:
                r = self.fetch(u, retries=1)
            except Exception as e:
                return u, None, str(e)
            return u, r, None

        pages = [{"url": first_resp.url, "status": first_resp.status_code}]
        while frontier and len(pages) < cap:
            batch = []
            for u in frontier:
                if (u not in visited and self.in_scope(u) and
                        Path(urlparse(u).path).suffix.lower() not in SKIP_EXT and len(batch) < cap - len(pages)):
                    visited.add(u)
                    batch.append(u)
            frontier = []
            with cf.ThreadPoolExecutor(self.cfg["workers"]) as ex:
                results = list(ex.map(fetch_page, batch))
            for u, r, err in results:
                if r is None:
                    broken.append({"url": u, "error": err})
                    continue
                pages.append({"url": u, "final_url": r.url, "status": r.status_code})
                self.check_reflection(u, r)
                if r.status_code >= 400:
                    if r.status_code not in (401, 403, 429):
                        broken.append({"url": u, "status": r.status_code})
                    continue
                for k, _ in parse_qsl(urlparse(r.url).query, keep_blank_values=True):
                    params[k.lower()] += 1
                if "text/html" in r.headers.get("Content-Type", "").lower():
                    p = PageParser(r.url)
                    p.feed(r.text[:1_000_000])
                    self.analyze_page(r.url, r.text, p, r.headers)
                    frontier += list(p.links)
        for b in broken[:25]:
            if b.get("status"):
                self.add("low", "CRAWL-BROKEN-URL", "Broken URL discovered", f"{b['url']} returned {b['status']}.",
                         "Repair or remove the reference.", url=b["url"])
        return {"pages": pages, "pages_scanned": len(pages), "broken": broken, "parameters": dict(params.most_common(50))}

    # -- passive indicators (read-only; nothing is injected or exploited)
    def analyze_jwt(self, tok, url, where, httponly=None):
        try:
            hdr = json.loads(b64url(tok.split(".")[0]) or "{}")
            pl = json.loads(b64url(tok.split(".")[1]) or "{}")
        except Exception:
            return
        if not isinstance(hdr, dict) or not isinstance(pl, dict):
            return
        alg, ev = str(hdr.get("alg", "")), mask(tok)

        def j(sev, rule, title, detail, rec="", conf="medium"):
            self.add(sev, rule, title, detail, rec, ev, url, conf)

        j("medium" if httponly is False else "low", "JWT-EXPOSED", f"JWT visible in {where}",
          f"alg={alg or '?'}; claims: {', '.join(list(pl)[:8])}", "Keep tokens out of page-readable locations unless intended (HttpOnly cookies).")
        if alg.lower() == "none":
            j("high", "JWT-ALG-NONE", "JWT uses alg=none", "Unsigned token.", "Reject unsigned tokens server-side.", "high")
        if any(k in hdr for k in ("jku", "x5u", "jwk")):
            j("medium", "JWT-HEADER-KEY-URL", "JWT header carries a key location (jku/x5u/jwk)", ", ".join(k for k in ("jku", "x5u", "jwk") if k in hdr),
              "Servers must ignore attacker-supplied key locations and use a fixed key set.", "low")
        kid = str(hdr.get("kid", ""))
        if kid and re.search(r"""[./\\'"|;]""", kid):
            j("medium", "JWT-KID-SUSPICIOUS", "JWT kid contains path/injection-like characters", kid[:60],
              "Validate kid against an allow-list; never use it in file paths or queries.", "low")
        exp, iat = pl.get("exp"), pl.get("iat")
        if exp is None:
            j("medium", "JWT-NO-EXPIRY", "JWT has no exp claim", "Token never expires.", "Issue short-lived tokens with exp.")
        elif isinstance(exp, (int, float)):
            life = exp - (iat if isinstance(iat, (int, float)) else time.time())
            if life > 30 * 86400:
                j("low", "JWT-LONG-LIVED", "JWT lifetime exceeds 30 days", f"~{int(life / 86400)} days", "Shorten lifetimes; use refresh tokens.")
        sens = [k for k in pl if SENSITIVE_KEY_RE.search(str(k))]
        if sens:
            j("low", "JWT-SENSITIVE-CLAIMS", "JWT payload carries personal/sensitive claims", ", ".join(sens[:6]),
              "JWT payloads are only base64-encoded (readable); keep sensitive data out.")
        if any(str(k).lower() in ("role", "roles", "admin", "is_admin", "isadmin", "scope", "permissions") for k in pl):
            j("info", "JWT-PRIVILEGE-CLAIMS", "JWT carries privilege claims", ", ".join(k for k in pl if str(k).lower() in ("role", "roles", "admin", "is_admin", "isadmin", "scope", "permissions")),
              "Authorization must rely on server-verified signatures, never on client-held claims alone.", "low")

    def check_serialized(self, value, url, where):
        v = unquote(value or "")
        if len(v) < 8:
            return
        for rx, label, sev in SERIALIZED_RX:
            if rx.search(v):
                self.add(sev, "DESER-SERIALIZED-DATA", f"Serialized object in {where}", label,
                         "Never deserialize client-controlled data without integrity protection (signing/MAC) or use a data-only format like JSON.",
                         mask(v), url, "medium" if sev != "info" else "low")
                return

    def scan_client_side(self, code, url):
        code = code[:1_000_000]
        if DOM_FLOW_RX.search(code):
            self.add("low", "CLIENT-DOM-SOURCE-SINK", "Possible DOM-XSS source-to-sink flow",
                     "Browser-controlled input (URL/referrer/window.name) appears to reach an HTML/eval sink.",
                     "Use textContent or a sanitizer; do not pass location/referrer data to innerHTML/eval. (Static heuristic.)", "", url, "low")
        for m in POSTMSG_RX.finditer(code):
            if "origin" not in code[m.end():m.end() + 600]:
                self.add("low", "CLIENT-POSTMESSAGE-NO-ORIGIN", "postMessage handler without visible origin check", "Message listener never mentions 'origin'.",
                         "Verify event.origin against an allow-list.", "", url, "low")
                break
        for rx, rule, sev, title, rec in CLIENT_PATTERNS:
            m = rx.search(code)
            if m:
                self.add(sev, rule, title, f"Pattern found in {url}.", rec, mask(m.group(0)), url, "low")

    def check_reflection(self, url, resp):
        params = [(k, v) for k, v in parse_qsl(urlparse(url).query) if len(v) >= 4]
        if not params:
            return
        skip = {"date", "content-length", "content-type", "etag", "last-modified", "vary", "cache-control", "server", "connection", "content-encoding"}
        for x in list(resp.history) + [resp]:
            for hk, hv in x.headers.items():
                if hk.lower() in skip:
                    continue
                for k, v in params:
                    if v in hv:
                        loc = hk.lower() == "location"
                        self.add("low", "CRLF-PARAM-IN-LOCATION" if loc else "CRLF-PARAM-REFLECTED-IN-HEADER",
                                 "Parameter value used in Location redirect" if loc else "Parameter value reflected in a response header",
                                 f"Parameter '{k}' appears in {hk}.",
                                 "Allow-list redirect targets and strip CR/LF from any value placed in headers.", "", url, "medium")

    def check_oauth_url(self, u, q):
        d = {k.lower(): v for k, v in q}
        if "client_id" not in d or "response_type" not in d:
            return
        rt = d["response_type"].lower().split()
        ru = d.get("redirect_uri", "")
        if "state" not in d:
            self.add("medium", "OAUTH-NO-STATE", "OAuth authorize URL without state", "Missing state parameter (CSRF on the login flow).", "Always send and verify a random state.", url=u)
        if "token" in rt or "id_token" in rt:
            self.add("low", "OAUTH-IMPLICIT-FLOW", "OAuth implicit/hybrid flow in use", d["response_type"], "Prefer authorization code + PKCE.", url=u)
        if "code" in rt and "code_challenge" not in d:
            self.add("info", "OAUTH-NO-PKCE", "Authorization code flow without PKCE", u[:120], "Use PKCE (S256), especially for public clients.", url=u, conf="low")
        if ru.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1)", ru):
            self.add("medium", "OAUTH-REDIRECT-HTTP", "OAuth redirect_uri uses plaintext HTTP", ru[:120], "Register HTTPS redirect URIs only.", url=u)
        if "*" in ru:
            self.add("medium", "OAUTH-REDIRECT-WILDCARD", "OAuth redirect_uri contains a wildcard", ru[:120], "Use exact-match redirect URI registration.", url=u)

    def check_xml_surface(self, base):
        res = {}
        u = urljoin(base.rstrip("/") + "/", "xmlrpc.php")
        try:
            r = self.fetch(u, retries=0)
            if r.status_code in (200, 405) and re.search(r"XML-RPC server accepts POST requests only", r.text, re.I):
                self.add("medium", "XXE-XMLRPC-ENDPOINT", "XML-RPC endpoint exposed", u,
                         "Disable xmlrpc.php if unused (XML parsing and brute-force amplification surface).", url=u, conf="high")
        except Exception:
            pass
        cands = {e for e in (self.js_endpoints | self.urls_seen) if re.search(r"\.asmx|\.svc|/soap|/ws/|wsdl", e, re.I) and self.in_scope(e)}
        for e in sorted(cands)[:8]:
            w = e if "wsdl" in e.lower() else e.split("?")[0] + "?wsdl"
            try:
                rr = self.fetch(w, retries=0)
            except Exception:
                continue
            res[w] = rr.status_code
            if rr.status_code == 200 and re.search(r"<(?:\w+:)?definitions\b", rr.text[:5000]):
                self.add("low", "XXE-WSDL-EXPOSED", "SOAP/WSDL service description exposed", w,
                         "SOAP/XML services parse attacker-influenced XML: ensure DTDs/external entities are disabled; restrict WSDL if not needed.", url=w)
        return res

    def check_more_indicators(self):
        res = {}
        urls = sorted(self.urls_seen | self.js_endpoints)
        idor, sens, sessid, state, crlf, versions, gql = {}, {}, {}, {}, {}, set(), False
        for u in urls:
            p = urlparse(u)
            q = parse_qsl(p.query, keep_blank_values=True)
            if re.search(r"%0d%0a", u, re.I):
                crlf[u] = 1
            m = re.search(r"/api/v(\d+)(?:/|$)", p.path)
            if m:
                versions.add(m.group(1))
            gql = gql or "graphql" in p.path.lower()
            if self.in_scope(u):
                m = IDOR_PATH_RX.search(p.path)
                if m:
                    idor.setdefault(f"/{m.group(1).lower()}/<id>", u)
                for k, v in q:
                    kl = k.lower()
                    if kl in IDOR_PARAMS and v.isdigit():
                        idor.setdefault(f"?{kl}=<number>", u)
                    if kl in SENSITIVE_PARAMS:
                        sens.setdefault(kl, u)
                    if kl in SESSION_PARAMS:
                        sessid.setdefault(kl, u)
                    self.check_serialized(v, u, f"URL parameter {k!r}")
                if re.search(r";jsessionid=", p.path, re.I):
                    sessid.setdefault("jsessionid(path)", u)
                if STATE_CHANGE_RX.search(p.path):
                    state.setdefault(p.path, u)
            self.check_oauth_url(u, q)
        first = lambda d: next(iter(d.values()))
        if idor:
            self.add("info", "IDOR-OBJECT-REFERENCES", "Direct object references in URLs", ", ".join(sorted(idor)[:8]),
                     "Verify per-object authorization server-side (test manually with two accounts).", url=first(idor), conf="low")
        if sens:
            self.add("medium", "CRYPTO-SENSITIVE-IN-URL", "Sensitive-looking data in URL query string", ", ".join(sorted(sens)),
                     "URLs are logged and leak via Referer; send secrets in POST bodies/headers.", url=first(sens))
        if sessid:
            self.add("medium", "SESSION-ID-IN-URL", "Session identifier in URL", ", ".join(sorted(sessid)),
                     "Keep session IDs in cookies only.", url=first(sessid))
        if state:
            self.add("low", "CSRF-STATE-CHANGE-GET", "State-changing actions reachable via GET links", ", ".join(sorted(state)[:5]),
                     "Use POST/DELETE with CSRF protection for state-changing actions.", url=first(state), conf="low")
        if crlf:
            self.add("low", "CRLF-ENCODED-SEQUENCE", "Encoded CR/LF sequence inside a link", first(crlf) if False else next(iter(crlf))[:120],
                     "Review why links carry %0d%0a; strip CR/LF from header values.", url=next(iter(crlf)))
        if len(versions) > 1:
            self.add("info", "API-MULTIPLE-VERSIONS", "Multiple API versions referenced", ", ".join("v" + v for v in sorted(versions)),
                     "Retire old API versions or apply the same controls to all (OWASP API9).", conf="low")
        if gql:
            self.add("info", "API-GRAPHQL-ENDPOINT", "GraphQL endpoint referenced",
                     "Introspection and depth/complexity limits cannot be verified passively.",
                     "Check manually that introspection is off in production and query limits exist.", conf="low")
        for page, f in self.forms_seen:
            files = [i for i in f["inputs"] if i["type"] == "file"]
            for i in f["inputs"]:
                n = (i["name"] or "").lower()
                if i["type"] == "hidden" and n in LOGIC_FIELDS:
                    self.add("low", "LOGIC-CLIENT-CONTROLLED-FIELD", "Security-relevant value sent from a hidden field", f"'{n}' in form {f['action']}",
                             "Never trust client-supplied prices/roles/IDs; recompute and authorize server-side.", url=page, conf="low")
                if i["type"] == "hidden" and i.get("value"):
                    self.check_serialized(i["value"], page, f"hidden field {n or '?'}")
                if i["type"] == "url" or (n in PARAM_CLASSES["SSRF"][1] and i["type"] in ("text", "url", "hidden")):
                    self.add("info", "SSRF-URL-INPUT", "Form input takes a URL/host value", f"'{n or i['type']}' in {f['action']}",
                             "If the server fetches it, allow-list destinations and block internal addresses.", url=page, conf="low")
            if files:
                if page.startswith("http://") or f["action"].startswith("http://"):
                    self.add("high", "UPLOAD-OVER-HTTP", "File upload form not protected by HTTPS", f["action"], "Serve uploads over HTTPS.", url=page)
                if f["method"] != "POST":
                    self.add("low", "UPLOAD-NOT-POST", "File upload form does not use POST", f["method"], "Uploads should use POST + multipart/form-data.", url=page)
                if all(not i.get("accept") for i in files):
                    self.add("info", "UPLOAD-NO-ACCEPT", "Upload input has no type restriction",
                             f["action"], "Client-side accept is only UX; make sure the server validates type, size and content.", url=page, conf="low")
                if any(re.search(r"svg|xml|docx|xlsx|pptx|odt", i.get("accept", ""), re.I) for i in files):
                    self.add("low", "UPLOAD-XML-FORMATS", "Upload accepts XML-based formats (SVG/Office)", f["action"],
                             "Parse with external entities disabled and sanitize SVG (XXE/stored-XSS surface).", url=page)
                if not any(h in (i["name"] or "").lower() for i in f["inputs"] for h in CSRF_HINTS):
                    self.add("low", "UPLOAD-NO-CSRF-TOKEN", "Upload form without visible CSRF token", f["action"], "Protect upload actions against CSRF.", url=page, conf="low")
        fu = self.checks.get("http", {}).get("final_url", self.target)
        base = f"{urlparse(fu).scheme}://{urlparse(fu).netloc}/"
        for pth in (".well-known/openid-configuration", ".well-known/oauth-authorization-server"):
            try:
                r = self.fetch(urljoin(base, pth), retries=0)
                if r.status_code != 200 or "json" not in r.headers.get("Content-Type", "").lower():
                    continue
                c = r.json()
            except Exception:
                continue
            res[pth] = True
            u = urljoin(base, pth)
            if "none" in c.get("id_token_signing_alg_values_supported", []):
                self.add("high", "OAUTH-ALG-NONE", "OIDC provider advertises alg=none for ID tokens", u, "Disable unsigned ID tokens.", url=u)
            if any("token" in str(x).split() for x in c.get("response_types_supported", [])):
                self.add("low", "OAUTH-IMPLICIT-ADVERTISED", "OIDC provider still advertises implicit flow", u, "Disable implicit/hybrid flows where possible.", url=u)
            if "password" in c.get("grant_types_supported", []):
                self.add("medium", "OAUTH-PASSWORD-GRANT", "Resource-owner password grant enabled", u, "Deprecated; use authorization code + PKCE.", url=u)
            cm = c.get("code_challenge_methods_supported")
            if not cm:
                self.add("info", "OAUTH-PKCE-NOT-ADVERTISED", "PKCE support not advertised", u, "Support and require PKCE (S256).", url=u, conf="low")
            elif "S256" not in cm:
                self.add("low", "OAUTH-PKCE-PLAIN-ONLY", "Only plain PKCE advertised", u, "Support S256.", url=u)
        return res

    # -- compromise indicators (read-only: nothing is executed or exploited)
    def scan_malicious(self, text, url, kind, parser=None):
        if "malware" in self.skip:
            return
        text = text[:1_500_000]
        page_host = (urlparse(url).hostname or "").lower()

        def hit(sev, rule, title, detail, evidence="", conf="medium"):
            self.add(sev, rule, title, detail, MAL_ADVICE, evidence, url, conf)

        m = MINER_RX.search(text)
        if m:
            hit("high", "MAL-CRYPTOMINER", "Possible in-browser cryptominer", f"Reference to {m.group(0)!r} in {kind}.", m.group(0), "high")
        m = OBFUSC_RX.search(text)
        if m:
            hit("medium", "MAL-OBFUSCATED-CODE", "Obfuscated dynamic code",
                f"Pattern typical of injected/packed payloads in {kind}.", mask(m.group(0)), "low")
        m = WEBSHELL_RX.search(text)
        if m:
            hit("critical", "MAL-WEBSHELL-UI", "Webshell signature in content", f"Marker {m.group(0)!r} in {kind}.", m.group(0))
        m = DEFACE_RX.search(text)
        if m:
            hit("high", "MAL-DEFACEMENT", "Possible defacement", f"Defacement-style text in {kind}.", re.sub(r"\s+", " ", m.group(0))[:120])
        if kind == "HTML":
            for tag in IFRAME_RX.findall(text)[:200]:
                src = re.search(r"""src\s*=\s*["']?([^"'\s>]+)""", tag, re.I)
                if not src:
                    continue
                host = (urlparse(urljoin(url, src.group(1))).hostname or "").lower()
                tiny = re.search(r"""(?:width|height)\s*=\s*["']?[01](?:px)?["'\s>]""", tag, re.I)
                hidden = re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}", tag, re.I)
                if host and host != page_host and (tiny or hidden):
                    hit("high", "MAL-HIDDEN-IFRAME", "Hidden iframe to external host", src.group(1), tag[:160])
            for blk in HIDDEN_BLOCK_RX.findall(text)[:50]:
                ext = [h for h in re.findall(r"""<a\b[^>]*href\s*=\s*["']https?://([^/"']+)""", blk, re.I) if h.lower() != page_host]
                if len(ext) >= 3 or (ext and SPAM_RX.search(blk)):
                    hit("medium", "MAL-HIDDEN-LINKS", "Hidden block of external links (possible SEO-spam injection)",
                        f"{len(ext)} external link(s) inside a hidden element.", ", ".join(ext[:5]))
                    break
            m = META_REFRESH_RX.search(text)
            if m and (urlparse(m.group(1)).hostname or "").lower() != page_host:
                hit("low", "MAL-META-REDIRECT", "Meta refresh to another domain", m.group(1), conf="low")
            for s_ in (parser.scripts if parser else []):
                h = (urlparse(s_["url"]).hostname or "").lower()
                if not h or h == page_host:
                    continue
                try:
                    ipaddress.ip_address(h)
                    raw = True
                except ValueError:
                    raw = False
                if raw or h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
                    hit("low", "MAL-SCRIPT-HOST", "Script loaded from raw IP / low-reputation TLD", s_["url"], conf="low")
            bodies = INLINE_SCRIPT_RX.findall(text)
        else:
            bodies = [text]
        for b in bodies:
            if CARD_RX.search(b) and EXFIL_RX.search(b) and re.search(r"addEventListener|onchange|onblur|onkeyup", b):
                hit("medium", "MAL-SKIMMER-PATTERN", "Possible payment-card skimmer pattern",
                    "Script reads card-like fields and sends data over the network.", conf="low")
                break

    # -- vulnerability indicators (passive: version/pattern based, nothing is exploited)
    def add_component(self, name, ver, src):
        with self.lock:
            self.components.setdefault(name, {}).setdefault(ver, set()).add(src)

    def detect_js_banner(self, text, url):
        for name, rx in JS_BANNERS:
            m = re.search(rx, text[:4000], re.I)
            if m:
                self.add_component(name, m.group(1), url)

    def collect_components(self):
        for u in list(self.script_urls):
            for name, ver in libs_from_url(u):
                self.add_component(name, ver, u)

    def check_components(self):
        inventory, banners = [], []
        for name, vers in sorted(self.components.items()):
            for ver, srcs in sorted(vers.items()):
                srcs = sorted(srcs)
                inventory.append({"name": name, "version": ver, "sources": srcs[:3]})
                v = vtuple(ver)
                hits = [(sev, why) for prod, lo, hi, sev, why in KNOWN_VULNS if prod == name and lo <= v < hi]
                if hits:
                    sev = min((h[0] for h in hits), key=SEV_ORDER.index)
                    self.add(sev, "VULN-COMPONENT-" + name.upper(), f"Known-vulnerable component: {name} {ver}",
                             "; ".join(dict.fromkeys(h[1] for h in hits)), f"Upgrade {name} to a patched release.",
                             srcs[0], srcs[0], "medium")
        h = self.checks.get("headers") or {}
        text = " ".join(str(v) for k, v in h.items() if k.lower() in ("server", "x-powered-by", "x-generator"))
        for prod, rx, limit, sev, why in BANNER_RULES:
            m = re.search(rx, text, re.I)
            if m:
                banners.append(f"{prod} {m.group(1)}")
                if vtuple(m.group(1)) < limit:
                    self.add(sev, "VULN-BANNER-" + re.sub(r"\W+", "-", prod.upper()),
                             f"Unsupported server component (banner): {prod} {m.group(1)}", why,
                             "Verify the real version (banners can be hidden or backported), then upgrade to a supported release.",
                             text[:120], self.target, "low")
        wp = {"plugins": self.wp_plugins, "themes": self.wp_themes}
        if self.wp_plugins or self.wp_themes:
            items = [f"{k} {v}" for k, v in {**self.wp_plugins, **self.wp_themes}.items()]
            self.add("info", "VULN-WP-INVENTORY", "WordPress plugins/themes detected with versions", ", ".join(items[:30]),
                     "Check each version against WPScan / Patchstack advisories and keep them updated.", url=self.target)
        return {"components": inventory, "banners": banners, "wordpress": wp}

    def check_osv(self):
        """Opt-in (--osv): sends only library name+version to api.osv.dev, never the target URL."""
        res, n = [], 0
        for name, vers in sorted(self.components.items()):
            for ver in sorted(vers):
                if n >= 25:
                    return res
                n += 1
                self.limiter.wait()
                r = requests.post(OSV_URL, json={"package": {"name": name, "ecosystem": "npm"}, "version": ver},
                                  headers={"User-Agent": self.cfg["user_agent"]}, timeout=self.cfg["timeout"])
                if not r.ok:
                    self.add("info", "VULN-OSV-UNAVAILABLE", "OSV.dev lookup failed", f"HTTP {r.status_code} for {name} {ver}.")
                    continue
                vulns = [v for v in r.json().get("vulns", []) if not v.get("withdrawn")]
                if not vulns:
                    continue
                ids = [v["id"] for v in vulns]
                worst = min((OSV_SEV.get(str(v.get("database_specific", {}).get("severity", "")).upper(), "medium")
                             for v in vulns), key=SEV_ORDER.index)
                top = next((v.get("summary", "") for v in vulns if v.get("summary")), "")
                res.append({"name": name, "version": ver, "count": len(ids), "ids": ids[:20]})
                self.add(worst, "VULN-OSV-" + name.upper(), f"OSV: {len(ids)} advisory(ies) for {name} {ver}",
                         f"{', '.join(ids[:6])}{' ...' if len(ids) > 6 else ''}. {top}"[:400],
                         "Upgrade to a patched version.", "https://osv.dev/vulnerability/" + ids[0],
                         sorted(vers[ver])[0], "medium")
        return res

    def check_entry_points(self):
        res = {"parameter_classes": {}, "upload_forms": [], "api_probes": []}
        found = {}
        for u in self.urls_seen:
            for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True):
                for cid, (_, names, _) in PARAM_CLASSES.items():
                    if k.lower() in names:
                        found.setdefault(cid, {}).setdefault(k.lower(), u)
        for cid, d in found.items():
            label, _, advice = PARAM_CLASSES[cid]
            res["parameter_classes"][cid] = sorted(d)
            self.add("info", "ENTRY-PARAM-" + cid, f"{label} parameter names observed", ", ".join(sorted(d)),
                     advice + " (Name-based heuristic; nothing was tested.)", next(iter(d.values())), conf="low")
        for page, f in self.forms_seen:
            if any(i["type"] == "file" for i in f["inputs"]):
                res["upload_forms"].append(f["action"])
                self.add("info", "ENTRY-FILE-UPLOAD", "File upload form found", f["action"],
                         "Review type/size validation, storage outside the web root, and malware scanning.", url=page)
        cands = set()
        for e in self.js_endpoints | {u for u in self.urls_seen if "/api/" in u.lower()}:
            e = e.split("#")[0]
            if re.search(r"""[{}$'"+]""", e) or not self.in_scope(e):
                continue
            if re.search(r"health|status|ping|version|swagger|openapi|docs|robots|sitemap|manifest", e, re.I):
                continue
            cands.add(e)
        for u in sorted(cands)[:12]:
            try:
                r = self.fetch(u, retries=0)
            except Exception:
                continue
            ct = r.headers.get("Content-Type", "").lower()
            rec = {"url": u, "status": r.status_code, "content_type": ct}
            if r.status_code == 200 and "json" in ct and len(r.content) > 2:
                try:
                    keys = json_keys(r.json())
                except Exception:
                    keys = []
                rec["fields"] = keys[:15]
                sens = [k for k in keys if SENSITIVE_KEY_RE.search(k)]
                self.add("medium" if sens else "low", "ENTRY-API-UNAUTH", "API endpoint returns data without authentication",
                         "GET returned JSON with no credentials" + (f"; sensitive-looking fields: {', '.join(sens[:6])}" if sens else "."),
                         "Confirm this endpoint is meant to be public; enforce authentication/authorization otherwise.",
                         "fields: " + ", ".join(keys[:10]), u, "low")
                if not any(k.lower().startswith(("x-ratelimit", "ratelimit", "retry-after")) for k in r.headers):
                    self.add("info", "API-NO-RATE-LIMIT-HEADERS", "No rate-limit headers on API response", u,
                             "Verify rate limiting/quotas exist server-side (OWASP API4).", url=u, conf="low")
                if r.headers.get("Access-Control-Allow-Origin") == "*":
                    self.add("low", "API-CORS-WILDCARD", "API allows any origin (CORS *)", u, "Restrict CORS on authenticated APIs.", url=u)
                if not re.search(r"/v\d+(?:/|$)", urlparse(u).path):
                    self.add("info", "API-UNVERSIONED", "API path has no version segment", u,
                             "Version APIs so old versions can be retired (OWASP API9).", url=u, conf="low")
                try:
                    data = r.json()
                    item = data[0] if isinstance(data, list) and data else data
                    if isinstance(item, dict) and isinstance(item.get("id"), int):
                        self.add("info", "IDOR-API-NUMERIC-ID", "API objects use sequential numeric IDs", "Objects expose an integer 'id' field.",
                                 "Enforce object-level authorization; prefer unguessable IDs (OWASP API1).", url=u, conf="low")
                except Exception:
                    pass
            if r.status_code == 200 and "xml" in ct:
                self.add("info", "XXE-XML-ENDPOINT", "API/endpoint returns XML", u,
                         "Confirm the XML parser disables external entities and DTD processing.", url=u, conf="low")
            res["api_probes"].append(rec)
        return res

    # -- orchestration
    def run(self):
        t0 = time.time()
        report = {"tool": "Website Security Toolkit", "version": VERSION, "target": self.target, "started_at": now()}
        try:
            r = self.fetch(self.target)
        except Exception as e:
            if self.defaulted:
                try:
                    self.target = "http://" + self.target[len("https://"):]
                    r = self.fetch(self.target)
                except Exception as e2:
                    e = e2
                    r = None
            else:
                r = None
            if r is None:
                self.add("critical", "TARGET-UNREACHABLE", "Target could not be fetched", str(e))
                return self.finish(report, t0)
        self.scope.add((urlparse(r.url).hostname or "").lower())
        final = r.url
        self.checks["http"] = {"status": r.status_code, "final_url": final,
                               "redirects": [{"status": x.status_code, "url": x.url} for x in r.history],
                               "content_type": r.headers.get("Content-Type", ""), "length": len(r.content)}
        if final.startswith("http://"):
            self.add("high", "HTTP-ONLY", "Site served over HTTP", final, "Use HTTPS everywhere.", url=final)
        if len(r.history) > 5:
            self.add("low", "REDIRECT-LONG", "Long redirect chain", f"{len(r.history)} redirects.", url=final)

        self.checks["headers"] = self.check_headers(r)
        self.checks["cookies"] = self.check_cookies(r)
        self.check_reflection(self.target, r)
        parser = PageParser(final)
        if "text/html" in r.headers.get("Content-Type", "").lower():
            parser.feed(r.text[:1_000_000])
            self.analyze_page(final, r.text, parser, r.headers)
            self.checks["page"] = {"title": parser.title.strip(), "forms": len(parser.forms),
                                   "scripts": len(parser.scripts), "images": parser.images, "meta": parser.meta}
            gen = parser.meta.get("generator")
            if gen and re.search(r"\d", gen):
                self.add("low", "META-GENERATOR", "Generator meta tag discloses version", gen, url=final)
        self.detect_tech(r.text, r.headers, self.checks["cookies"])

        if final.startswith("https://") and self.host:
            self.checks["tls"] = self.safe("tls", self.check_tls)
            self.checks["http_redirect"] = self.safe("redirect", self.check_http_redirect)
        self.checks["dns"] = self.safe("dns", self.check_dns)
        self.checks["exposure"] = self.safe("exposure", self.check_exposure, final)
        self.checks["meta_files"] = self.safe("meta", self.check_meta_files, final)
        self.checks["methods"] = self.safe("methods", self.check_methods, final)
        if self.do_crawl:
            self.checks["crawl"] = self.safe("crawl", self.crawl, r, parser)
        if "js" not in self.skip:
            js = list(self.scripts)[: self.cfg["max_js"]]
            with cf.ThreadPoolExecutor(self.cfg["workers"]) as ex:
                out = list(ex.map(lambda u: self.safe("js", self.analyze_js, u), js))
            self.checks["javascript"] = [x for x in out if x]
        self.collect_components()
        self.checks["vulnerabilities"] = {
            "components": self.safe("vuln", self.check_components),
            "osv": self.safe("osv", self.check_osv) if self.osv else None,
            "entry_points": self.safe("entry", self.check_entry_points),
            "indicators": self.safe("indicators", self.check_more_indicators),
            "xml_surface": self.safe("xml", self.check_xml_surface, final),
        }
        self.checks["compromise_indicators"] = sorted({f.rule_id for f in self.findings if f.rule_id.startswith("MAL-")})
        return self.finish(report, t0)

    def finish(self, report, t0):
        self.findings.sort(key=lambda f: SEV_ORDER.index(f.severity))
        counts = Counter(f.severity for f in self.findings)
        score = max(0, 100 - sum(WEIGHTS[f.severity] for f in self.findings))
        report.update({
            "finished_at": now(), "duration_seconds": round(time.time() - t0, 2),
            "score": score, "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F",
            "summary": {s: counts.get(s, 0) for s in SEV_ORDER},
            "technology": sorted(self.tech), "findings": [asdict(f) for f in self.findings],
            "checks": self.checks,
        })
        return report


# --------------------------------------------------------------------------- output
def print_report(r, summary_only=False):
    s = r["summary"]
    line = " ".join(f"{k.upper()}={v}" for k, v in s.items())
    if summary_only:
        print(f"Score={r['score']}/100 ({r['grade']}) | {line}")
        return
    print("\n" + "=" * 64 + f"\n Website Security Toolkit v{VERSION}\n" + "=" * 64)
    print(f"Target : {r['target']}\nScore  : {r['score']}/100 ({r['grade']})\nTime   : {r['duration_seconds']}s\n{line}")
    if r["technology"]:
        print("Tech   : " + ", ".join(r["technology"]))
    mal = [f for f in r["findings"] if f["rule_id"].startswith("MAL-")]
    if mal:
        print(f"!! {len(mal)} possible compromise indicator(s) - investigate these first")
    print()
    for f in r["findings"]:
        print(f"[{f['severity'].upper()}] {f['title']}\n  {f['detail']}")
        if f["recommendation"]:
            print(f"  -> {f['recommendation']}")
    crawl = r["checks"].get("crawl")
    if crawl:
        print(f"\nCrawler: {crawl['pages_scanned']} pages, {len(crawl['broken'])} broken")


def print_coverage():
    labels = {"detected": "DETECTED (passive)", "indicators": "INDICATORS ONLY", "not_tested": "NOT TESTED (needs active testing)"}
    print("Passive coverage map - nothing is injected, exploited or brute-forced.\n")
    for name, status, note in COVERAGE:
        print(f"[{labels[status]}] {name}\n    {note}")


def write_json(r, path):
    Path(path).write_text(json.dumps(r, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def write_csv(r, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(Finding.__dataclass_fields__))
        w.writeheader()
        w.writerows(r["findings"])


def write_md(r, path):
    L = [f"# Website Security Report", "", f"Target: {r['target']}", f"Score: {r['score']}/100 ({r['grade']})", ""]
    L += [f"- {k.title()}: {v}" for k, v in r["summary"].items()] + [""]
    for f in r["findings"]:
        L += [f"### {f['severity'].upper()} - {f['title']}" + (f" [{f['category']}]" if f.get("category") else ""), "", f["detail"], ""]
        if f["url"]:
            L += [f"URL: {f['url']}", ""]
        if f["recommendation"]:
            L += [f"Recommendation: {f['recommendation']}", ""]
    Path(path).write_text("\n".join(L), encoding="utf-8")


def write_html(r, path):
    colors = {"critical": "#b71c1c", "high": "#e65100", "medium": "#f9a825", "low": "#1565c0", "info": "#616161"}
    E = html.escape
    rows = "".join(
        f"<tr><td style='color:#fff;background:{colors[f['severity']]}'>{f['severity'].upper()}</td>"
        f"<td>{E(f['title'])}<br><small>{E(f.get('category', ''))}</small></td><td>{E(f['detail'])}<br><small>{E(f['url'])}</small></td>"
        f"<td>{E(f['recommendation'])}</td><td><code>{E(f['evidence'])}</code></td></tr>" for f in r["findings"])
    s = r["summary"]
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Website Security Report</title>
<style>body{{font-family:Arial,sans-serif;max-width:1200px;margin:40px auto;padding:0 20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}}
th{{background:#eee}}</style></head><body><h1>Website Security Report</h1>
<p><b>Target:</b> {E(r['target'])}<br><b>Score:</b> {r['score']}/100 ({r['grade']})<br>
<b>Technologies:</b> {E(', '.join(r['technology']) or 'none detected')}</p>
<p>{' | '.join(f"{k.title()}: {v}" for k, v in s.items())}</p>
<table><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Recommendation</th><th>Evidence</th></tr>{rows}</table>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


def write_sarif(r, path):
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, results = {}, []
    for f in r["findings"]:
        rules[f["rule_id"]] = {"id": f["rule_id"], "name": f["title"], "shortDescription": {"text": f["title"]}}
        res = {"ruleId": f["rule_id"], "level": lvl[f["severity"]], "message": {"text": f["detail"]}}
        if f["url"]:
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f["url"]}}}]
        results.append(res)
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "Website Security Toolkit", "version": VERSION,
                                           "rules": list(rules.values())}}, "results": results}]}
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def compare_reports(old, new):
    key = lambda f: (f.get("rule_id", ""), f.get("url", ""), f.get("title", ""))
    o, n = {key(f): f for f in old.get("findings", [])}, {key(f): f for f in new["findings"]}
    return {"old_score": old.get("score"), "new_score": new["score"],
            "new_findings": [n[k] for k in n.keys() - o.keys()],
            "resolved_findings": [o[k] for k in o.keys() - n.keys()],
            "unchanged_count": len(o.keys() & n.keys())}


def store_db(path, r):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT,started_at TEXT,"
                "finished_at TEXT,score INTEGER,grade TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER,rule_id TEXT,"
                "severity TEXT,title TEXT,url TEXT,detail TEXT,evidence TEXT)")
    cur = con.execute("INSERT INTO scans(target,started_at,finished_at,score,grade) VALUES(?,?,?,?,?)",
                      (r["target"], r["started_at"], r["finished_at"], r["score"], r["grade"]))
    con.executemany("INSERT INTO findings(scan_id,rule_id,severity,title,url,detail,evidence) VALUES(?,?,?,?,?,?,?)",
                    [(cur.lastrowid, f["rule_id"], f["severity"], f["title"], f["url"], f["detail"], f["evidence"])
                     for f in r["findings"]])
    con.commit()
    con.close()


def build_config(args):
    cfg = dict(DEFAULT_CONFIG)
    if args.config:
        cfg.update({k: v for k, v in json.loads(Path(args.config).read_text(encoding="utf-8")).items() if k in cfg})
    for k in ("timeout", "max_pages", "workers", "rate_limit"):
        if getattr(args, k) is not None:
            cfg[k] = getattr(args, k)
    cfg["allowed_hosts"] = list(cfg.get("allowed_hosts", [])) + args.allowed_host
    cfg["timeout"] = max(2, min(60, int(cfg["timeout"])))
    cfg["max_pages"] = max(1, min(500, int(cfg["max_pages"])))
    cfg["workers"] = max(1, min(20, int(cfg["workers"])))
    cfg["rate_limit"] = max(0.0, min(10.0, float(cfg["rate_limit"])))
    return cfg


def main():
    print_banner()
    ap = argparse.ArgumentParser(description="Defensive website security scanner (authorized targets only).")
    ap.add_argument("--url")
    ap.add_argument("--coverage", action="store_true", help="Print what is (and is not) covered, then exit")
    ap.add_argument("--crawl", action="store_true")
    ap.add_argument("--max-pages", dest="max_pages", type=int)
    ap.add_argument("--workers", type=int)
    ap.add_argument("--rate-limit", dest="rate_limit", type=float, help="Seconds between requests")
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--config", metavar="FILE")
    ap.add_argument("--allowed-host", action="append", default=[], help="Extra in-scope hostname (repeatable)")
    ap.add_argument("--skip", nargs="*", default=[], choices=["dns", "tls", "redirect", "exposure", "meta", "methods", "js", "crawl", "vuln", "entry", "malware", "indicators", "xml"])
    for fmt in ("json", "html", "csv", "md", "sarif"):
        ap.add_argument(f"--{fmt}", metavar="FILE")
    ap.add_argument("--db", metavar="FILE", help="SQLite scan history")
    ap.add_argument("--no-auto-install", action="store_true", help="Do not auto-install missing dependencies")
    ap.add_argument("--osv", action="store_true", help="Look up detected JS libraries on OSV.dev (sends library name+version only)")
    ap.add_argument("--compare", metavar="FILE", help="Older JSON report to diff against")
    ap.add_argument("--fail-on", choices=SEV_ORDER[:4], help="Exit 1 if a finding at/above this severity exists (CI)")
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()
    if args.coverage:
        print_coverage()
        return 0
    if not args.url:
        ap.error("--url is required")

    try:
        cfg = build_config(args)
    except Exception as e:
        print("Config error:", e)
        return 2
    print("Authorized defensive scanning only. Target:", args.url, file=sys.stderr)
    try:
        report = Scanner(args.url, cfg, args.crawl, args.skip, args.osv).run()
    except KeyboardInterrupt:
        print("\nScan stopped.")
        return 130

    print_report(report, args.summary_only)
    for fmt, fn in (("json", write_json), ("html", write_html), ("csv", write_csv), ("md", write_md), ("sarif", write_sarif)):
        path = getattr(args, fmt)
        if path:
            fn(report, path)
            print(f"{fmt.upper()} report: {path}")
    if args.db:
        store_db(args.db, report)
        print("Saved to DB:", args.db)
    if args.compare:
        try:
            old = json.loads(Path(args.compare).read_text(encoding="utf-8"))
            cmp = compare_reports(old, report)
            out = Path(args.compare).with_name(Path(args.compare).stem + "_comparison.json")
            out.write_text(json.dumps(cmp, indent=2, default=str), encoding="utf-8")
            print(f"Comparison: {out} | new={len(cmp['new_findings'])} resolved={len(cmp['resolved_findings'])}")
        except Exception as e:
            print("Comparison error:", e)
    if args.fail_on:
        limit = SEV_ORDER.index(args.fail_on)
        if any(SEV_ORDER.index(f["severity"]) <= limit for f in report["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

