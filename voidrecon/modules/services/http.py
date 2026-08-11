"""HTTP(S) enrichment: headers, title, tech fingerprint, security headers,
content discovery and interesting-file detection."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge


_UA = "Mozilla/5.0 (compatible; voidrecon/1.0)"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Header -> technology fingerprints.
_TECH_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-generator": "X-Generator",
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-backend-server": "Backend",
}

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]


class _LinkFormParser(HTMLParser):
    """Pull out forms (esp. login/password) and script sources."""

    def __init__(self):
        super().__init__()
        self.has_password = False
        self.forms: List[str] = []
        self.scripts: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password = True
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(url: str, timeout: float = 8.0, method: str = "GET",
           vhost: Optional[str] = None):
    """Return (status, headers-dict, body-str) or (None, {}, '') on error.

    When *vhost* is set, the request is sent with an explicit Host header so
    name-based virtual hosts serve their real content.
    """
    hdrs = {"User-Agent": _UA}
    if vhost:
        hdrs["Host"] = vhost
    req = urllib.request.Request(url, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = b""
            if method == "GET":
                body = resp.read(200_000)
            return resp.status, headers, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return exc.code, headers, ""
    except Exception:
        return None, {}, ""


def enrich(host: HostReport, port: int, secure: bool,
           vhost: Optional[str] = None) -> None:
    scheme = "https" if secure else "http"
    base = f"{scheme}://{host.resolved_ip}:{port}"
    label = f"{scheme}://{host.resolved_ip}:{port}"
    tag = f" (vhost {vhost})" if vhost else ""
    utils.section(f"HTTP {label}{tag}")

    status, headers, body = _fetch(base + "/", vhost=vhost)
    if status is None:
        utils.log("warn", "no HTTP response", indent=1)
        return
    utils.log("good", f"HTTP {status}", indent=1)

    pfx = f"[{vhost}] " if vhost else ""
    _headers_and_tech(host, port, headers, pfx)
    _title_and_meta(host, port, body, pfx)
    _security_headers(host, port, headers, secure)
    _redirect_hostnames(host, headers)
    _comments_and_emails(host, port, body, pfx)
    _forms(host, port, body)
    _content_discovery(host, port, base, vhost)


def _headers_and_tech(host: HostReport, port: int, headers: Dict[str, str],
                      pfx: str = "") -> None:
    server = headers.get("server", "")
    if server:
        utils.kv("server", server, indent=4)
        host.add(Finding(title=f"{pfx}Server header: {server}", severity="info",
                         category="web", port=port, service="http"))
    for key, label in _TECH_HEADERS.items():
        if key in headers and key != "server":
            val = headers[key]
            utils.kv(label, val, indent=4)
            host.add(Finding(title=f"{pfx}{label}: {val}", severity="info",
                             category="web", port=port, service="http"))
            for sev, note in knowledge.match_hints(val):
                host.add(Finding(title=note, severity=sev, category="web",
                                 port=port, service="http", evidence=val))
    # Version hints from the server banner itself.
    for sev, note in knowledge.match_hints(server):
        host.add(Finding(title=note, severity=sev, category="web",
                         port=port, service="http", evidence=server))
        utils.log("warn", note, indent=2)

    # Interesting cookies (session frameworks leak the stack).
    cookie = headers.get("set-cookie", "")
    for name in ("PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "laravel_session",
                 "csrftoken", "connect.sid"):
        if name.lower() in cookie.lower():
            utils.kv("cookie", name, indent=4)
            host.add(Finding(title=f"Framework cookie: {name}", severity="info",
                             category="web", port=port, service="http"))


def _title_and_meta(host: HostReport, port: int, body: str, pfx: str = "") -> None:
    if not body:
        return
    m = _TITLE_RE.search(body)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        if title:
            utils.kv("title", title, indent=4)
            host.add(Finding(title=f"{pfx}Page title: {title}", severity="info",
                             category="web", port=port, service="http"))
    g = _GENERATOR_RE.search(body)
    if g:
        gen = g.group(1).strip()
        utils.kv("generator", gen, indent=4)
        host.add(Finding(title=f"{pfx}Generator: {gen}", severity="info",
                         category="web", port=port, service="http"))
        for sev, note in knowledge.match_hints(gen):
            host.add(Finding(title=note, severity=sev, category="web",
                             port=port, service="http", evidence=gen))


def _security_headers(host: HostReport, port: int, headers: Dict[str, str],
                      secure: bool) -> None:
    missing = [h for h in _SECURITY_HEADERS if h not in headers]
    if secure is False and "strict-transport-security" in missing:
        missing.remove("strict-transport-security")
    if missing:
        host.add(Finding(
            title="Missing security headers",
            detail=", ".join(missing),
            severity="low", category="web", port=port, service="http",
        ))


def _redirect_hostnames(host: HostReport, headers: Dict[str, str]) -> None:
    loc = headers.get("location", "")
    m = re.search(r"https?://([^/:]+)", loc)
    if m and host.add_hostname(m.group(1)):
        utils.log("good", f"redirect reveals hostname: "
                          f"{utils.c(m.group(1), utils.C.CYAN)}", indent=2)


def _comments_and_emails(host: HostReport, port: int, body: str,
                         pfx: str = "") -> None:
    if not body:
        return
    for raw in _COMMENT_RE.findall(body)[:20]:
        text = raw.strip()
        low = text.lower()
        if any(k in low for k in ("pass", "todo", "user", "cred", "key",
                                  "secret", "debug", "fixme", "flag")):
            snippet = re.sub(r"\s+", " ", text)[:160]
            host.add(Finding(
                title=f"{pfx}Interesting HTML comment",
                detail=snippet, severity="low",
                category="leak", port=port, service="http",
                evidence=snippet,
            ))
            utils.log("warn", f"comment: {snippet}", indent=2)
    emails = set(_EMAIL_RE.findall(body))
    for email in list(emails)[:10]:
        host.add(Finding(title=f"Email/username leak: {email}", severity="info",
                         category="leak", port=port, service="http"))


def _forms(host: HostReport, port: int, body: str) -> None:
    if not body:
        return
    parser = _LinkFormParser()
    try:
        parser.feed(body)
    except Exception:
        return
    if parser.has_password:
        host.add(Finding(
            title="Login form detected",
            detail="Password input present — candidate for auth brute/bypass.",
            severity="low", category="web", port=port, service="http",
        ))
        utils.log("good", "login form present", indent=2)


def _content_discovery(host: HostReport, port: int, base: str,
                       vhost: Optional[str] = None) -> None:
    """Probe a short list of high-signal paths."""
    utils.log("info", "probing common paths", indent=1)
    pfx = f"[{vhost}] " if vhost else ""
    hits: List[Tuple[str, int]] = []
    for path in knowledge.COMMON_WEB_PATHS:
        url = f"{base}/{path}"
        status, headers, _ = _fetch(url, timeout=5.0, method="GET", vhost=vhost)
        if status is None:
            continue
        if status in (200, 401, 403, 301, 302):
            hits.append((path, status))
            sev = "info"
            cat = "web"
            note = f"{status} /{path}"
            # Grade the juicy ones up.
            if status == 200 and any(x in path for x in (
                    ".git", ".env", "config.php", "dump.sql", "backup",
                    "phpinfo", "flag.txt", "user.txt", "swagger")):
                sev, cat = "high", "leak"
            elif status in (401, 403):
                sev = "low"
            host.add(Finding(title=f"{pfx}Path {note}", severity=sev, category=cat,
                             port=port, service="http", evidence=url))
            mark = "hot" if sev == "high" else ("good" if status == 200 else "dim")
            utils.log(mark, f"{status}  /{path}", indent=2)
    if not hits:
        utils.log("dim", "no notable paths", indent=2)
