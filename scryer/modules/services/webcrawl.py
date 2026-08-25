"""Web crawling + JavaScript endpoint/secret scraping, and orchestration of
external web tools (whatweb, feroxbuster/ffuf) when installed.

The crawler is pure-python and always runs: it pulls same-origin links and
script sources one level deep, then scrapes JS for API endpoints and
hard-coded secrets (API keys, tokens) — a rich source of attack surface that
banner-grabbing misses.
"""

from __future__ import annotations

import re
import ssl
import urllib.request
from html.parser import HTMLParser
from typing import Optional, Set

from ...core import utils, tooling
from ...core.report import HostReport, Finding
from ...data import knowledge


_UA = "Mozilla/5.0 (compatible; scryer/2.0)"
_ENDPOINT_RE = re.compile(r"""["'`](/[A-Za-z0-9_./?=&%-]{2,120})["'`]""")
_FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|ajax)|url)\s*\(\s*["'`]([^"'`]+)["'`]""")
_JS_SECRET_RE = re.compile(
    r"""(?i)(?:api[_-]?key|apikey|access[_-]?token|secret|auth[_-]?token|"""
    r"""bearer|client[_-]?secret)["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{12,})""")


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.add(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.add(a["src"])
        elif tag in ("link",) and a.get("href", "").endswith(".js"):
            self.scripts.add(a["href"])


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = None


def _get_opener():
    global _opener
    if _opener is None:
        _opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=_ctx()))
    return _opener


def _get(url: str, vhost: Optional[str], timeout: float = 8.0) -> str:
    """Fetch a URL (connecting to the target IP, optional Host header). Does
    not follow redirects, so a vhost-redirecting base doesn't abort the crawl."""
    hdrs = {"User-Agent": _UA}
    if vhost:
        hdrs["Host"] = vhost
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with _get_opener().open(req, timeout=timeout) as r:
            return r.read(400_000).decode("utf-8", "replace")
    except Exception:
        return ""


def crawl(host: HostReport, port: int, secure: bool,
          vhost: Optional[str] = None, max_pages: int = 12) -> None:
    scheme = "https" if secure else "http"
    authority = f"{host.resolved_ip}:{port}"
    base = f"{scheme}://{authority}"
    utils.log("info", "crawling + scraping JS", indent=1)

    home = _get(base + "/", vhost)
    if not home:
        return
    parser = _Links()
    try:
        parser.feed(home)
    except Exception:
        pass

    js_urls = {_absolute(base, s) for s in parser.scripts}
    page_urls = {_absolute(base, l) for l in parser.links
                 if _same_site(base, _absolute(base, l))}

    endpoints: Set[str] = set()
    # Scrape JS files (best signal for endpoints/secrets).
    for ju in list(js_urls)[:max_pages]:
        body = _get(ju, vhost)
        if not body:
            continue
        _scrape_js_secrets(host, port, ju, body, vhost)
        for m in _ENDPOINT_RE.findall(body):
            endpoints.add(m)
        for m in _FETCH_RE.findall(body):
            if m.startswith("/"):
                endpoints.add(m)

    # Shallow crawl of same-site HTML pages for more endpoints/comments.
    for pu in list(page_urls)[:max_pages]:
        body = _get(pu, vhost)
        for m in _ENDPOINT_RE.findall(body or ""):
            endpoints.add(m)

    # Report the interesting endpoints (api/admin/internal/etc.).
    interesting = sorted(e for e in endpoints if _is_interesting(e))
    if interesting:
        pfx = f"[{vhost}] " if vhost else ""
        shown = ", ".join(interesting[:25])
        utils.log("good", f"{len(interesting)} endpoints from JS/crawl", indent=2)
        host.add(Finding(
            title=f"{pfx}Endpoints discovered via JS/crawl ({len(interesting)})",
            detail=shown[:400],
            severity="low", category="web", port=port, service="http",
            evidence="\n".join(interesting[:80])))
    # Return endpoints so callers (e.g. paramvoid) can target them.
    return interesting


def _scrape_js_secrets(host, port, url, body, vhost):
    pfx = f"[{vhost}] " if vhost else ""
    seen = set()
    for m in _JS_SECRET_RE.finditer(body):
        val = m.group(1)
        if val in seen or val.lower() in ("function", "undefined", "null"):
            continue
        seen.add(val)
        utils.log("hot", f"secret in JS ({url.split('/')[-1]}): {val[:40]}", indent=2)
        host.add(Finding(
            title=f"{pfx}Hard-coded secret in JavaScript",
            detail=f"{val[:60]} in {url}",
            severity="high", category="leak", port=port, service="http",
            evidence=f"{url}: {val}"))
    for label, value, sev in knowledge.extract_secrets(body):
        host.add(Finding(
            title=f"{pfx}{label} in JavaScript",
            detail=f"{value[:60]} in {url}",
            severity=sev, category="leak", port=port, service="http",
            evidence=f"{url}: {value}"))


def whatweb(host: HostReport, port: int, secure: bool, vhost=None) -> None:
    """Run whatweb and ingest a concise fingerprint line when installed. When a
    vhost is given, target it by name (needs it resolvable via /etc/hosts)."""
    ww = tooling.resolve("whatweb")
    if not ww:
        return
    scheme = "https" if secure else "http"
    url = f"{scheme}://{vhost or host.resolved_ip}:{port}"
    rc, out, _ = utils.run([ww, "-a", "3", "--no-errors", url], timeout=60)
    line = (out or "").strip().splitlines()[0] if out.strip() else ""
    if line:
        pfx = f"[{vhost}] " if vhost else ""
        utils.log("good", f"whatweb{(' ' + vhost) if vhost else ''}: {line[:120]}",
                  indent=1)
        host.add(Finding(title=f"{pfx}whatweb fingerprint", detail=line[:400],
                         severity="info", category="web", port=port,
                         service="http", evidence=out[:800]))


def dir_brute(host: HostReport, port: int, secure: bool,
              vhost: Optional[str] = None) -> None:
    """Heavy content discovery with feroxbuster/ffuf + a SecLists wordlist.
    Opt-in (engine gates on --web-brute) because it is slow and loud."""
    scheme = "https" if secure else "http"
    target = f"{scheme}://{vhost or host.resolved_ip}:{port}"
    wl = tooling.find_wordlist("dir")
    if not wl:
        utils.log("dim", "no wordlist found for dir brute (install seclists)", indent=1)
        return

    ferox = tooling.resolve("feroxbuster")
    ffuf = tooling.resolve("ffuf")
    if ferox:
        cmd = [ferox, "-u", target, "-w", wl, "-k", "-t", "50",
               "--silent", "-d", "2"]
    elif ffuf:
        cmd = [ffuf, "-u", f"{target}/FUZZ", "-w", wl, "-ac", "-s"]
    else:
        utils.log("dim", "feroxbuster/ffuf not installed for dir brute", indent=1)
        return

    utils.log("info", f"dir brute: {' '.join(cmd)}", indent=1)
    rc, out, _ = utils.run(cmd, timeout=600)
    hits = [l.strip() for l in (out or "").splitlines() if l.strip()]
    paths = sorted({_first_path(l) for l in hits if _first_path(l)})
    if paths:
        utils.log("good", f"{len(paths)} paths from dir brute", indent=2)
        host.add(Finding(
            title=f"{len(paths)} paths found via dir brute on :{port}",
            detail=", ".join(paths[:40]),
            severity="medium", category="web", port=port, service="http",
            evidence="\n".join(paths[:120])))


# --- helpers ---------------------------------------------------------------
def _absolute(base: str, ref: str) -> str:
    from urllib.parse import urljoin
    return urljoin(base + "/", ref)


def _same_site(base: str, url: str) -> bool:
    from urllib.parse import urlparse
    return urlparse(base).netloc == urlparse(url).netloc and url.startswith("http")


def _is_interesting(path: str) -> bool:
    low = path.lower()
    if any(low.endswith(ext) for ext in
           (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff",
            ".woff2", ".ico", ".ttf")):
        return False
    return any(k in low for k in
               ("api", "admin", "login", "user", "account", "internal",
                "graphql", "upload", "config", "debug", "token", "auth",
                "v1", "v2", "private", "secret", "backup", "export"))


def _first_path(line: str) -> str:
    m = re.search(r"https?://[^/\s]+(/\S*)", line)
    if m:
        return m.group(1)
    m = re.match(r"(/\S+)", line)
    return m.group(1) if m else ""
