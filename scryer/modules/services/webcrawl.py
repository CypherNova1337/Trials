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
from ...data import knowledge, filetypes
from .. import bruteforce


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

    # Classify any interesting file types linked from the page / JS (a link to
    # backup.zip, id_rsa, db.sqlite, capture.pcap, …).
    pfx = f"[{vhost}] " if vhost else ""
    seen_ft = set()
    for href in set(parser.links) | endpoints:
        info = filetypes.classify(href)
        if info and info[1] in ("critical", "high") and href not in seen_ft:
            seen_ft.add(href)
            cat, sev, note, _tag = info
            utils.log("hot", f"linked {cat} file: {href}", indent=2)
            host.add(Finding(
                title=f"{pfx}Linked {cat} file: {href}",
                detail=note, severity=sev, category="leak", port=port,
                service="http", evidence=href))

    # Parameterized URLs (?x=…) are prime SQLi/param targets — hand over a
    # ready sqlmap line for the first couple (deduped by the report).
    param_urls = []
    for ref in set(parser.links) | endpoints:
        full = _absolute(base, ref) if not ref.startswith("http") else ref
        if "?" in full and "=" in full.split("?", 1)[1] and _same_site(base, full):
            param_urls.append(full)
    for purl in sorted(set(param_urls))[:2]:
        target = purl if not vhost else purl.replace(authority, f"{vhost}:{port}")
        bruteforce.sqlmap(host, port, target)

    # Parent directories of discovered assets are often the real foothold: a
    # linked /cdn-cgi/login/script.js means /cdn-cgi/login/ is a login panel the
    # bare site never links to (HTB Oopsie). Probe those directories.
    _probe_asset_dirs(host, port, base, parser, endpoints, vhost)

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


def _probe_asset_dirs(host, port, base, parser, endpoints, vhost) -> None:
    """GET the parent directories of linked assets/endpoints and flag any that
    are login panels — the classic hidden foothold (/cdn-cgi/login/)."""
    from urllib.parse import urlparse
    dirs = set()
    for ref in set(parser.links) | set(parser.scripts) | set(endpoints):
        full = _absolute(base, ref) if not ref.startswith("http") else ref
        if not _same_site(base, full):
            continue
        path = urlparse(full).path
        # Walk up each path component -> candidate directories.
        parts = [p for p in path.split("/") if p]
        for i in range(1, len(parts)):
            dirs.add("/" + "/".join(parts[:i]) + "/")
    for d in sorted(dirs):
        if d in ("/", "/css/", "/js/", "/images/", "/img/", "/fonts/",
                 "/assets/", "/static/", "/themes/", "/scripts/"):
            continue
        body = _get(base + d, vhost)
        if not body:
            continue
        low = body.lower()
        if 'type="password"' in low or "type='password'" in low or "login" in low:
            url = (f"http://{vhost}:{port}{d}" if vhost else base + d)
            if url not in host.login_urls:
                host.login_urls.append(url)
            pfx = f"[{vhost}] " if vhost else ""
            utils.log("hot", f"login panel at {d} (hidden — from asset path)", indent=2)
            host.add(Finding(
                title=f"{pfx}Hidden login panel: {d}",
                detail=f"{url} — a login page the site never links to, found via "
                       "an asset path. Try default creds / a guest login / SQLi; "
                       "check for IDOR on any ?id= and role/user cookies "
                       "(broken access control).",
                severity="high", category="web", port=port, service="http",
                evidence=url))
            guest = _guest_link(body)
            if guest:
                host.add(Finding(
                    title=f"{pfx}Guest login available at {d}",
                    detail="A 'login as guest' option exists — use it, then look "
                           "for IDOR (increment ?id=) and cookie role/user "
                           "tampering to reach admin (Oopsie pattern).",
                    severity="medium", category="web", port=port, service="http",
                    confidence="potential", evidence=guest))


def _guest_link(body: str) -> str:
    m = re.search(r'href=["\']([^"\']*)["\'][^>]*>\s*(?:login as )?guest',
                  body, re.I)
    if m:
        return m.group(1)
    return "guest" if re.search(r"login as guest", body, re.I) else ""


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

    # Fuzz file extensions relevant to the detected server tech (php/asp/…).
    # Keep only simple alnum extensions the fuzzers handle cleanly; scryer's own
    # backup-probing covers the .bak/~/tar.gz style variants of found files.
    raw_exts = filetypes.ext_candidates_for(filetypes.tech_from_text(_tech_blob(host)))
    exts = [e for e in raw_exts if e.isalnum()]
    ferox_x = ",".join(exts)
    ffuf_e = ",".join("." + e for e in exts)

    ferox = tooling.resolve("feroxbuster")
    ffuf = tooling.resolve("ffuf")
    if ferox:
        cmd = [ferox, "-u", target, "-w", wl, "-k", "-t", "50",
               "--silent", "-d", "2", "-x", ferox_x]
    elif ffuf:
        cmd = [ffuf, "-u", f"{target}/FUZZ", "-w", wl, "-ac", "-s", "-e", ffuf_e]
    else:
        utils.log("dim", "feroxbuster/ffuf not installed for dir brute", indent=1)
        return
    utils.log("info", f"dir brute extensions: {ferox_x}", indent=1)

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
def _tech_blob(host: HostReport) -> str:
    """Gather server/tech text from findings so we can pick fuzz extensions."""
    bits = []
    for f in host.findings:
        t = f.title.lower()
        if any(k in t for k in ("server header", "x-powered-by", "generator",
                                "identified", "whatweb", "page title")):
            bits.append(f.title + " " + (f.evidence or ""))
    for p in host.open_ports:
        bits.append((p.get("service") or "") + " " + (p.get("version") or ""))
    return " ".join(bits)


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
