"""HTTP(S) enrichment: headers, title, tech fingerprint, security headers,
content discovery and interesting-file detection."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Dict, List, Optional

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge


_UA = "Mozilla/5.0 (compatible; scryer/1.0)"
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return 3xx responses instead of following them.

    Critical for recon: CTF boxes commonly redirect the bare IP to a vhost
    (http://10.10.10.10/ -> http://box.htb/). Following that blindly makes the
    request fail when the vhost isn't in /etc/hosts — and buries the very
    hostname we most need. We keep the 3xx so its Location header is captured.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = None


def _get_opener():
    global _opener
    if _opener is None:
        _opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=_ctx()))
    return _opener


def _fetch(url: str, timeout: float = 8.0, method: str = "GET",
           vhost: Optional[str] = None):
    """Return (status, headers-dict, body-str) or (None, {}, '') on error.

    Redirects are NOT followed — a 3xx is returned with its headers so the
    caller can read the Location (and any vhost it reveals). When *vhost* is
    set, the request is sent with an explicit Host header so name-based virtual
    hosts serve their real content.
    """
    hdrs = {"User-Agent": _UA}
    if vhost:
        hdrs["Host"] = vhost
    req = urllib.request.Request(url, method=method, headers=hdrs)
    try:
        with _get_opener().open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = b""
            if method == "GET":
                body = resp.read(200_000)
            status = getattr(resp, "status", None) or resp.getcode()
            return status, headers, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        body = b""
        try:
            body = exc.read(200_000)
        except Exception:
            pass
        return exc.code, headers, body.decode("utf-8", "replace")
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
    _webapp_exploit_hint(host, port, headers, body, pfx)
    _security_headers(host, port, headers, secure)
    _redirect_hostnames(host, port, headers)
    _comments_and_emails(host, port, body, pfx)
    scan_body_for_flags(host, port, base + "/", body, pfx)
    _forms(host, port, body)
    _content_discovery(host, port, base, vhost)


def scan_body_for_flags(host: HostReport, port: int, source: str, body: str,
                        pfx: str = "") -> None:
    """Spot flag-format tokens (HTB{…}, flag{…}, 32-hex) sitting in a response
    body / comment and surface them immediately."""
    for tok in knowledge.find_flags(body or ""):
        # Skip bare 32-hex that is almost certainly an asset hash, not a flag.
        looks_hashy = len(tok) == 32 and "/" not in source and (
            "css" in source or "js" in source or "static" in source)
        if looks_hashy:
            continue
        print("  " + utils.c(f"⚑ possible flag on {source}: ", utils.C.GREEN, utils.C.BOLD)
              + utils.c(tok, utils.C.YELLOW, utils.C.BOLD))
        host.add(Finding(
            title=f"{pfx}Possible flag in page content",
            detail=tok,
            severity="critical", category="flag", port=port, service="http",
            evidence=f"{source}: {tok}"))


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
                                 port=port, service="http", evidence=val,
                                 confidence="potential"))
    # Version hints from the server banner itself.
    for sev, note in knowledge.match_hints(server):
        host.add(Finding(title=note, severity=sev, category="web",
                         port=port, service="http", evidence=server,
                         confidence="potential"))
        utils.log("warn", f"{note} (potential)", indent=2)

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
                             port=port, service="http", evidence=gen,
                             confidence="potential"))


def _webapp_exploit_hint(host: HostReport, port: int, headers: Dict[str, str],
                         body: str, pfx: str = "") -> None:
    """When a known web app is identified, surface an exploit-lookup lead."""
    gen = ""
    g = _GENERATOR_RE.search(body or "")
    if g:
        gen = g.group(1)
    title = ""
    tm = _TITLE_RE.search(body or "")
    if tm:
        title = tm.group(1)
    app, version = knowledge.identify_webapp(
        headers.get("server", ""), headers.get("x-powered-by", ""),
        headers.get("x-generator", ""), gen, title, body or "")
    if not app:
        return
    label = f"{app} {version}" if version else app
    utils.log("good", f"web app: {label}", indent=2)
    if version:
        host.add(Finding(
            title=f"{pfx}{app} {version} identified — check for public exploits",
            detail=f"Known app + exact version. Look up known exploits/CVEs, "
                   f"e.g. `searchsploit {app}` or search '{app} {version} "
                   f"exploit'. Authenticated flaws often need a low-priv login.",
            severity="medium", category="web", port=port, service="http",
            evidence=label, confidence="potential"))
    else:
        host.add(Finding(
            title=f"{pfx}{app} identified (version unknown)",
            detail="Fingerprint the exact version, then check exploits/CVEs.",
            severity="info", category="web", port=port, service="http",
            evidence=app))


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


def _redirect_hostnames(host: HostReport, port: int, headers: Dict[str, str]) -> None:
    loc = headers.get("location", "")
    m = re.search(r"https?://([^/:]+)", loc)
    if not m:
        return
    name = m.group(1)
    if _looks_like_ip(name):
        return
    is_new = host.add_hostname(name)
    if is_new:
        utils.log("hot", f"redirect reveals vhost: "
                         f"{utils.c(name, utils.C.CYAN, utils.C.BOLD)} "
                         f"-> will re-probe with Host: {name}", indent=2)
        host.add(Finding(
            title=f"Redirect reveals virtual host: {name}",
            detail=f"The site redirects to {loc.strip()} — add "
                   f"'{host.resolved_ip} {name}' to /etc/hosts, then this name "
                   f"fronts the real content (scryer re-probes it automatically).",
            severity="medium", category="host", port=port, service="http",
            evidence=loc.strip()))


def _looks_like_ip(name: str) -> bool:
    parts = name.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


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


def _norm(body: str) -> str:
    return re.sub(r"\s+", " ", (body or ""))[:3000]


def _similar(a: str, a_len: int, b: str, b_len: int) -> float:
    from difflib import SequenceMatcher
    if not a and not b:
        return 1.0
    # Quick length gate before the (costlier) ratio.
    hi = max(a_len, b_len) or 1
    if abs(a_len - b_len) / hi > 0.4:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _calibrate_404(base: str, vhost: Optional[str]) -> Optional[dict]:
    """Learn how the server answers a path that certainly does not exist.

    Many apps return 200 (SPA catch-all) or a fixed redirect for *every*
    unknown path. We fetch two random paths and, crucially, compare their
    *content* — catch-all servers echo a byte-identical page, so a real file
    can be told apart even when its size is close. Returns None when the
    server behaves normally (unknown -> 404) or is too dynamic to filter on.
    """
    import uuid
    samples = []
    for _ in range(2):
        rand = uuid.uuid4().hex + ".html"
        status, headers, body = _fetch(f"{base}/{rand}", timeout=5.0,
                                       method="GET", vhost=vhost)
        if status is None:
            continue
        samples.append((status, _norm(body), len(body or ""),
                        headers.get("location", "")))
    if not samples:
        return None
    statuses = {s[0] for s in samples}
    if statuses <= {404, 410}:
        return None  # honest 404s — content discovery is trustworthy
    if len(samples) == 2 and samples[0][0] == samples[1][0]:
        ratio = _similar(samples[0][1], samples[0][2],
                         samples[1][1], samples[1][2])
    else:
        ratio = 1.0
    if ratio < 0.85:
        return None  # responses vary per request — can't filter reliably
    s = samples[0]
    return {"status": s[0], "body": s[1], "len": s[2], "location": s[3]}


def _is_soft404(cal: Optional[dict], status: int, body: str, body_len: int,
                location: str) -> bool:
    """True when a probe is indistinguishable from the catch-all baseline."""
    if not cal or status != cal["status"]:
        return False
    if status in (301, 302, 307, 308):
        return location == cal["location"]
    # Real content differs from the catch-all page even at a similar size.
    return _similar(_norm(body), body_len, cal["body"], cal["len"]) >= 0.9


def _content_discovery(host: HostReport, port: int, base: str,
                       vhost: Optional[str] = None) -> None:
    """Probe a short list of high-signal paths, calibrated against soft-404s."""
    utils.log("info", "probing common paths", indent=1)
    pfx = f"[{vhost}] " if vhost else ""

    cal = _calibrate_404(base, vhost)
    if cal:
        utils.log("dim", f"catch-all detected (unknown paths -> {cal['status']}); "
                         f"filtering soft-404s", indent=2)

    hits = 0
    for path in knowledge.COMMON_WEB_PATHS:
        url = f"{base}/{path}"
        status, headers, body = _fetch(url, timeout=5.0, method="GET", vhost=vhost)
        if status is None or status not in (200, 401, 403, 301, 302):
            continue
        if _is_soft404(cal, status, body or "", len(body or ""),
                       headers.get("location", "")):
            continue  # server answers this for everything — not a real hit

        hits += 1
        sev, cat = "info", "web"
        note = f"{status} /{path}"
        juicy = any(x in path for x in (
            ".git", ".env", "config.php", "dump.sql", "backup",
            "phpinfo", "flag.txt", "user.txt", "swagger"))
        # Only grade a leak "high" when we actually got content back (200 with
        # a non-empty body), not on a bare redirect or an empty 200.
        if status == 200 and juicy and body and body.strip():
            sev, cat = "high", "leak"
        elif status in (401, 403):
            sev = "low"
        host.add(Finding(title=f"{pfx}Path {note}", severity=sev, category=cat,
                         port=port, service="http", evidence=url))
        mark = "hot" if sev == "high" else ("good" if status == 200 else "dim")
        utils.log(mark, f"{status}  /{path}", indent=2)

        # Exposed git repo is a foothold in itself — call it out explicitly.
        if path == ".git/config" and status == 200 and body:
            host.add(Finding(
                title=f"{pfx}Exposed .git repository",
                detail="/.git/ is web-accessible — dump it (git-dumper) to "
                       "recover source and often committed credentials.",
                severity="high", category="leak", port=port, service="http",
                evidence=url))

        # Flag / proof file — grab it and print the contents outright.
        fname = path.rsplit("/", 1)[-1].lower()
        if status == 200 and body and body.strip() and fname in knowledge.FLAG_FILES:
            dump_flag_file(host, port, url, body, pfx)

        # Pull credentials out of leaked config files.
        if status == 200 and body and path in knowledge.SECRET_FILES:
            _harvest_secrets(host, port, path, body, pfx)

    if not hits:
        utils.log("dim", "no notable paths", indent=2)


def dump_flag_file(host: HostReport, port: int, url: str, body: str,
                   pfx: str = "") -> None:
    """Print the contents of a discovered flag/proof file and record it."""
    content = body.strip()
    # Prefer an actual flag token if the file wraps it in markup/whitespace.
    tokens = list(knowledge.find_flags(content))
    display = content if len(content) <= 400 else content[:400] + " …"

    bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
    print("\n  " + bar)
    print("  " + utils.c("║ FLAG FILE FOUND", utils.C.GREEN, utils.C.BOLD)
          + utils.c(f"  {url}", utils.C.GREY))
    for line in display.splitlines() or [display]:
        print("  " + utils.c("║ ", utils.C.GREEN, utils.C.BOLD)
              + utils.c(line, utils.C.YELLOW, utils.C.BOLD))
    print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")

    host.add(Finding(
        title=f"{pfx}FLAG captured: {url.rsplit('/', 1)[-1]}",
        detail=(", ".join(tokens) if tokens else display),
        severity="critical", category="flag", port=port, service="http",
        evidence=f"{url}\n{content[:800]}"))


def _harvest_secrets(host: HostReport, port: int, path: str, body: str,
                     pfx: str) -> None:
    seen = set()
    for label, value, sev in knowledge.extract_secrets(body):
        key = (label, value)
        if key in seen:
            continue
        seen.add(key)
        shown = value if len(value) <= 60 else value[:57] + "..."
        utils.log("hot", f"{label} in /{path}: {shown}", indent=3)
        host.add(Finding(
            title=f"{pfx}{label} leaked in /{path}",
            detail=f"{label} = {shown}",
            severity=sev, category="cred", port=port, service="http",
            evidence=f"/{path}: {value}"))
    # docker-compose reveals the internal service topology (extra targets).
    if "docker-compose" in path:
        images = re.findall(r"image:\s*([^\s]+)", body)
        if images:
            host.add(Finding(
                title=f"{pfx}Internal services from {path}",
                detail="images: " + ", ".join(sorted(set(images))[:12]),
                severity="medium", category="leak", port=port, service="http",
                evidence=body[:400]))
            utils.log("good", f"compose images: {', '.join(sorted(set(images))[:6])}",
                      indent=3)
