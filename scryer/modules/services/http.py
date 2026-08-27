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
from ...data import knowledge, filetypes
from .. import bruteforce
from . import cloud


_UA = "Mozilla/5.0 (compatible; scryer/1.0)"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
# Absolute URLs referenced by the page (href/src/action) — a rich source of
# the box's real domain (e.g. an <img src="http://thetoppers.htb/...">).
_URL_HOST_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']https?://([a-z0-9.\-]+)""", re.I)
# TLDs that on a CTF/lab box always mean "this is the target's own vhost".
_CTF_TLDS = {"htb", "thm", "ctf", "lab", "box", "vl", "offsec", "local",
             "corp", "internal", "home", "lan", "test", "dev"}
# Third-party hosts we never want to treat as the target's own domain.
_DOMAIN_BLOCKLIST = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "icloud.com", "protonmail.com", "example.com", "example.org", "email.com",
    "w3.org", "schema.org", "googleapis.com", "gstatic.com", "google.com",
    "cloudflare.com", "jquery.com", "bootstrapcdn.com", "jsdelivr.net",
    "unpkg.com", "fontawesome.com", "github.com", "githubusercontent.com",
    "wordpress.org", "gravatar.com", "youtube.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "linkedin.com", "mozilla.org",
}
_FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
             "yahoo.com", "icloud.com", "protonmail.com", "aol.com",
             "mail.com", "example.com"}

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
        # Details of the login form (the one containing a password field), so
        # callers can build a hydra http-post-form line.
        self.login_action = ""
        self.login_method = "post"
        self.login_user_field = ""
        self.login_pass_field = ""
        self._cur_action = ""
        self._cur_method = "post"
        self._cur_user = ""
        self._cur_pass = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur_action = a.get("action", "")
            self._cur_method = (a.get("method", "post") or "post").lower()
            self._cur_user = ""
            self._cur_pass = ""
            self.forms.append(self._cur_action)
        elif tag == "input":
            itype = a.get("type", "text").lower()
            name = a.get("name", "")
            if itype == "password":
                self.has_password = True
                self._cur_pass = name
                # Commit this form as the login form.
                self.login_action = self._cur_action
                self.login_method = self._cur_method
                self.login_user_field = self._cur_user
                self.login_pass_field = name
            elif itype in ("text", "email", "tel", "") and name and not self._cur_user:
                self._cur_user = name
                # If the password field was already seen, backfill the user field.
                if self._cur_pass and not self.login_user_field:
                    self.login_user_field = name
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


def _fetch_bytes(url: str, n: int = 64, timeout: float = 6.0,
                 vhost: Optional[str] = None) -> bytes:
    """Fetch the first *n* raw bytes of a URL (for magic-byte sniffing)."""
    hdrs = {"User-Agent": _UA}
    if vhost:
        hdrs["Host"] = vhost
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with _get_opener().open(req, timeout=timeout) as resp:
            return resp.read(n)
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(n)
        except Exception:
            return b""
    except Exception:
        return b""


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
    _server_language(host, port, headers, body, pfx)
    _title_and_meta(host, port, body, pfx)
    _webapp_exploit_hint(host, port, headers, body, pfx)
    _security_headers(host, port, headers, secure)
    _redirect_hostnames(host, port, headers)
    _harvest_domains(host, port, body or "", pfx)
    _comments_and_emails(host, port, body, pfx)
    scan_body_for_flags(host, port, base + "/", body, pfx)
    cloud.scan(host, port, body, pfx)
    cloud.detect_s3_endpoint(host, port, body, headers, vhost, pfx)
    _forms(host, port, body, secure=secure)
    _content_discovery(host, port, base, vhost)


def scan_body_for_flags(host: HostReport, port: int, source: str, body: str,
                        pfx: str = "") -> None:
    """Spot flag-format tokens (HTB{…}, flag{…}, 32-hex) sitting in a response
    body / comment and surface them immediately. Also pulls hard-coded password
    hashes out of source (e.g. md5(...) === "..."), classifying those as
    crackable creds rather than flags."""
    hashes = set(knowledge.find_hashes(body or ""))
    for tok in knowledge.find_flags(body or ""):
        if tok in hashes:
            continue  # a hash embedded in code, reported below — not a flag
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
    for h in hashes:
        utils.log("hot", f"hard-coded hash: {h}", indent=2)
        host.add(Finding(
            title=f"{pfx}Hard-coded password hash in source",
            detail=f"{h} — identify + crack: nth '{h}'; hashcat -m 0 (MD5) "
                   "hash.txt rockyou.txt. Reuse the plaintext across logins/SSH.",
            severity="high", category="cred", port=port, service="http",
            confidence="potential", evidence=f"{source}: {h}"))


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


def _server_language(host: HostReport, port: int, headers: Dict[str, str],
                     body: str, pfx: str = "") -> None:
    """Answer 'what language generates these pages?' by fusing every signal:
    X-Powered-By, the Server banner, framework cookies, and file extensions
    linked in the page. Emits one clear, prominent finding."""
    powered = headers.get("x-powered-by", "")
    server = headers.get("server", "")
    cookie = headers.get("set-cookie", "")
    blob = f"{powered} {server}".lower()
    ck = cookie.lower()
    body_low = (body or "")[:200_000].lower()

    langs: Dict[str, str] = {}   # language -> evidence

    def note(lang: str, why: str) -> None:
        langs.setdefault(lang, why)

    # --- X-Powered-By (most explicit) ---
    if "php" in blob:
        note("PHP", f"X-Powered-By/Server: {powered or server}")
    if "asp.net" in blob or "asp.net" in ck.replace(" ", ""):
        note("C# / ASP.NET", f"X-Powered-By/Server: {powered or server}")
    if "express" in blob:
        note("JavaScript / Node.js (Express)", f"X-Powered-By: {powered}")
    if "servlet" in blob or "jsp" in blob:
        note("Java (JSP/Servlet)", f"X-Powered-By: {powered}")

    # --- Server banner tech ---
    if "iis" in blob and "C# / ASP.NET" not in langs:
        note("C# / ASP.NET (likely)", f"Server: {server}")
    if any(w in blob for w in ("werkzeug", "gunicorn", "uwsgi", "flask",
                               "django", "hypercorn", "uvicorn", "python")):
        note("Python", f"Server: {server or powered}")
    if any(w in blob for w in ("tomcat", "jetty", "coyote", "wildfly",
                               "jboss", "glassfish", "servlet")):
        note("Java", f"Server: {server}")
    if "passenger" in blob or "puma" in blob or "unicorn" in blob or "mongrel" in blob:
        note("Ruby (Rack/Rails)", f"Server: {server}")
    if "next.js" in blob or "nextjs" in blob:
        note("JavaScript / Node.js (Next.js)", f"Server: {server or powered}")

    # --- Framework cookies (match cookie NAMES exactly to avoid substring
    # collisions like sessionid vs JSESSIONID / ASP.NET_SessionId) ---
    names = {re.split(r"\s*=", tok.strip(), 1)[0].lower()
             for tok in re.split(r"[;,]", cookie) if "=" in tok}
    cookie_exact = {
        "phpsessid": ("PHP", "PHPSESSID cookie"),
        "ci_session": ("PHP (CodeIgniter)", "ci_session cookie"),
        "laravel_session": ("PHP (Laravel)", "laravel_session cookie"),
        "jsessionid": ("Java (JSP/Servlet)", "JSESSIONID cookie"),
        "asp.net_sessionid": ("C# / ASP.NET", "ASP.NET_SessionId cookie"),
        "csrftoken": ("Python (Django)", "csrftoken cookie"),
        "sessionid": ("Python (Django, likely)", "sessionid cookie"),
        "connect.sid": ("JavaScript / Node.js", "connect.sid cookie"),
    }
    for name, (lang, why) in cookie_exact.items():
        if name in names:
            note(lang, why)
    # Prefix-style cookie names.
    for name in names:
        if name.startswith("symfony"):
            note("PHP (Symfony)", "symfony cookie")
        elif name.startswith("aspsessionid"):
            note("VBScript/JScript (classic ASP)", "ASPSESSIONID cookie")
        elif name.startswith("_rails") or name.endswith("_session_id"):
            note("Ruby (Rails)", "Rails session cookie")
        elif name.startswith("rack.session"):
            note("Ruby (Rack)", "rack.session cookie")

    # --- File extensions linked in the page (weak, corroborating signal) ---
    ext_lang = {".php": "PHP", ".asp": "VBScript/JScript (classic ASP)",
                ".aspx": "C# / ASP.NET", ".jsp": "Java (JSP)",
                ".jspx": "Java (JSP)", ".do": "Java (Struts)",
                ".py": "Python", ".rb": "Ruby", ".cgi": "CGI (Perl/C/shell)",
                ".pl": "Perl"}
    for ext, lang in ext_lang.items():
        if lang in langs:
            continue
        if re.search(r'href=["\'][^"\']*' + re.escape(ext) + r'(?:["\'?#])', body_low):
            note(lang, f"{ext} links on page")

    if not langs:
        return
    summary = "; ".join(f"{lang} ({why})" for lang, why in langs.items())
    primary = next(iter(langs))
    utils.log("good", f"server-side language: {summary}", indent=2)
    host.add(Finding(
        title=f"{pfx}Server-side language: {', '.join(langs)}",
        detail=f"Page generation stack inferred from response signals — {summary}.",
        severity="info", category="web", port=port, service="http",
        evidence=summary))
    if not host.tech_stack:
        host.tech_stack = primary


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


def _registrable(domain: str) -> str:
    """Last two labels — the vhost-brute base (thetoppers.htb from x.thetoppers.htb)."""
    parts = domain.strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else ""


def _plausible_target_domain(domain: str) -> bool:
    """Is *domain* the box's own domain (worth vhost-brute + /etc/hosts), rather
    than a third-party CDN / freemail / analytics host?"""
    domain = domain.strip(".").lower()
    if not domain or _looks_like_ip(domain) or "." not in domain:
        return False
    reg = _registrable(domain)
    if reg in _DOMAIN_BLOCKLIST or domain in _DOMAIN_BLOCKLIST:
        return False
    tld = domain.rsplit(".", 1)[-1]
    # A CTF/lab TLD is an unambiguous yes.
    return tld in _CTF_TLDS


def _harvest_domains(host: HostReport, port: int, body: str, pfx: str = "") -> None:
    """Learn the target's own domain from the page so vhost brute has a base to
    work from — the usual reason a CTF box '404s on the IP but everything lives
    behind name.htb'. Registers each discovered domain (and its registrable
    parent) as a hostname; the engine then vhost-brutes and /etc/hosts-maps it.
    """
    if not body:
        return
    found = set()
    # 1) Email domains (contact@thetoppers.htb) — strongest signal on a landing
    #    page. Accept the box's own domain even without a CTF TLD, but never
    #    public freemail.
    for email in set(_EMAIL_RE.findall(body)):
        dom = email.split("@", 1)[-1].lower()
        if _registrable(dom) in _FREEMAIL:
            continue
        if _plausible_target_domain(dom) or _registrable(dom) not in _DOMAIN_BLOCKLIST:
            found.add(dom)
    # 2) Absolute URLs the page references (img/script/link/a/form).
    for hoststr in set(_URL_HOST_RE.findall(body)):
        if _plausible_target_domain(hoststr):
            found.add(hoststr.lower())

    for dom in sorted(found):
        # Register both the fqdn and its registrable parent so vhost brute has a
        # base regardless of whether the page named a sub or the apex.
        for name in {dom, _registrable(dom)}:
            if name and not _looks_like_ip(name) and host.add_hostname(name):
                utils.log("hot", f"domain from page: "
                                 f"{utils.c(name, utils.C.CYAN, utils.C.BOLD)} "
                                 f"-> vhost-brute + /etc/hosts", indent=2)
                host.add(Finding(
                    title=f"{pfx}Target domain discovered: {name}",
                    detail=f"Referenced in the page served on :{port}. Added as "
                           "a virtual-host base — scryer brute-forces its "
                           "subdomains and maps it in /etc/hosts.",
                    severity="info", category="host", port=port, service="http",
                    evidence=name))


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


def _forms(host: HostReport, port: int, body: str, secure: bool = False) -> None:
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
        # Hand the operator a ready hydra http-post-form line. An empty/self
        # action posts to the current page ("/"), NOT a guessed "/login" (which
        # 404s and sends sqlmap/hydra at a dead endpoint).
        action = (parser.login_action or "/").strip()
        if action in ("", "#", "."):
            action = "/"
        if not action.startswith("/"):
            action = "/" + action.lstrip("./")
        ufield = parser.login_user_field or "username"
        pfield = parser.login_pass_field or "password"
        bruteforce.suggest(
            host, port, "http-form", secure=secure, path=action,
            user_field=ufield, pass_field=pfield)
        # A login form is also a prime SQLi target (auth bypass / dump).
        scheme = "https" if secure else "http"
        target = f"{scheme}://{host.resolved_ip}:{port}{action}"
        bruteforce.sqlmap(host, port, target,
                          data=f"{ufield}=admin&{pfield}=x")


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
    return {"status": s[0], "body": s[1], "len": s[2], "location": s[3],
            "redir_target": _redir_target(s[3])}


def _redir_target(location: str) -> str:
    """scheme://host[:port] of a redirect Location, ignoring path/query.

    A catch-all that preserves $request_uri (nginx `return 301 https://h$uri`)
    hands back a *different* Location for every path, so comparing the full URL
    never matches the baseline. Comparing only the target host does."""
    if not location:
        return ""
    from urllib.parse import urlparse
    p = urlparse(location.strip())
    return f"{p.scheme}://{p.netloc}".lower() if p.netloc else ""


def _is_soft404(cal: Optional[dict], status: int, body: str, body_len: int,
                location: str) -> bool:
    """True when a probe is indistinguishable from the catch-all baseline."""
    if not cal or status != cal["status"]:
        return False
    if status in (301, 302, 307, 308):
        # Prefer target-host comparison (survives $request_uri-preserving
        # redirects); fall back to exact match for relative redirects.
        if cal.get("redir_target"):
            return _redir_target(location) == cal["redir_target"]
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
        # Whole-site redirect to a different host/scheme (e.g. IP -> https vhost,
        # or http -> https): every path here is a soft-404 and the real content
        # lives behind that host, which scryer scans on its own pass. Don't burn
        # 100 requests re-confirming that — skip with a one-line note.
        if cal["status"] in (301, 302, 307, 308) and cal.get("redir_target"):
            from urllib.parse import urlparse
            cur = urlparse(base)
            cur_auth = f"{cur.scheme}://{cur.netloc}".lower()
            if cal["redir_target"] != cur_auth:
                utils.log("dim", f"all paths redirect to {cal['redir_target']} "
                                 f"— skipping path probe here (content lives "
                                 f"behind that host)", indent=2)
                return
        utils.log("dim", f"catch-all detected (unknown paths -> {cal['status']}); "
                         f"filtering soft-404s", indent=2)

    hits = 0
    found_paths = []
    for path in knowledge.COMMON_WEB_PATHS:
        url = f"{base}/{path}"
        status, headers, body = _fetch(url, timeout=5.0, method="GET", vhost=vhost)
        if status is None or status not in (200, 401, 403, 301, 302):
            continue
        if _is_soft404(cal, status, body or "", len(body or ""),
                       headers.get("location", "")):
            continue  # server answers this for everything — not a real hit

        hits += 1
        if status == 200:
            found_paths.append(path)
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

        # Classify by file type (extension + magic bytes) and grade it.
        if status == 200:
            _classify_file(host, port, path, url, body, headers, vhost, pfx)

        # Flag / proof file — grab it and print the contents outright.
        fname = path.rsplit("/", 1)[-1].lower()
        if status == 200 and body and body.strip() and fname in knowledge.FLAG_FILES:
            dump_flag_file(host, port, url, body, pfx)

        # Pull credentials out of leaked config files.
        if status == 200 and body and path in knowledge.SECRET_FILES:
            _harvest_secrets(host, port, path, body, pfx)

    if not hits:
        utils.log("dim", "no notable paths", indent=2)

    # Chase backups of discovered source/pages (viewdoc.jsp -> viewdoc.jsp.bak).
    _probe_backups(host, port, base, found_paths, cal, vhost, pfx)


def _classify_file(host: HostReport, port: int, path: str, url: str,
                   body: str, headers: Dict[str, str], vhost, pfx: str) -> None:
    """Grade a discovered file by its type; confirm binary/high-value ones by
    sniffing magic bytes (catches keys/DBs/captures served with odd names)."""
    info = filetypes.classify(path)
    ctype = (headers or {}).get("content-type", "")
    # Sniff magic bytes when the type is high-value or the body looks binary.
    label = None
    high_value = info and info[1] in ("critical", "high")
    binlike = "text" not in ctype and "html" not in ctype and "json" not in ctype
    if high_value or binlike:
        raw = _fetch_bytes(url, n=64, vhost=vhost)
        label = filetypes.sniff(raw)

    if label:
        sev = filetypes.magic_severity(label) or "medium"
        mark = "hot" if sev in ("critical", "high") else "good"
        utils.log(mark, f"{label}: /{path}", indent=3)
        host.add(Finding(
            title=f"{pfx}{label} exposed: /{path}",
            detail=f"Confirmed by magic bytes at {url}. "
                   + (info[2] if info else ""),
            severity=sev, category="leak", port=port, service="http",
            evidence=url))
        return

    if info:
        cat, sev, note, tag = info
        if sev == "info":
            return
        mark = "hot" if sev in ("critical", "high") else "good"
        utils.log(mark, f"{cat} file (/{path})", indent=3)
        host.add(Finding(
            title=f"{pfx}{cat.title()} file exposed: /{path}",
            detail=note, severity=sev, category="leak", port=port,
            service="http", evidence=url))
        # Text-bearing source/backup/config files often carry creds inline.
        if cat in ("backup", "source", "config") and body and body.strip():
            for lbl, val, s in _all_secrets(body):
                utils.log("hot", f"{lbl} in /{path}: {val[:50]}", indent=4)
                host.add(Finding(
                    title=f"{pfx}{lbl} in /{path}", detail=f"{lbl} = {val}",
                    severity=s, category="cred", port=port, service="http",
                    evidence=f"{url}: {val}"))


def _probe_backups(host: HostReport, port: int, base: str, found_paths: List[str],
                   cal, vhost, pfx: str, cap: int = 40) -> None:
    """For each discovered source/page, request common backup variants — the
    classic 'source of the running page' leak."""
    seeds = [p for p in found_paths
             if filetypes.classify(p) and filetypes.classify(p)[0] == "source"]
    # Also try backups of common index pages even if not individually found.
    for guess in ("index.php", "index.html", "index.jsp", "index.aspx", "login.php"):
        if guess not in seeds:
            seeds.append(guess)
    if not seeds:
        return
    utils.log("info", "probing for source/config backups", indent=1)
    tried = 0
    for seed in seeds:
        for cand in filetypes.backup_candidates(seed):
            if tried >= cap:
                return
            tried += 1
            url = f"{base}/{cand}"
            status, headers, body = _fetch(url, timeout=5.0, method="GET", vhost=vhost)
            if status != 200 or not body or not body.strip():
                continue
            if _is_soft404(cal, status, body, len(body), headers.get("location", "")):
                continue
            utils.log("hot", f"backup file: /{cand}", indent=2)
            host.add(Finding(
                title=f"{pfx}Source/backup file exposed: /{cand}",
                detail="Likely the source of the running page — read it for "
                       "logic flaws and hard-coded credentials.",
                severity="high", category="leak", port=port, service="http",
                evidence=url))
            for label, value, sev in _all_secrets(body):
                host.add(Finding(
                    title=f"{pfx}{label} in /{cand}", detail=f"{label} = {value}",
                    severity=sev, category="cred", port=port, service="http",
                    evidence=f"{url}: {value}"))


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


def _all_secrets(body: str):
    """Both env-style and code-idiom secret extraction, deduped by value."""
    seen = set()
    for lbl, val, sev in knowledge.extract_secrets(body):
        if val not in seen:
            seen.add(val)
            yield lbl, val, sev
    for lbl, val, sev in knowledge.extract_code_secrets(body):
        if val not in seen:
            seen.add(val)
            yield lbl, val, sev


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
