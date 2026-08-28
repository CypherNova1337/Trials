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

import json
import re
import concurrent.futures
from typing import Optional

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge

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
          fetch=None) -> None:
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

    for path, st, hd, body in results:
        if not st or st >= 400 or not body:
            continue
        low = body.lower()
        if path.startswith(("actuator", "env", "trace")):
            _actuator(host, port, path, base, body, pfx, vhost)
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
