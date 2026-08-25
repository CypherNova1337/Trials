"""HTTP parameter discovery via paramvoid.

Drives the operator's paramvoid (https://github.com/CypherNova1337/paramvoid)
to brute-force hidden GET parameters on discovered endpoints. Hidden params are
a classic path to IDOR / LFI / SQLi / SSRF / debug toggles on CTF web targets.
Opt-in (engine gates on --web-brute) and skipped cleanly when paramvoid is
absent. paramvoid replaces arjun as scryer's parameter-discovery backend.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import List, Optional

from ...core import utils, tooling
from ...core.report import HostReport, Finding


def discover(host: HostReport, port: int, secure: bool, base_url: str,
             endpoints: Optional[List[str]] = None, max_targets: int = 6) -> None:
    """Run paramvoid against the base URL plus a few discovered endpoints."""
    pv = tooling.resolve("paramvoid")
    if not pv:
        utils.log("dim", "paramvoid not installed — skipping parameter discovery "
                         "(scryer --toolcheck --install)", indent=1)
        return

    targets = _target_urls(base_url, endpoints)[:max_targets]
    utils.section(f"PARAMS paramvoid ({len(targets)} endpoint(s))")
    wl = tooling.find_wordlist("params")

    total = 0
    for url in targets:
        total += _run_one(host, port, pv, url, wl)
    if total:
        utils.log("good", f"{total} hidden parameter(s) discovered", indent=1)
    else:
        utils.log("dim", "no hidden parameters found", indent=1)


def _run_one(host: HostReport, port: int, pv: str, url: str,
             wl: Optional[str]) -> int:
    fd, out_path = tempfile.mkstemp(prefix="scryer_pv_", suffix=".txt")
    os.close(fd)
    try:
        cmd = [pv, "-u", url, "-oT", out_path, "--rate-limit", "20"]
        if wl:
            cmd += ["-w", wl]
        utils.log("info", f"paramvoid -u {url}", indent=1)
        rc, out, err = utils.run(cmd, timeout=240)
        params = _parse_output(out_path, out)
        if rc != 0 and not params:
            utils.log("dim", f"paramvoid rc={rc}: {(err or '').strip()[:80]}", indent=2)
        for method, param in params:
            utils.log("hot", f"param: {param} ({method}) on {url}", indent=2)
            host.add(Finding(
                title=f"Hidden parameter: {param}",
                detail=f"{method} {url}?{param}= — found by paramvoid. Test for "
                       f"IDOR / LFI / SQLi / SSRF / debug toggles.",
                severity="medium", category="web", port=port, service="http",
                evidence=f"{method} {url} :: {param}"))
        return len(params)
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _parse_output(path: str, stdout: str):
    """paramvoid -oT writes tab-separated `url<TAB>method<TAB>param` lines."""
    found, seen = [], set()
    text = ""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        pass
    for line in (text + "\n" + (stdout or "")).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\t+", line)
        if len(parts) >= 3:
            method, param = parts[1].strip().upper(), parts[2].strip()
        elif len(parts) == 1 and re.fullmatch(r"[\w.\-\[\]]+", parts[0]):
            method, param = "GET", parts[0]
        else:
            continue
        key = (method, param)
        if param and key not in seen:
            seen.add(key)
            found.append(key)
    return found


def _target_urls(base_url: str, endpoints: Optional[List[str]]) -> List[str]:
    urls, seen = [], set()
    for u in [base_url] + [_join(base_url, e) for e in (endpoints or [])]:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def _join(base: str, ep: str) -> str:
    if ep.startswith("http"):
        return ep
    from urllib.parse import urljoin
    return urljoin(base.rstrip("/") + "/", ep.lstrip("/"))
