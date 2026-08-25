"""SMB / NetBIOS enrichment.

Pure-Python SMB is heavy, so this module drives external tooling when
present (smbclient, nmblookup, enum4linux, rpcclient) and degrades quietly
when it is not. The goal is to surface null-session shares and hostnames.
"""

from __future__ import annotations

import re

from ...core import utils
from ...core.report import HostReport, Finding


def enrich(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"SMB {ip}:{port}")

    _nmblookup(host, ip)
    shares = _list_shares(host, ip)
    if shares:
        _null_read_check(host, ip, port, shares)
    _rpc_users(host, ip, port)

    if not utils.have("smbclient") and not utils.have("nmblookup"):
        utils.log("dim", "no smbclient/nmblookup on PATH — install to enum shares",
                  indent=2)


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
    interesting = [s for s in shares if s.upper() not in ("IPC$", "PRINT$")]
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
