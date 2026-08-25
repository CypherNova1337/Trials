"""NFS and rsync enumeration — often world-readable and full of loot."""

from __future__ import annotations

import re

from ...core import utils, tooling
from ...core.report import HostReport, Finding


def nfs(host: HostReport, port: int = 2049) -> None:
    ip = host.resolved_ip
    utils.section(f"NFS {ip}:{port}")
    if tooling.resolve("showmount"):
        rc, out, _ = utils.run(["showmount", "-e", ip], timeout=20)
        exports = [l.strip() for l in (out or "").splitlines()[1:] if l.strip()]
        if exports:
            utils.log("hot", f"{len(exports)} NFS export(s)", indent=1)
            for e in exports:
                utils.log("good", e, indent=2)
            host.add(Finding(
                title="NFS exports available",
                detail="; ".join(exports),
                severity="high", category="leak", port=port, service="nfs",
                evidence="\n".join(exports)))
            host.add(Finding(
                title="Mount NFS exports and check for loot / no_root_squash",
                detail="mount -t nfs " + ip + ":<export> /mnt; a no_root_squash "
                       "export enables a classic SUID privesc.",
                severity="info", category="service", port=port, service="nfs",
                confidence="potential"))
        else:
            utils.log("dim", "no exports listed (or access denied)", indent=1)
    else:
        utils.log("dim", "install nfs-common (showmount) to list exports", indent=1)


def rsync(host: HostReport, port: int = 873) -> None:
    ip = host.resolved_ip
    utils.section(f"rsync {ip}:{port}")
    if tooling.resolve("rsync"):
        rc, out, err = utils.run(
            ["rsync", "-av", "--list-only", "--timeout=10", f"rsync://{ip}:{port}/"],
            timeout=25)
        modules = [l.split()[0] for l in (out or "").splitlines()
                   if l.strip() and not l.startswith(" ")]
        if modules:
            utils.log("hot", f"rsync modules: {', '.join(modules)}", indent=1)
            host.add(Finding(
                title="rsync modules listable (unauthenticated)",
                detail=", ".join(modules),
                severity="high", category="leak", port=port, service="rsync",
                evidence=out[:400]))
            host.add(Finding(
                title="Pull rsync module contents",
                detail=f"rsync -av rsync://{ip}:{port}/<module>/ ./loot/",
                severity="info", category="service", port=port, service="rsync",
                confidence="potential"))
        else:
            utils.log("dim", "no modules listed / auth required", indent=1)
    else:
        utils.log("dim", "rsync client not installed", indent=1)
