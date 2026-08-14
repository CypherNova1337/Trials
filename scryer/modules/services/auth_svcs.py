"""Lightweight enrichment for auth-bearing services: FTP anonymous login and
SSH banner / auth-method inspection. Pure standard library."""

from __future__ import annotations

import ftplib
import socket

from ...core import utils
from ...core.report import HostReport, Finding


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------
def ftp(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"FTP {ip}:{port}")
    try:
        conn = ftplib.FTP()
        conn.connect(ip, port, timeout=10)
        banner = conn.getwelcome() or ""
        if banner:
            utils.kv("banner", banner.strip(), indent=4)
    except Exception as exc:
        utils.log("warn", f"FTP connect failed: {exc}", indent=1)
        return

    try:
        conn.login("anonymous", "anonymous@scryer")
        utils.log("hot", "anonymous FTP login succeeded", indent=2)
        host.add(Finding(
            title="Anonymous FTP login allowed",
            severity="high", category="cred", port=port, service="ftp",
        ))
        try:
            listing = []
            conn.retrlines("LIST", listing.append)
            if listing:
                sample = "\n".join(listing[:20])
                utils.log("good", f"{len(listing)} entries in FTP root", indent=3)
                host.add(Finding(
                    title="Anonymous FTP directory listing",
                    detail=f"{len(listing)} entries",
                    severity="medium", category="leak", port=port,
                    service="ftp", evidence=sample,
                ))
                for line in listing:
                    name = line.split()[-1] if line.split() else ""
                    if name.lower() in ("user.txt", "flag.txt") or name.endswith(
                            (".txt", ".sql", ".bak", ".zip", ".conf")):
                        utils.log("hot", f"interesting file: {name}", indent=3)
        except Exception:
            pass
    except ftplib.error_perm:
        utils.log("dim", "anonymous login rejected", indent=2)
    except Exception as exc:
        utils.log("warn", f"login attempt error: {exc}", indent=2)
    finally:
        try:
            conn.quit()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
def ssh(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"SSH {ip}:{port}")
    try:
        with socket.create_connection((ip, port), timeout=8) as sock:
            sock.settimeout(6)
            banner = sock.recv(256).decode("latin-1", "replace").strip()
    except Exception as exc:
        utils.log("warn", f"SSH banner grab failed: {exc}", indent=1)
        return
    if banner:
        utils.kv("banner", banner, indent=4)
        host.add(Finding(title=f"SSH banner: {banner}", severity="info",
                         category="service", port=port, service="ssh"))
        from ...data.knowledge import match_hints
        for sev, note in match_hints(banner):
            host.add(Finding(title=note, severity=sev, category="service",
                             port=port, service="ssh", evidence=banner,
                             confidence="potential"))
            utils.log("warn", f"{note} (potential)", indent=2)

    if utils.have("ssh"):
        # Ask the server which auth methods it will accept.
        rc, out, err = utils.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "PreferredAuthentications=none", "-o", "ConnectTimeout=6",
             f"nobody@{ip}", "-p", str(port), "exit"], timeout=15)
        blob = err + out
        m = _auth_methods(blob)
        if m:
            utils.kv("auth methods", m, indent=4)
            host.add(Finding(title=f"SSH auth methods: {m}", severity="info",
                             category="service", port=port, service="ssh"))
            if "password" in m:
                host.add(Finding(
                    title="SSH password authentication enabled",
                    detail="Candidate for credential brute-forcing.",
                    severity="low", category="service", port=port, service="ssh",
                ))


def _auth_methods(text: str) -> str:
    import re
    m = re.search(r"authentications that can continue:\s*([\w,\-]+)", text, re.I)
    return m.group(1) if m else ""
