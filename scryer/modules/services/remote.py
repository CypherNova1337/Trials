"""Remote-access services: RDP, VNC, WinRM. Lightweight banner/auth checks
plus the standard next-step methodology."""

from __future__ import annotations

import socket

from ...core import utils, tooling
from ...core.report import HostReport, Finding


def rdp(host: HostReport, port: int = 3389) -> None:
    ip = host.resolved_ip
    utils.section(f"RDP {ip}:{port}")
    host.add(Finding(
        title="RDP exposed",
        detail="Check NLA and gather host/domain via NTLM. "
               "netexec rdp <ip> -u '' -p '' pulls the target's NTLM info; "
               "with creds: xfreerdp /v:<ip> /u:USER /p:PASS.",
        severity="info", category="service", port=port, service="rdp",
        confidence="potential"))
    if tooling.resolve("netexec"):
        rc, out, _ = utils.run(["netexec", "rdp", ip, "-u", "", "-p", ""], timeout=25)
        if out and "(name:" in out:
            utils.log("good", out.strip().splitlines()[-1][:120], indent=1)
            host.add(Finding(title="RDP NTLM info", detail=out[:300],
                             severity="info", category="host", port=port,
                             service="rdp", evidence=out[:600]))


def vnc(host: HostReport, port: int = 5900) -> None:
    ip = host.resolved_ip
    utils.section(f"VNC {ip}:{port}")
    try:
        with socket.create_connection((ip, port), timeout=6) as s:
            s.settimeout(5)
            banner = s.recv(32).decode("latin-1", "replace").strip()
    except OSError as exc:
        utils.log("warn", f"connect failed: {exc}", indent=1)
        return
    if banner.startswith("RFB"):
        utils.kv("protocol", banner, indent=4)
        host.add(Finding(
            title=f"VNC server ({banner})",
            detail="Test for no-auth / weak password: vncviewer <ip>::%d . "
                   "Old RealVNC (CVE-2006-2369) allowed auth bypass." % port,
            severity="medium", category="service", port=port, service="vnc",
            evidence=banner, confidence="potential"))
        utils.log("good", f"VNC {banner} — try vncviewer {ip}::{port}", indent=1)


def winrm(host: HostReport, port: int = 5985) -> None:
    ip = host.resolved_ip
    utils.section(f"WinRM {ip}:{port}")
    host.add(Finding(
        title="WinRM exposed",
        detail="With valid creds this is a full shell: "
               "evil-winrm -i <ip> -u USER -p PASS. Spray creds with "
               "netexec winrm <ip> -u users.txt -p passwords.txt.",
        severity="info", category="service", port=port, service="winrm",
        confidence="potential"))
    utils.log("info", f"evil-winrm -i {ip} -u USER -p PASS  (once you have creds)",
              indent=1)
