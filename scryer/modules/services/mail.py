"""SMTP enrichment: banner, capabilities, open-relay hint and user-enumeration
vector detection (VRFY / EXPN / RCPT). Pure standard library."""

from __future__ import annotations

import socket

from ...core import utils
from ...core.report import HostReport, Finding


def _talk(sock, cmd: str, timeout: float = 5.0) -> str:
    try:
        if cmd:
            sock.sendall((cmd + "\r\n").encode())
        sock.settimeout(timeout)
        return sock.recv(1024).decode("latin-1", "replace").strip()
    except OSError:
        return ""


def enrich(host: HostReport, port: int = 25) -> None:
    ip = host.resolved_ip
    utils.section(f"SMTP {ip}:{port}")
    try:
        sock = socket.create_connection((ip, port), timeout=8)
    except OSError as exc:
        utils.log("warn", f"connect failed: {exc}", indent=1)
        return

    banner = _talk(sock, "")
    if banner:
        utils.kv("banner", banner, indent=4)
        host.add(Finding(title=f"SMTP banner: {banner}", severity="info",
                         category="service", port=port, service="smtp",
                         evidence=banner))
    ehlo = _talk(sock, "EHLO scryer.local")
    if ehlo:
        caps = [l.split("-", 1)[-1].split()[0] for l in ehlo.splitlines()
                if l[3:4] in ("-", " ") and len(l) > 4]
        if caps:
            utils.kv("capabilities", ", ".join(sorted(set(caps)))[:120], indent=4)

    # VRFY / EXPN user-enumeration probe.
    vrfy = _talk(sock, "VRFY root")
    if vrfy.startswith(("250", "252")):
        utils.log("hot", "VRFY enabled — user enumeration possible", indent=2)
        host.add(Finding(
            title="SMTP VRFY user enumeration enabled",
            detail="VRFY returned a positive code — enumerate users with "
                   "smtp-user-enum -M VRFY -U users.txt -t <ip>.",
            severity="medium", category="cred", port=port, service="smtp",
            evidence=vrfy))
    expn = _talk(sock, "EXPN root")
    if expn.startswith("250"):
        host.add(Finding(title="SMTP EXPN enabled (mailing-list enumeration)",
                         severity="low", category="service", port=port,
                         service="smtp", evidence=expn))

    try:
        _talk(sock, "QUIT")
        sock.close()
    except OSError:
        pass
