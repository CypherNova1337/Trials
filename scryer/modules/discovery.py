"""Target resolution and liveness checks."""

from __future__ import annotations

import socket
from typing import Optional

from ..core import utils
from ..core.report import HostReport, Finding


def resolve(host: HostReport) -> Optional[str]:
    """Resolve the target to an IP and capture reverse-DNS / aliases."""
    target = host.target
    if utils.is_ip(target):
        host.resolved_ip = target
        # Reverse lookup for a possible hostname.
        try:
            name, aliases, _ = socket.gethostbyaddr(target)
            host.add_hostname(name)
            for a in aliases:
                host.add_hostname(a)
        except OSError:
            pass
        return target

    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
        host.resolved_ip = ip
        host.add_hostname(target)
        utils.log("good", f"{target} resolves to {utils.c(ip, utils.C.CYAN)}")
        return ip
    except OSError as exc:
        utils.log("bad", f"could not resolve {target}: {exc}")
        return None


def liveness(host: HostReport, ip: str, timeout: float = 2.0) -> bool:
    """Best-effort host-up check.

    ICMP needs root, so we prefer a TCP knock on common ports and fall back
    to the system `ping`. A "down" result is advisory only — many CTF hosts
    drop pings but still serve ports, so scanning continues regardless.
    """
    for port in (80, 443, 22, 445, 3389):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                utils.log("good", f"host up (tcp/{port} reachable)")
                return True
        except OSError:
            continue

    if utils.have("ping"):
        rc, _out, _ = utils.run(["ping", "-c", "1", "-W", "1", ip], timeout=5)
        if rc == 0:
            utils.log("good", "host up (icmp echo)")
            return True

    utils.log("warn", "host did not answer probes — continuing anyway")
    host.add(Finding(
        title="Host silent to liveness probes",
        detail="No TCP knock or ICMP reply; firewall/filtered. Scan proceeds.",
        severity="info",
        category="host",
    ))
    return False
