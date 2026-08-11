"""TLS certificate inspection — pulls subject/SAN/issuer and feeds any
discovered hostnames back into scope."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import List

from ...core import utils
from ...core.report import HostReport, Finding


def enrich(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"TLS {ip}:{port}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host.hostnames[0]
                                 if host.hostnames else None) as tls:
                cert = tls.getpeercert()
                version = tls.version()
                cipher = tls.cipher()
    except Exception as exc:
        utils.log("warn", f"TLS handshake failed: {exc}", indent=1)
        return

    if version:
        utils.kv("protocol", version, indent=4)
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            host.add(Finding(
                title=f"Weak TLS protocol offered: {version}",
                severity="medium", category="service", port=port, service="tls",
            ))
            utils.log("warn", f"weak protocol {version}", indent=2)
    if cipher:
        utils.kv("cipher", cipher[0], indent=4)

    if not cert:
        # verify_mode=NONE means getpeercert may be empty; try binary form.
        utils.log("dim", "no parsed certificate (self-signed likely)", indent=2)
        return

    subject = _flatten(cert.get("subject", []))
    issuer = _flatten(cert.get("issuer", []))
    cn = subject.get("commonName")
    if cn:
        utils.kv("subject CN", cn, indent=4)
        if host.add_hostname(cn):
            utils.log("good", f"cert CN adds hostname {utils.c(cn, utils.C.CYAN)}",
                      indent=2)
    if issuer.get("commonName"):
        utils.kv("issuer", issuer["commonName"], indent=4)

    sans: List[str] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    new = [s for s in sans if host.add_hostname(s)]
    if sans:
        utils.kv("SAN", ", ".join(sans), indent=4)
    for name in new:
        utils.log("good", f"SAN adds hostname {utils.c(name, utils.C.CYAN)}", indent=2)

    if sans or cn:
        host.add(Finding(
            title="TLS certificate identities",
            detail=", ".join(sorted(set(filter(None, [cn, *sans])))),
            severity="info", category="host", port=port, service="tls",
        ))

    _check_expiry(host, port, cert)


def _flatten(rdn_seq) -> dict:
    out = {}
    for rdn in rdn_seq:
        for key, value in rdn:
            out[key] = value
    return out


def _check_expiry(host: HostReport, port: int, cert: dict) -> None:
    not_after = cert.get("notAfter")
    if not not_after:
        return
    try:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return
    if exp < datetime.utcnow():
        host.add(Finding(title="TLS certificate expired", detail=not_after,
                         severity="low", category="service", port=port, service="tls"))
        utils.log("warn", f"certificate expired ({not_after})", indent=2)
