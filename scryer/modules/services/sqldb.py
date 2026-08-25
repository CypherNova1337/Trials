"""SQL database checks: banner/version plus a *safe* default-credential probe
(a single well-known login per engine — never a brute force)."""

from __future__ import annotations

import socket

from ...core import utils, tooling
from ...core.report import HostReport, Finding


def _banner(ip: str, port: int, timeout: float = 5.0) -> bytes:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(512)
    except OSError:
        return b""


def mysql(host: HostReport, port: int = 3306) -> None:
    ip = host.resolved_ip
    utils.section(f"MySQL {ip}:{port}")
    data = _banner(ip, port)
    ver = ""
    if len(data) > 5:
        # Handshake packet: version is a NUL-terminated string after 5 bytes.
        end = data.find(b"\x00", 5)
        if end > 5:
            ver = data[5:end].decode("latin-1", "replace")
    if ver:
        utils.kv("version", ver, indent=4)
        host.add(Finding(title=f"MySQL version: {ver}", severity="info",
                         category="service", port=port, service="mysql",
                         evidence=ver))
    elif b"is not allowed to connect" in data or b"Host" in data:
        host.add(Finding(title="MySQL restricts connecting hosts",
                         detail=data[:120].decode("latin-1", "replace"),
                         severity="info", category="service", port=port,
                         service="mysql"))
    _try_default(host, port, "mysql", "mysql",
                 ["-h", ip, "-P", str(port), "-u", "root", "-e", "SELECT 1"])


def postgresql(host: HostReport, port: int = 5432) -> None:
    ip = host.resolved_ip
    utils.section(f"PostgreSQL {ip}:{port}")
    host.add(Finding(
        title="PostgreSQL exposed",
        detail="Try default creds postgres/postgres; with access, "
               "COPY ... FROM PROGRAM can give RCE on old versions.",
        severity="info", category="service", port=port, service="postgresql",
        confidence="potential"))
    utils.log("info", "try: psql -h %s -U postgres (postgres/postgres)" % ip, indent=1)


def mssql(host: HostReport, port: int = 1433) -> None:
    ip = host.resolved_ip
    utils.section(f"MSSQL {ip}:{port}")
    host.add(Finding(
        title="Microsoft SQL Server exposed",
        detail="Enumerate with `netexec mssql <ip> -u sa -p ''`; if you land a "
               "login, xp_cmdshell may give command execution.",
        severity="info", category="service", port=port, service="mssql",
        confidence="potential"))
    if tooling.resolve("netexec"):
        utils.log("info", f"netexec mssql {ip} -u sa -p ''", indent=1)


def _try_default(host: HostReport, port: int, engine: str, client_key: str,
                 args) -> None:
    """Attempt a single passwordless default login when the client exists."""
    client = tooling.resolve(client_key)
    if not client:
        return
    rc, out, err = utils.run([client, *args], timeout=12)
    blob = (out + err).lower()
    if rc == 0 and "error" not in blob and "denied" not in blob:
        utils.log("hot", f"{engine}: passwordless root/sa login works!", indent=1)
        host.add(Finding(
            title=f"{engine} accepts default/passwordless login",
            detail="A well-known account logs in with no password.",
            severity="critical", category="cred", port=port, service=engine))
