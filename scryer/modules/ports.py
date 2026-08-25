"""Port scanning and banner grabbing.

Two backends:
  * A threaded pure-Python TCP connect scanner (always available).
  * An optional nmap wrapper for -sV service/version detection when nmap
    is installed and the user opts in.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
from typing import Iterable, List

from ..core import utils
from ..core.report import HostReport, Finding
from ..data import knowledge


def _grab_banner(ip: str, port: int, timeout: float) -> str:
    """Connect, optionally send a probe, and read a short banner."""
    probe = knowledge.SERVICE_PROBES.get(port, b"")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    pass
            try:
                data = sock.recv(512)
            except socket.timeout:
                data = b""
            return data.decode("latin-1", "replace").strip()
    except OSError:
        return ""


def _scan_one(ip: str, port: int, timeout: float):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except OSError:
        return None
    banner = _grab_banner(ip, port, timeout)
    return port, banner


def connect_scan(host: HostReport, ip: str, ports: Iterable[int],
                 timeout: float = 1.5, workers: int = 200) -> List[int]:
    """Threaded TCP connect scan. Returns the sorted list of open ports."""
    ports = list(ports)
    utils.log("info", f"connect-scan {len(ports)} ports on {ip} "
                      f"({workers} workers, {timeout}s timeout)")
    open_ports: List[int] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result is None:
                continue
            port, banner = result
            open_ports.append(port)
            svc = knowledge.PORT_SERVICE.get(port, "")
            version = _version_from_banner(banner)
            entry = host.add_port(port, "tcp", svc, version, banner)
            _report_open(host, entry, banner)

    open_ports.sort()
    utils.log("good", f"{len(open_ports)} open ports: "
                      f"{utils.c(', '.join(map(str, open_ports)) or '-', utils.C.CYAN)}")
    return open_ports


def _report_open(host: HostReport, entry: dict, banner: str) -> None:
    port = entry["port"]
    svc = entry["service"] or "unknown"
    label = f"{port}/tcp {svc}"
    if entry["version"]:
        label += f" ({entry['version']})"
    utils.log("good", label, indent=1)

    # Version-based vuln hints feed straight into findings.
    text = " ".join(filter(None, [entry["version"], banner]))
    for sev, note in knowledge.match_hints(text):
        host.add(Finding(
            title=note,
            detail=f"Inferred from the {svc} banner — confirm the exact "
                   f"version before relying on it.",
            severity=sev,
            category="service",
            port=port,
            service=svc,
            evidence=banner[:200] if banner else None,
            confidence="potential",
        ))
        utils.log("hot" if sev in ("critical", "high") else "warn", note, indent=2)


_VERSION_RE = re.compile(
    r"(SSH-[\d.]+-\S+|Apache/[\d.]+|nginx/[\d.]+|Microsoft-IIS/[\d.]+|"
    r"vsftpd [\d.]+|ProFTPD [\d.]+|OpenSSH[_ ][\w.]+|Werkzeug/[\d.]+|"
    r"lighttpd/[\d.]+|Jetty\S*|Tomcat[/ ]?[\d.]*)",
    re.IGNORECASE,
)


def _version_from_banner(banner: str) -> str:
    if not banner:
        return ""
    m = _VERSION_RE.search(banner)
    if m:
        return m.group(1)
    # First non-empty line, trimmed — good enough for FTP/SMTP greetings.
    first = banner.splitlines()[0].strip() if banner.splitlines() else ""
    return first[:60]


# ---------------------------------------------------------------------------
# Optional nmap backend for richer service/version + OS detection
# ---------------------------------------------------------------------------
def nmap_service_scan(host: HostReport, ip: str, ports: List[int],
                      timeout: int = 300) -> None:
    """Run `nmap -sV` against known-open ports and merge results/OS guess."""
    if not ports or not utils.have("nmap"):
        return
    port_arg = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-sV", "-Pn", "-T4", "-p", port_arg, ip]
    utils.log("info", f"nmap service scan: {' '.join(cmd)}")
    rc, out, err = utils.run(cmd, timeout=timeout)
    if rc != 0 and not out:
        utils.log("warn", f"nmap failed: {err.strip() or rc}")
        return
    _merge_nmap(host, out)


_NMAP_LINE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$")


def _merge_nmap(host: HostReport, output: str) -> None:
    by_port = {p["port"]: p for p in host.open_ports}
    for line in output.splitlines():
        m = _NMAP_LINE.match(line.strip())
        if not m:
            if line.lower().startswith("os details") or "Running:" in line:
                host.os_guess = line.split(":", 1)[-1].strip()
            continue
        port = int(m.group(1))
        service = m.group(2)
        version = m.group(3).strip()
        entry = by_port.get(port)
        if entry:
            entry["service"] = service or entry["service"]
            if version:
                entry["version"] = version
        else:
            entry = host.add_port(port, "tcp", service, version)
            by_port[port] = entry
        for sev, note in knowledge.match_hints(f"{service} {version}"):
            host.add(Finding(
                title=note, severity=sev, category="service",
                port=port, service=service, evidence=version,
                confidence="potential",
            ))
