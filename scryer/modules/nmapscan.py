"""nmap / rustscan orchestration with NSE script ingestion.

When nmap is present scryer uses it as the scan engine: rustscan (or masscan)
finds open ports fast across the full range, then nmap runs -sV -sC on just
those ports and we parse the XML — including the NSE script output, which
carries a huge amount of free intel (ftp-anon, smb-os-discovery, ssl-cert,
http-title, http-robots, ssh-auth-methods, …). Falls back to the pure-python
scanner when nmap is absent.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..core import utils, tooling
from ..core.report import HostReport, Finding


# NSE scripts whose output we promote above plain info.
_SCRIPT_SEVERITY = {
    "ftp-anon": ("high", "cred"),
    "smb-os-discovery": ("info", "host"),
    "smb-enum-shares": ("medium", "service"),
    "smb-enum-users": ("high", "cred"),
    "smb2-security-mode": ("info", "service"),
    "ssl-cert": ("info", "host"),
    "ssl-dh-params": ("medium", "service"),
    "http-title": ("info", "web"),
    "http-robots.txt": ("low", "web"),
    "http-git": ("high", "leak"),
    "http-config-backup": ("high", "leak"),
    "http-auth": ("low", "web"),
    "ssh-auth-methods": ("info", "service"),
    "ssh2-enum-algos": ("info", "service"),
    "dns-zone-transfer": ("high", "service"),
    "nfs-showmount": ("medium", "service"),
    "rsync-list-modules": ("medium", "service"),
    "mysql-empty-password": ("critical", "cred"),
    "ms-sql-empty-password": ("critical", "cred"),
    "vnc-info": ("medium", "service"),
    "rdp-ntlm-info": ("info", "host"),
    "clamav-exec": ("critical", "service"),
}


def available() -> bool:
    return tooling.resolve("nmap") is not None


def orchestrate(host: HostReport, ip: str, opts) -> Optional[List[int]]:
    """Run the nmap-based scan pipeline. Returns open ports, or None if nmap
    is unavailable (caller then uses the python scanner)."""
    if not available():
        return None

    nmap = tooling.resolve("nmap")
    # 1) Fast port discovery across the requested range.
    if opts.ports == "full":
        prange = "1-65535"
    elif opts.ports == "top":
        prange = None  # let nmap use its top-ports
    else:
        prange = opts.ports

    discovered = _fast_ports(ip, prange, opts)
    if discovered is not None and not discovered:
        utils.log("warn", "no open TCP ports found")
        return []

    # 2) Deep -sV -sC on the discovered (or requested) ports.
    if discovered:
        port_arg = ["-p", ",".join(map(str, discovered))]
    elif prange:
        port_arg = ["-p", prange]
    else:
        port_arg = ["--top-ports", "1000"]

    cmd = [nmap, "-sV", "-sC", "-Pn", "-T4", *port_arg, "-oX", "-", ip]
    utils.log("info", f"nmap deep scan: {' '.join(cmd)}")
    rc, out, err = utils.run(cmd, timeout=opts.nmap_timeout)
    if not out:
        utils.log("warn", f"nmap produced no XML ({err.strip()[:120]}) — "
                          f"falling back to python scan")
        return None
    ports = _parse_xml(host, out)

    # 3) Optional UDP top-ports (needs root for real results).
    if getattr(opts, "udp", False):
        _udp_scan(host, ip, opts)

    return ports


def _fast_ports(ip: str, prange: Optional[str], opts) -> Optional[List[int]]:
    """Use rustscan/masscan for a fast sweep; None means 'let nmap do it'."""
    rustscan = tooling.resolve("rustscan")
    if rustscan and prange != None:
        cmd = [rustscan, "-a", ip, "--range",
               prange if prange and "-" in prange else "1-65535",
               "-g", "--", "-Pn"]
        # rustscan -g greppable prints: ip -> [22,80,443]
        rc, out, _ = utils.run(cmd, timeout=min(opts.nmap_timeout, 600))
        m = re.search(r"\[([\d,]+)\]", out or "")
        if m:
            ports = sorted(int(p) for p in m.group(1).split(",") if p)
            utils.log("good", f"rustscan found {len(ports)} open ports", indent=1)
            return ports
    return None


def _parse_xml(host: HostReport, xml: str) -> List[int]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        utils.log("warn", f"could not parse nmap XML: {exc}")
        return []

    open_ports: List[int] = []
    for host_el in root.findall("host"):
        # hostnames from nmap (PTR etc.)
        for hn in host_el.findall("./hostnames/hostname"):
            name = hn.get("name")
            if name:
                host.add_hostname(name)
        # OS guess
        for osm in host_el.findall("./os/osmatch"):
            if not host.os_guess:
                host.os_guess = f"{osm.get('name')} ({osm.get('accuracy')}%)"

        for port_el in host_el.findall("./ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            proto = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            service = version = ""
            secure = False
            if svc_el is not None:
                service = svc_el.get("name", "")
                product = svc_el.get("product", "")
                ver = svc_el.get("version", "")
                extra = svc_el.get("extrainfo", "")
                version = " ".join(x for x in (product, ver, extra) if x).strip()
                secure = (svc_el.get("tunnel") == "ssl"
                          or "https" in service or "ssl" in service)
            entry = host.add_port(portid, proto, service, version)
            entry["secure"] = secure
            open_ports.append(portid)

            label = f"{portid}/{proto} {service or '?'}"
            if version:
                label += f" ({version})"
            utils.log("good", label, indent=1)

            # version-based weakness hints
            from ..data import knowledge
            for sev, note in knowledge.match_hints(f"{service} {version}"):
                host.add(Finding(title=note, severity=sev, category="service",
                                 port=portid, service=service, evidence=version,
                                 confidence="potential"))

            # NSE script output
            for script in port_el.findall("script"):
                _ingest_script(host, portid, service, script.get("id", ""),
                               script.get("output", ""))

    open_ports.sort()
    utils.log("good", f"{len(open_ports)} open ports via nmap: "
                      f"{utils.c(', '.join(map(str, open_ports)) or '-', utils.C.CYAN)}")
    return open_ports


def _ingest_script(host: HostReport, port: int, service: str,
                   sid: str, output: str) -> None:
    output = (output or "").strip()
    if not output:
        return
    sev, cat = _SCRIPT_SEVERITY.get(sid, ("info", "service"))

    # Pull hostnames out of ssl-cert / smb-os-discovery for scope expansion.
    if sid in ("ssl-cert", "smb-os-discovery"):
        for name in re.findall(r"(?:DNS:|Computer name:|FQDN:)\s*([A-Za-z0-9_.-]+)",
                               output):
            host.add_hostname(name)
    if sid == "ftp-anon" and "Anonymous FTP login allowed" in output:
        sev, cat = "high", "cred"

    first = output.splitlines()[0][:100] if output.splitlines() else output[:100]
    host.add(Finding(
        title=f"nmap {sid}: {first}",
        detail=output[:500],
        severity=sev, category=cat, port=port, service=service,
        evidence=output[:1500],
    ))
    mark = "hot" if sev in ("critical", "high") else "good" if sev != "info" else "dim"
    utils.log(mark, f"{sid}: {first}", indent=2)


def _udp_scan(host: HostReport, ip: str, opts) -> None:
    nmap = tooling.resolve("nmap")
    cmd = [nmap, "-sU", "--top-ports", "50", "-Pn", "-T4", "-oX", "-", ip]
    utils.log("info", "nmap UDP top-50 (needs root for accurate results)")
    rc, out, err = utils.run(cmd, timeout=opts.nmap_timeout)
    if not out:
        utils.log("dim", "UDP scan produced nothing (root required?)", indent=1)
        return
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return
    for port_el in root.findall("./host/ports/port"):
        state = port_el.find("state")
        st = state.get("state") if state is not None else ""
        if st not in ("open", "open|filtered"):
            continue
        portid = int(port_el.get("portid"))
        svc_el = port_el.find("service")
        service = svc_el.get("name", "") if svc_el is not None else ""
        host.add_port(portid, "udp", service, "")
        utils.log("good", f"{portid}/udp {service or '?'} ({st})", indent=1)
        host.add(Finding(title=f"Open UDP port {portid}/{service}",
                         severity="info", category="port", port=portid,
                         service=service))
