"""The orchestrator.

Runs recon in adaptive phases and dispatches service-specific deep modules
based on what the port scan actually finds. A second dispatch pass runs if
earlier modules discover new hostnames (e.g. a TLS SAN), so virtual-host-only
content gets a look too.
"""

from __future__ import annotations

from typing import List

from . import utils
from .report import HostReport, Finding
from ..data import knowledge
from ..modules import discovery, ports
from ..modules.services import http, tls, dns, smb, auth_svcs, datastores


class Engine:
    def __init__(self, target: str, opts) -> None:
        self.opts = opts
        self.host = HostReport(target=target)
        self._dispatched: set = set()

    # -- phases -------------------------------------------------------------
    def run(self) -> HostReport:
        host = self.host
        ip = discovery.resolve(host)
        if not ip:
            host.note("Target unresolvable", severity="high", category="host")
            host.finished = utils.now_iso()
            return host

        discovery.liveness(host, ip)

        port_list = self._port_selection()
        open_ports = ports.connect_scan(
            host, ip, port_list,
            timeout=self.opts.timeout, workers=self.opts.workers)

        if self.opts.nmap and open_ports:
            ports.nmap_service_scan(host, ip, open_ports, timeout=self.opts.nmap_timeout)

        if not open_ports:
            utils.log("warn", "no open ports — nothing to enrich")
            host.finished = utils.now_iso()
            return host

        # First deep pass over discovered services.
        before = set(host.hostnames)
        self._dispatch(open_ports)

        # Adaptive re-pass: hostnames discovered *during* enrichment (a TLS
        # SAN, an HTTP redirect) may front name-based virtual hosts. Re-probe
        # web ports with an explicit Host header for each new name.
        discovered = [h for h in host.hostnames if h not in before]
        if discovered:
            utils.log("info", f"virtual-host pass for: {', '.join(discovered)}")
            self._vhost_pass(open_ports, discovered)

        self._os_inference()
        host.finished = utils.now_iso()
        return host

    # -- helpers ------------------------------------------------------------
    def _port_selection(self) -> List[int]:
        if self.opts.ports == "top":
            return knowledge.TOP_PORTS
        if self.opts.ports == "full":
            return list(range(1, 65536))
        # explicit comma list
        out = []
        for chunk in self.opts.ports.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                out.extend(range(int(a), int(b) + 1))
            elif chunk.isdigit():
                out.append(int(chunk))
        return out or knowledge.TOP_PORTS

    def _dispatch(self, open_ports: List[int]) -> None:
        host = self.host
        for entry in list(host.open_ports):
            port = entry["port"]
            svc = (entry.get("service") or "").lower()
            key = ("web" if self._is_web(port, svc) else svc, port)
            if key in self._dispatched:
                continue

            handled = self._dispatch_one(host, port, svc)
            if handled:
                self._dispatched.add(key)

    def _vhost_pass(self, open_ports: List[int], hostnames: List[str]) -> None:
        """Re-probe each web port once per newly discovered hostname."""
        host = self.host
        web_ports = [e["port"] for e in host.open_ports
                     if self._is_web(e["port"], (e.get("service") or "").lower())]
        for port in web_ports:
            secure = (port in knowledge.HTTPS_PORTS)
            for name in hostnames:
                http.enrich(host, port, secure=secure, vhost=name)

    def _dispatch_one(self, host, port: int, svc: str) -> bool:
        try:
            if self._is_web(port, svc):
                secure = port in knowledge.HTTPS_PORTS or "https" in svc or "ssl" in svc
                if secure:
                    tls.enrich(host, port)
                http.enrich(host, port, secure=secure)
                return True

            if port in (443, 8443) or "ssl" in svc:
                tls.enrich(host, port)
                return True
            if svc == "dns" or port == 53:
                dns.enrich(host, port)
                return True
            if port in (139, 445) or "smb" in svc or "netbios" in svc:
                smb.enrich(host, port)
                return True
            if port == 21 or svc == "ftp":
                auth_svcs.ftp(host, port)
                return True
            if port in (22, 2222) or svc == "ssh":
                auth_svcs.ssh(host, port)
                return True
            if port == 6379 or svc == "redis":
                datastores.redis(host, port)
                return True
            if port == 11211 or svc == "memcached":
                datastores.memcached(host, port)
                return True
            if port in (9200, 9300) or svc == "elasticsearch":
                datastores.elasticsearch(host, port)
                return True
            if port in (27017, 27018) or svc == "mongodb":
                datastores.mongodb(host, port)
                return True
        except Exception as exc:  # keep one bad module from killing the scan
            utils.log("bad", f"module error on port {port}: {exc}")
        return False

    @staticmethod
    def _is_web(port: int, svc: str) -> bool:
        return (port in knowledge.HTTP_PORTS or port in knowledge.HTTPS_PORTS
                or "http" in svc)

    def _os_inference(self) -> None:
        """Cheap OS guess from service mix when nmap didn't provide one."""
        host = self.host
        if host.os_guess:
            return
        svcs = " ".join((p.get("service") or "") + " " + (p.get("banner") or "")
                        for p in host.open_ports).lower()
        windows_signals = ("microsoft", "netbios", "msrpc", "rdp", "winrm",
                           "iis", "ms-wbt")
        linux_signals = ("openssh", "ubuntu", "debian", "apache", "vsftpd",
                         "unix", "linux")
        win = sum(s in svcs for s in windows_signals)
        lin = sum(s in svcs for s in linux_signals)
        if win > lin and win:
            host.os_guess = "Windows (inferred from service mix)"
        elif lin > win and lin:
            host.os_guess = "Linux/Unix (inferred from service mix)"
        if host.os_guess:
            host.add(Finding(title=f"OS guess: {host.os_guess}",
                             severity="info", category="host"))
