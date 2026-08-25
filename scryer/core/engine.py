"""The orchestrator.

Runs recon in adaptive phases and dispatches service-specific deep modules
based on what the port scan actually finds. A second dispatch pass runs if
earlier modules discover new hostnames (e.g. a TLS SAN), so virtual-host-only
content gets a look too.
"""

from __future__ import annotations

from typing import List

from . import utils, hostsfile
from .report import HostReport, Finding
from ..data import knowledge
from ..modules import discovery, ports, fingerprint, nmapscan, exploitintel
from ..modules.services import (
    http, tls, dns, smb, auth_svcs, datastores, ldap, vhost,
    snmp, mail, netshares, sqldb, remote, webcrawl, params)


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

        # Port discovery: prefer the nmap/rustscan pipeline (fast + NSE intel);
        # fall back to the pure-python scanner when nmap is unavailable or the
        # user forced --no-nmap.
        open_ports = None
        used_nmap = False
        if not getattr(self.opts, "no_nmap", False):
            open_ports = nmapscan.orchestrate(host, ip, self.opts)
            used_nmap = open_ports is not None
        if open_ports is None:
            open_ports = ports.connect_scan(
                host, ip, self._port_selection(),
                timeout=self.opts.timeout, workers=self.opts.workers)

        if not open_ports:
            utils.log("warn", "no open ports — nothing to enrich")
            host.finished = utils.now_iso()
            return host

        # Confirm what each port actually speaks before dispatching modules.
        # nmap -sV is authoritative, so only fingerprint when it didn't run.
        if not used_nmap:
            fingerprint.refine(host, timeout=max(self.opts.timeout, 4.0))

        # First deep pass over discovered services.
        before = set(host.hostnames)
        self._dispatch(open_ports)

        # Virtual-host brute forcing — the usual foothold on hard web boxes.
        if not self.opts.no_vhost:
            self._vhost_brute()

        # Make discovered vhosts resolvable so the external tools (and the
        # operator's browser) work; always surface the exact /etc/hosts line.
        self._hosts_step()

        # Adaptive re-pass: hostnames discovered *during* enrichment (a TLS
        # SAN, an HTTP redirect, a vhost hit) may front name-based virtual
        # hosts. Re-probe web ports with an explicit Host header for each.
        discovered = [h for h in host.hostnames if h not in before]
        if discovered:
            utils.log("info", f"virtual-host pass for: {', '.join(discovered)}")
            self._vhost_pass(open_ports, discovered)

        self._ad_methodology()
        self._os_inference()

        # Turn identified versions into concrete Exploit-DB leads.
        if not getattr(self.opts, "no_searchsploit", False):
            exploitintel.run(host)

        host.finished = utils.now_iso()
        return host

    def _vhost_brute(self) -> None:
        host = self.host
        web = [e for e in host.open_ports
               if self._is_web(e["port"], (e.get("service") or "").lower())]
        for entry in web:
            secure = bool(entry.get("secure")) or entry["port"] in knowledge.HTTPS_PORTS
            vhost.brute(host, entry["port"], secure,
                        domain=getattr(self.opts, "vhost_domain", None))

    def _hosts_step(self) -> None:
        names = hostsfile.vhost_names(self.host)
        if not names:
            return
        ip = self.host.resolved_ip
        cmd = hostsfile.command(ip, names)
        if getattr(self.opts, "add_hosts", False):
            if hostsfile.add(ip, names):
                utils.log("good", f"added to /etc/hosts: {ip} {' '.join(names)}")
            else:
                utils.log("warn", f"could not edit /etc/hosts — run: {cmd}")
        else:
            utils.log("warn", f"add these vhosts to /etc/hosts (or use "
                              f"--add-hosts): {utils.c(ip + ' ' + ' '.join(names), utils.C.CYAN)}")
        self.host.add(Finding(
            title="Virtual hosts need /etc/hosts entries",
            detail=cmd,
            severity="info", category="host",
            evidence=cmd))

    def _ad_methodology(self) -> None:
        """If the port mix looks like an AD domain controller, drop the
        standard next-step methodology so the user has a plan even before
        credentials."""
        ports_open = {e["port"] for e in self.host.open_ports}
        if not ({88} & ports_open and ({389, 636, 3268} & ports_open)):
            return
        self.host.add(Finding(
            title="Active Directory domain controller detected",
            detail="Kerberos + LDAP + SMB present. Next steps: enumerate users "
                   "(anonymous LDAP / RID cycling / rpcclient), AS-REP roast "
                   "(GetNPUsers.py), then password-spray; with any creds run "
                   "BloodHound and Kerberoast (GetUserSPNs.py). Add the DC FQDN "
                   "to /etc/hosts for LDAP/Kerberos to work.",
            severity="info", category="host", confidence="potential"))
        utils.log("info", "Active Directory DC fingerprint — see methodology finding")

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
        """Re-probe each web port for each newly discovered hostname, running
        the full pure-python web treatment (enrich + crawl) via Host header —
        this is where a box like Orion actually serves its content."""
        host = self.host
        web = [e for e in host.open_ports
               if self._is_web(e["port"], (e.get("service") or "").lower())]
        for entry in web:
            secure = bool(entry.get("secure")) or entry["port"] in knowledge.HTTPS_PORTS
            for name in hostnames:
                http.enrich(host, entry["port"], secure=secure, vhost=name)
                endpoints = webcrawl.crawl(host, entry["port"], secure,
                                           vhost=name) or []
                if getattr(self.opts, "web_brute", False) or \
                        getattr(self.opts, "params", False):
                    scheme = "https" if secure else "http"
                    # External tools need the vhost resolvable (/etc/hosts);
                    # target it by name so they hit the right virtual host.
                    base_url = f"{scheme}://{name}:{entry['port']}"
                    params.discover(host, entry["port"], secure, base_url, endpoints)

    def _dispatch_one(self, host, port: int, svc: str) -> bool:
        try:
            entry = self._entry(port)
            secure = bool(entry.get("secure")) if entry else False
            if self._is_web(port, svc):
                secure = secure or port in knowledge.HTTPS_PORTS or "https" in svc
                if secure:
                    tls.enrich(host, port)
                http.enrich(host, port, secure=secure)
                webcrawl.whatweb(host, port, secure)
                endpoints = webcrawl.crawl(host, port, secure) or []
                if getattr(self.opts, "web_brute", False):
                    webcrawl.dir_brute(host, port, secure)
                if getattr(self.opts, "web_brute", False) or \
                        getattr(self.opts, "params", False):
                    scheme = "https" if secure else "http"
                    base_url = f"{scheme}://{host.resolved_ip}:{port}"
                    params.discover(host, port, secure, base_url, endpoints)
                return True

            if secure or port in (443, 8443) or "ssl" in svc:
                tls.enrich(host, port)
                return True
            if svc == "dns" or port == 53:
                dns.enrich(host, port)
                return True
            if port in (139, 445) or "smb" in svc or "netbios" in svc:
                smb.enrich(host, port)
                return True
            if port in (389, 636, 3268, 3269) or "ldap" in svc:
                ldap.enrich(host, port)
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
            if port in (25, 465, 587) or svc in ("smtp", "smtps", "submission"):
                mail.enrich(host, port)
                return True
            if port == 161 or "snmp" in svc:
                snmp.enrich(host, port)
                return True
            if port == 2049 or svc == "nfs":
                netshares.nfs(host, port)
                return True
            if port == 873 or svc == "rsync":
                netshares.rsync(host, port)
                return True
            if port == 3306 or svc == "mysql":
                sqldb.mysql(host, port)
                return True
            if port == 5432 or svc in ("postgresql", "postgres"):
                sqldb.postgresql(host, port)
                return True
            if port == 1433 or "ms-sql" in svc or svc == "mssql":
                sqldb.mssql(host, port)
                return True
            if port == 3389 or svc in ("rdp", "ms-wbt-server"):
                remote.rdp(host, port)
                return True
            if port in (5900, 5901, 5902) or svc == "vnc":
                remote.vnc(host, port)
                return True
            if port in (5985, 5986) or "winrm" in svc or "wsman" in svc:
                remote.winrm(host, port)
                return True
        except Exception as exc:  # keep one bad module from killing the scan
            utils.log("bad", f"module error on port {port}: {exc}")
        return False

    def _entry(self, port: int):
        for e in self.host.open_ports:
            if e["port"] == port:
                return e
        return None

    @staticmethod
    def _is_web(port: int, svc: str) -> bool:
        # Prefer the observed protocol; fall back to the port map only when a
        # port was never fingerprinted (e.g. nmap-only entries).
        if svc in ("http", "https"):
            return True
        if svc and "http" not in svc:
            return False
        return port in knowledge.HTTP_PORTS or port in knowledge.HTTPS_PORTS

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
