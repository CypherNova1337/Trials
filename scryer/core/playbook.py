"""Actionable next-step generation.

Turns the recon findings into copy-paste commands tuned to the tools that are
actually installed. Every open service and notable finding yields the exact
command you'd type next — dir brute, share enum, AS-REP roast, searchsploit —
with the target IP, port, domain and best available wordlist already filled in.
The block is printed at the end of a run and written to `commands.sh`.
"""

from __future__ import annotations

from typing import List, Tuple

from . import utils, tooling
from .report import HostReport


class Playbook:
    def __init__(self, host: HostReport):
        self.host = host
        self.ip = host.resolved_ip or host.target
        self.domain = self._pick_domain()
        # Prefer a real hostname (the box's domain) over 'localhost'/IP so the
        # emitted URLs hit the right virtual host.
        self.vhost = self.domain or self.ip
        # AD realm: strip a leading host label (dc01.corp.htb -> corp.htb).
        self.realm = self._pick_realm()
        self.items: List[Tuple[str, str, str]] = []  # (group, note, command)

    def _pick_realm(self):
        if not self.domain:
            return None
        labels = self.domain.split(".")
        return ".".join(labels[1:]) if len(labels) >= 3 else self.domain

    def _pick_domain(self):
        for h in self.host.hostnames:
            if "." in h and h != "localhost" and not h.replace(".", "").isdigit():
                return h
        return None

    def _wl(self, kind: str, default: str) -> str:
        return (tooling.find_wordlist(kind)
                or tooling.bundled_wordlist(kind) or default)

    def add(self, group: str, note: str, command: str):
        self.items.append((group, note, command))

    # -- builders -----------------------------------------------------------
    def build(self) -> "Playbook":
        self._hosts()
        self._general()
        for entry in sorted(self.host.open_ports, key=lambda e: e["port"]):
            self._for_port(entry)
        self._from_findings()
        return self

    def _hosts(self):
        from . import hostsfile
        names = hostsfile.vhost_names(self.host)
        if names:
            self.add("hosts", "map vhosts so tools + browser resolve them",
                     hostsfile.command(self.ip, names))

    def _general(self):
        if not tooling.resolve("nmap"):
            return
        self.add("recon", "full TCP + default scripts",
                 f"nmap -p- -sVC -T4 -oA scryer_{self.ip} {self.ip}")
        self.add("recon", "top UDP ports",
                 f"sudo nmap -sU --top-ports 50 -oA scryer_{self.ip}_udp {self.ip}")

    def _for_port(self, entry):
        port = entry["port"]
        svc = (entry.get("service") or "").lower()
        secure = bool(entry.get("secure"))
        ip = self.ip

        if svc in ("http", "https") or "http" in svc:
            self._web(port, secure)
        if svc == "ftp" or port == 21:
            self.add("ftp", "anon login",
                     f"ftp {ip} {port}   # try anonymous / anonymous")
            if tooling.resolve("hydra"):
                self.add("ftp", "brute (loud)",
                         f"hydra -L {self._wl('users','users.txt')} "
                         f"-P {self._wl('passwords','rockyou.txt')} "
                         f"ftp://{ip}:{port} -t 8 -f")
        if svc == "ssh" or port in (22, 2222):
            self.add("ssh", "brute (loud, last resort)",
                     f"hydra -L {self._wl('users','users.txt')} "
                     f"-P {self._wl('passwords','rockyou.txt')} "
                     f"ssh://{ip}:{port} -t 4 -f")
        if port in (139, 445) or "smb" in svc or "netbios" in svc:
            self._smb(port)
        if port in (389, 636, 3268) or "ldap" in svc:
            self._ldap(port)
        if port == 88 or "kerberos" in svc:
            self._kerberos()
        if port == 161 or "snmp" in svc:
            self._snmp()
        if port == 2049 or "nfs" in svc:
            self.add("nfs", "list exports",
                     f"showmount -e {ip}   # then mount -t nfs {ip}:/share /mnt")
        if port == 873 or "rsync" in svc:
            self.add("rsync", "list modules",
                     f"rsync -av --list-only rsync://{ip}/")
        if port == 3306 or svc == "mysql":
            self.add("mysql", "try default creds",
                     f"mysql -h {ip} -u root -p''   # then -u root -proot")
        if port == 5432 or svc == "postgresql":
            self.add("postgres", "try default creds",
                     f"psql -h {ip} -U postgres   # postgres/postgres")
        if port == 1433 or svc == "mssql":
            self.add("mssql", "connect / enum",
                     f"netexec mssql {ip} -u sa -p '' --local-auth")
        if port == 3389 or svc == "rdp":
            self.add("rdp", "check NLA / connect",
                     f"netexec rdp {ip} -u '' -p ''   # xfreerdp /v:{ip} /u:user")
        if port in (5900, 5901) or svc == "vnc":
            self.add("vnc", "connect (often no/weak auth)",
                     f"vncviewer {ip}::{port}")
        if port in (5985, 5986) or "winrm" in svc:
            self.add("winrm", "shell with creds",
                     f"evil-winrm -i {ip} -u USER -p PASS")

    def _web(self, port, secure):
        scheme = "https" if secure else "http"
        base = f"{scheme}://{self.vhost}:{port}"
        ip_base = f"{scheme}://{self.ip}:{port}"
        dirwl = self._wl("dir", "/usr/share/wordlists/dirb/common.txt")

        if tooling.resolve("feroxbuster"):
            self.add("web", "recursive content discovery",
                     f"feroxbuster -u {base} -w {dirwl} -k -t 50")
        elif tooling.resolve("ffuf"):
            self.add("web", "content discovery (filter soft-404 by size!)",
                     f"ffuf -u {base}/FUZZ -w {dirwl} -ac -c")
        else:
            self.add("web", "content discovery",
                     f"gobuster dir -u {base} -w {dirwl} -k")

        if tooling.resolve("whatweb"):
            self.add("web", "tech fingerprint", f"whatweb -a3 {base}")
        if tooling.resolve("nikto"):
            self.add("web", "server vuln scan", f"nikto -h {base}")
        if self.domain:
            vwl = self._wl("vhost", "/usr/share/seclists/Discovery/DNS/"
                                    "subdomains-top1million-5000.txt")
            reg = ".".join(self.domain.split(".")[-2:])
            if tooling.resolve("ffuf"):
                self.add("web", "vhost fuzz (set -fs to the default page size)",
                         f"ffuf -u {ip_base} -H 'Host: FUZZ.{reg}' -w {vwl} -c")
            elif tooling.resolve("gobuster"):
                self.add("web", "vhost brute",
                         f"gobuster vhost -u {ip_base} --domain {reg} -w {vwl} -k")
        if tooling.resolve("paramvoid"):
            pwl = tooling.find_wordlist("params")
            wflag = f" -w {pwl}" if pwl else ""
            self.add("web", "parameter discovery (paramvoid)",
                     f"paramvoid -u {base}/{wflag} -oT paramvoid.txt")

    def _smb(self, port):
        ip = self.ip
        if tooling.resolve("enum4linux-ng"):
            self.add("smb", "full AD/SMB enum", f"enum4linux-ng -A {ip}")
        elif tooling.resolve("enum4linux"):
            self.add("smb", "full SMB enum", f"enum4linux -a {ip}")
        if tooling.resolve("netexec"):
            self.add("smb", "shares (null session)",
                     f"netexec smb {ip} -u '' -p '' --shares")
            self.add("smb", "RID cycling for users",
                     f"netexec smb {ip} -u '' -p '' --rid-brute 5000")
        self.add("smb", "list shares", f"smbclient -N -L //{ip}/")

    def _ldap(self, port):
        ip = self.ip
        base = ""
        if self.realm:
            base = " -b '" + ",".join(f"DC={p}" for p in self.realm.split(".")) + "'"
        self.add("ldap", "anonymous dump",
                 f"ldapsearch -x -H ldap://{ip}{base} '(objectClass=*)'")
        if tooling.resolve("netexec"):
            self.add("ldap", "users via LDAP",
                     f"netexec ldap {ip} -u '' -p '' --users")

    def _kerberos(self):
        ip = self.ip
        dom = self.realm or "DOMAIN.LOCAL"
        if tooling.resolve("kerbrute"):
            uwl = self._wl("users", "/usr/share/seclists/Usernames/"
                                    "top-usernames-shortlist.txt")
            self.add("kerberos", "user enumeration",
                     f"kerbrute userenum -d {dom} --dc {ip} {uwl}")
        self.add("kerberos", "AS-REP roast (no creds needed)",
                 f"impacket-GetNPUsers {dom}/ -dc-ip {ip} -usersfile users.txt "
                 f"-no-pass -format hashcat")

    def _snmp(self):
        ip = self.ip
        if tooling.resolve("snmpwalk"):
            self.add("snmp", "walk (public)",
                     f"snmpwalk -v2c -c public {ip} .1")
            self.add("snmp", "processes / software / ports",
                     f"snmpwalk -v2c -c public {ip} 1.3.6.1.2.1.25.4.2.1.2")
        if tooling.resolve("onesixtyone"):
            self.add("snmp", "community brute",
                     f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/"
                     f"snmp.txt {ip}")

    def _from_findings(self):
        # searchsploit leads for every identified app+version.
        if not tooling.resolve("searchsploit"):
            return
        seen = set()
        for f in self.host.findings:
            if "identified" in f.title and f.evidence:
                term = f.evidence.strip()
                if term and term not in seen:
                    seen.add(term)
                    self.add("exploit", f"search Exploit-DB for {term}",
                             f"searchsploit {term}")

    # -- output -------------------------------------------------------------
    def render_console(self):
        if not self.items:
            return
        utils.section("Next steps  (copy-paste)")
        last = None
        for group, note, cmd in self.items:
            if group != last:
                print(f"\n  {utils.c('# ' + group.upper(), utils.C.MAGENTA, utils.C.BOLD)}")
                last = group
            print(f"  {utils.c(cmd, utils.C.CYAN)}")
            if note:
                print(f"      {utils.c(note, utils.C.GREY)}")

    def write_script(self, path: str):
        lines = ["#!/usr/bin/env bash",
                 f"# scryer next-step playbook for {self.host.target} ({self.ip})",
                 f"# generated {utils.now_iso()}",
                 "set -u", ""]
        last = None
        for group, note, cmd in self.items:
            if group != last:
                lines.append(f"\n### {group.upper()}")
                last = group
            if note:
                lines.append(f"# {note}")
            lines.append(cmd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
