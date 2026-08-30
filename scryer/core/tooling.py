"""External-tool registry and orchestration.

scryer is a *full orchestrator*: for every job it prefers the best real tool
on the box (nmap, ffuf, feroxbuster, enum4linux-ng, snmpwalk, …) and falls
back to a pure-python implementation only when that tool is absent — so it is
fast and deep on Kali but never dead on a bare shell.

`scryer --toolcheck` audits what is installed; `--toolcheck --install` installs
whatever is missing via the detected package manager. Nothing here is executed
unless the user asks for it.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import List, Optional

from . import utils


@dataclass
class ExtTool:
    name: str                       # primary binary expected on PATH
    purpose: str
    apt: Optional[str] = None       # apt package that provides it
    pipx: Optional[str] = None      # pipx / pip package
    go: Optional[str] = None        # `go install` path
    alts: List[str] = field(default_factory=list)  # equivalents that also count
    essential: bool = False         # part of the recommended minimum kit

    def resolve(self) -> Optional[str]:
        for cand in (self.name, *self.alts):
            # Absolute / ~-prefixed candidates: accept a direct executable file.
            if cand.startswith("/") or cand.startswith("~"):
                ep = os.path.expanduser(cand)
                if os.path.isfile(ep) and os.access(ep, os.X_OK):
                    return ep
                continue
            path = shutil.which(cand)
            if path:
                return path
        return None

    def available(self) -> bool:
        return self.resolve() is not None


# The kit. Ordered by category. `alts` lets one row cover interchangeable tools.
REGISTRY: List[ExtTool] = [
    # --- discovery / scanning ---
    ExtTool("nmap", "service/version/script scanning", apt="nmap", essential=True),
    ExtTool("rustscan", "very fast full-range TCP port sweep",
            apt="rustscan", alts=["masscan"]),
    ExtTool("masscan", "mass TCP port sweep", apt="masscan"),
    # --- web ---
    ExtTool("feroxbuster", "recursive content discovery",
            apt="feroxbuster", alts=["ffuf", "gobuster"], essential=True),
    ExtTool("ffuf", "web/vhost/param fuzzing", apt="ffuf", essential=True),
    ExtTool("gobuster", "dir/dns/vhost brute", apt="gobuster"),
    ExtTool("whatweb", "web tech fingerprinting", apt="whatweb", essential=True),
    ExtTool("nikto", "web server vuln scanning", apt="nikto"),
    ExtTool("wpscan", "WordPress scanning", apt="wpscan"),
    # paramvoid is the operator's own parameter-discovery tool (replaces arjun).
    ExtTool("paramvoid", "HTTP parameter discovery",
            go="github.com/CypherNova1337/paramvoid@latest",
            alts=["~/go/bin/paramvoid", "~/Tools/paramvoid/paramvoid",
                  "~/Tools/paramvoid/paramvoid.bin"],
            essential=True),
    ExtTool("katana", "fast web crawler", go="github.com/projectdiscovery/katana/cmd/katana@latest"),
    # --- SMB / AD / Windows ---
    ExtTool("enum4linux-ng", "SMB/LDAP AD enumeration",
            apt="enum4linux-ng", alts=["enum4linux"], essential=True),
    ExtTool("netexec", "SMB/LDAP/WinRM swiss-army",
            pipx="netexec", alts=["nxc", "crackmapexec", "cme"], essential=True),
    ExtTool("smbclient", "SMB share access", apt="smbclient", essential=True),
    ExtTool("rpcclient", "MSRPC enumeration", apt="samba-common-bin"),
    ExtTool("nbtscan", "NetBIOS name scanning", apt="nbtscan"),
    ExtTool("kerbrute", "Kerberos user enum / spray",
            go="github.com/ropnop/kerbrute@latest"),
    ExtTool("GetNPUsers.py", "AS-REP roasting",
            pipx="impacket", alts=["impacket-GetNPUsers", "GetNPUsers"]),
    ExtTool("GetUserSPNs.py", "Kerberoasting (Impacket)",
            pipx="impacket", alts=["impacket-GetUserSPNs", "GetUserSPNs"]),
    ExtTool("bloodhound-python", "BloodHound AD collector",
            pipx="bloodhound", alts=["bloodhound.py"]),
    ExtTool("ldapsearch", "LDAP queries", apt="ldap-utils", essential=True),
    ExtTool("evil-winrm", "WinRM shell", apt="evil-winrm"),
    # --- other services ---
    ExtTool("snmpwalk", "SNMP enumeration", apt="snmp", essential=True),
    ExtTool("onesixtyone", "SNMP community brute", apt="onesixtyone"),
    ExtTool("showmount", "NFS export listing", apt="nfs-common"),
    ExtTool("rsync", "rsync module listing", apt="rsync"),
    ExtTool("hydra", "credential brute forcing", apt="hydra"),
    ExtTool("john", "offline password cracking (John the Ripper)",
            apt="john", alts=["/usr/sbin/john"]),
    ExtTool("zip2john", "zip -> john hash converter", apt="john",
            alts=["/usr/sbin/zip2john"]),
    ExtTool("sqlmap", "automated SQL injection", apt="sqlmap"),
    ExtTool("netexec", "AD/SMB swiss-army (CME successor)", apt="netexec",
            alts=["nxc", "crackmapexec"]),
    ExtTool("impacket-mssqlclient", "MSSQL client (Impacket)",
            apt="python3-impacket", alts=["mssqlclient.py"]),
    ExtTool("impacket-psexec", "SMB psexec shell (Impacket)",
            apt="python3-impacket", alts=["psexec.py"]),
    ExtTool("impacket-secretsdump", "remote hash dump (Impacket)",
            apt="python3-impacket", alts=["secretsdump.py"]),
    ExtTool("evil-winrm", "WinRM shell", apt="evil-winrm"),
    ExtTool("binwalk", "firmware / embedded-file carver", apt="binwalk"),
    ExtTool("exiftool", "media metadata reader", apt="libimage-exiftool-perl",
            alts=["exiftool"]),
    ExtTool("pdftotext", "PDF text extraction (onboarding docs)",
            apt="poppler-utils"),
    ExtTool("redis-cli", "Redis client", apt="redis-tools"),
    ExtTool("mysql", "MySQL client", apt="default-mysql-client", alts=["mariadb"]),
    ExtTool("psql", "PostgreSQL client", apt="postgresql-client"),
    ExtTool("dig", "DNS queries", apt="dnsutils", alts=["host", "nslookup"]),
    ExtTool("aws", "AWS CLI (S3-compatible bucket exploitation)",
            apt="awscli", alts=["aws"]),
    ExtTool("java", "JRE (runs the rogue-jndi Log4Shell gadget server)",
            apt="default-jre", alts=["java"]),
    ExtTool("mvn", "Maven (auto-builds the rogue-jndi Log4Shell gadget)",
            apt="maven"),
    ExtTool("git", "clone exploit tooling (rogue-jndi, etc.)", apt="git"),
    ExtTool("sshpass", "non-interactive SSH password auth", apt="sshpass"),
    ExtTool("msfconsole", "Metasploit Framework (CVE auto-exploitation)",
            apt="metasploit-framework", alts=["msfconsole"]),
    ExtTool("php", "PHP CLI (runs PHP-based exploit PoCs)", apt="php-cli",
            alts=["php"]),
    # --- exploit intel / wordlists ---
    ExtTool("searchsploit", "offline Exploit-DB search",
            apt="exploitdb", essential=True),
    ExtTool("seclists", "wordlist collection (SecLists)", apt="seclists",
            alts=["/usr/share/seclists"], essential=True),
]


def resolve(name: str) -> Optional[str]:
    """Return the path to a tool (respecting alternatives), or None."""
    for t in REGISTRY:
        if t.name == name or name in t.alts:
            return t.resolve()
    return shutil.which(name)


def crack_wordlist() -> Optional[str]:
    """Locate rockyou.txt — the standard deep cracking list — decompressing a
    packaged rockyou.txt.gz once if that's all that's present. Cracking a zip or
    a hash needs depth (the small spray list won't cut it: HTB 'Vaccine's
    backup.zip password 741852963 is in rockyou but not in any top-1000 list)."""
    direct = [
        os.path.expanduser("~/Documents/Wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt"),
        os.path.expanduser("~/Documents/Wordlists/rockyou.txt"),
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt",
        os.path.expanduser("~/SecLists/Passwords/Leaked-Databases/rockyou.txt"),
        os.path.expanduser("~/rockyou.txt"),
    ]
    env = os.environ.get("SCRYER_ROCKYOU")
    if env:
        direct.insert(0, os.path.expanduser(env))
    for p in direct:
        if os.path.isfile(p) and os.path.getsize(p) > 1_000_000:
            return p
    # Fall back to a gzipped rockyou (Kali default) — decompress once to cache.
    import gzip
    for gz in ("/usr/share/wordlists/rockyou.txt.gz",
               os.path.expanduser("~/Documents/Wordlists/rockyou.txt.gz")):
        if os.path.isfile(gz):
            cache = os.path.join(os.path.expanduser("~/.cache/scryer"), "rockyou.txt")
            try:
                if not (os.path.isfile(cache) and os.path.getsize(cache) > 1_000_000):
                    os.makedirs(os.path.dirname(cache), exist_ok=True)
                    with gzip.open(gz, "rb") as src, open(cache, "wb") as dst:
                        dst.write(src.read())
                return cache
            except OSError:
                continue
    return None


def find_wordlist(kind: str) -> Optional[str]:
    """Locate a sensible SecLists wordlist for *kind* if SecLists is present.

    kind: 'dir' | 'vhost' | 'dns' | 'passwords' | 'users' | 'crack'
    """
    if kind == "crack":
        return crack_wordlist() or find_wordlist("passwords")
    # Operator's SecLists location first, then env override, then the usual
    # Kali/packaged paths.
    roots = [
        os.path.expanduser("~/Documents/Wordlists/SecLists"),
        os.environ.get("SCRYER_SECLISTS", ""),
        "/usr/share/seclists",
        "/usr/share/wordlists/seclists",
        os.path.expanduser("~/Documents/Wordlists/seclists"),
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/wordlists/SecLists"),
    ]
    roots = [os.path.expanduser(r) for r in roots if r]
    candidates = {
        "dir": ["Discovery/Web-Content/raft-medium-directories.txt",
                "Discovery/Web-Content/directory-list-2.3-medium.txt",
                "Discovery/Web-Content/common.txt"],
        "vhost": ["Discovery/DNS/subdomains-top1million-5000.txt",
                  "Discovery/DNS/subdomains-top1million-20000.txt",
                  "Discovery/DNS/namelist.txt"],
        "dns": ["Discovery/DNS/subdomains-top1million-5000.txt",
                "Discovery/DNS/namelist.txt"],
        "params": ["Discovery/Web-Content/burp-parameter-names.txt",
                   "Discovery/Web-Content/api/objects.txt"],
        "passwords": ["Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
                      "Passwords/Common-Credentials/best110.txt",
                      "rockyou.txt"],
        "users": ["Usernames/top-usernames-shortlist.txt",
                  "Usernames/Names/names.txt"],
    }.get(kind, [])
    # A common non-SecLists fallback for dir brute:
    if kind == "dir":
        candidates.append("../dirb/common.txt")
    for root in roots:
        for rel in candidates:
            path = os.path.normpath(os.path.join(root, rel))
            if os.path.isfile(path):
                return path
    # Kali ships these independently of SecLists — but only as the right KIND:
    # dirb/common.txt is a DIRECTORY list (never a password list), rockyou is
    # passwords. Mismatching them (common.txt as -P) produces broken commands.
    if kind == "dir" and os.path.isfile("/usr/share/wordlists/dirb/common.txt"):
        return "/usr/share/wordlists/dirb/common.txt"
    if kind == "passwords" and os.path.isfile("/usr/share/wordlists/rockyou.txt"):
        return "/usr/share/wordlists/rockyou.txt"
    # Last resort: scryer's own bundled lists (always present in the repo).
    return bundled_wordlist(kind)


def bundled_shell(name: str) -> Optional[str]:
    """Path to a bundled webshell in the repo's shells/ dir (terminal.php,
    cmd.php, ...). Works for a repo checkout / editable install; returns None if
    not found (e.g. a packaged install without the shells/ tree)."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    roots = [os.environ.get("SCRYER_SHELLS", ""),
             os.path.join(repo_root, "shells")]
    for r in roots:
        if r:
            p = os.path.join(os.path.expanduser(r), name)
            if os.path.isfile(p):
                return p
    return None


def bundled_wordlist(kind: str) -> Optional[str]:
    """Path to a wordlist shipped inside the scryer package.

    kind: 'users' | 'passwords'. These always exist so brute-force command
    suggestions have something to point at even without SecLists installed.
    """
    fname = {"users": "users.txt", "passwords": "passwords.txt"}.get(kind)
    if not fname:
        return None
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "data", "wordlists", fname)
    return path if os.path.isfile(path) else None


# ---------------------------------------------------------------------------
# System check + install
# ---------------------------------------------------------------------------
def _pkg_manager() -> Optional[str]:
    for mgr in ("apt-get", "apt", "dnf", "yum", "pacman", "brew"):
        if shutil.which(mgr):
            return mgr
    return None


def system_check() -> None:
    """Print an inventory of external tools grouped by present/missing."""
    print(utils.banner())
    present, missing = [], []
    for t in REGISTRY:
        (present if t.available() else missing).append(t)

    utils.section("Tool inventory")
    print(f"  {utils.c(str(len(present)) + ' present', utils.C.GREEN)}, "
          f"{utils.c(str(len(missing)) + ' missing', utils.C.YELLOW)} "
          f"of {len(REGISTRY)} known tools\n")

    for t in REGISTRY:
        ok = t.available()
        mark = utils.c("  ok ", utils.C.GREEN) if ok else utils.c("MISS", utils.C.YELLOW)
        star = utils.c("*", utils.C.CYAN, utils.C.BOLD) if t.essential else " "
        loc = t.resolve() if ok else (f"apt:{t.apt}" if t.apt else
                                      f"pipx:{t.pipx}" if t.pipx else
                                      f"go:{t.go}" if t.go else "manual")
        print(f"  [{mark}]{star} {t.name:<16} {utils.c(t.purpose, utils.C.GREY)}")
        if not ok:
            print(f"          {utils.c('install: ' + str(loc), utils.C.GREY)}")

    ess_missing = [t for t in missing if t.essential]
    if missing:
        print(f"\n  {utils.c('*', utils.C.CYAN)} = recommended minimum kit "
              f"({len(ess_missing)} of those missing)")
        print(f"  Run {utils.c('scryer --toolcheck --install', utils.C.BOLD)} "
              f"to install the missing tools.")
    else:
        utils.log("good", "full kit present — you are ready.")


def install_missing(assume_yes: bool = False) -> None:
    """Install missing tools via the detected package manager / pipx / go."""
    missing = [t for t in REGISTRY if not t.available()]
    if not missing:
        utils.log("good", "nothing to install — full kit present.")
        return

    mgr = _pkg_manager()
    apt_pkgs = sorted({t.apt for t in missing if t.apt})
    pipx_pkgs = sorted({t.pipx for t in missing if t.pipx and not t.apt})
    go_pkgs = sorted({t.go for t in missing if t.go and not t.apt and not t.pipx})

    sudo = [] if os.geteuid() == 0 else (["sudo"] if shutil.which("sudo") else [])
    plan = []
    if apt_pkgs and mgr:
        if mgr in ("apt-get", "apt"):
            plan.append(sudo + [mgr, "install", "-y", *apt_pkgs])
        elif mgr in ("dnf", "yum"):
            plan.append(sudo + [mgr, "install", "-y", *apt_pkgs])
        elif mgr == "pacman":
            plan.append(sudo + [mgr, "-S", "--noconfirm", *apt_pkgs])
        elif mgr == "brew":
            plan.append([mgr, "install", *apt_pkgs])
    if pipx_pkgs:
        installer = "pipx" if shutil.which("pipx") else "pip"
        for p in pipx_pkgs:
            plan.append([installer, "install", p])
    if go_pkgs and shutil.which("go"):
        for p in go_pkgs:
            plan.append(["go", "install", p])

    if not plan:
        utils.log("warn", "no supported package manager found to install with.")
        return

    utils.section("Install plan")
    for cmd in plan:
        print("  " + utils.c(" ".join(cmd), utils.C.CYAN))
    unhandled = [t.name for t in missing
                 if not t.apt and not t.pipx and not t.go]
    if unhandled:
        utils.log("warn", f"install manually: {', '.join(unhandled)}")

    if not assume_yes:
        try:
            ans = input(f"\n  {utils.c('Proceed with install? [y/N] ', utils.C.BOLD)}")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            utils.log("info", "aborted — nothing installed.")
            return

    for cmd in plan:
        utils.log("info", f"running: {' '.join(cmd)}")
        rc, out, err = utils.run(cmd, timeout=1800)
        if rc == 0:
            utils.log("good", f"ok: {cmd[0]} {cmd[1] if len(cmd) > 1 else ''}")
        else:
            utils.log("bad", f"failed ({rc}): {(err or out).strip()[:200]}")
    utils.log("info", "re-run `scryer --toolcheck` to confirm.")
