"""Autonomous execution loop — the agent that closes the observe/act cycle.

The rules brain and the local-LLM advisor recommend moves; this drives them.
Each turn it asks the local model for the SINGLE next command toward the flag,
validates that command against a strict safety allowlist, runs it, scans the
output for flags and credentials (feeding them back into the host state), and
loops — until a flag lands, the model says it's done, or the step budget runs
out.

Safety is the whole design here, because the command source is an LLM:

  * OFF by default; only runs with --agent, and only when a local model
    (Ollama) is reachable. No cloud, no API key.
  * Every command must start with an allowlisted offensive/recon tool and must
    not contain a destructive or system-mutating token (rm, dd, mkfs, shutdown,
    redirects into system paths, pipe-to-shell, sudo-to-arbitrary, …).
  * Interactive confirmation before each command by default; --agent-auto runs
    hands-off (still allowlisted). In a non-TTY session without --agent-auto it
    stays a dry run — it prints what it WOULD run and never executes.

Authorised targets only — this issues real attacks against the host.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from typing import List, Optional, Tuple

from ..core import utils
from ..core.report import HostReport, Finding
from ..data import knowledge
from . import aiadvisor

_MAX_STEPS = 6
_CMD_TIMEOUT = 180

# Leading binaries the agent may run. Offensive/recon tooling + a few read-only
# utilities. Deliberately excludes interpreters (python/bash/perl/…), which
# would be arbitrary code execution.
_ALLOWED = {
    "nmap", "rustscan", "masscan", "ffuf", "feroxbuster", "gobuster", "whatweb",
    "nikto", "wpscan", "curl", "netexec", "nxc", "crackmapexec", "cme",
    "smbclient", "smbmap", "rpcclient", "enum4linux", "enum4linux-ng",
    "ldapsearch", "kerbrute", "evil-winrm", "hydra", "john", "hashcat",
    "sqlmap", "ssh", "sshpass", "showmount", "mount", "snmpwalk", "onesixtyone",
    "dig", "host", "nslookup", "redis-cli", "mysql", "psql", "mongo", "aws",
    "smbget", "wget", "nbtscan", "crackmapexec", "getent", "finger",
    "cat", "grep", "head", "tail", "strings", "ls", "file", "xxd",
}
# Impacket + BloodHound wrappers are allowed by prefix.
_ALLOWED_PREFIX = ("impacket-", "getnpusers", "getuserspns", "secretsdump",
                   "psexec", "wmiexec", "smbexec", "dcomexec", "atexec",
                   "bloodhound", "certipy", "ntlmrelayx", "getst", "gettgt")
# Any of these anywhere in the command line is an instant reject.
_DENY = re.compile(
    r"(?i)(\brm\b|\bdd\b|mkfs|shred|wipefs|cryptsetup|fdisk|parted|"
    r"shutdown|reboot|halt|poweroff|init\s+0|\bkill(all)?\b|"
    r">\s*/(?:dev|etc|bin|boot|sys|proc|usr|lib|var)|"
    r"/dev/(?:sd|nvme|mapper|null\s*2>|zero)|"
    r"\|\s*(?:sh|bash|zsh|python|perl)|"
    r"(?:curl|wget)[^\n]*\|\s*\w|"
    r":\(\)\s*\{|fork|chmod\s+-R|chown\s+-R|chattr|"
    r"\bmv\s+/|\bcp\s+/dev|passwd\b|useradd|userdel|"
    r"iptables|ufw\b|systemctl|service\s+\w+\s+stop|"
    r"\beval\b|\bexec\b|base64\s+-d|history\s+-c)")
_INTERP = {"python", "python3", "perl", "ruby", "php", "bash", "sh", "zsh",
           "ksh", "node", "awk", "gawk", "lua", "tclsh", "expect"}


def run(host: HostReport, opts) -> None:
    if not getattr(opts, "agent", False):
        return
    if not aiadvisor.resolve(opts):
        utils.log("warn", "--agent needs a local LLM (Ollama) to drive the loop "
                          "— start it (`ollama serve`) or set $SCRYER_OLLAMA; "
                          "the ranked ATTACK PLAN above is the manual version")
        return

    auto = getattr(opts, "agent_auto", False)
    tty = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False
    dry = not auto and not tty          # no way to confirm -> dry run only
    steps = getattr(opts, "agent_steps", None) or _MAX_STEPS

    utils.section("AGENT LOOP")
    utils.log("warn", "autonomous exploitation loop — authorized targets only. "
                     + ("DRY RUN (no TTY to confirm; use --agent-auto to execute)"
                        if dry else ("hands-off (--agent-auto)" if auto
                                     else "you confirm each command")))

    history: List[Tuple[str, str]] = []
    for step in range(1, steps + 1):
        cmd = _next_command(host, history, opts)
        if cmd is None:
            utils.log("info", "agent: model reports nothing left to try — stopping")
            break
        utils.log("info", f"[step {step}/{steps}] proposed: "
                          + utils.c(cmd, utils.C.CYAN))
        ok, reason = _is_safe(cmd)
        if not ok:
            utils.log("bad", f"rejected (safety: {reason}) — skipping")
            history.append((cmd, f"[blocked by scryer: {reason}]"))
            continue
        if dry:
            history.append((cmd, "[dry run — not executed]"))
            continue
        if not auto and not _confirm(cmd):
            history.append((cmd, "[skipped by operator]"))
            continue

        out = _execute(cmd)
        got_flag = _observe(host, cmd, out)
        history.append((cmd, out[-2000:]))
        if got_flag:
            utils.log("hot", "agent: flag captured — stopping the loop")
            break
    else:
        utils.log("info", f"agent: reached the {steps}-step budget")


# --------------------------------------------------------------------------
def _next_command(host, history, opts) -> Optional[str]:
    prompt = _prompt(host, history)
    resp = aiadvisor.ask(opts, prompt)
    if not resp:
        return None
    if re.search(r"\bDONE\b", resp) and "CMD:" not in resp:
        return None
    return _extract_cmd(resp)


def _prompt(host, history) -> str:
    from ..core import brain
    ports = ", ".join(f"{p['port']}/{p.get('service') or '?'}"
                      for p in sorted(host.open_ports, key=lambda x: x["port"]))
    creds = ", ".join(host.creds[:8]) or "none yet"
    plan = "; ".join(m.title for m in brain.build(host)[:5])
    hist = ""
    for c, o in history[-4:]:
        hist += f"\n$ {c}\n{o[-500:].strip()}\n"
    return (
        "You are driving an autonomous penetration test of an AUTHORISED CTF/lab "
        "host. Respond with EXACTLY ONE next shell command to run, on a single "
        "line, prefixed with 'CMD: '. Use only offensive/recon tools (netexec, "
        "impacket-*, evil-winrm, smbclient, ldapsearch, curl, sqlmap, hashcat, "
        "ssh/sshpass, nmap, ffuf, showmount, etc.). No interpreters, no "
        "destructive commands. When you have a user or root flag, or nothing "
        "useful is left, respond with 'DONE'. Do not explain.\n\n"
        f"Target: {host.target} ({host.resolved_ip})  OS: {host.os_guess or '?'}\n"
        f"Open ports: {ports}\n"
        f"Recovered credentials: {creds}\n"
        f"Ranked plan: {plan}\n"
        + ("Commands run so far and their output:" + hist if hist
           else "No commands run yet.")
        + "\n\nCMD:")


def _extract_cmd(resp: str) -> Optional[str]:
    m = re.search(r"CMD:\s*(.+)", resp)
    if m:
        cand = m.group(1)
    else:
        # No CMD: marker — take the first real line, skipping ``` code fences
        # and blank lines the model may wrap the command in.
        cand = ""
        for line in resp.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("```"):     # skip blanks + code fences
                continue
            s = re.sub(r"^[\$#]\s*", "", raw.strip("`").strip())
            if s:
                cand = s
                break
    cand = cand.strip().strip("`").strip()
    cand = re.sub(r"^[\$#]\s*", "", cand)
    return cand or None


# --------------------------------------------------------------------------
def _is_safe(cmd: str) -> Tuple[bool, str]:
    cmd = cmd.strip()
    if not cmd or len(cmd) > 500:
        return False, "empty or over-long"
    if _DENY.search(cmd):
        return False, "destructive/forbidden token"
    if "\n" in cmd or "\r" in cmd:
        return False, "multi-line"
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return False, "unparseable quoting"
    if not parts:
        return False, "empty"
    # sudo <tool> — allow only if the wrapped tool is itself allowed
    idx = 0
    if parts[0] == "sudo":
        idx = 1
        if len(parts) < 2:
            return False, "bare sudo"
    lead = os.path.basename(parts[idx]).lower()
    if lead in _INTERP:
        return False, f"interpreter ({lead})"
    if lead in _ALLOWED or any(lead.startswith(p) for p in _ALLOWED_PREFIX):
        return True, "ok"
    return False, f"'{lead}' not in allowlist"


def _confirm(cmd: str) -> bool:
    try:
        ans = input(utils.c("    run this? [y/N/q] ", utils.C.YELLOW)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans == "q":
        raise KeyboardInterrupt
    return ans == "y"


def _execute(cmd: str) -> str:
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=_CMD_TIMEOUT, errors="replace")
        out = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return f"[timed out after {_CMD_TIMEOUT}s]"
    except OSError as exc:
        return f"[failed to run: {exc}]"
    # echo a trimmed tail so the operator sees what happened
    tail = out.strip().splitlines()[-12:]
    for line in tail:
        print("      " + utils.c(line[:200], utils.C.GREY))
    return out


def _observe(host: HostReport, cmd: str, out: str) -> bool:
    got = False
    for tok in knowledge.find_flags(out or "", allow_hex=True):
        got = True
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ FLAG (agent)", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title="FLAG via agent loop", detail=tok, severity="critical",
            category="flag", service="agent", evidence=f"{cmd}: {tok}"))
    # harvest any credentials the command surfaced
    for _u, pw in list(knowledge.find_conn_creds(out)) + \
            list(knowledge.find_windows_creds(out)):
        host.add_cred(pw)
    for _lbl, val, _sev in knowledge.extract_secrets(out):
        host.add_cred(val)
    return got
