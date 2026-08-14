"""Virtual-host / subdomain brute forcing.

On CTF and red-team web targets the real entry point is often a name-based
virtual host that the server's default block hides (e.g. `git.nexus.htb`,
`panel.pterodactyl.htb`). This module fuzzes the HTTP `Host:` header against a
wordlist and reports only names whose response differs from the target's
default response — the same size/hash filtering you'd do by hand with ffuf's
`-fs`, done automatically.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import re
import socket
import ssl
from typing import List, Optional, Tuple

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _request(ip: str, port: int, secure: bool, host_header: str,
             timeout: float = 6.0) -> Optional[Tuple[int, int, str]]:
    """Raw HTTP/1.0 GET with an arbitrary Host header.

    Returns (status, body_length, title) or None. We speak HTTP directly so we
    fully control the Host header and avoid any client-side normalization.
    """
    req = (f"GET / HTTP/1.1\r\nHost: {host_header}\r\n"
           f"User-Agent: scryer\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        raw.settimeout(timeout)
        sock = raw
        if secure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host_header)
        sock.sendall(req.encode("latin-1", "replace"))
        chunks = []
        total = 0
        while total < 65536:
            try:
                buf = sock.recv(8192)
            except (socket.timeout, ssl.SSLError):
                break
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    data = b"".join(chunks).decode("latin-1", "replace")
    head, _, body = data.partition("\r\n\r\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head)
    status = int(m.group(1)) if m else 0
    title = ""
    tm = _TITLE_RE.search(body)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:80]
    return status, len(body), title


def _signature(resp: Optional[Tuple[int, int, str]]) -> Optional[Tuple[int, int, str]]:
    if resp is None:
        return None
    status, length, title = resp
    # Bucket body length so trivial dynamic differences don't defeat the filter.
    return status, length // 64, title


def _candidate_domains(host: HostReport, explicit: Optional[str]) -> List[str]:
    doms = []
    if explicit:
        doms.append(explicit.lstrip(".").lower())
    for name in host.hostnames:
        name = name.lower()
        # Use registrable-ish parent: last two labels (nexus.htb from a.nexus.htb).
        parts = name.split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[-2:])
            if parent not in doms:
                doms.append(parent)
    return doms


def brute(host: HostReport, port: int, secure: bool,
          domain: Optional[str] = None, workers: int = 40,
          wordlist: Optional[List[str]] = None) -> None:
    ip = host.resolved_ip
    domains = _candidate_domains(host, domain)
    if not domains:
        utils.log("dim", "vhost brute skipped: no base domain "
                         "(pass -D <domain>, e.g. -D nexus.htb)", indent=1)
        return

    words = wordlist or knowledge.COMMON_VHOSTS
    for base in domains:
        _brute_domain(host, ip, port, secure, base, words, workers)


def _brute_domain(host: HostReport, ip: str, port: int, secure: bool,
                  base: str, words: List[str], workers: int) -> None:
    utils.section(f"VHOST fuzz {base} on {ip}:{port}")

    # Baseline: how the server answers a Host it does not know. Use two random
    # names; if they differ from each other the target is too noisy to filter.
    b1 = _signature(_request(ip, port, secure, f"nonexistent-{_rand()}.{base}"))
    b2 = _signature(_request(ip, port, secure, f"nonexistent-{_rand()}.{base}"))
    baseline = b1
    if b1 and b2 and b1 != b2:
        utils.log("warn", "unstable default response — vhost filtering is "
                          "best-effort", indent=1)
        baseline = None
    elif b1:
        # Detect the classic Nginx/Apache default-server catch-all.
        utils.log("dim", f"default vhost baseline: HTTP {b1[0]}, ~{b1[1]*64}B", indent=1)
        host.add(Finding(
            title=f"Default virtual-host catch-all on :{port}",
            detail="Unknown Host headers fall back to a default server block. "
                   "Real vhosts must be found by name, not by port — brute the "
                   "Host header (this scan does).",
            severity="info", category="web", port=port, service="http",
        ))

    found: List[str] = []

    def probe(word: str):
        fqdn = f"{word}.{base}"
        sig = _signature(_request(ip, port, secure, fqdn))
        if sig is None:
            return None
        if baseline is not None and sig == baseline:
            return None
        if sig[0] in (400, 0):
            return None
        return fqdn, sig

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(probe, words):
            if not result:
                continue
            fqdn, sig = result
            found.append(fqdn)
            status, lbucket, title = sig
            new = host.add_hostname(fqdn)
            extra = f' "{title}"' if title else ""
            utils.log("hot" if new else "good",
                      f"vhost {fqdn}  ->  HTTP {status}, ~{lbucket*64}B{extra}",
                      indent=1)
            host.add(Finding(
                title=f"Virtual host discovered: {fqdn}",
                detail=f"HTTP {status}, distinct from default response"
                       + (f', title: {title}' if title else ""),
                severity="medium", category="web", port=port, service="http",
                evidence=fqdn,
            ))

    if not found:
        utils.log("dim", "no distinct virtual hosts found", indent=1)


def _rand() -> str:
    import uuid
    return uuid.uuid4().hex[:10]
