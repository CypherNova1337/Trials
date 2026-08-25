"""Virtual-host / subdomain brute forcing.

On CTF and red-team web targets the real entry point is often a name-based
virtual host that the server's default block hides (e.g. `git.nexus.htb`,
`panel.pterodactyl.htb`). This module fuzzes the HTTP `Host:` header against a
wordlist and reports only names whose response differs from the target's
default response — the same size/hash filtering you'd do by hand with ffuf's
`-fs`, done automatically.

The hard part is the *catch-all*: many servers answer HTTP 200 (or an
identical page) for **every** unknown Host header. A naive size/status filter
then flags the whole wordlist. To avoid that this module builds its baseline
from several random probes, compares each candidate against the baseline by
content similarity (not just status+length), and — as a backstop — bails out
entirely when more than a sane number of "distinct" hosts appear, since that
only happens when the baseline itself is a blanket catch-all.
"""

from __future__ import annotations

import concurrent.futures
import difflib
import re
import socket
import ssl
from typing import List, Optional, Tuple

from ...core import utils, tooling
from ...core.report import HostReport, Finding
from ...data import knowledge


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# If more than this many *distinct* vhosts survive filtering, the target is
# almost certainly a catch-all whose baseline we failed to model — real boxes
# rarely expose this many name-based vhosts. Discard and warn instead of
# flooding /etc/hosts and the enrichment phase with garbage.
_MAX_VHOSTS = 25
# Bodies are normalised + capped before similarity comparison (keeps difflib
# fast across a 12k wordlist and ignores volatile per-request tokens).
_BODY_CAP = 3000
_SIMILAR = 0.90


class _Resp:
    __slots__ = ("status", "length", "title", "norm")

    def __init__(self, status: int, length: int, title: str, norm: str):
        self.status = status
        self.length = length
        self.title = title
        self.norm = norm


_VOLATILE_RE = re.compile(r"[0-9a-f]{8,}|\d+", re.IGNORECASE)


def _normalize(body: str, host_header: str) -> str:
    """Strip the echoed Host header and volatile tokens (ids, dates, csrf,
    lengths) so two renderings of the same default page compare as equal."""
    b = body[:_BODY_CAP].lower()
    if host_header:
        b = b.replace(host_header.lower(), "")
    b = _VOLATILE_RE.sub("", b)
    return re.sub(r"\s+", " ", b).strip()


def _request(ip: str, port: int, secure: bool, host_header: str,
             timeout: float = 6.0) -> Optional[_Resp]:
    """Raw HTTP/1.1 GET with an arbitrary Host header.

    Returns a _Resp (status, body length, title, normalised body) or None. We
    speak HTTP directly so we fully control the Host header and avoid any
    client-side normalization.
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
    return _Resp(status, len(body), title, _normalize(body, host_header))


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

    words = wordlist or _load_words()
    for base in domains:
        _brute_domain(host, ip, port, secure, base, words, workers)


def _load_words(cap: int = 12000) -> List[str]:
    """Prefer a SecLists vhost/subdomain wordlist; fall back to the built-in
    curated list when SecLists isn't installed. Capped so a run stays sane."""
    path = tooling.find_wordlist("vhost")
    if not path:
        return knowledge.COMMON_VHOSTS
    words: List[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w)
                if len(words) >= cap:
                    break
    except OSError:
        return knowledge.COMMON_VHOSTS
    # Front-load the high-signal curated names, then the wordlist (deduped).
    seen = set(knowledge.COMMON_VHOSTS)
    merged = list(knowledge.COMMON_VHOSTS)
    merged += [w for w in words if w not in seen]
    utils.log("info", f"vhost wordlist: {len(merged)} names "
                      f"(SecLists: {path.split('/')[-1]})", indent=1)
    return merged


def _build_baseline(ip: str, port: int, secure: bool, base: str) -> List[_Resp]:
    """Probe several guaranteed-nonexistent hosts to model the server's
    default/catch-all response. Returns the distinct baseline responses (there
    can be more than one — some servers alternate)."""
    probes = []
    for _ in range(4):
        r = _request(ip, port, secure, f"nonexistent-{_rand()}.{base}")
        if r is not None:
            probes.append(r)
    return probes


def _matches_baseline(resp: _Resp, baseline: List[_Resp]) -> bool:
    """True if resp looks like the server's default/catch-all answer."""
    for b in baseline:
        if resp.status != b.status:
            continue
        # Same status. If either body is empty/near-empty, status match is
        # enough (a bare 200/403/404 with no content is the default block).
        if not resp.norm and not b.norm:
            return True
        if not resp.norm or not b.norm:
            # One empty, one not: only a match if both are tiny.
            if resp.length < 64 and b.length < 64:
                return True
            continue
        sm = difflib.SequenceMatcher(None, resp.norm, b.norm)
        # quick_ratio is a cheap upper bound; only pay for the real ratio when
        # it's plausibly a match.
        if sm.quick_ratio() >= _SIMILAR and sm.ratio() >= _SIMILAR:
            return True
    return False


def _brute_domain(host: HostReport, ip: str, port: int, secure: bool,
                  base: str, words: List[str], workers: int) -> None:
    utils.section(f"VHOST fuzz {base} on {ip}:{port}")

    baseline = _build_baseline(ip, port, secure, base)
    if not baseline:
        utils.log("warn", "no baseline response — server not answering the "
                          "bare IP; vhost filtering disabled", indent=1)
    else:
        statuses = sorted({b.status for b in baseline})
        lens = sorted({b.length for b in baseline})
        utils.log("dim",
                  f"default vhost baseline: HTTP {statuses}, "
                  f"{lens[0]}-{lens[-1]}B", indent=1)
        if any(b.status == 200 for b in baseline):
            host.add(Finding(
                title=f"Default virtual-host catch-all on :{port}",
                detail="Unknown Host headers fall back to a default server "
                       "block that answers 200. Real vhosts are matched by "
                       "content difference from this default, not by status.",
                severity="info", category="web", port=port, service="http",
            ))

    def probe(word: str):
        fqdn = f"{word}.{base}"
        resp = _request(ip, port, secure, fqdn)
        if resp is None:
            return None
        if resp.status in (400, 0):
            return None
        if baseline and _matches_baseline(resp, baseline):
            return None
        return fqdn, resp

    candidates: List[Tuple[str, _Resp]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(probe, words):
            if result:
                candidates.append(result)

    # Backstop: a flood of "distinct" hosts means the baseline didn't capture
    # the server's catch-all behaviour. Report nothing rather than poison
    # /etc/hosts and the enrichment phase with the entire wordlist.
    if len(candidates) > _MAX_VHOSTS:
        utils.log("warn",
                  f"{len(candidates)} Host headers answered differently from "
                  f"baseline — this is a catch-all, not {len(candidates)} real "
                  f"vhosts. Suppressing (filter unreliable on this target).",
                  indent=1)
        host.add(Finding(
            title=f"Virtual-host brute inconclusive on :{port} (catch-all)",
            detail=f"{len(candidates)} names differed from the default "
                   "response, which indicates a wildcard/catch-all vhost "
                   "rather than that many real hosts. Re-run with an explicit "
                   "-D <domain> and a curated list, or verify names manually "
                   "(ffuf -fs) before trusting them.",
            severity="info", category="web", port=port, service="http",
            confidence="potential",
        ))
        return

    if not candidates:
        utils.log("dim", "no distinct virtual hosts found", indent=1)
        return

    for fqdn, resp in candidates:
        new = host.add_hostname(fqdn)
        extra = f' "{resp.title}"' if resp.title else ""
        utils.log("hot" if new else "good",
                  f"vhost {fqdn}  ->  HTTP {resp.status}, ~{resp.length}B{extra}",
                  indent=1)
        host.add(Finding(
            title=f"Virtual host discovered: {fqdn}",
            detail=f"HTTP {resp.status}, distinct from default response"
                   + (f', title: {resp.title}' if resp.title else ""),
            severity="medium", category="web", port=port, service="http",
            evidence=fqdn,
        ))


def _rand() -> str:
    import uuid
    return uuid.uuid4().hex[:10]
