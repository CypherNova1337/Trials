"""PCAP analysis for forensics challenges (needs tshark).

Pulls the high-signal stuff out of a capture: HTTP requests + transferred files,
cleartext credentials (HTTP Basic, FTP, Telnet), DNS queries (exfil/tunnels),
and any flag sitting in a payload. Exported HTTP objects are dropped in a loot
dir and run through the file forensic pass.
"""

from __future__ import annotations

import os
import tempfile
from typing import Set

from ..core import utils, tooling
from ..data import knowledge


def analyze(path: str, flags: Set[str]) -> None:
    tshark = tooling.resolve("tshark")
    if not tshark:
        utils.log("dim", "tshark not installed — `apt install tshark` for pcap "
                         "analysis (or use the tshark one-liners in "
                         "notes/ctf-oneliners.md)", indent=1)
        return
    utils.section(f"PCAP {os.path.basename(path)}")

    # 1) Aggregate readable text from common protocols, hunt flags in it.
    rc, out, _ = utils.run(
        [tshark, "-r", path, "-Y",
         "http || ftp || telnet || dns || data-text-lines || tftp",
         "-T", "fields",
         "-e", "http.request.full_uri", "-e", "http.file_data",
         "-e", "ftp.request.arg", "-e", "ftp.response.arg",
         "-e", "telnet.data", "-e", "dns.qry.name",
         "-e", "data-text-lines", "-e", "http.authorization"],
        timeout=180)
    blob = out or ""
    for tok in knowledge.find_flags(blob):
        flags.add(tok)
        utils.log("hot", f"flag in packet payload: {tok}", indent=2)

    # 2) Cleartext credentials.
    rc, creds, _ = utils.run(
        [tshark, "-r", path, "-Y",
         'http.authorization || ftp.request.command=="USER" || '
         'ftp.request.command=="PASS" || telnet',
         "-T", "fields", "-e", "http.authorization", "-e", "ftp.request.arg"],
        timeout=90)
    seen = set()
    for line in (creds or "").splitlines():
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        detail = line
        if line.lower().startswith("basic "):
            import base64
            try:
                detail = "HTTP Basic: " + base64.b64decode(line.split()[1]).decode("latin-1")
            except Exception:
                pass
        utils.log("good", f"credential in traffic: {detail[:80]}", indent=2)

    # 3) DNS queries (long random labels = exfil / DNS tunnel).
    rc, dns, _ = utils.run([tshark, "-r", path, "-Y",
                            "dns.flags.response==0", "-T", "fields",
                            "-e", "dns.qry.name"], timeout=60)
    names = sorted({n.strip() for n in (dns or "").splitlines() if n.strip()})
    if names:
        utils.log("good", f"{len(names)} DNS queries "
                          f"(e.g. {', '.join(names[:5])})", indent=2)
        # A flag is sometimes chunked across subdomain labels.
        joined = "".join(n.split(".")[0] for n in names)
        for tok in knowledge.find_flags(joined):
            flags.add(tok)

    # 4) Export HTTP objects and forensically scan them.
    outdir = os.path.join(tempfile.mkdtemp(prefix="scryer_pcap_"), "objects")
    os.makedirs(outdir, exist_ok=True)
    utils.run([tshark, "-r", path, "--export-objects", f"http,{outdir}"],
              timeout=120)
    files = [os.path.join(outdir, f) for f in os.listdir(outdir)] \
        if os.path.isdir(outdir) else []
    if files:
        utils.log("good", f"exported {len(files)} HTTP object(s) -> {outdir}",
                  indent=2)
        from . import crack
        # a lightweight report shim so crack can record findings
        for fp in files:
            for tok in _scan_file_flags(fp):
                flags.add(tok)
        _ = crack   # (crack.scan_file needs a HostReport; we flag-scan directly)


def _scan_file_flags(path: str) -> Set[str]:
    out: Set[str] = set()
    try:
        with open(path, "rb") as fh:
            raw = fh.read(4_000_000)
    except OSError:
        return out
    from . import crypto
    text = raw.decode("latin-1", "replace")
    for tok in knowledge.find_flags(text):
        out.add(tok)
    for _chain, tok in crypto.hunt(raw, max_depth=3):
        out.add(tok)
    return out
