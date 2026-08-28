"""Local artifact analysis for Jeopardy-style CTF challenges.

Some challenge cards hand you a file to download (.pcap, .zip, .raw, .png, a
disk image, a blob of ciphertext) instead of a live host. This module is the
offline entry point: classify the file, route it to the right analyzer, and
surface every flag it can find — no network recon involved.

    pcap / pcapng          -> pcap.analyze (HTTP/DNS/creds + exported objects)
    zip / tar / gz / kdbx  -> crack.handle_archive (crack + extract + scan)
    everything else        -> crack.scan_file (text creds/flags or the binary
                              forensic pass) + crypto.hunt (layered decode/XOR)

Flags are printed as they're found and collected into a final summary.
"""

from __future__ import annotations

import os
from typing import List, Set

from ..core import utils
from ..core.report import HostReport

_PCAP_EXTS = (".pcap", ".pcapng", ".cap")
_ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".kdbx", ".7z", ".rar")


def analyze(path: str) -> List[str]:
    """Analyze one local file end to end. Returns the distinct flags found."""
    if not os.path.isfile(path):
        utils.log("bad", f"no such file: {path}")
        return []

    utils.log("info", f"artifact: {utils.c(path, utils.C.CYAN, utils.C.BOLD)} "
                      f"({_human_size(path)})")

    host = HostReport(target=os.path.basename(path))
    flags: Set[str] = set()
    low = path.lower()

    if low.endswith(_PCAP_EXTS):
        from . import pcap
        pcap.analyze(path, flags)
    elif low.endswith(_ARCHIVE_EXTS):
        from . import crack
        crack.handle_archive(host, path)
    else:
        _analyze_generic(host, path, flags)

    # Fold in any flags crack recorded on the synthetic host report.
    for f in host.findings:
        if f.category == "flag" and f.detail:
            flags.add(f.detail)

    _summary(sorted(flags))
    return sorted(flags)


def _analyze_generic(host: HostReport, path: str, flags: Set[str]) -> None:
    """A single non-archive file: forensic/text scan + layered crypto decode."""
    from . import crack, crypto

    # crack.scan_file handles both text (creds/flags/hashes) and binary media
    # (strings, base64, appended-data stego, binwalk, exiftool).
    crack.scan_file(host, path)

    # Layered encoding / classical-crypto pass over the raw bytes. Great for the
    # ciphertext-in-a-txt-file cards; harmless on anything else.
    try:
        with open(path, "rb") as fh:
            raw = fh.read(8_000_000)
    except OSError:
        return
    for chain, tok in crypto.hunt(raw, max_depth=6):
        if tok not in flags:
            flags.add(tok)
            utils.log("hot", f"flag via {chain}: {tok}", indent=1)


def decode(data: str) -> List[str]:
    """Solve a ciphertext/encoded string passed on the command line."""
    from . import crypto
    utils.section("decode")
    return crypto.solve(data, label="input string")


def _summary(flags: List[str]) -> None:
    print()
    if flags:
        bar = utils.c("═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("  " + bar)
        print("  " + utils.c(f"⚑ {len(flags)} FLAG(S)", utils.C.GREEN, utils.C.BOLD))
        for tok in flags:
            print("  " + utils.c(f"  {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + bar)
    else:
        utils.log("dim", "no flag recovered automatically — try the manual "
                         "one-liners in notes/ctf-oneliners.md (strings, "
                         "binwalk, stegseek, zsteg, CyberChef Magic)")


def _human_size(path: str) -> str:
    try:
        n = os.path.getsize(path)
    except OSError:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"
