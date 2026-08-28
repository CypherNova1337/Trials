"""Encoding / classical-crypto solver for Jeopardy CTF challenges.

Given a string or blob, peel encoding layers (base64/32/16/85, hex, URL, gzip,
ROT-N, Atbash) and brute single-byte XOR, hunting for a flag at every layer.
Recursive, so nested encodings (base64(rot13(...))) unwrap automatically.

Pure standard library. Flag detection reuses knowledge.find_flags, so any
`name{...}` (securewv{}, flag{}, HTB{}, …) or 32-hex token is caught.
"""

from __future__ import annotations

import base64
import gzip
import re
import string
import urllib.parse
import zlib
from typing import List, Tuple

from ..data import knowledge

_PRINTABLE = set(bytes(string.printable, "ascii"))
_B64_ONLY = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
_B32_ONLY = re.compile(rb"^[A-Z2-7=\s]+$")
_HEX_ONLY = re.compile(rb"^[0-9a-fA-F\s]+$")


def _printable_ratio(b: bytes) -> float:
    return sum(1 for x in b if x in _PRINTABLE) / len(b) if b else 0.0


def _rot(text: str, n: int) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def _atbash(text: str) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr(219 - ord(c)))
        elif "A" <= c <= "Z":
            out.append(chr(155 - ord(c)))
        else:
            out.append(c)
    return "".join(out)


def _decoders(b: bytes):
    """Yield (name, decoded_bytes) for each transform that plausibly applies."""
    s = b.strip()
    # base64 / base32 / base16 — only when the alphabet fits (avoids garbage).
    if _B64_ONLY.match(s) and len(s) >= 8:
        try:
            yield "base64", base64.b64decode(s + b"=" * (-len(s) % 4), validate=False)
        except Exception:
            pass
    if _B32_ONLY.match(s) and len(s) >= 8:
        try:
            yield "base32", base64.b32decode(s + b"=" * (-len(s) % 8))
        except Exception:
            pass
    if _HEX_ONLY.match(s):
        h = re.sub(rb"\s", b"", s)
        if len(h) >= 8 and len(h) % 2 == 0:
            try:
                yield "hex", bytes.fromhex(h.decode())
            except Exception:
                pass
    for name, fn in (("base85", base64.b85decode), ("ascii85", base64.a85decode)):
        try:
            yield name, fn(s)
        except Exception:
            pass
    if b"%" in b:
        try:
            yield "url", urllib.parse.unquote_to_bytes(b)
        except Exception:
            pass
    if b[:2] == b"\x1f\x8b":
        try:
            yield "gzip", gzip.decompress(b)
        except Exception:
            pass
    else:
        try:
            yield "zlib", zlib.decompress(b)
        except Exception:
            pass


# Flag prefixes that identify the real answer among ROT/XOR brute candidates.
# Add the event's format via set_flag_prefix() (e.g. "securewv").
KNOWN_PREFIXES = {"flag", "securewv", "ctf", "htb", "thm", "pctf", "picoctf",
                  "key", "cyberwv", "wvctf", "uiuctf", "cvwctf"}


def set_flag_prefix(prefix: str) -> None:
    if prefix:
        KNOWN_PREFIXES.add(prefix.strip().rstrip("{").lower())
        knowledge.register_flag_prefix(prefix)


def _plausible(tok: str, strict: bool) -> bool:
    """Drop XOR/ROT garbage that only coincidentally contains {...}. In *strict*
    mode (ROT/XOR brute, which yield 25+ near-identical candidates) require a
    known flag prefix so the real answer isn't buried."""
    if "{" not in tok:
        return True   # 32-hex
    prefix = tok.split("{", 1)[0].lower()
    body = tok[tok.index("{") + 1: tok.rindex("}")]
    if not body:
        return False
    if strict:
        return prefix in KNOWN_PREFIXES
    good = sum(1 for c in body if c.isalnum() or c in "_- .!@#")
    return good / len(body) >= 0.7


def hunt(data, max_depth: int = 6) -> List[Tuple[str, str]]:
    """Return [(transform-chain, flag)] for every flag found while decoding."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    results: List[Tuple[str, str]] = []
    seen = set()

    def emit(chain: str, text: str, strict: bool = False):
        for tok in knowledge.find_flags(text):
            pair = (chain, tok)
            if pair not in results and _plausible(tok, strict):
                results.append(pair)

    def classical(b: bytes, chain: List[str], xor: bool):
        """ROT/Atbash (+ single-byte XOR at shallow depth) at THIS layer, so a
        rot/xor nested under a base decode is still found. strict=True so only a
        known-prefix flag survives the 25+ near-identical brute candidates."""
        txt = b.decode("latin-1", "replace")
        base = " -> ".join(chain)
        pre = f"{base} -> " if base else ""
        for n in range(1, 26):
            emit(f"{pre}rot{n}", _rot(txt, n), strict=True)
        emit(f"{pre}atbash", _atbash(txt), strict=True)
        if xor:
            for k in range(1, 256):
                x = bytes(c ^ k for c in b)
                if _printable_ratio(x) > 0.8:
                    emit(f"{pre}xor 0x{k:02x}",
                         x.decode("latin-1", "replace"), strict=True)

    def rec(b: bytes, chain: List[str], depth: int):
        emit(" -> ".join(chain) or "plain", b.decode("latin-1", "replace"))
        classical(b, chain, xor=depth <= 1)
        if depth >= max_depth:
            return
        for name, dec in _decoders(b):
            if not dec or dec == b:
                continue
            key = (name, dec[:80])
            if key in seen:
                continue
            seen.add(key)
            if _printable_ratio(dec) > 0.8 or knowledge.find_flags(
                    dec.decode("latin-1", "replace")):
                rec(dec, chain + [name], depth + 1)

    rec(data, [], 0)
    return results


def solve(data, label: str = "input") -> List[str]:
    """Convenience wrapper for CLI: hunt + return distinct flags, printing the
    transform chain for each."""
    from ..core import utils
    flags = []
    for chain, tok in hunt(data):
        if tok in flags:
            continue
        flags.append(tok)
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c(f"║ FLAG via {chain}", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
    if not flags:
        from ..core import utils as u
        u.log("dim", f"no flag found in {label} by layered decode/XOR/ROT "
                     "(try CyberChef Magic, or it may need a real cipher)")
    return flags


# expose the classical helpers for reuse
rot = _rot
atbash = _atbash
