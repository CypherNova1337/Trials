"""Interactive service connector for Jeopardy 'nc HOST PORT' challenges.

Opens a raw TCP socket to a challenge service and relays it to your terminal
like netcat, but with three assists running on the stream:

  * flag watch    — every byte in/out is scanned for a flag and highlighted
  * auto-solve    — arithmetic / "what is X op Y" prompts (the usual gate on
                    beginner pwn/misc services) are computed and answered for
                    you, so proof-of-work countdowns clear themselves
  * auto-decode   — a base64/hex blob in the banner is run through the layered
                    decoder in case the flag is just encoded at you

You can still type at any time; your input is forwarded to the service. Ctrl-C
(or the service closing) ends the session and prints any flags seen.

Pure standard library (socket + select).
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import operator
import re
import select
import socket
import string
import sys
import time
from typing import List, Optional, Set, Tuple

from ..core import utils
from ..data import knowledge

_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow, ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}
# A run of arithmetic characters — filtered to real expressions (a digit + an
# operator) and paren-balanced before evaluation.
_EXPR_RE = re.compile(r"[\d\s()+\-*/%.]{3,}")
_ASK = re.compile(r"(?:\?|=\s*$|what\s+is|solve|answer|result|compute|"
                  r"calculat|sum of|product of)", re.I)
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{16,}")


def connect(target: str, auto: bool = True, timeout: float = 600.0) -> List[str]:
    host, port = _parse(target)
    if port is None:
        utils.log("bad", f"invalid target '{target}' — use HOST:PORT "
                         "(e.g. 10.10.10.5:1337)")
        return []

    utils.section(f"CONNECT {host}:{port}")
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except OSError as exc:
        utils.log("bad", f"connect failed: {exc}")
        return []
    utils.log("good", f"connected to {host}:{port}"
                      + ("  (auto-solve on — type any time, Ctrl-C to quit)"
                         if auto else "  (raw relay — Ctrl-C to quit)"))

    flags: Set[str] = set()
    seen_tokens: Set[str] = set()
    solved_pow: Set[str] = set()
    context = ""    # rolling recent text (for multi-line PoW specs)
    sock.setblocking(False)
    deadline = time.time() + timeout
    pending = b""   # partial line buffer for the auto-solver
    watch_stdin = _stdin_usable()
    try:
        while time.time() < deadline:
            watch = [sock] + ([sys.stdin] if watch_stdin else [])
            r, _, _ = select.select(watch, [], [], 0.5)
            if sock in r:
                try:
                    data = sock.recv(8192)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    break
                if not data:
                    utils.log("dim", "service closed the connection")
                    break
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
                _scan(data, flags)
                if auto:
                    pending = _auto(sock, pending + data, seen_tokens, flags)
                    context = (context + data.decode("utf-8", "replace"))[-4000:]
                    _maybe_pow(sock, context, solved_pow)
            if watch_stdin and sys.stdin in r:
                line = sys.stdin.readline()
                if not line:
                    # stdin EOF (piped input exhausted, or no TTY): stop relaying
                    # keystrokes but keep the service session running so the
                    # auto-solver can still clear the challenge.
                    watch_stdin = False
                    continue
                try:
                    sock.sendall(line.encode())
                except OSError:
                    break
    except KeyboardInterrupt:
        print()
    finally:
        try:
            sock.close()
        except OSError:
            pass

    _summary(sorted(flags))
    return sorted(flags)


# --------------------------------------------------------------------------
def _auto(sock: socket.socket, buf: bytes, seen: Set[str],
          flags: Set[str]) -> bytes:
    """Answer a complete challenge line if we can. Returns the leftover
    (incomplete) tail to carry into the next read."""
    text = buf.decode("utf-8", "replace")
    lines = text.splitlines()
    if not lines:
        return b""
    # The last line is "complete" if the buffer ended with a newline OR it looks
    # like a prompt awaiting input (many services print "What is..? " with no
    # newline and block on recv). Otherwise defer it as a partial tail.
    ends_nl = text.endswith(("\n", "\r"))
    tail = b""
    if not ends_nl and not lines[-1].rstrip().endswith((":", "?", "=", ">")):
        tail = lines.pop().encode()

    for line in lines[-6:]:                       # recent lines only
        ans = _solve(line)
        if ans is not None:
            utils.log("good", f"auto-answer: {line.strip()[:60]} -> {ans}")
            try:
                sock.sendall((ans + "\n").encode())
            except OSError:
                pass
            continue
        # encoded flag sitting in the banner?
        for tok in _TOKEN_RE.findall(line):
            if tok in seen:
                continue
            seen.add(tok)
            _decode_token(tok, flags)
    return tail if len(tail) < 8192 else b""


def _solve(line: str) -> Optional[str]:
    if not _ASK.search(line):
        return None
    best = None
    for m in _EXPR_RE.finditer(line):
        expr = _balance(m.group().strip())
        if not expr or not any(c.isdigit() for c in expr):
            continue
        if not any(op in expr for op in "+-*/%"):
            continue
        val = _safe_eval(expr)
        if val is not None:
            best = expr, val          # take the last (usually the real prompt)
    if best is None:
        return None
    _expr, val = best
    if isinstance(val, float) and val.is_integer():
        val = int(val)
    if isinstance(val, float):
        return f"{val:.6f}".rstrip("0").rstrip(".")
    return str(val)


def _balance(expr: str) -> str:
    """Trim unmatched parentheses off a regex-carved expression."""
    while expr.count(")") > expr.count("("):
        expr = expr[::-1].replace(")", "", 1)[::-1]
    while expr.count("(") > expr.count(")"):
        expr = expr.replace("(", "", 1)
    return expr.strip()


# --------------------------------------------------------------------------
# proof-of-work (hashcash / sha256-leading-zeros)
# --------------------------------------------------------------------------
_HASH_FNS = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256,
             "sha512": hashlib.sha512}
_POW_TRIGGER = re.compile(r"(sha-?(?:1|256|512)|md5|hashcash|proof[\s-]*of[\s-]*"
                          r"work|\bpow\b)", re.I)
# The kctf / redpwn "curl … pow …" gate has its own tool — detect + advise.
_KCTF = re.compile(r"(pwn\.red/pow|kctf|redpwn/pow|python3?\s+\S*pow\S*\.py|"
                   r"\bs\.[A-Za-z0-9+/=]{20,})")


def _maybe_pow(sock: socket.socket, context: str, solved: Set[str]) -> None:
    """Detect a proof-of-work gate in the recent stream and, if it's a
    brute-forceable hash-with-leading-zeros challenge, solve and answer it."""
    if not _POW_TRIGGER.search(context):
        return
    # Only fire when the service is actually waiting on us (a prompt tail).
    if not context.rstrip().endswith((":", "?", ">", ")", "=")) \
            and "\n" not in context[-200:]:
        return
    spec = _parse_pow(context)
    if not spec:
        if _KCTF.search(context):
            key = "kctf"
            if key not in solved:
                solved.add(key)
                utils.log("warn", "kctf/redpwn proof-of-work detected — run the "
                                  "printed `curl … | sh` / pow command in a shell "
                                  "and paste its answer (not brute-forceable here)")
        return
    algo, prefix, nzeros, unit, leading = spec
    key = f"{algo}:{prefix}:{nzeros}:{unit}:{leading}"
    if key in solved:
        return
    solved.add(key)
    utils.log("info", f"proof-of-work: {algo} with {nzeros} leading "
                      f"{'zero bits' if unit == 'bits' else 'hex zeros'}"
                      + (f" on '{prefix[:24]}'+X" if prefix else "")
                      + " — solving…")
    answer = _brute_pow(algo, prefix, nzeros, unit, leading, budget=25.0)
    if answer is None:
        utils.log("warn", "proof-of-work exceeded the time budget — solve it "
                          "manually (difficulty too high for the auto-solver)")
        return
    full, suffix = answer
    send = suffix if prefix else full
    utils.log("good", f"proof-of-work solved -> {send}")
    try:
        sock.sendall((send + "\n").encode())
    except OSError:
        pass


def _parse_pow(text: str):
    """Return (algo, prefix, nzeros, unit, leading) or None.

    Handles the common phrasings: 'sha256(prefix + X) starts with N zero bits',
    'find a string whose sha256 begins with N zeroes', hashcash 'mbN'."""
    low = text.lower()
    algo = "sha256"
    for name in ("sha512", "sha256", "sha1", "md5"):
        if name in low or name.replace("sha", "sha-") in low:
            algo = name
            break

    leading = not any(w in low for w in ("ends with", "trailing", "suffix of the"))
    unit = "bits" if "bit" in low else "hex"

    n = None
    m = re.search(r"(\d+)\s*(?:leading\s+)?(?:zero(?:e?s)?|nibble|hex|"
                  r"char|digit|bit)", low)
    if m:
        n = int(m.group(1))
    else:                              # 'starts with 0000' literal run of zeros
        m2 = re.search(r"(?:with|:)\s*[\"']?(0{2,})", low)
        if m2:
            n = len(m2.group(1))
            unit = "hex"
    mh = re.search(r"\bm?b(\d{1,2})\b", low)        # hashcash -mbN
    if mh and n is None:
        n, unit = int(mh.group(1)), "bits"
    if not n or n <= 0 or n > 64:
        return None

    prefix = _pow_prefix(text)
    return algo, prefix, n, unit, leading


def _pow_prefix(text: str) -> str:
    """Extract the fixed prefix the server wants prepended, if any."""
    # sha256(PREFIX + X) / sha256(PREFIX+something) / hash(TOKEN + ...)
    for pat in (r"(?:prefix|challenge|token|seed|salt)\s*(?:is|=|:)\s*"
                r"[\"']?([A-Za-z0-9+/=_-]{4,})",
                # sha256("PREFIX"+X) / sha256(PREFIX + suffix) — tolerate quotes
                r"sha-?\d*\s*\(\s*[\"']?([A-Za-z0-9+/=_-]{4,})[\"']?\s*\+",
                # "PREFIX"+X anywhere (quoted literal followed by concatenation)
                r"[\"']([A-Za-z0-9+/=_-]{4,})[\"']\s*\+\s*[A-Za-z_]",
                r"starts?\s+with\s+the\s+string\s+[\"']([^\"']+)[\"']",
                r"\bXXXX\b.*?([A-Za-z0-9]{6,})"):
        m = re.search(pat, text, re.I)
        if m:
            cand = m.group(1)
            if cand.lower() not in _POW_PLACEHOLDERS:
                return cand
    return ""


# Formula placeholders that are NOT the actual prefix value.
_POW_PLACEHOLDERS = {
    "zero", "zeros", "zeroes", "bits", "the", "prefix", "suffix", "input",
    "string", "value", "data", "msg", "message", "nonce", "your", "some",
    "answer", "hash", "result",
}


def _brute_pow(algo: str, prefix: str, nzeros: int, unit: str, leading: bool,
               budget: float = 25.0) -> Optional[Tuple[str, str]]:
    fn = _HASH_FNS.get(algo, hashlib.sha256)
    pre = prefix.encode()
    end = time.time() + budget
    # counter -> short printable suffixes, widening length as needed
    charset = string.ascii_letters + string.digits
    checked = 0
    for length in range(1, 12):
        for combo in itertools.product(charset, repeat=length):
            suffix = "".join(combo)
            digest = fn(pre + suffix.encode()).hexdigest()
            if _zeros_ok(digest, nzeros, unit, leading):
                return prefix + suffix, suffix
            checked += 1
            if checked % 200000 == 0 and time.time() > end:
                return None
    return None


def _zeros_ok(hexdigest: str, n: int, unit: str, leading: bool) -> bool:
    if unit == "hex":
        return (hexdigest.startswith("0" * n) if leading
                else hexdigest.endswith("0" * n))
    # bit-level: n leading/trailing zero bits
    val = int(hexdigest, 16)
    total = len(hexdigest) * 4
    if leading:
        return val >> (total - n) == 0
    return val & ((1 << n) - 1) == 0


def _safe_eval(expr: str):
    try:
        node = ast.parse(expr, mode="eval").body
        return _ev(node)
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError,
            OverflowError, KeyError):
        return None


def _ev(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        if isinstance(node.op, ast.Pow):
            # guard against giant exponents (DoS / OverflowError)
            r = _ev(node.right)
            if abs(r) > 64:
                raise ValueError("exponent too large")
        return _OPS[type(node.op)](_ev(node.left), _ev(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_ev(node.operand))
    raise ValueError("unsupported expression")


def _decode_token(tok: str, flags: Set[str]) -> None:
    from . import crypto
    for chain, flag in crypto.hunt(tok, max_depth=4):
        if flag not in flags:
            flags.add(flag)
            utils.log("hot", f"flag via {chain}: {flag}")


def _scan(data: bytes, flags: Set[str]) -> None:
    for tok in knowledge.find_flags(data.decode("utf-8", "replace")):
        if tok not in flags:
            flags.add(tok)
            print()
            utils.log("hot", f"FLAG: {tok}")


def _stdin_usable() -> bool:
    """True if stdin is a real fd we can select on (a TTY or a live pipe)."""
    try:
        return sys.stdin is not None and sys.stdin.fileno() >= 0
    except (ValueError, OSError, AttributeError):
        return False


def _parse(target: str):
    target = target.strip()
    # accept HOST:PORT, HOST PORT, or nc-style "nc HOST PORT"
    target = re.sub(r"^\s*nc\s+", "", target)
    if ":" in target:
        host, _, port = target.rpartition(":")
    else:
        parts = target.split()
        if len(parts) == 2:
            host, port = parts
        else:
            return target, None
    try:
        return host.strip(), int(port)
    except ValueError:
        return host.strip(), None


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
        utils.log("dim", "session ended — no flag seen on the wire")
