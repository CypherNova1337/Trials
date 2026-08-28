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
import operator
import re
import select
import socket
import sys
import time
from typing import List, Optional, Set

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
