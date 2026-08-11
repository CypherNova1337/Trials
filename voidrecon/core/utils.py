"""Shared helpers: colored output, logging, timing and small utilities."""

from __future__ import annotations

import os
import sys
import shutil
import socket
import subprocess
import time
from datetime import datetime


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class C:
    """ANSI color codes. Automatically disabled when output is not a TTY."""

    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def wrap(cls, text: str, *codes: str) -> str:
        if not cls._enabled or not codes:
            return text
        return "".join(codes) + text + cls.RESET

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False


def c(text: str, *codes: str) -> str:
    return C.wrap(text, *codes)


# ---------------------------------------------------------------------------
# Console banners / section headers
# ---------------------------------------------------------------------------
def banner() -> str:
    art = r"""
 __      __    _     _ ___
 \ \    / /__ (_)___| |  _ \ ___ __ ___ _ _
  \ \/\/ / _ \| / _` |   / -_) _/ _ \ ' \
   \_/\_/\___/|_\__,_|_|_\___\__\___/_||_|
"""
    tag = "        deep recon toolkit  ::  voidsec-hub"
    return c(art, C.CYAN, C.BOLD) + c(tag, C.MAGENTA) + "\n"


def section(title: str) -> None:
    line = "─" * max(4, 60 - len(title))
    print("\n" + c(f"┌─[ {title} ]{line}", C.BLUE, C.BOLD))


def kv(key: str, value, indent: int = 2) -> None:
    pad = " " * indent
    print(f"{pad}{c(key + ':', C.GREY)} {value}")


# ---------------------------------------------------------------------------
# Status logging with severity/tag markers
# ---------------------------------------------------------------------------
_MARKS = {
    "info": (c("[*]", C.BLUE), C.RESET),
    "good": (c("[+]", C.GREEN), C.GREEN),
    "warn": (c("[!]", C.YELLOW), C.YELLOW),
    "bad": (c("[-]", C.RED), C.RED),
    "hot": (c("[HOT]", C.RED, C.BOLD), C.RED),
    "dim": (c("[.]", C.GREY), C.GREY),
}


def log(kind: str, msg: str, indent: int = 0) -> None:
    mark, _ = _MARKS.get(kind, _MARKS["info"])
    pad = "  " * indent
    print(f"{pad}{mark} {msg}")


# ---------------------------------------------------------------------------
# External tool detection
# ---------------------------------------------------------------------------
def have(tool: str) -> bool:
    """Return True if an external binary is available on PATH."""
    return shutil.which(tool) is not None


def run(cmd, timeout: int = 60, text: bool = True):
    """Run an external command, returning (returncode, stdout, stderr).

    Never raises on non-zero exit; returns (-1, '', reason) on failure.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"{cmd[0]}: not found"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def is_ip(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


class Timer:
    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.time() - self.start

    def __str__(self) -> str:
        return f"{getattr(self, 'elapsed', 0):.1f}s"
