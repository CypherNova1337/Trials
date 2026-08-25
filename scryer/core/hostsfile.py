"""/etc/hosts helper.

CTF boxes routinely redirect the bare IP to a virtual host (orion.htb) and
serve nothing useful until that name resolves. scryer's own probes work by
connecting to the IP with a Host header, but the *external* tools it suggests
(paramvoid, feroxbuster, whatweb) and the operator's browser all need the name
in /etc/hosts. This module surfaces the exact line and, with --add-hosts, adds
it (using sudo when not already root).
"""

from __future__ import annotations

import os
import subprocess
from typing import List

from . import utils

HOSTS_PATH = "/etc/hosts"


def vhost_names(host) -> List[str]:
    """Discovered hostnames that need an /etc/hosts entry (skip the bare IP)."""
    ip = host.resolved_ip or ""
    out = []
    for name in host.hostnames:
        n = name.strip().lower()
        if n and "." in n and n != ip and not _is_ip(n) and n not in out:
            out.append(n)
    return out


def already_mapped(ip: str, name: str) -> bool:
    try:
        with open(HOSTS_PATH, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0]
                fields = line.split()
                if len(fields) >= 2 and fields[0] == ip and name in fields[1:]:
                    return True
    except OSError:
        pass
    return False


def command(ip: str, names: List[str]) -> str:
    return f"echo '{ip} {' '.join(names)}' | sudo tee -a {HOSTS_PATH}"


def add(ip: str, names: List[str]) -> bool:
    """Append missing `ip name` mappings to /etc/hosts. Returns True on success.
    Uses sudo when the file isn't directly writable."""
    missing, seen = [], set()
    for n in names:
        if n not in seen and not already_mapped(ip, n):
            seen.add(n)
            missing.append(n)
    if not missing:
        return True
    line = f"{ip} {' '.join(missing)}\n"
    # Direct write when we can (running as root).
    try:
        if os.access(HOSTS_PATH, os.W_OK):
            with open(HOSTS_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
            return True
    except OSError:
        pass
    # Otherwise go through sudo tee (may prompt for a password on the tty).
    if utils.have("sudo"):
        try:
            proc = subprocess.run(["sudo", "tee", "-a", HOSTS_PATH],
                                  input=line, text=True, capture_output=True,
                                  timeout=60)
            return proc.returncode == 0
        except Exception:
            return False
    return False


def _is_ip(name: str) -> bool:
    parts = name.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
