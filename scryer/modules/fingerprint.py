"""Active protocol fingerprinting.

The port number is only a hint. Before dispatching deep modules we actually
probe each open port to learn what it *really* speaks — so HTTPS on 8500 or a
plain-HTTP admin panel on 8443 is classified correctly, and TLS-wrapped
services are handled with the right transport.

Everything here is observation-based: a service label is only upgraded when we
see the protocol behave, never on the port number alone.
"""

from __future__ import annotations

import socket
import ssl
from typing import Optional, Tuple

from ..core import utils
from ..data import knowledge


def _tls_probe(ip: str, port: int, timeout: float) -> Optional[str]:
    """Return the negotiated TLS version if the port completes a handshake."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as tls:
                return tls.version() or "TLS"
    except (ssl.SSLError, OSError):
        return None


def _http_over(sock, host_header: str) -> Optional[str]:
    """Send an HTTP request on an (already connected) socket, return the
    status line if the peer answers like an HTTP server."""
    try:
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {host_header}\r\n"
            f"User-Agent: scryer\r\n\r\n".encode())
        data = sock.recv(256)
    except OSError:
        return None
    text = data.decode("latin-1", "replace")
    if text.startswith("HTTP/"):
        return text.splitlines()[0].strip()
    return None


def _http_plain(ip: str, port: int, timeout: float, host_header: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return _http_over(sock, host_header)
    except OSError:
        return None


def _http_tls(ip: str, port: int, timeout: float, host_header: str) -> Optional[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as tls:
                tls.settimeout(timeout)
                return _http_over(tls, host_header)
    except (ssl.SSLError, OSError):
        return None


def identify(ip: str, port: int, banner: str, host_header: str,
             timeout: float = 5.0) -> Tuple[str, bool, str]:
    """Determine (service, secure, evidence) for an open port by probing.

    Falls back to the banner-derived guess and finally the port map, so the
    result is never worse than the port-number heuristic — only better.
    """
    banner = banner or ""

    # 1) SSH / FTP / SMTP announce themselves on connect; trust a clear banner.
    low = banner.lower()
    if low.startswith("ssh-"):
        return "ssh", False, banner.splitlines()[0][:60]
    if banner[:3].isdigit() and ("ftp" in low or port in (21, 2121)):
        return "ftp", False, banner.splitlines()[0][:60]

    # 2) Does it complete a TLS handshake? If so, is it HTTPS or generic TLS?
    tls_ver = _tls_probe(ip, port, timeout)
    if tls_ver:
        status = _http_tls(ip, port, timeout, host_header)
        if status:
            return "https", True, status
        # TLS but not HTTP — keep the port's nominal service, mark secure.
        svc = knowledge.PORT_SERVICE.get(port, "tls")
        return (svc if svc not in ("http", "https") else "tls"), True, tls_ver

    # 3) Plain HTTP?
    status = _http_plain(ip, port, timeout, host_header)
    if status:
        return "http", False, status

    # 4) Fall back to banner keywords, then the static port map.
    for name in ("mysql", "redis", "mongodb", "postgres", "smtp", "imap",
                 "pop3", "vnc", "rdp"):
        if name in low:
            return name, False, banner.splitlines()[0][:60] if banner else ""
    return knowledge.PORT_SERVICE.get(port, ""), False, ""


def refine(host, timeout: float = 5.0) -> None:
    """Fingerprint every open port and update the report in place."""
    host_header = host.hostnames[0] if host.hostnames else (host.resolved_ip or "")
    utils.log("info", "fingerprinting open ports (protocol probe)")
    for entry in host.open_ports:
        port = entry["port"]
        prior = entry.get("service") or ""
        svc, secure, evidence = identify(
            host.resolved_ip, port, entry.get("banner", ""), host_header, timeout)
        entry["secure"] = secure
        if svc:
            entry["service"] = svc
        if svc and svc != prior:
            utils.log("good",
                      f"{port}/tcp -> {utils.c(svc, utils.C.CYAN)}"
                      f"{' (TLS)' if secure else ''}"
                      f"{'  [was ' + prior + ']' if prior and prior != svc else ''}",
                      indent=1)
