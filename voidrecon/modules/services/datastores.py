"""Unauthenticated-access checks for common datastores that turn up on lab
boxes: Redis, Elasticsearch, MongoDB and Memcached."""

from __future__ import annotations

import socket
import urllib.request

from ...core import utils
from ...core.report import HostReport, Finding


def _raw(ip: str, port: int, payload: bytes, timeout: float = 6.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            return s.recv(4096).decode("latin-1", "replace")
    except OSError:
        return ""


def redis(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"Redis {ip}:{port}")
    resp = _raw(ip, port, b"INFO\r\n")
    if "redis_version" in resp:
        ver = ""
        for line in resp.splitlines():
            if line.startswith("redis_version:"):
                ver = line.split(":", 1)[1].strip()
        utils.log("hot", f"unauthenticated Redis (v{ver})", indent=2)
        host.add(Finding(
            title="Unauthenticated Redis access",
            detail=f"INFO returned without AUTH (v{ver}). CONFIG SET can write "
                   f"SSH keys / webshells for RCE.",
            severity="high", category="service", port=port, service="redis",
            evidence=resp[:300],
        ))
    elif "NOAUTH" in resp:
        utils.log("dim", "Redis requires auth", indent=2)


def memcached(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"Memcached {ip}:{port}")
    resp = _raw(ip, port, b"stats\r\n")
    if "STAT " in resp:
        utils.log("hot", "unauthenticated Memcached stats", indent=2)
        host.add(Finding(
            title="Unauthenticated Memcached access",
            detail="stats returned without auth — may leak cached data.",
            severity="medium", category="service", port=port, service="memcached",
            evidence=resp[:300],
        ))


def elasticsearch(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"Elasticsearch {ip}:{port}")
    for path in ("/", "/_cat/indices?v", "/_cluster/health"):
        url = f"http://{ip}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "voidrecon"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                body = resp.read(4000).decode("utf-8", "replace")
        except Exception:
            continue
        if path == "/" and '"cluster_name"' in body:
            utils.log("hot", "open Elasticsearch cluster", indent=2)
            host.add(Finding(
                title="Unauthenticated Elasticsearch access",
                detail="Cluster metadata readable without auth.",
                severity="high", category="service", port=port,
                service="elasticsearch", evidence=body[:300],
            ))
        elif path.endswith("indices?v") and body.strip():
            idx = [l.split()[2] for l in body.splitlines()[1:] if len(l.split()) > 2]
            if idx:
                host.add(Finding(
                    title="Elasticsearch indices exposed",
                    detail=", ".join(idx[:20]), severity="medium",
                    category="leak", port=port, service="elasticsearch",
                ))


def mongodb(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"MongoDB {ip}:{port}")
    if utils.have("mongosh") or utils.have("mongo"):
        client = "mongosh" if utils.have("mongosh") else "mongo"
        rc, out, _ = utils.run(
            [client, "--host", ip, "--port", str(port), "--quiet",
             "--eval", "db.adminCommand('listDatabases')"], timeout=15)
        if rc == 0 and ("databases" in out or "totalSize" in out):
            utils.log("hot", "unauthenticated MongoDB access", indent=2)
            host.add(Finding(
                title="Unauthenticated MongoDB access",
                detail="listDatabases succeeded without auth.",
                severity="high", category="service", port=port,
                service="mongodb", evidence=out[:300],
            ))
    else:
        utils.log("dim", "no mongo client on PATH to confirm auth state", indent=2)
