"""SNMP enumeration (UDP/161).

Prefers snmpwalk/onesixtyone; falls back to a hand-built SNMPv2c GET for
sysDescr so a community string can still be confirmed with no tools installed.
SNMP frequently leaks running processes, installed software, listening ports,
user accounts and network interfaces — very high value when open.
"""

from __future__ import annotations

import socket
from typing import Optional

from ...core import utils, tooling
from ...core.report import HostReport, Finding

COMMUNITIES = ["public", "private", "community", "manager"]

# High-value OID branches worth walking once a community is confirmed.
_OID_HINTS = {
    "1.3.6.1.2.1.25.4.2.1.2": "running processes",
    "1.3.6.1.2.1.25.6.3.1.2": "installed software",
    "1.3.6.1.2.1.6.13.1.3": "listening TCP ports",
    "1.3.6.1.4.1.77.1.2.25": "user accounts",
}


def enrich(host: HostReport, port: int = 161) -> None:
    ip = host.resolved_ip
    utils.section(f"SNMP {ip}:{port}/udp")

    community = None
    if tooling.resolve("snmpwalk"):
        community = _snmpwalk(host, ip, port)
    else:
        community = _raw_probe(host, ip, port)

    if community:
        host.add(Finding(
            title=f"SNMP community string valid: {community}",
            detail="Walk high-value branches: processes, software, listening "
                   "ports, and (on Windows) user accounts.",
            severity="high", category="cred", port=port, service="snmp"))
    else:
        utils.log("dim", "no SNMP response / no valid community", indent=1)


def _snmpwalk(host: HostReport, ip: str, port: int) -> Optional[str]:
    snmpwalk = tooling.resolve("snmpwalk")
    for comm in COMMUNITIES:
        rc, out, _ = utils.run(
            [snmpwalk, "-v2c", "-c", comm, "-t", "2", "-r", "1",
             f"{ip}:{port}", "1.3.6.1.2.1.1.1.0"], timeout=15)
        if rc == 0 and "=" in out and "Timeout" not in out:
            desc = out.split("=", 1)[1].strip()
            utils.log("hot", f"community '{comm}' valid — sysDescr: {desc[:80]}",
                      indent=1)
            host.add(Finding(title=f"SNMP sysDescr: {desc[:120]}", severity="info",
                             category="host", port=port, service="snmp",
                             evidence=desc))
            for oid, label in _OID_HINTS.items():
                rc2, out2, _ = utils.run(
                    [snmpwalk, "-v2c", "-c", comm, "-t", "2", f"{ip}:{port}", oid],
                    timeout=20)
                lines = [l for l in (out2 or "").splitlines() if "=" in l]
                if lines:
                    utils.log("good", f"{label}: {len(lines)} entries", indent=2)
                    host.add(Finding(
                        title=f"SNMP {label} ({len(lines)})",
                        detail="\n".join(l.split("=", 1)[-1].strip()
                                         for l in lines[:30]),
                        severity="medium", category="leak", port=port,
                        service="snmp", evidence="\n".join(lines[:60])))
            return comm
    return None


def _raw_probe(host: HostReport, ip: str, port: int) -> Optional[str]:
    """Minimal SNMPv2c GET for sysDescr.0 with each candidate community."""
    for comm in COMMUNITIES:
        pkt = _build_get(comm, [1, 3, 6, 1, 2, 1, 1, 1, 0])
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.5)
            s.sendto(pkt, (ip, port))
            data, _ = s.recvfrom(2048)
            s.close()
        except OSError:
            continue
        # A response of any kind for this community means it is accepted.
        text = _printable(data)
        utils.log("hot", f"community '{comm}' answered (install snmpwalk to "
                         f"enumerate fully)", indent=1)
        if text:
            host.add(Finding(title=f"SNMP sysDescr: {text[:120]}", severity="info",
                             category="host", port=port, service="snmp",
                             evidence=text))
        return comm
    return None


# --- tiny BER/ASN.1 encoder for a single SNMPv2c GET request ---------------
def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = value.__len__()
    lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + value


def _int(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() // 8) + 1, "big") if n else b"\x00"
    return _tlv(0x02, b)


def _oid(parts) -> bytes:
    first = 40 * parts[0] + parts[1]
    body = bytearray([first])
    for p in parts[2:]:
        if p < 0x80:
            body.append(p)
        else:
            chunk = []
            while p:
                chunk.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body.extend(chunk)
    return _tlv(0x06, bytes(body))


def _build_get(community: str, oid) -> bytes:
    varbind = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))   # OID + NULL
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xA0,                                     # GetRequest PDU
               _int(0x1337) + _int(0) + _int(0) + varbinds)
    msg = _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)  # v2c=1
    return msg


def _printable(data: bytes) -> str:
    out = "".join(chr(b) if 32 <= b < 127 else "" for b in data)
    return out.strip()
