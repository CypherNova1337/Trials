"""LDAP / Active Directory enrichment.

Attempts an anonymous LDAP bind to recover the naming context and, when the
directory allows it, a user list — a very common foothold on AD boxes. Uses
`ldapsearch` when present; otherwise falls back to a minimal raw-socket
rootDSE probe that still recovers the base domain. Also surfaces the standard
AD attack methodology when the domain-controller port mix is present.
"""

from __future__ import annotations

import re
import socket

from ...core import utils
from ...core.report import HostReport, Finding


def enrich(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"LDAP {ip}:{port}")

    base = _anonymous_ldapsearch(host, ip, port)
    if base is None:
        _rootdse_raw(host, ip, port)


def _anonymous_ldapsearch(host: HostReport, ip: str, port: int):
    if not utils.have("ldapsearch"):
        return None
    # rootDSE — no bind DN, no base: works anonymously on most DCs.
    rc, out, err = utils.run(
        ["ldapsearch", "-x", "-H", f"ldap://{ip}:{port}", "-s", "base",
         "namingContexts", "defaultNamingContext", "dnsHostName"],
        timeout=25)
    if rc != 0 and not out:
        utils.log("dim", f"anonymous rootDSE query failed: {err.strip()[:80]}",
                  indent=2)
        return None

    contexts = re.findall(r"namingContexts:\s*(.+)", out)
    default = re.findall(r"defaultNamingContext:\s*(.+)", out)
    dns_name = re.findall(r"dnsHostName:\s*(.+)", out)
    base_dn = (default or contexts or [""])[0].strip()

    if dns_name:
        host.add_hostname(dns_name[0].strip())
        utils.log("good", f"DC hostname: {utils.c(dns_name[0].strip(), utils.C.CYAN)}",
                  indent=2)
    if base_dn:
        domain = _dn_to_domain(base_dn)
        utils.log("hot", f"anonymous LDAP bind — base DN {base_dn}", indent=2)
        host.add(Finding(
            title="Anonymous LDAP bind allowed",
            detail=f"rootDSE readable without credentials. Base DN: {base_dn}"
                   + (f" (domain {domain})" if domain else ""),
            severity="high", category="service", port=port, service="ldap",
            evidence=out[:400]))
        if domain:
            host.add_hostname(domain)
        _dump_users(host, ip, port, base_dn)
        return base_dn
    return None


def _dump_users(host: HostReport, ip: str, port: int, base_dn: str) -> None:
    rc, out, _ = utils.run(
        ["ldapsearch", "-x", "-H", f"ldap://{ip}:{port}", "-b", base_dn,
         "(&(objectClass=user)(objectCategory=person))", "sAMAccountName"],
        timeout=30)
    users = re.findall(r"sAMAccountName:\s*(.+)", out or "")
    users = [u.strip() for u in users if u.strip()]
    if users:
        utils.log("hot", f"anonymous user enumeration: {len(users)} users", indent=2)
        host.add(Finding(
            title="AD users enumerated via anonymous LDAP",
            detail=", ".join(users[:40]) + (" ..." if len(users) > 40 else ""),
            severity="high", category="cred", port=port, service="ldap",
            evidence="\n".join(users[:100])))
        host.add(Finding(
            title="User list recovered — try AS-REP roasting / password spraying",
            detail="Feed this list to GetNPUsers.py (AS-REP roast, no creds "
                   "needed for accounts with pre-auth disabled) and to a spray "
                   "with common/seasonal passwords.",
            severity="info", category="cred", port=port, service="ldap",
            confidence="potential"))


def _rootdse_raw(host: HostReport, ip: str, port: int) -> None:
    """Minimal anonymous rootDSE search over a raw socket (no ldapsearch).

    Sends a hand-built LDAPv3 anonymous bind + search for namingContexts and
    scrapes any DC=... strings from the reply. Best-effort; a positive parse is
    reliable, a miss just means 'inconclusive'.
    """
    bind = bytes.fromhex("300c020101600702010304008000")
    search = bytes.fromhex(
        "3033020102633004000a01000a0100020100020100010100"
        "870b6f626a656374436c617373301c04176e616d696e67436f6e7465787473")
    try:
        with socket.create_connection((ip, port), timeout=8) as s:
            s.settimeout(6)
            s.sendall(bind)
            s.recv(1024)
            s.sendall(search)
            data = s.recv(4096)
    except OSError:
        utils.log("dim", "raw LDAP probe failed", indent=2)
        return
    text = data.decode("latin-1", "replace")
    dns = re.findall(r"(DC=[A-Za-z0-9_-]+(?:,DC=[A-Za-z0-9_-]+)+)", text)
    if dns:
        base_dn = dns[0]
        domain = _dn_to_domain(base_dn)
        utils.log("good", f"LDAP base DN (raw): {base_dn}", indent=2)
        host.add(Finding(
            title="LDAP naming context exposed (anonymous)",
            detail=f"Base DN {base_dn}" + (f" -> domain {domain}" if domain else "")
                   + ". Install ldapsearch for full user enumeration.",
            severity="medium", category="service", port=port, service="ldap"))
        if domain:
            host.add_hostname(domain)
    else:
        utils.log("dim", "no anonymous LDAP data (install ldapsearch for more)",
                  indent=2)


def _dn_to_domain(dn: str) -> str:
    parts = re.findall(r"DC=([^,]+)", dn, re.IGNORECASE)
    return ".".join(parts).lower() if parts else ""
