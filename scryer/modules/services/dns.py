"""DNS probing: version.bind chaos query and an AXFR zone-transfer attempt
when external tools (dig/host) are available."""

from __future__ import annotations

from ...core import utils
from ...core.report import HostReport, Finding


def enrich(host: HostReport, port: int) -> None:
    ip = host.resolved_ip
    utils.section(f"DNS {ip}:{port}")

    if utils.have("dig"):
        # CHAOS TXT version.bind — often leaks the resolver software/version.
        rc, out, _ = utils.run(
            ["dig", f"@{ip}", "version.bind", "chaos", "txt", "+short"], timeout=15)
        ver = out.strip().strip('"')
        if rc == 0 and ver:
            utils.kv("version.bind", ver, indent=4)
            host.add(Finding(title=f"DNS version: {ver}", severity="info",
                             category="service", port=port, service="dns"))
            for sev, note in utils_import_hints(ver):
                host.add(Finding(title=note, severity=sev, category="service",
                                 port=port, service="dns", evidence=ver,
                                 confidence="potential"))

    # AXFR against any hostnames we know (domains discovered via TLS/HTTP).
    domains = _candidate_domains(host)
    for dom in domains:
        _try_axfr(host, ip, port, dom)
    if not domains:
        utils.log("dim", "no candidate domain for AXFR (need a hostname)", indent=2)


def utils_import_hints(text: str):
    from ...data.knowledge import match_hints
    return match_hints(text)


def _candidate_domains(host: HostReport):
    doms = set()
    for name in host.hostnames:
        parts = name.split(".")
        if len(parts) >= 2:
            doms.add(".".join(parts[-2:]))
            doms.add(name)
    return sorted(doms)


def _try_axfr(host: HostReport, ip: str, port: int, domain: str) -> None:
    if utils.have("dig"):
        rc, out, _ = utils.run(["dig", f"@{ip}", "-p", str(port), domain, "axfr"],
                               timeout=20)
    elif utils.have("host"):
        rc, out, _ = utils.run(["host", "-l", domain, ip], timeout=20)
    else:
        return
    low = out.lower()
    transferred = "xfr size" in low or (rc == 0 and domain in low and
                                        "failed" not in low and "transfer failed" not in low
                                        and out.count("\n") > 3)
    if transferred and "transfer failed" not in low and "connection timed out" not in low:
        utils.log("hot", f"AXFR zone transfer allowed for {domain}!", indent=2)
        host.add(Finding(
            title=f"DNS zone transfer (AXFR) allowed: {domain}",
            detail="Full zone can be enumerated — high-value host/subdomain leak.",
            severity="high", category="service", port=port, service="dns",
            evidence=out[:800],
        ))
        # Feed discovered names back into scope.
        for line in out.splitlines():
            fields = line.split()
            if len(fields) >= 1 and fields[0].endswith("."):
                host.add_hostname(fields[0])
    else:
        utils.log("dim", f"AXFR refused for {domain}", indent=2)
