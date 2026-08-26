"""Findings store and multi-format reporting (console / JSON / Markdown)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .utils import c, C, now_iso


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": (C.RED, C.BOLD),
    "high": (C.RED,),
    "medium": (C.YELLOW,),
    "low": (C.CYAN,),
    "info": (C.GREY,),
}


@dataclass
class Finding:
    """A single piece of recon intelligence."""

    title: str
    detail: str = ""
    severity: str = "info"           # critical|high|medium|low|info
    category: str = "general"        # port|service|web|cred|leak|host|...
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: Optional[str] = None
    # "confirmed" = we directly observed the behaviour (a 200 with body, an
    # anonymous login that worked). "potential" = inferred from a banner or
    # version string and NOT verified — treat as a lead, not a fact.
    confidence: str = "confirmed"
    data: Dict[str, Any] = field(default_factory=dict)

    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class HostReport:
    """Everything we learned about a single target host."""

    target: str
    resolved_ip: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    os_guess: Optional[str] = None
    tech_stack: Optional[str] = None
    s3_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    creds: List[str] = field(default_factory=list)   # recovered plaintext creds
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    started: str = field(default_factory=now_iso)
    finished: Optional[str] = None
    _seen: set = field(default_factory=set, repr=False)

    # -- mutation helpers ---------------------------------------------------
    def add(self, finding: Finding) -> None:
        # Skip exact duplicates so repeat passes don't inflate the report.
        sig = (finding.title, finding.port, finding.severity, finding.detail)
        if sig in self._seen:
            return
        self._seen.add(sig)
        self.findings.append(finding)

    def note(self, title: str, **kw) -> None:
        self.findings.append(Finding(title=title, **kw))

    def add_cred(self, value: str) -> None:
        """Record a recovered plaintext credential for later password-reuse
        spraying. Skips hash-looking and placeholder values."""
        v = (value or "").strip()
        if not v or len(v) > 128 or v in self.creds:
            return
        low = v.lower()
        if low in ("changeme", "password", "null", "none", "true", "false"):
            pass  # still useful to spray, keep them
        # Skip pure long hex (that's a hash, not a plaintext password).
        if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
            return
        self.creds.append(v)

    def add_hostname(self, name: str) -> bool:
        name = name.strip().lower().rstrip(".")
        if name and name not in self.hostnames and not _looks_like_ip(name):
            self.hostnames.append(name)
            return True
        return False

    def add_port(self, port: int, proto: str, service: str = "",
                 version: str = "", banner: str = "") -> Dict[str, Any]:
        entry = {
            "port": port,
            "proto": proto,
            "service": service,
            "version": version,
            "banner": banner,
        }
        self.open_ports.append(entry)
        return entry

    # -- serialization ------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("_seen", None)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
# Reporters
# ---------------------------------------------------------------------------
def summarize_console(host: HostReport) -> None:
    print("\n" + c("═" * 64, C.BLUE, C.BOLD))
    print(c(f"  RECON SUMMARY  ::  {host.target}", C.CYAN, C.BOLD))
    print(c("═" * 64, C.BLUE, C.BOLD))

    # Flags first — the whole point of a CTF run.
    flags = [f for f in host.findings if f.category == "flag"]
    if flags:
        print("  " + c("⚑ FLAGS", C.GREEN, C.BOLD))
        seen = set()
        for f in flags:
            val = f.detail or f.title
            if val in seen:
                continue
            seen.add(val)
            print("  " + c(f"  {val}", C.YELLOW, C.BOLD)
                  + c(f"   ({f.service or ''}:{f.port or ''})", C.GREY))
        print()

    if host.resolved_ip:
        print(f"  {c('IP', C.GREY)}        {host.resolved_ip}")
    if host.hostnames:
        print(f"  {c('Hostnames', C.GREY)} {', '.join(host.hostnames)}")
    if host.os_guess:
        print(f"  {c('OS guess', C.GREY)}  {host.os_guess}")
    if host.tech_stack:
        print(f"  {c('Web stack', C.GREY)} {host.tech_stack}")
    print(f"  {c('Open ports', C.GREY)} {len(host.open_ports)}")

    if host.open_ports:
        print("\n  " + c("PORT      SERVICE          VERSION", C.BOLD))
        for p in sorted(host.open_ports, key=lambda x: x["port"]):
            pp = f"{p['port']}/{p['proto']}"
            svc = p.get("service") or "?"
            ver = p.get("version") or ""
            print(f"  {pp:<9} {svc:<16} {ver}")

    # findings grouped by severity
    ranked = sorted(host.findings, key=lambda f: (f.rank(), f.category))
    interesting = [f for f in ranked if f.severity != "info"]
    if interesting:
        print("\n  " + c("NOTABLE FINDINGS", C.BOLD))
        for f in interesting:
            codes = SEVERITY_COLOR.get(f.severity, (C.GREY,))
            sev = f.severity.upper() + ("?" if f.confidence == "potential" else "")
            tag = c(f"[{sev}]", *codes)
            loc = f" :{f.port}" if f.port else ""
            hint = c("  (potential — verify)", C.GREY) if f.confidence == "potential" else ""
            print(f"  {tag} {f.title}{c(loc, C.GREY)}{hint}")
            if f.detail:
                print(f"        {c(f.detail, C.GREY)}")

    print()


def to_json(host: HostReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(host.to_dict(), fh, indent=2, default=str)


def to_markdown(host: HostReport, path: str) -> None:
    lines: List[str] = []
    lines.append(f"# Recon Report — {host.target}")
    lines.append("")
    lines.append(f"- **Target:** `{host.target}`")
    if host.resolved_ip:
        lines.append(f"- **Resolved IP:** `{host.resolved_ip}`")
    if host.hostnames:
        lines.append(f"- **Hostnames:** {', '.join(f'`{h}`' for h in host.hostnames)}")
    if host.os_guess:
        lines.append(f"- **OS guess:** {host.os_guess}")
    if host.tech_stack:
        lines.append(f"- **Web stack:** {host.tech_stack}")
    lines.append(f"- **Scan window:** {host.started} → {host.finished or '?'}")
    lines.append("")

    lines.append("## Open Ports")
    lines.append("")
    if host.open_ports:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("|------|-------|---------|---------|")
        for p in sorted(host.open_ports, key=lambda x: x["port"]):
            lines.append(
                f"| {p['port']} | {p['proto']} | {p.get('service') or ''} "
                f"| {p.get('version') or ''} |"
            )
    else:
        lines.append("_No open ports found._")
    lines.append("")

    ranked = sorted(host.findings, key=lambda f: (f.rank(), f.category))
    lines.append("## Findings")
    lines.append("")
    if ranked:
        for f in ranked:
            suffix = " _(potential — unverified)_" if f.confidence == "potential" else ""
            lines.append(f"### [{f.severity.upper()}] {f.title}{suffix}")
            if f.port:
                lines.append(f"- Port: `{f.port}`  Service: `{f.service or ''}`")
            if f.detail:
                lines.append(f"- {f.detail}")
            if f.evidence:
                lines.append("")
                lines.append("```")
                lines.append(f.evidence.strip())
                lines.append("```")
            lines.append("")
    else:
        lines.append("_No findings recorded._")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
