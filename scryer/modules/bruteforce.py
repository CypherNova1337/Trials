"""Ready-to-run brute-force command suggestions.

scryer doesn't spray passwords itself (loud, and often out of scope for a recon
pass), but when it identifies a login surface it hands the operator a
copy-paste hydra command already pointed at the bundled user/password lists —
one less thing to assemble by hand mid-box.
"""

from __future__ import annotations

from typing import Optional

from ..core import utils, tooling
from ..core.report import HostReport, Finding


def _lists():
    """Best available (users, passwords) wordlists — SecLists if present, else
    scryer's bundled lists (which always exist)."""
    users = tooling.find_wordlist("users") or tooling.bundled_wordlist("users")
    pwds = tooling.find_wordlist("passwords") or tooling.bundled_wordlist("passwords")
    return users, pwds


def suggest(host: HostReport, port: int, service: str,
            secure: bool = False, path: str = "/",
            user_field: str = "username", pass_field: str = "password",
            fail_marker: Optional[str] = None,
            username: Optional[str] = None) -> None:
    """Emit a hydra command tuned for *service*.

    service: 'ssh' | 'ftp' | 'rdp' | 'smb' | 'http-form' | 'http-basic'
    """
    users, pwds = _lists()
    ip = host.resolved_ip
    ulist = f"-l {username}" if username else f"-L {users}"
    plist = f"-P {pwds}"

    if service in ("ssh", "ftp", "rdp"):
        rate = {"ssh": "-t 4", "ftp": "-t 8", "rdp": "-t 1"}[service]
        cmd = f"hydra {ulist} {plist} {service}://{ip} {rate} -f -I"
        tip = "wrong creds trigger lockouts on SSH — keep -t low"
    elif service == "smb":
        cmd = (f"netexec smb {ip} -u {users} -p {pwds} "
               f"--continue-on-success")
        tip = "netexec is quieter than hydra for SMB; watch the lockout policy"
    elif service == "http-basic":
        scheme = "https-get" if secure else "http-get"
        cmd = f"hydra {ulist} {plist} {ip} -s {port} {scheme} {path}"
        tip = "HTTP Basic-Auth realm"
    elif service == "http-form":
        scheme = "https-post-form" if secure else "http-post-form"
        marker = fail_marker or "Invalid"
        body = f"{user_field}=^USER^&{pass_field}=^PASS^"
        cmd = (f'hydra {ulist} {plist} {ip} -s {port} {scheme} '
               f'"{path}:{body}:F={marker}"')
        tip = ("adjust the F= failure string to the app's real error text "
               "(or use S= for a success marker)")
    else:
        return

    ulabel = username or (users.split("/")[-1] if users else "users")
    utils.log("info", f"brute-force ready ({service}): {cmd}", indent=2)
    host.add(Finding(
        title=f"Brute-force command ready: {service} on :{port}",
        detail=f"{cmd}\n\nUsers: {ulabel}  Passwords: "
               f"{pwds.split('/')[-1] if pwds else 'passwords.txt'}. {tip}.",
        severity="info", category="access", port=port,
        service=service, evidence=cmd, confidence="potential"))
