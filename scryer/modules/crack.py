"""Offline loot cracking + scanning.

When scryer recovers an archive (anonymous FTP, an exposed backup.zip, a
writable share), the flag is usually one crack away. This module:

  1. Detects whether a zip is encrypted.
  2. If not, extracts it directly.
  3. If it is, cracks the password with zip2john + john (rockyou / the best
     available password list), then extracts with the recovered password.
  4. Scans everything it extracted for flags, credentials and hard-coded
     secrets — so a backup.zip that hides an admin hash or a flag surfaces
     automatically.

External tools are used when present (zip2john, john); without them scryer
prints the exact commands to run by hand.
"""

from __future__ import annotations

import base64
import os
import re
import zipfile
from typing import Optional

from ..core import utils, tooling
from ..core.report import HostReport, Finding
from ..data import knowledge

# Files small enough to slurp for forensic analysis.
_MAX_ANALYZE = 8 * 1024 * 1024
_B64_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")


def loot_dir(host: HostReport) -> str:
    """A stable per-target loot directory under the CWD."""
    d = os.path.join(os.getcwd(), "scryer_loot", host.resolved_ip or "target")
    os.makedirs(d, exist_ok=True)
    return d


def handle_archive(host: HostReport, path: str, port: int = 0,
                   service: str = "", pfx: str = "") -> None:
    """Entry point: crack (if needed) + extract + scan a recovered archive."""
    low = path.lower()
    if low.endswith(".zip"):
        _handle_zip(host, path, port, service, pfx)
    elif low.endswith((".kdbx",)):
        _hint_keepass(host, path, port, service, pfx)
    # tar/gz are rarely encrypted — just extract + scan.
    elif low.endswith((".tar.gz", ".tgz", ".tar", ".gz")):
        dest = _extract_tar(path)
        if dest:
            scan_dir(host, dest, port, service, pfx)


# --- zip -------------------------------------------------------------------
def _handle_zip(host: HostReport, path: str, port: int, service: str, pfx: str) -> None:
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()
        encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
    except Exception as exc:
        utils.log("dim", f"not a readable zip ({exc}): {path}", indent=3)
        return

    dest = path + "_extracted"
    os.makedirs(dest, exist_ok=True)

    if not encrypted:
        try:
            zf.extractall(dest)
            utils.log("good", f"extracted {os.path.basename(path)} "
                              f"({len(names)} files)", indent=3)
        except Exception:
            pass
        scan_dir(host, dest, port, service, pfx)
        return

    utils.log("hot", f"{os.path.basename(path)} is password-protected — cracking",
              indent=3)
    host.add(Finding(
        title=f"{pfx}Password-protected archive recovered: {os.path.basename(path)}",
        detail=f"Contains: {', '.join(names[:15])}", severity="medium",
        category="loot", port=port, service=service, evidence=path))

    password = _crack_zip(host, path, port, service, pfx)
    if not password:
        return
    try:
        zf.extractall(dest, pwd=password.encode())
        utils.log("good", f"extracted with password '{password}'", indent=3)
        scan_dir(host, dest, port, service, pfx)
    except Exception as exc:
        utils.log("warn", f"cracked ({password}) but extraction failed: {exc}",
                  indent=3)


def _crack_zip(host: HostReport, path: str, port: int, service: str,
               pfx: str) -> Optional[str]:
    zip2john = tooling.resolve("zip2john")
    john = tooling.resolve("john")
    # Cracking needs depth — prefer rockyou over the small spray list.
    wl = tooling.crack_wordlist()
    weak = False
    if not wl:
        wl = tooling.find_wordlist("passwords")
        weak = True
        utils.log("warn", "rockyou.txt not found — cracking with a small list "
                          "(set $SCRYER_ROCKYOU or install rockyou for real "
                          "coverage)", indent=3)
    if not (zip2john and john and wl):
        cmd = (f"zip2john {path} > hash.txt && "
               f"john --wordlist={wl or '/usr/share/wordlists/rockyou.txt'} hash.txt "
               f"&& john --show hash.txt")
        utils.log("warn", "zip2john/john/wordlist missing — crack by hand:", indent=3)
        utils.log("info", cmd, indent=4)
        host.add(Finding(
            title=f"{pfx}Archive needs cracking: {os.path.basename(path)}",
            detail=cmd, severity="medium", category="loot", port=port,
            service=service, confidence="potential", evidence=path))
        return None

    hashfile = path + ".john"
    rc, out, _ = utils.run([zip2john, path], timeout=60)
    if rc != 0 or not out.strip():
        return None
    try:
        with open(hashfile, "w") as fh:
            fh.write(out)
    except OSError:
        return None

    utils.log("info", f"john --wordlist={os.path.basename(wl)} (up to 4m)", indent=3)
    utils.run([john, f"--wordlist={wl}", hashfile], timeout=240)
    rc, show, _ = utils.run([john, "--show", hashfile], timeout=30)
    password = _parse_john_show(show)
    if password:
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ ARCHIVE PASSWORD CRACKED", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {os.path.basename(path)} : {password}",
                             utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title=f"{pfx}Cracked archive password: {password}",
            detail=f"{os.path.basename(path)} password is '{password}' "
                   "(zip2john + john). Reuse it — passwords are recycled across "
                   "services on CTF boxes.",
            severity="high", category="cred", port=port, service=service,
            evidence=f"{path}:{password}"))
        host.add_cred(password)
    else:
        tail = (" — this was the SMALL bundled list; install rockyou (or set "
                "$SCRYER_ROCKYOU) and re-run for real coverage") if weak else \
               " — try rockyou + rules (john --rules) or a bigger list"
        utils.log("dim", f"john didn't crack it{tail}", indent=3)
        host.add(Finding(
            title=f"{pfx}Archive not cracked: {os.path.basename(path)}",
            detail=f"zip2john {path} > h && john --wordlist="
                   f"{tooling.crack_wordlist() or 'rockyou.txt'} --rules h && "
                   "john --show h", severity="medium", category="loot",
            port=port, service=service, confidence="potential", evidence=path))
    return password


_JOHN_FMT = {32: "raw-md5", 40: "raw-sha1", 64: "raw-sha256"}


def crack_hash(host: HostReport, h: str, source: str, port: int = 0,
               service: str = "", pfx: str = "") -> Optional[str]:
    """Try to crack a raw hash (md5/sha1/sha256) with john + rockyou. On success
    the plaintext is recorded as a credential (and pooled for password reuse);
    on failure a ready hashcat/john command is left behind."""
    fmt = _JOHN_FMT.get(len(h))
    john = tooling.resolve("john")
    wl = tooling.crack_wordlist()
    hc_mode = {32: 0, 40: 100, 64: 1400}.get(len(h), 0)
    if not (fmt and john and wl):
        host.add(Finding(
            title=f"{pfx}Hard-coded hash in {source}",
            detail=f"{h} — crack it: echo {h} > h.txt && hashcat -m {hc_mode} "
                   "h.txt rockyou.txt   (0=MD5,100=SHA1,1400=SHA256).",
            severity="medium", category="cred", port=port, service=service,
            confidence="potential", evidence=f"{source}: {h}"))
        return None

    import tempfile
    hf = os.path.join(tempfile.gettempdir(), f"scryer_hash_{h[:12]}.txt")
    try:
        with open(hf, "w") as fh:
            fh.write(h + "\n")
    except OSError:
        return None
    utils.log("info", f"cracking {fmt} hash with rockyou", indent=3)
    utils.run([john, f"--format={fmt}", f"--wordlist={wl}", hf], timeout=180)
    _rc, show, _ = utils.run([john, f"--format={fmt}", "--show", hf], timeout=30)
    # john --show on a bare-hash file prints "?:<plaintext>" (login is '?'), not
    # "<hash>:<plaintext>", so parse the field after the first colon generically.
    plain = _parse_john_show(show)
    if plain:
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c("║ HASH CRACKED", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {h} ({fmt}) = {plain}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title=f"{pfx}Cracked hash from {source}: {plain}",
            detail=f"{h} ({fmt}) = '{plain}'. Found in {source}. Try it on the "
                   "login form / SSH / every service (password reuse).",
            severity="high", category="cred", port=port, service=service,
            evidence=f"{source}: {h}={plain}"))
        host.add_cred(plain)
    else:
        host.add(Finding(
            title=f"{pfx}Hard-coded hash in {source} (not cracked)",
            detail=f"{h} — john+rockyou missed it; try rules or hashcat -m "
                   f"{hc_mode} with a bigger list.", severity="medium",
            category="cred", port=port, service=service,
            confidence="potential", evidence=f"{source}: {h}"))
    return plain


def _parse_john_show(show: str) -> Optional[str]:
    for line in (show or "").splitlines():
        if ":" in line and not line.strip().endswith("cracked, 0 left") \
                and "password hash" not in line:
            parts = line.split(":")
            if len(parts) >= 2 and parts[1]:
                return parts[1]
    return None


# --- other archive types ---------------------------------------------------
def _extract_tar(path: str) -> Optional[str]:
    import tarfile
    dest = path + "_extracted"
    try:
        os.makedirs(dest, exist_ok=True)
        with tarfile.open(path) as tf:
            # Guard against path traversal in malicious tars.
            safe = [m for m in tf.getmembers()
                    if not (m.name.startswith("/") or ".." in m.name)]
            tf.extractall(dest, members=safe)
        return dest
    except Exception:
        return None


def _hint_keepass(host: HostReport, path: str, port: int, service: str, pfx: str) -> None:
    cmd = (f"keepass2john {path} > kp.hash && "
           "john --wordlist=/usr/share/wordlists/rockyou.txt kp.hash")
    utils.log("hot", f"KeePass database recovered: {os.path.basename(path)}", indent=3)
    host.add(Finding(
        title=f"{pfx}KeePass database recovered: {os.path.basename(path)}",
        detail=f"Crack it offline: {cmd}", severity="high", category="loot",
        port=port, service=service, confidence="potential", evidence=path))


# --- loot scanning ---------------------------------------------------------
def scan_dir(host: HostReport, root: str, port: int = 0, service: str = "",
             pfx: str = "") -> None:
    """Mine every file under *root*: text files for flags/creds/secrets, binary
    and media files through the forensic pass (strings, base64, appended data,
    carving, metadata)."""
    if os.path.isfile(root):
        scan_file(host, root, port, service, pfx)
        return
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            scan_file(host, os.path.join(dirpath, name), port, service, pfx)


def _report_flag(host: HostReport, tok: str, source: str, port: int,
                 service: str, pfx: str, label: str = "FLAG") -> None:
    bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
    print("\n  " + bar)
    print("  " + utils.c(f"║ {label}: {source}", utils.C.GREEN, utils.C.BOLD))
    print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
    print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
    host.add(Finding(
        title=f"{pfx}FLAG recovered: {source}", detail=tok,
        severity="critical", category="flag", port=port, service=service,
        evidence=f"{source}: {tok}"))


def scan_file(host: HostReport, path: str, port: int = 0, service: str = "",
              pfx: str = "") -> None:
    """Mine a single recovered file. Text -> flags/creds/secrets; binary/media
    -> the forensic pass."""
    try:
        size = os.path.getsize(path)
        if size == 0 or size > _MAX_ANALYZE:
            return
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return
    rel = os.path.basename(path)
    # Documents (PDF / Office) first — their real text lives in compressed (or
    # at least non-obvious) streams, and even an uncompressed PDF would be
    # mis-scanned as raw text. Extract the actual text and mine it, then still
    # run the binary forensic pass for stego.
    is_doc = raw[:5] == b"%PDF-" or (
        raw[:2] == b"PK" and rel.lower().endswith((".docx", ".xlsx", ".pptx")))
    doc = _extract_doc_text(path, raw)
    if doc:
        utils.log("good", f"extracted {len(doc)} chars of text from {rel}", indent=3)
        _dump_doc_text(host, rel, doc)
        _scan_text(host, rel, doc, port, service, pfx)
        _scan_doc_creds(host, rel, doc, port, service, pfx)
        _forensics(host, path, rel, raw, port, service, pfx)
        return
    if is_doc:
        # A document we could not read — never fail silently; the whole path may
        # hinge on it (an onboarding PDF with the password).
        utils.log("warn", f"{rel} is a document but text extraction returned "
                          "nothing — open it by hand; for scale install "
                          "poppler-utils (pdftotext) or `pip install pypdf`",
                  indent=3)
        host.add(Finding(
            title=f"{pfx}Unreadable document (open manually): {rel}",
            detail=f"{rel} was recovered but scryer could not extract its text. "
                   "It may hold credentials / the naming convention. Open it: "
                   "pdftotext / any viewer.", severity="high", category="loot",
            port=port, service=service, evidence=rel))
    if _looks_text(raw):
        _scan_text(host, rel, raw.decode("utf-8", "replace"), port, service, pfx)
    else:
        _forensics(host, path, rel, raw, port, service, pfx)


def _extract_doc_text(path: str, raw: bytes) -> str:
    """Pull readable text out of a PDF or an OOXML (docx/xlsx/pptx) file."""
    low = path.lower()
    if raw[:5] == b"%PDF-" or low.endswith(".pdf"):
        return _pdf_text(path)
    if raw[:2] == b"PK" and low.endswith((".docx", ".xlsx", ".pptx")):
        return _ooxml_text(path)
    return ""


def _pdf_text(path: str) -> str:
    tool = tooling.resolve("pdftotext")
    if tool:
        rc, out, _ = utils.run([tool, "-q", "-layout", path, "-"], timeout=30)
        if out and out.strip():
            return out
    try:                                   # pure-python reader, if installed
        try:
            from pypdf import PdfReader
        except Exception:
            from PyPDF2 import PdfReader
        reader = PdfReader(path)
        text = "\n".join((p.extract_text() or "") for p in reader.pages[:50])
        if text.strip():
            return text
    except Exception:
        pass
    # Zero-dependency fallback so scryer reads onboarding PDFs on a bare box
    # (no poppler, no pypdf). Handles FlateDecode + uncompressed content streams.
    try:
        with open(path, "rb") as fh:
            return _pdf_text_builtin(fh.read())
    except OSError:
        return ""


def _pdf_text_builtin(raw: bytes) -> str:
    """Extract visible text from a PDF using only the standard library.

    Walks the file's content streams, zlib-inflates the FlateDecode ones, and
    pulls the operands of the text-showing operators (Tj / TJ). Good enough for
    the simple business documents CTF boxes hand out; not a full PDF parser."""
    import zlib
    chunks = []
    pos = 0
    while True:
        s = raw.find(b"stream", pos)
        if s == -1:
            break
        start = s + 6
        if raw[start:start + 2] == b"\r\n":
            start += 2
        elif raw[start:start + 1] in (b"\n", b"\r"):
            start += 1
        end = raw.find(b"endstream", start)
        if end == -1:
            break
        data = raw[start:end].rstrip(b"\r\n")
        pos = end + 9
        try:
            data = zlib.decompress(data)
        except Exception:
            pass                       # already-plain content stream
        chunks.append(_pdf_ops_text(data))
    return "\n".join(c for c in chunks if c and c.strip())


def _pdf_ops_text(data: bytes) -> str:
    s = data.decode("latin-1", "replace")
    out = []
    # (string) Tj   and   [ (a) -10 (b) ] TJ
    for m in re.finditer(r"\[((?:[^\[\]\\]|\\.)*)\]\s*TJ"
                         r"|\(((?:[^()\\]|\\.)*)\)\s*Tj", s):
        if m.group(2) is not None:
            out.append(_pdf_unescape(m.group(2)))
        else:
            for sm in re.finditer(r"\(((?:[^()\\]|\\.)*)\)", m.group(1)):
                out.append(_pdf_unescape(sm.group(1)))
        out.append(" ")
    return "".join(out)


def _pdf_unescape(s: str) -> str:
    s = (s.replace(r"\(", "(").replace(r"\)", ")").replace(r"\n", "\n")
          .replace(r"\r", "\r").replace(r"\t", "\t").replace("\\\\", "\\"))
    return re.sub(r"\\([0-7]{1,3})", lambda m: chr(int(m.group(1), 8) & 0xFF), s)


def _ooxml_text(path: str) -> str:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return ""
    parts = []
    for name in zf.namelist():
        if name.endswith(".xml") and any(
                k in name for k in ("document", "sharedStrings", "slide", "sheet")):
            try:
                xml = zf.read(name).decode("utf-8", "replace")
            except Exception:
                continue
            parts.append(re.sub(r"<[^>]+>", " ", xml))
    return "\n".join(parts)


_HOSTNAME_RE = re.compile(
    r"(?:https?://)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)", re.I)
_HOST_TLD_OK = re.compile(r"\.(htb|thm|local|lab|corp|internal|vl|box|ctf)$", re.I)


def _harvest_hostnames(text: str):
    """Pull CTF-plausible hostnames out of document/mail text (URLs or bare
    FQDNs). Restricted to lab TLDs + subdomains of an already-known style so a
    real internet domain in the prose isn't chased."""
    out = set()
    for m in _HOSTNAME_RE.finditer(text or ""):
        name = m.group(1).lower().rstrip(".")
        if name.replace(".", "").isdigit():          # not an IP
            continue
        if _HOST_TLD_OK.search(name) and 1 <= name.count(".") <= 4:
            out.add(name)
    return out


def _dump_doc_text(host: HostReport, rel: str, text: str) -> None:
    """Save the extracted document text to loot and echo a short snippet, so a
    credential phrased in a way the regexes miss is still visible to the
    operator (and to the AI advisor / agent)."""
    snippet = " ".join(text.split())[:280]
    utils.log("dim", f"  “{snippet}{'…' if len(text) > 280 else ''}”", indent=3)
    try:
        ip = host.resolved_ip or "target"
        d = os.path.join(os.getcwd(), "scryer_loot", ip, "docs")
        os.makedirs(d, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", rel) + ".txt"
        with open(os.path.join(d, safe), "w") as fh:
            fh.write(text)
    except OSError:
        pass


def _scan_doc_creds(host: HostReport, rel: str, text: str, port: int,
                    service: str, pfx: str) -> None:
    """Loose credential/username mining for onboarding-style documents, where a
    password sits in prose ('Default password: Welcome2Corp!') rather than in a
    config-file idiom. Also harvests emails/usernames for the mail + spray pass."""
    for label, value in knowledge.find_doc_creds(text):
        if label == "Username scheme":
            utils.log("good", f"username scheme in {rel}: {value}", indent=3)
            host.add(Finding(
                title=f"{pfx}Username scheme in document {rel}",
                detail=f"{value} (from {rel}). Derive the mailbox/SSH usernames "
                       "from this and spray the password below.",
                severity="info", category="host", port=port, service=service,
                evidence=value))
            continue
        utils.log("hot", f"{label} in {rel}: {value}", indent=3)
        host.add(Finding(
            title=f"{pfx}{label} in document {rel}",
            detail=f"{value} (from {rel}). Try it over SSH / IMAP / the web "
                   "login, sprayed across the usernames below.",
            severity="high", category="cred", port=port, service=service,
            evidence=f"{rel}: {value}"))
        host.add_cred(value)
    # emails -> mailbox usernames for the mail pass
    emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
    if emails:
        host.__dict__.setdefault("emails", set()).update(e.lower() for e in emails)
        utils.log("good", f"{len(emails)} email(s) in {rel}: "
                          + ", ".join(list(emails)[:6]), indent=3)
    # names + conventions -> a real username list to spray creds over
    users = knowledge.username_variants(text)
    if users:
        host.__dict__.setdefault("usernames", set()).update(users)
        utils.log("good", f"{len(users)} candidate username(s) from {rel}: "
                          + ", ".join(sorted(users)[:10]), indent=3)
    # hostnames / URLs in the doc (e.g. 'Webmail URL: http://mail001.enigma.htb')
    # -> register them so the engine maps + web-enriches the new host.
    for hostname in _harvest_hostnames(text):
        if host.add_hostname(hostname):
            utils.log("hot", f"host from {rel}: "
                             f"{utils.c(hostname, utils.C.CYAN, utils.C.BOLD)} "
                             "-> enumerate", indent=3)
            host.add(Finding(
                title=f"{pfx}Host discovered in document: {hostname}",
                detail=f"{hostname} (referenced in {rel}). scryer maps it and "
                       "web-enriches it — try the recovered creds on any login "
                       "there (webmail / portal).", severity="high",
                category="host", port=port, service=service, evidence=hostname))


def _looks_text(raw: bytes) -> bool:
    sample = raw[:2048]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return not sample or printable / len(sample) > 0.85


def _forensics(host: HostReport, path: str, rel: str, raw: bytes,
               port: int, service: str, pfx: str) -> None:
    """Flag-hunt a binary/media file the way you would by hand: ASCII + wide
    strings, base64 blobs, data appended after an image footer, plus binwalk /
    exiftool when they're installed."""
    utils.log("info", f"forensic scan: {rel}", indent=3)
    found = set()

    def hunt(text: str, source: str):
        for tok in knowledge.find_flags(text or ""):
            if tok not in found:
                found.add(tok)
                _report_flag(host, tok, source, port, service, pfx)

    # 1) ASCII strings + 2) wide-char (UTF-16 LE/BE) strings.
    hunt(_ascii_strings(raw), f"{rel} (strings)")
    hunt(raw.decode("utf-16-le", "ignore"), f"{rel} (utf-16-le)")
    hunt(raw.decode("utf-16-be", "ignore"), f"{rel} (utf-16-be)")

    # 3) base64-encoded flags (a couple of nested layers).
    for blob in _B64_RE.findall(raw)[:400]:
        dec = _b64_multi(blob)
        if dec:
            hunt(dec, f"{rel} (base64)")

    # 4) data appended after a standard image/file footer (classic stego).
    trailing = _trailing_after_footer(raw)
    if trailing is not None:
        off, extra = trailing
        utils.log("hot", f"{rel}: {len(extra)} bytes appended after footer "
                          f"(offset {off}) — carving", indent=4)
        host.add(Finding(
            title=f"{pfx}Appended data after file footer: {rel}",
            detail=f"{len(extra)} bytes trail the image/file end at offset {off} "
                   "— extract and inspect (binwalk / dd). Classic stego hiding "
                   "spot.", severity="high", category="loot", port=port,
            service=service, evidence=rel))
        hunt(_ascii_strings(extra), f"{rel} (appended)")
        for blob in _B64_RE.findall(extra)[:100]:
            dec = _b64_multi(blob)
            if dec:
                hunt(dec, f"{rel} (appended/base64)")
        # If the appended blob is itself an archive, recurse.
        carved = path + ".trailer"
        try:
            with open(carved, "wb") as fh:
                fh.write(extra)
            if extra[:2] == b"PK":
                handle_archive(host, carved, port, service, pfx)
        except OSError:
            pass

    # 5) external carvers / metadata, when present.
    _binwalk(host, path, rel, port, service, pfx, hunt)
    _exiftool(host, path, rel, port, service, pfx, hunt)


def _ascii_strings(raw: bytes, minlen: int = 4) -> str:
    out, cur = [], []
    for b in raw:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur).decode("latin-1"))
            cur = []
    if len(cur) >= minlen:
        out.append(bytes(cur).decode("latin-1"))
    return "\n".join(out)


def _b64_multi(blob: bytes, rounds: int = 3) -> str:
    """Decode up to `rounds` nested base64 layers; return the first decode that
    yields mostly-printable text (where a flag might hide)."""
    data = blob
    best = ""
    for _ in range(rounds):
        try:
            dec = base64.b64decode(data + b"=" * (-len(data) % 4), validate=False)
        except Exception:
            break
        if not dec:
            break
        text = dec.decode("latin-1", "replace")
        printable = sum(1 for c in dec if 9 <= c <= 13 or 32 <= c <= 126)
        if dec and printable / len(dec) > 0.85:
            best = text
            data = dec  # try to peel another layer
        else:
            break
    return best


# File-format footers: signature prefix -> footer marker.
_FOOTERS = [
    (b"\x89PNG\r\n\x1a\n", b"\x49\x45\x4e\x44\xae\x42\x60\x82"),   # PNG IEND+CRC
    (b"\xff\xd8\xff", b"\xff\xd9"),                                 # JPEG EOI
    (b"GIF8", b"\x00\x3b"),                                          # GIF trailer
]


def _trailing_after_footer(raw: bytes):
    """If the file is a known image type and bytes follow its footer, return
    (offset, trailing_bytes)."""
    for sig, footer in _FOOTERS:
        if raw.startswith(sig):
            idx = raw.rfind(footer)
            if idx == -1:
                return None
            end = idx + len(footer)
            if end < len(raw) - 1:   # tolerate a stray padding byte
                extra = raw[end:]
                if extra.strip(b"\x00\r\n "):
                    return end, extra
            return None
    return None


def _binwalk(host, path, rel, port, service, pfx, hunt) -> None:
    tool = tooling.resolve("binwalk")
    if not tool:
        return
    outdir = path + ".binwalk"
    rc, out, _ = utils.run([tool, "--run-as=root", "-e", "--directory", outdir, path],
                           timeout=120)
    if rc != 0:
        # older binwalk without --directory
        utils.run([tool, "-e", path], timeout=120)
        outdir = os.path.join(os.path.dirname(path), f"_{rel}.extracted")
    if out and ("compressed" in out.lower() or "archive" in out.lower()
                or "zip" in out.lower()):
        utils.log("good", f"binwalk found embedded data in {rel}", indent=4)
        host.add(Finding(
            title=f"{pfx}Embedded files inside {rel} (binwalk)",
            detail=out[:400], severity="medium", category="loot", port=port,
            service=service, evidence=rel))
    if os.path.isdir(outdir):
        for dp, _d, fs in os.walk(outdir):
            for f in fs:
                try:
                    with open(os.path.join(dp, f), "rb") as fh:
                        hunt(_ascii_strings(fh.read(_MAX_ANALYZE)),
                             f"{rel} (binwalk:{f})")
                except OSError:
                    pass


def _exiftool(host, path, rel, port, service, pfx, hunt) -> None:
    tool = tooling.resolve("exiftool")
    if not tool:
        return
    rc, out, _ = utils.run([tool, path], timeout=30)
    if rc == 0 and out:
        hunt(out, f"{rel} (exif)")
        # Surface comment/author/description fields explicitly.
        for line in out.splitlines():
            low = line.lower()
            if any(k in low for k in ("comment", "description", "artist",
                                      "author", "keywords", "user comment")):
                val = line.split(":", 1)[-1].strip()
                if val and len(val) > 3:
                    utils.log("good", f"exif {line.split(':',1)[0].strip()}: "
                                      f"{val[:60]}", indent=4)


def _scan_text(host: HostReport, rel: str, body: str, port: int,
               service: str, pfx: str) -> None:
    # Hashes-in-context first, so a bare 32-hex that is really a password hash
    # embedded in code isn't also mis-reported as a flag. (A standalone hex in
    # user.txt/root.txt has no keyword context, so it stays a flag.)
    hashes = set(knowledge.find_hashes(body)) if hasattr(knowledge, "find_hashes") else set()
    # Bare 32-hex only counts as a flag from an actual flag file (user.txt /
    # root.txt / flag.txt) or a file whose entire content is one 32-hex token —
    # otherwise a stray md5 in a config/doc gets mis-reported as a flag.
    base = os.path.basename(rel).lower()
    allow_hex = (base in knowledge.FLAG_FILES
                 or bool(re.fullmatch(r"[0-9a-fA-F]{32}", body.strip())))
    # Flags (skipping anything already identified as a credential hash).
    for tok in knowledge.find_flags(body, allow_hex=allow_hex):
        if tok in hashes:
            continue
        bar = utils.c("╔" + "═" * 56, utils.C.GREEN, utils.C.BOLD)
        print("\n  " + bar)
        print("  " + utils.c(f"║ FLAG in recovered file: {rel}", utils.C.GREEN, utils.C.BOLD))
        print("  " + utils.c(f"║ {tok}", utils.C.YELLOW, utils.C.BOLD))
        print("  " + utils.c("╚" + "═" * 56, utils.C.GREEN, utils.C.BOLD) + "\n")
        host.add(Finding(
            title=f"{pfx}FLAG in recovered loot: {rel}", detail=tok,
            severity="critical", category="flag", port=port, service=service,
            evidence=f"{rel}: {tok}"))
    # Credentials / hard-coded secrets (env-style + code idioms).
    secrets = list(knowledge.extract_secrets(body))
    if hasattr(knowledge, "extract_code_secrets"):
        secrets += list(knowledge.extract_code_secrets(body))
    seen = set()
    for label, value, sev in secrets:
        if value in seen:
            continue
        seen.add(value)
        utils.log("hot", f"{label} in {rel}: {value[:50]}", indent=3)
        host.add(Finding(
            title=f"{pfx}{label} in recovered file {rel}",
            detail=f"{value[:80]} (from {rel})", severity=sev, category="cred",
            port=port, service=service, evidence=f"{rel}: {value}"))
        if "pass" in label.lower() or "credential" in label.lower():
            host.add_cred(value)
    # PHP DB-connect positional creds (db.php: mysqli_connect(...,'user','pass',...))
    # + ADO/.NET connection strings (dtsConfig/web.config: Password=..;User ID=..).
    for duser, dpw in list(knowledge.find_db_creds(body)) + list(knowledge.find_conn_creds(body)):
        acct = duser.split("\\")[-1] if duser else "?"
        utils.log("hot", f"credential in {rel}: {duser or acct} / {dpw}", indent=3)
        host.add(Finding(
            title=f"{pfx}Credential in {rel}: {duser or acct}",
            detail=f"{duser or acct}:{dpw} (from {rel}). Reuse it across "
                   "SMB/MSSQL/WinRM/SSH — password reuse is the usual pivot.",
            severity="high", category="cred", port=port, service=service,
            evidence=f"{rel}: {duser or acct}:{dpw}"))
        host.add_cred(dpw)
    # Hard-coded hashes (e.g. md5(...) === "..."): try to crack them outright.
    for h in list(hashes)[:5]:
        utils.log("hot", f"hash in {rel}: {h}", indent=3)
        crack_hash(host, h, rel, port, service, pfx)
    # Prose credentials — onboarding/HR text files ("Default password: ...").
    if rel.lower().endswith((".txt", ".md", ".csv", ".log", ".rtf", ".text")):
        _scan_doc_creds(host, rel, body, port, service, pfx)
