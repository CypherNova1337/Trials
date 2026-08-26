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

import os
import zipfile
from typing import Optional

from ..core import utils, tooling
from ..core.report import HostReport, Finding
from ..data import knowledge


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
    wl = tooling.find_wordlist("passwords")
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
        utils.log("dim", "john didn't crack it with this wordlist — try "
                         "rockyou + rules, or a bigger list", indent=3)
    return password


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
    """Read every text-ish file under *root* and mine it for flags, credentials
    and hard-coded secrets."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            fpath = os.path.join(dirpath, name)
            try:
                if os.path.getsize(fpath) > 512_000:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    body = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(fpath, root)
            _scan_text(host, rel, body, port, service, pfx)


def scan_file(host: HostReport, path: str, port: int = 0, service: str = "",
              pfx: str = "") -> None:
    """Mine a single recovered file for flags/credentials/secrets."""
    try:
        if os.path.getsize(path) > 512_000:
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            body = fh.read()
    except OSError:
        return
    _scan_text(host, os.path.basename(path), body, port, service, pfx)


def _scan_text(host: HostReport, rel: str, body: str, port: int,
               service: str, pfx: str) -> None:
    # Hashes-in-context first, so a bare 32-hex that is really a password hash
    # embedded in code isn't also mis-reported as a flag. (A standalone hex in
    # user.txt/root.txt has no keyword context, so it stays a flag.)
    hashes = set(knowledge.find_hashes(body)) if hasattr(knowledge, "find_hashes") else set()
    # Flags (skipping anything already identified as a credential hash).
    for tok in knowledge.find_flags(body):
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
    # Hard-coded hashes (e.g. md5(...) === "..."): report with a crack hint.
    for h in hashes:
        utils.log("hot", f"hash in {rel}: {h}", indent=3)
        host.add(Finding(
            title=f"{pfx}Hard-coded hash in {rel}",
            detail=f"{h} — identify + crack: hashid '{h}'; hashcat -m <mode> "
                   "(0=MD5) with rockyou.",
            severity="medium", category="cred", port=port, service=service,
            confidence="potential", evidence=f"{rel}: {h}"))
