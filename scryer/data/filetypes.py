"""File-type intelligence.

Classify web files by extension AND magic bytes, grade the ones that matter,
and generate backup / extension candidates for discovery. Grounded in the
file-based footholds that recur across HTB / CTF boxes:

  * exposed SSH private keys (id_rsa, *.pem, *.ppk)
  * credential stores — KeePass (.kdbx), .psafe3, browser/rclone/wallet files
  * source-code backups (viewdoc.bak leaks viewdoc.jsp's source), vim .swp
  * .env / config / secrets files (DB creds, API keys)
  * database dumps (.sql, .sqlite, .bak)
  * packet captures (.pcap) — creds in cleartext traffic
  * archives (.zip/.tar.gz) full of source or credentials
  * office docs / PDFs carrying metadata and embedded creds
"""

from __future__ import annotations

from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Extension -> (category, severity, note). Severity is the *potential* value
# of the file if reachable; scryer confirms with content where it can.
# ---------------------------------------------------------------------------
_KEY = ("private-key", "critical",
        "Private key — try it for SSH/decrypt straight away.")
_CRED = ("cred-store", "critical",
         "Credential store — crack offline (keepass2john / hashcat) for a vault of creds.")
_KEYSTORE = ("keystore", "high", "Keystore/PKCS12 — extract keys/certs (openssl / keytool).")
_BACKUP = ("backup", "high",
           "Backup of a live file — often leaks source or an older config with creds.")
_ARCHIVE = ("archive", "medium",
            "Archive — download and unpack; frequently holds source or credentials.")
_DB = ("database", "high", "Database/dump — grep for users, hashes and passwords.")
_CONFIG = ("config", "high", "Config file — check for DB creds, API keys, secrets.")
_SOURCE = ("source", "medium",
           "Server source — read for logic flaws and hard-coded credentials.")
_CAPTURE = ("capture", "high",
            "Packet capture — follow TCP streams for cleartext creds (Wireshark).")
_DOC = ("document", "low", "Document — check metadata (exiftool) and body for creds.")
_CERT = ("certificate", "low", "Certificate — inspect for hostnames / validity.")
_IMGDUMP = ("disk/dump", "medium", "Disk/memory image — carve for creds and secrets.")
_LOG = ("log", "low", "Log — may leak paths, tokens, usernames.")

EXT_INFO = {
    # private keys
    "pem": _KEY, "key": _KEY, "ppk": _KEY, "priv": _KEY, "pk8": _KEY, "id_rsa": _KEY,
    # credential stores
    "kdbx": _CRED, "kdb": _CRED, "psafe3": _CRED, "agilekeychain": _CRED,
    "opvault": _CRED, "keychain": _CRED, "wallet": _CRED, "vault": _CRED,
    "kwallet": _CRED,
    # keystores
    "pfx": _KEYSTORE, "p12": _KEYSTORE, "jks": _KEYSTORE, "keystore": _KEYSTORE,
    # backups / editor swap
    "bak": _BACKUP, "old": _BACKUP, "orig": _BACKUP, "save": _BACKUP, "bkp": _BACKUP,
    "backup": _BACKUP, "copy": _BACKUP, "tmp": _BACKUP, "temp": _BACKUP,
    "swp": _BACKUP, "swo": _BACKUP, "swn": _BACKUP, "~": _BACKUP,
    # archives
    "zip": _ARCHIVE, "rar": _ARCHIVE, "7z": _ARCHIVE, "tar": _ARCHIVE,
    "gz": _ARCHIVE, "tgz": _ARCHIVE, "bz2": _ARCHIVE, "xz": _ARCHIVE,
    "tar.gz": _ARCHIVE, "tar.bz2": _ARCHIVE, "tar.xz": _ARCHIVE, "war": _ARCHIVE,
    # databases
    "sql": _DB, "db": _DB, "sqlite": _DB, "sqlite3": _DB, "mdb": _DB, "accdb": _DB,
    "dbf": _DB, "dump": _DB, "sql.gz": _DB, "sql.zip": _DB, "bacpac": _DB, "mdf": _DB,
    # config / secrets
    "env": _CONFIG, "conf": _CONFIG, "config": _CONFIG, "cfg": _CONFIG, "ini": _CONFIG,
    "yml": _CONFIG, "yaml": _CONFIG, "toml": _CONFIG, "properties": _CONFIG,
    "htpasswd": _CONFIG, "npmrc": _CONFIG, "netrc": _CONFIG, "pgpass": _CONFIG,
    # source
    "php": _SOURCE, "phps": _SOURCE, "php3": _SOURCE, "php5": _SOURCE, "phtml": _SOURCE,
    "inc": _SOURCE, "asp": _SOURCE, "aspx": _SOURCE, "asmx": _SOURCE, "ashx": _SOURCE,
    "jsp": _SOURCE, "jspx": _SOURCE, "py": _SOURCE, "rb": _SOURCE, "pl": _SOURCE,
    "cgi": _SOURCE, "java": _SOURCE, "cs": _SOURCE, "go": _SOURCE, "sh": _SOURCE,
    "ps1": _SOURCE, "vbs": _SOURCE, "lua": _SOURCE, "cfm": _SOURCE,
    # captures
    "pcap": _CAPTURE, "pcapng": _CAPTURE, "cap": _CAPTURE, "etl": _CAPTURE,
    # documents
    "pdf": _DOC, "doc": _DOC, "docx": _DOC, "xls": _DOC, "xlsx": _DOC, "ppt": _DOC,
    "pptx": _DOC, "odt": _DOC, "ods": _DOC, "rtf": _DOC, "csv": _DOC, "one": _DOC,
    # certs
    "crt": _CERT, "cer": _CERT, "csr": _CERT, "der": _CERT, "pub": _CERT,
    # disk / memory
    "vmdk": _IMGDUMP, "vdi": _IMGDUMP, "vhd": _IMGDUMP, "vhdx": _IMGDUMP,
    "ova": _IMGDUMP, "ovf": _IMGDUMP, "img": _IMGDUMP, "iso": _IMGDUMP,
    "dmp": _IMGDUMP, "core": _IMGDUMP, "mem": _IMGDUMP, "raw": _IMGDUMP,
    # logs
    "log": _LOG,
}

# Bare filenames (no useful extension) that are high value by name.
NAME_INFO = {
    "id_rsa": _KEY, "id_dsa": _KEY, "id_ecdsa": _KEY, "id_ed25519": _KEY,
    "id_rsa.pub": _CERT, "authorized_keys": ("config", "medium",
        "authorized_keys — reveals users with key access."),
    "known_hosts": ("config", "low", "known_hosts — reveals reachable internal hosts."),
    ".netrc": _CONFIG, ".pgpass": _CONFIG, ".git-credentials": ("config", "high",
        ".git-credentials — plaintext repo creds."),
    ".bash_history": ("config", "medium", "Shell history — often contains passwords."),
    ".mysql_history": ("config", "medium", "MySQL history — may contain passwords."),
    ".dockercfg": _CONFIG, ".npmrc": _CONFIG, "credentials": _CONFIG,
    "secrets": _CONFIG, "web.config": ("config", "high",
        "web.config — connection strings, machineKey, secrets."),
    ".htpasswd": ("config", "high", ".htpasswd — crackable credential hashes."),
    "shadow": ("cred-store", "critical", "/etc/shadow — crack with hashcat mode 1800."),
    "passwd": ("config", "medium", "/etc/passwd — enumerate users (and LFI proof)."),
    "wp-config.php": _CONFIG, "configuration.php": _CONFIG, "settings.py": _CONFIG,
    "local.settings.json": _CONFIG, "appsettings.json": _CONFIG,
}

_COMPOUND = ("tar.gz", "tar.bz2", "tar.xz", "sql.gz", "sql.zip", "tar.z")


def _split_ext(path: str) -> Tuple[str, str]:
    base = path.rstrip("/").split("/")[-1].lower()
    for c in _COMPOUND:
        if base.endswith("." + c):
            return base, c
    if base.endswith("~"):
        return base, "~"
    _, dot, ext = base.rpartition(".")
    return base, (ext if dot else "")


def classify(path: str):
    """Return (category, severity, note, tag) for a path, or None if boring.
    *tag* is the extension or filename that matched."""
    base, ext = _split_ext(path)
    if base in NAME_INFO:
        cat, sev, note = NAME_INFO[base]
        return cat, sev, note, base
    if ext and ext in EXT_INFO:
        cat, sev, note = EXT_INFO[ext]
        return cat, sev, note, ext
    return None


# ---------------------------------------------------------------------------
# Magic-byte signatures — classify content regardless of extension (catches
# mislabeled files and polyglots, e.g. a KeePass db served as .txt).
# ---------------------------------------------------------------------------
_MAGIC = [
    (b"-----BEGIN OPENSSH PRIVATE KEY", "OpenSSH private key"),
    (b"-----BEGIN RSA PRIVATE KEY", "RSA private key"),
    (b"-----BEGIN EC PRIVATE KEY", "EC private key"),
    (b"-----BEGIN DSA PRIVATE KEY", "DSA private key"),
    (b"-----BEGIN PGP PRIVATE KEY", "PGP private key"),
    (b"PuTTY-User-Key-File", "PuTTY private key (.ppk)"),
    (b"\x03\xd9\xa2\x9a", "KeePass database (.kdbx)"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"PK\x03\x04", "ZIP archive (source/creds?)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"\xd4\xc3\xb2\xa1", "pcap capture"),
    (b"\xa1\xb2\xc3\xd4", "pcap capture"),
    (b"\x0a\x0d\x0d\x0a", "pcapng capture"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"),
    (b"\xd0\xcf\x11\xe0", "MS Office (legacy) document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
]

# Which magic labels are worth surfacing as findings, and at what severity.
_MAGIC_SEV = {
    "OpenSSH private key": "critical", "RSA private key": "critical",
    "EC private key": "critical", "DSA private key": "critical",
    "PGP private key": "critical", "PuTTY private key (.ppk)": "critical",
    "KeePass database (.kdbx)": "critical", "SQLite database": "high",
    "ZIP archive (source/creds?)": "medium", "RAR archive": "medium",
    "7-Zip archive": "medium", "gzip archive": "medium", "bzip2 archive": "medium",
    "pcap capture": "high", "pcapng capture": "high",
    "MS Office (legacy) document": "low", "PDF document": "low",
    "ELF executable": "low", "Windows PE executable": "low",
}


def sniff(data: bytes) -> Optional[str]:
    """Return a human label for the file type of *data* by magic bytes."""
    if not data:
        return None
    for sig, label in _MAGIC:
        if data.startswith(sig):
            return label
    return None


def magic_severity(label: str) -> Optional[str]:
    return _MAGIC_SEV.get(label)


# ---------------------------------------------------------------------------
# Discovery candidate generation
# ---------------------------------------------------------------------------
# Suffixes appended to a discovered file to find its backup (viewdoc.jsp ->
# viewdoc.jsp.bak, viewdoc.jsp~, .viewdoc.jsp.swp, viewdoc.jsp.save ...).
_BACKUP_SUFFIXES = [".bak", "~", ".old", ".save", ".orig", ".txt", ".bkp",
                    ".backup", ".1", ".swp", ".zip"]


def backup_candidates(path: str) -> List[str]:
    """Given a path like 'admin/config.php', yield likely backup paths."""
    path = path.strip("/")
    if not path or path.endswith("/"):
        return []
    cands = [path + s for s in _BACKUP_SUFFIXES]
    # vim swap lives beside the file as .name.swp
    d = path.rsplit("/", 1)
    if len(d) == 2:
        cands.append(f"{d[0]}/.{d[1]}.swp")
    else:
        cands.append(f".{path}.swp")
    # drop the extension entirely: index.php -> index.bak / index.old
    base, _dot, ext = path.rpartition(".")
    if _dot and ext and "/" not in ext:
        cands += [base + ".bak", base + ".old", base + "~"]
    # de-dup, preserve order
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# Extensions to fuzz during content discovery, keyed by detected server tech.
EXT_BY_TECH = {
    "php": ["php", "phps", "php.bak", "php~", "inc", "bak", "old", "txt", "zip"],
    "asp": ["asp", "aspx", "asmx", "ashx", "config", "bak", "old", "txt", "zip"],
    "java": ["jsp", "jspx", "do", "action", "war", "bak", "old", "txt", "zip"],
    "python": ["py", "py.bak", "pyc", "wsgi", "bak", "old", "txt", "zip"],
    "generic": ["bak", "old", "txt", "zip", "tar.gz", "sql", "conf", "config", "~"],
}


def ext_candidates_for(tech: str) -> List[str]:
    return EXT_BY_TECH.get(tech, EXT_BY_TECH["generic"])


def tech_from_text(text: str) -> str:
    """Infer a tech bucket from a server/x-powered-by/url blob for ext fuzzing."""
    t = (text or "").lower()
    if any(k in t for k in ("php", "wordpress", "laravel", "drupal", "joomla")):
        return "php"
    if any(k in t for k in ("asp.net", "iis", "aspx", "microsoft-iis")):
        return "asp"
    if any(k in t for k in ("java", "tomcat", "jetty", "jboss", "servlet", "jsp")):
        return "java"
    if any(k in t for k in ("python", "werkzeug", "flask", "django", "gunicorn")):
        return "python"
    return "generic"


# High-value bare filenames to fold into the built-in discovery list.
INTERESTING_FILENAMES = [
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/id_rsa",
    "authorized_keys", ".netrc", ".git-credentials", ".bash_history",
    "backup.zip", "backup.tar.gz", "backup.sql", "site.zip", "www.zip",
    "web.zip", "source.zip", "app.zip", "html.tar.gz", "db.sqlite3",
    "database.sqlite", "dump.sql", "database.sql", "users.sql",
    "Database.kdbx", "database.kdbx", "passwords.kdbx", "keepass.kdbx",
    "capture.pcap", "dump.pcap", "traffic.pcap", "web.config",
    "wp-config.php.bak", "config.php.bak", "config.php~", "config.php.save",
    "index.php.bak", "index.php~", ".htpasswd", "credentials.txt",
    "passwords.txt", "users.txt", "notes.txt", "todo.txt",
]
