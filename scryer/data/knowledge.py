"""Static knowledge: common port map, service probes and version hint rules."""

from __future__ import annotations

import re

# Common TCP ports probed in the default "top" scan. Curated toward the
# services that actually show up on CTF / lab boxes.
TOP_PORTS = [
    21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 465, 512, 513, 514, 587, 623, 636, 873, 990, 993, 995,
    1099, 1433, 1521, 2049, 2121, 2222, 3000, 3128, 3306, 3389, 3690,
    4369, 5000, 5432, 5555, 5601, 5672, 5900, 5985, 5986, 6000, 6379,
    6667, 7001, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 27018, 50000,
]

# Well-known port -> nominal service name.
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    79: "finger", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 512: "exec",
    513: "login", 514: "shell", 587: "submission", 636: "ldaps",
    873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1099: "java-rmi", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2121: "ftp", 2222: "ssh", 3000: "http", 3128: "http-proxy",
    3306: "mysql", 3389: "rdp", 3690: "svn", 4369: "epmd",
    5000: "http", 5432: "postgresql", 5555: "adb", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
    6000: "x11", 6379: "redis", 6667: "irc", 7001: "weblogic",
    8000: "http", 8008: "http", 8009: "ajp13", 8080: "http",
    8081: "http", 8443: "https", 8888: "http", 9000: "http",
    9090: "http", 9200: "elasticsearch", 9300: "elasticsearch",
    10000: "http", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 50000: "http",
}

# Ports that should be treated as HTTP(S) by the web module.
HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 10000, 50000}
HTTPS_PORTS = {443, 8443, 5601}

# Payloads that coax a banner out of otherwise-quiet services, keyed by port.
SERVICE_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    25: b"",       # SMTP greets on connect
    110: b"",      # POP3 greets on connect
    143: b"",      # IMAP greets on connect
    21: b"",       # FTP greets on connect
    22: b"",       # SSH greets on connect
    6379: b"INFO\r\n",
    11211: b"stats\r\n",
}

# Version-string heuristics. Each rule maps a compiled regex to a
# (severity, note) hint surfaced against the matching banner/version.
_RAW_HINTS = [
    (r"(?i)craft ?cms", "high", "Craft CMS — check version for CVE-2023-41892 (unauth RCE) and CVE-2024-56145."),
    (r"vsftpd 2\.3\.4", "critical", "vsftpd 2.3.4 ships a well-known backdoor (CVE-2011-2523)."),
    (r"ProFTPD 1\.3\.[35]", "high", "ProFTPD 1.3.3c/1.3.5 have public RCE (mod_copy / backdoor)."),
    (r"OpenSSH [1-6]\.", "low", "Old OpenSSH — check for username enumeration / weak KEX."),
    (r"OpenSSH 7\.[0-6]", "low", "OpenSSH <7.7 vulnerable to username enumeration (CVE-2018-15473)."),
    (r"Apache/2\.4\.49", "critical", "Apache 2.4.49 path traversal / RCE (CVE-2021-41773)."),
    (r"Apache/2\.4\.50", "high", "Apache 2.4.50 incomplete fix, still exploitable (CVE-2021-42013)."),
    (r"Microsoft-IIS/6\.0", "high", "IIS 6.0 WebDAV RCE (CVE-2017-7269)."),
    (r"(?i)samba 3\.", "high", "Samba 3.x — check SambaCry / usermap_script (CVE-2007-2447)."),
    (r"(?i)samba 4\.[0-5]", "medium", "Older Samba 4.x — review CVE-2017-7494 exposure."),
    (r"(?i)webmin", "medium", "Webmin exposed — several versions carry auth-bypass RCE."),
    (r"(?i)jenkins", "medium", "Jenkins exposed — check for anon script console / old CVEs."),
    (r"(?i)tomcat", "low", "Tomcat — probe /manager/html for weak creds and PUT upload."),
    (r"(?i)phpmyadmin", "medium", "phpMyAdmin exposed — check version CVEs and default creds."),
    (r"(?i)drupal 7", "high", "Drupal 7 — Drupalgeddon 1/2 (CVE-2014-3704 / 2018-7600)."),
    (r"(?i)wordpress", "low", "WordPress — enumerate plugins/users and check xmlrpc.php."),
    (r"(?i)heartbleed|openssl 1\.0\.1[ -f]", "high", "OpenSSL 1.0.1 branch — check for Heartbleed."),
    (r"(?i)shellshock|mod_cgi", "medium", "CGI present — probe for Shellshock (CVE-2014-6271)."),
    (r"(?i)redis", "high", "Redis often unauthenticated — try CONFIG SET for RCE / SSH key write."),
    (r"(?i)elasticsearch", "medium", "Elasticsearch — check for open indices and old RCE CVEs."),
    (r"(?i)mongodb", "medium", "MongoDB — test for no-auth access to databases."),
    (r"(?i)memcached", "low", "Memcached — may be UDP-amplifiable / leak cached data."),
]

VERSION_HINTS = [(re.compile(pat), sev, note) for pat, sev, note in _RAW_HINTS]


def match_hints(text: str):
    """Yield (severity, note) for every version-hint rule matching *text*."""
    if not text:
        return
    for pattern, sev, note in VERSION_HINTS:
        if pattern.search(text):
            yield sev, note


# Small built-in path list for lightweight web content discovery. Kept short
# on purpose — this is a signal-finder, not a replacement for a real fuzzer.
COMMON_WEB_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env",
    ".env.bak", ".env.example", ".htaccess", "admin/", "administrator/",
    "login", "login.php", "wp-login.php", "wp-admin/", "wp-config.php",
    "wp-config.php.bak", "phpmyadmin/", "server-status", "server-info",
    "config.php", "config.php.bak", "config.json", "config.yml",
    "configuration.php", "settings.py", "application.properties",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "backup/", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "api/", "api/v1/", "graphql", "swagger.json",
    "openapi.json", "swagger-ui/", "actuator", "actuator/health",
    "actuator/env", "manager/html", "console/", "cgi-bin/", "uploads/",
    "test.php", "info.php", "phpinfo.php", "readme.html", "CHANGELOG.md",
    "composer.json", "package.json", "id_rsa", ".ssh/id_rsa",
    ".well-known/security.txt",
    # flag / proof files — grabbed and printed automatically when found
    "flag", "flag.txt", "flags.txt", "user.txt", "root.txt", "proof.txt",
    "user.flag", "root.flag", "flag.php", "flag.html",
]

# High-value files by type (keys, credential stores, backups, dumps, captures)
# — appended to the discovery list from the file-type knowledge base.
try:
    from . import filetypes as _ft
    for _f in _ft.INTERESTING_FILENAMES:
        if _f not in COMMON_WEB_PATHS:
            COMMON_WEB_PATHS.append(_f)
except Exception:  # pragma: no cover - keep discovery working if import fails
    pass

# Filenames that hold a flag/proof — when one of these returns content, scryer
# prints the contents outright instead of just noting the path.
FLAG_FILES = {
    "flag", "flag.txt", "flags.txt", "user.txt", "root.txt", "proof.txt",
    "user.flag", "root.flag", "flag.php", "flag.html", "flag.json",
}

# Recognisable flag formats: HTB{...}/flag{...}/CTF{...} and the bare 32-hex
# HTB-style hash. Used to spot flags inside any response body too.
FLAG_RE = re.compile(
    r"(?:[A-Za-z0-9_]{2,20}\{[^}\r\n]{2,120}\}|\b[0-9a-fA-F]{32}\b)")


def find_flags(text: str):
    """Yield distinct flag-format tokens found in *text*."""
    if not text:
        return
    seen = set()
    for m in FLAG_RE.finditer(text):
        tok = m.group(0)
        if tok not in seen:
            seen.add(tok)
            yield tok

# Files worth downloading and parsing for secrets when they return content.
SECRET_FILES = {
    ".env", ".env.bak", ".env.example", "docker-compose.yml",
    "docker-compose.yaml", "config.php", "config.php.bak", "wp-config.php",
    "wp-config.php.bak", "config.json", "config.yml", "settings.py",
    "application.properties", "database.sql", "dump.sql", "db.sql",
    ".git/config", "id_rsa", ".ssh/id_rsa", "actuator/env",
}

# Regexes that pull credentials / keys out of leaked config bodies. Each entry
# is (label, compiled-regex, severity). The value is captured in group 1.
_RAW_SECRETS = [
    ("DB password", r"(?im)^\s*(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|"
     r"POSTGRES_PASSWORD|PGPASSWORD)\s*[:=]\s*[\"']?([^\s\"'#]+)", "high"),
    ("DB username", r"(?im)^\s*(?:DB_USERNAME|DATABASE_USER|MYSQL_USER|"
     r"POSTGRES_USER)\s*[:=]\s*[\"']?([^\s\"'#]+)", "medium"),
    ("DB host", r"(?im)^\s*(?:DB_HOST|DATABASE_HOST|MYSQL_HOST)\s*[:=]\s*"
     r"[\"']?([^\s\"'#]+)", "low"),
    ("App/secret key", r"(?im)^\s*(?:APP_KEY|SECRET_KEY|JWT_SECRET|"
     r"ENCRYPTION_KEY|API_SECRET)\s*[:=]\s*[\"']?([^\s\"'#]+)", "high"),
    ("API token", r"(?im)^\s*(?:API_KEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN)"
     r"\s*[:=]\s*[\"']?([^\s\"'#]+)", "high"),
    ("AWS access key", r"(AKIA[0-9A-Z]{16})", "critical"),
    ("AWS secret key", r"(?im)aws_secret_access_key\s*[:=]\s*"
     r"[\"']?([A-Za-z0-9/+=]{40})", "critical"),
    ("Private key", r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----",
     "critical"),
    ("Slack token", r"(xox[baprs]-[0-9A-Za-z-]{10,})", "high"),
    ("Generic password", r"(?im)^\s*(?:password|passwd|pass|pwd)\s*[:=]\s*"
     r"[\"']([^\"'\n]{3,})[\"']", "medium"),
    ("Mail credentials", r"(?im)^\s*(?:MAIL_PASSWORD|SMTP_PASSWORD)\s*[:=]\s*"
     r"[\"']?([^\s\"'#]+)", "medium"),
    ("Connection string", r"((?:mysql|postgres|postgresql|mongodb|redis|"
     r"amqp)://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+)", "high"),
]
SECRET_PATTERNS = [(label, re.compile(pat), sev) for label, pat, sev in _RAW_SECRETS]


def extract_secrets(text: str):
    """Yield (label, value, severity) for every secret pattern found in text."""
    if not text:
        return
    for label, pattern, sev in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            yield label, value.strip(), sev


# Code-idiom secret patterns for SOURCE / backup / config files (PHP define(),
# variable assignments, hash/array pairs) — too permissive for arbitrary HTML,
# so only run against files scryer has classified as source/backup/config.
_CODE_SECRETS = [
    # define('DB_PASSWORD', 'value')  /  define("SECRET_KEY","value")
    (re.compile(r"""(?i)define\s*\(\s*['"]([A-Za-z0-9_]*"""
                r"""(?:pass|pwd|secret|api[_-]?key|token|passwd)[A-Za-z0-9_]*)"""
                r"""['"]\s*,\s*['"]([^'"\n]{3,120})['"]"""), "high"),
    # $db_password = 'value'  /  password: "value"  /  pwd => 'value'
    (re.compile(r"""(?i)[$@]?\b([A-Za-z0-9_]*"""
                r"""(?:passw(?:or)?d|_pass|\bpass|pwd|secret|api[_-]?key|"""
                r"""auth[_-]?token|token)[A-Za-z0-9_]*)\b"""
                r"""\s*(?:=>|=|:)\s*['"]([^'"\n]{3,120})['"]"""), "high"),
]
_PLACEHOLDER = re.compile(r"(?i)^(?:your|example|changeme|xxx+|test|password|"
                          r"placeholder|<[^>]+>|\$\{|%[a-z]|null|none|true|false)$")


def extract_code_secrets(text: str):
    """Yield (label, value, severity) for credential idioms in source/config."""
    if not text:
        return
    seen = set()
    for pattern, sev in _CODE_SECRETS:
        for m in pattern.finditer(text):
            name, value = m.group(1), m.group(2).strip()
            if not value or _PLACEHOLDER.match(value):
                continue
            key = (name.lower(), value)
            if key in seen:
                continue
            seen.add(key)
            yield f"Credential ({name})", value, sev


# Curated virtual-host / subdomain wordlist. On CTF boxes the real foothold
# frequently hides behind a name-based vhost (git., dev., admin., …) that the
# default server block hides. Ordered roughly by how often it pays off.
COMMON_VHOSTS = [
    "www", "dev", "development", "staging", "stage", "test", "testing",
    "uat", "qa", "admin", "administrator", "portal", "dashboard", "panel",
    "cpanel", "webmail", "mail", "smtp", "imap", "api", "api-dev", "apiv1",
    "app", "apps", "internal", "intranet", "corp", "private", "secret",
    "hidden", "backup", "backups", "old", "legacy", "beta", "demo",
    "git", "gitlab", "gitea", "svn", "repo", "jenkins", "ci", "build",
    "phpmyadmin", "pma", "adminer", "db", "database", "sql", "mysql",
    "grafana", "kibana", "prometheus", "monitor", "monitoring", "status",
    "vpn", "remote", "ssh", "ftp", "files", "share", "cloud", "nextcloud",
    "docs", "wiki", "confluence", "jira", "support", "help", "helpdesk",
    "shop", "store", "billing", "payment", "pay", "invoice", "crm", "erp",
    "auth", "sso", "login", "account", "accounts", "user", "users",
    "blog", "news", "forum", "chat", "mattermost", "rocket", "vault",
    "s3", "minio", "registry", "docker", "kube", "k8s", "manage",
]

# Web-app fingerprint -> exploit-lookup hint. When an app name AND version are
# both observed, scryer surfaces a lead to check public exploits/CVEs. This is
# a research pointer, not a claim that the box is vulnerable.
WEBAPP_SIGNATURES = [
    (r"(?i)craft ?cms", "Craft CMS"),
    (r"(?i)krayin", "Krayin CRM"),
    (r"(?i)pterodactyl", "Pterodactyl Panel"),
    (r"(?i)gitea", "Gitea"),
    (r"(?i)gitlab", "GitLab"),
    (r"(?i)jenkins", "Jenkins"),
    (r"(?i)grafana", "Grafana"),
    (r"(?i)jira|atlassian", "Atlassian Jira/Confluence"),
    (r"(?i)wordpress", "WordPress"),
    (r"(?i)joomla", "Joomla"),
    (r"(?i)drupal", "Drupal"),
    (r"(?i)magento", "Magento"),
    (r"(?i)nextcloud|owncloud", "Nextcloud/ownCloud"),
    (r"(?i)laravel", "Laravel"),
    (r"(?i)tomcat", "Apache Tomcat"),
    (r"(?i)jboss|wildfly", "JBoss/WildFly"),
    (r"(?i)weblogic", "Oracle WebLogic"),
    (r"(?i)coldfusion", "Adobe ColdFusion"),
    (r"(?i)roundcube", "Roundcube Webmail"),
    (r"(?i)zabbix", "Zabbix"),
    (r"(?i)moodle", "Moodle"),
]
WEBAPP_SIGNATURES = [(re.compile(p), name) for p, name in WEBAPP_SIGNATURES]

_VERSION_NEAR = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")


def identify_webapp(*texts):
    """Return (app_name, version_or_None) for the first app signature that
    matches any of the given text blobs (server header, title, generator …)."""
    blob = " ".join(t for t in texts if t)
    for pattern, name in WEBAPP_SIGNATURES:
        m = pattern.search(blob)
        if m:
            tail = blob[m.end():m.end() + 24]
            vm = _VERSION_NEAR.search(tail)
            return name, (vm.group(1) if vm else None)
    return None, None
