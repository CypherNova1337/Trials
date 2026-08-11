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
    ".htaccess", "admin/", "administrator/", "login", "login.php",
    "wp-login.php", "wp-admin/", "phpmyadmin/", "server-status",
    "config.php", "config.php.bak", "backup/", "backup.zip", "dump.sql",
    "api/", "api/v1/", "swagger.json", "swagger-ui/", "actuator",
    "actuator/health", "manager/html", "console/", "cgi-bin/",
    "uploads/", "test.php", "info.php", "phpinfo.php", "readme.html",
    ".well-known/security.txt", "user.txt", "flag.txt",
]
