# scryer

**Deep, adaptive recon toolkit for CTF and lab environments** (Hack The Box,
TryHackMe, VulnHub, OSCP-style boxes).

`scryer` is a single-shot enumeration tool that goes wide *and* deep on a
target. Point it at a box and it resolves the host, scans ports, fingerprints
every service it finds, and then fires service-specific deep modules that pull
out the kind of information you actually pivot on: banners and versions, web
tech stacks, hidden files, TLS certificate identities, SMB shares, anonymous
logins, unauthenticated datastores, DNS zone transfers, and more.

It is **adaptive**: what it discovers in one phase drives the next. A hostname
found in a TLS certificate is fed back in and re-probed as a virtual host. A
leaked `.env` is parsed for database credentials. A web app plus its exact
version becomes an exploit-lookup lead. Everything is collected into a single
structured report you can read on the console or export to JSON / Markdown.

It is also **honest about certainty**. Anything scryer directly observed (a
config file that returned its contents, an anonymous login that worked) is
marked `confirmed`; anything merely inferred from a banner or version string
is marked `potential — verify` and never dressed up as a confirmed finding.

---

## Highlights

- **Everything from one command** — no juggling ten tools and copy-pasting IPs.
- **Finds the hidden foothold** — virtual-host / subdomain brute forcing with
  automatic soft-404 filtering, the way real boxes hide `git.`, `dev.` and
  `admin.` behind a default server block.
- **Pulls the loot** — extracts DB credentials, API keys, tokens and private
  keys out of leaked `.env`, `docker-compose.yml`, `.git/config` and other
  config files; enumerates Active Directory over anonymous LDAP.
- **Accurate by construction** — active protocol fingerprinting (not port-number
  guessing), content-similarity soft-404 detection (not blind size filtering),
  and a `confirmed` / `potential` confidence split on every finding.
- **Adaptive dispatch** — deep modules run only for services that are actually
  open, and re-run against every hostname discovered mid-scan.
- **Pure standard library core** — runs on Python 3.8+ alone. External tools
  (`nmap`, `smbclient`, `rpcclient`, `ldapsearch`, `dig`, `mongosh`) are used
  automatically *when present* and skipped cleanly when not.
- **Portable reports** — colorized console output plus optional JSON and
  Markdown exports for your notes / write-ups.

## What it collects

| Area        | Information gathered |
|-------------|----------------------|
| Host        | Resolution, reverse DNS, liveness, OS inference from service mix |
| Ports       | Threaded TCP connect scan, banner grabbing, version extraction |
| Fingerprint | Active protocol probe — real HTTP/HTTPS/TLS/SSH/FTP detection regardless of port number |
| HTTP(S)     | Status, server/tech headers, page title, generator meta, framework cookies, security-header gaps, login forms, interesting HTML comments, email/username leaks |
| Web discovery | High-signal path probing (`.git`, `.env`, backups, `swagger`, …) with **content-similarity soft-404 filtering** so catch-all servers don't produce false hits |
| Secrets     | Credential/key extraction from leaked `.env`, `docker-compose.yml`, `.git/config`, `wp-config.php`, `*.sql` (DB creds, API keys, AWS keys, private keys, connection strings) + internal service topology from compose files |
| VHosts      | **Host-header brute forcing** against a subdomain wordlist, default-server catch-all detection, discovered vhosts fed back and re-enriched |
| Web apps    | Fingerprints known apps (Gitea, WordPress, Jenkins, Krayin, Pterodactyl, …) + version and surfaces an exploit/CVE-lookup lead |
| TLS         | Protocol/cipher, subject CN, SANs (fed back as new hostnames), issuer, expiry, weak-protocol flags |
| DNS         | `version.bind`, AXFR zone-transfer attempts |
| SMB         | NetBIOS names, null-session share listing + read checks, RPC user enumeration |
| LDAP / AD   | Anonymous bind, naming context / domain, user enumeration, and Active Directory attack-path methodology (AS-REP roast, Kerberoast, BloodHound) |
| FTP         | Anonymous login, directory listing, interesting files |
| SSH         | Banner, supported auth methods, password-auth flag |
| Datastores  | Unauthenticated Redis / Elasticsearch / MongoDB / Memcached checks |
| Versions    | Banner matching against a built-in weakness knowledge base |

## Install

No dependencies required for the core.

```bash
git clone https://github.com/CypherNova1337/Trials
cd Trials
python3 -m scryer --help
```

Optionally install it as a command:

```bash
pip install .
scryer --help
```

## Usage

```bash
# Fast default: curated top-ports scan + full enrichment
python3 -m scryer 10.10.10.10

# Brute virtual hosts against a known base domain (finds git.nexus.htb, …)
python3 -m scryer 10.10.10.10 -D nexus.htb

# Specific ports / ranges
python3 -m scryer target.htb -p 22,80,443,8000-8100

# Full 65k port sweep
python3 -m scryer 10.10.10.10 -p full

# Add nmap -sV service + OS detection when nmap is installed
python3 -m scryer 10.10.10.10 --nmap

# Save JSON + Markdown reports
python3 -m scryer 10.10.10.10 -o loot/

# Just the summary, no phase chatter
python3 -m scryer 10.10.10.10 -q
```

### Options

| Flag | Description |
|------|-------------|
| `-p, --ports` | `top` (default), `full`, or a list like `22,80,443,8000-8100` |
| `-t, --timeout` | Per-port connect timeout (default `1.5s`) |
| `-w, --workers` | Concurrent scan threads (default `200`) |
| `-D, --vhost-domain` | Base domain for vhost brute forcing (auto-derived from discovered hostnames if omitted) |
| `--no-vhost` | Skip virtual-host / subdomain brute forcing |
| `--nmap` | Use `nmap -sV` for service/version + OS detection if installed |
| `--nmap-timeout` | Timeout for the nmap phase (default `300s`) |
| `-o, --output DIR` | Write `<target>.json` and `<target>.md` into `DIR` |
| `-q, --quiet` | Print only the final summary |
| `--no-color` | Disable ANSI colors |

> **Tip:** on Hack The Box, add the box's domain to `/etc/hosts` and pass it
> with `-D` (e.g. `-D nexus.htb`) so scryer can brute-force the virtual hosts
> that usually hide the real foothold.

## Optional external tools

`scryer` auto-detects and uses these when they are on your `PATH`; none are
required:

`nmap` · `smbclient` · `nmblookup` · `rpcclient` · `ldapsearch` ·
`dig` / `host` · `mongosh` / `mongo` · `ping`

## Project layout

```
scryer/
├── __main__.py          # CLI
├── core/
│   ├── engine.py        # adaptive orchestrator + AD methodology inference
│   ├── report.py        # findings model (confidence-aware) + reporters
│   └── utils.py         # colors, logging, external-tool runner
├── data/
│   └── knowledge.py     # ports, probes, weakness rules, vhost + secret rules
└── modules/
    ├── discovery.py     # resolution + liveness
    ├── ports.py         # scanner + banner grab + optional nmap
    ├── fingerprint.py   # active protocol identification
    └── services/        # http, tls, dns, smb, ldap, vhost, auth_svcs, datastores
```

## Legal / ethics

This tool is for **authorized** security testing and learning only — CTF
platforms, lab machines you own, and engagements you have written permission
for. Scanning systems you do not have permission to test is illegal in most
jurisdictions. You are responsible for how you use it.

## License

MIT
