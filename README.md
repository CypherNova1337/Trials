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

- **Orchestrator, not another silo** — for every job scryer drives the best
  real tool on the box (nmap, rustscan, ffuf/feroxbuster, whatweb,
  enum4linux-ng, netexec, snmpwalk, searchsploit …) and falls back to a
  pure-python implementation only when that tool is missing. Fast and deep on
  Kali, never dead on a bare shell.
- **`--toolcheck` / `--install`** — audits your kit and installs whatever is
  missing via the detected package manager, so a fresh box is ready in one line.
- **Finds the hidden foothold** — virtual-host / subdomain brute forcing with
  automatic soft-404 filtering, the way real boxes hide `git.`, `dev.` and
  `admin.` behind a default server block.
- **Pulls the loot** — extracts DB credentials, API keys, tokens and private
  keys from leaked `.env`, `docker-compose.yml`, `.git/config` and config
  files, **and from JavaScript**; enumerates AD over anonymous LDAP; walks SNMP.
- **Tells you what to type next** — every finding turns into a copy-paste
  command tuned to your installed tools (dir brute, share enum, AS-REP roast,
  searchsploit), printed at the end and saved to `commands.sh`.
- **Accurate by construction** — active protocol fingerprinting (not port-number
  guessing), content-similarity soft-404 detection (not blind size filtering),
  and a `confirmed` / `potential` confidence split on every finding.
- **Portable reports** — colorized console output plus JSON, Markdown and a
  runnable command script.

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
| Web crawl   | Same-origin crawl + **JavaScript scraping** for API endpoints and hard-coded secrets; `whatweb` fingerprint; optional full `feroxbuster`/`ffuf` dir brute |
| Web apps    | Fingerprints known apps (Gitea, WordPress, Jenkins, Krayin, Pterodactyl, …) + version and surfaces an exploit/CVE-lookup lead |
| TLS         | Protocol/cipher, subject CN, SANs (fed back as new hostnames), issuer, expiry, weak-protocol flags |
| DNS         | `version.bind`, AXFR zone-transfer attempts |
| SMB         | NetBIOS names, null-session share listing + read checks, RPC user enumeration (enum4linux-ng / netexec when present) |
| LDAP / AD   | Anonymous bind, naming context / domain, user enumeration, DC detection + AD attack-path methodology (AS-REP roast, Kerberoast, BloodHound) |
| SNMP        | Community-string check + walk of processes / software / listening ports / users (snmpwalk, with a raw-socket fallback) |
| SMTP        | Banner, capabilities, VRFY/EXPN user-enumeration vector detection |
| NFS / rsync | Export and module listing (world-readable shares) |
| SQL DBs     | MySQL / MSSQL / PostgreSQL version + safe default-credential probe |
| Remote      | RDP (NLA/NTLM info), VNC (auth/version), WinRM methodology |
| FTP / SSH   | Anonymous login, directory listing; SSH auth methods / password-auth flag |
| Datastores  | Unauthenticated Redis / Elasticsearch / MongoDB / Memcached checks |
| Exploit intel | Runs `searchsploit` on every identified product+version and folds hits back in |
| Next steps  | Per-service copy-paste command playbook written to `commands.sh` |
| Versions    | Banner matching against a built-in weakness knowledge base |

## Install

The core needs no dependencies.

```bash
git clone https://github.com/CypherNova1337/Trials
cd Trials
python3 -m scryer --help          # run in place
# or install as a command:
pip install .
scryer --help
```

### First run: check your kit

```bash
scryer --toolcheck                # audit installed tools
sudo scryer --toolcheck --install # install everything missing
```

scryer runs fine with nothing installed, but the more of the kit it finds, the
faster and deeper it goes. `--toolcheck` shows exactly what is present, what is
missing, and how each missing tool would be installed.

## Usage

```bash
# Default: nmap/rustscan if present (python scanner otherwise) + full enrichment
scryer 10.10.10.10

# Live CTF one-liner: brute vhosts, scan UDP too, save everything
scryer 10.10.10.10 -D box.htb --udp -o loot/

# Specific ports / full sweep
scryer target.htb -p 22,80,443,8000-8100
scryer 10.10.10.10 -p full

# Heavy web content brute (feroxbuster/ffuf + SecLists) per web port
scryer 10.10.10.10 --web-brute

# Parameter discovery on crawled endpoints (paramvoid)
scryer 10.10.10.10 --params

# Force the pure-python scanner (no nmap)
scryer 10.10.10.10 --no-nmap

# Active exploit chains (S3 -> shell, authed login -> SQLi -> shell, ...)
scryer 10.10.10.10 --exploit

# Jeopardy CTF: analyze a downloaded artifact offline (no network recon)
scryer --file capture.pcap --flag-format securewv   # traffic + creds + objects
scryer --file secret.zip                            # crack + extract + scan
scryer --file challenge.png                         # strings / stego / decode

# Peel encoding layers off a string (base64/32/16/85, hex, ROT-N, XOR, ...)
scryer --decode 'c2VjdXJld3Z7ZXhhbXBsZX0='

# Interactive nc-style session: relays your terminal, watches for flags, and
# auto-answers arithmetic / proof-of-work gates on the service
scryer --connect 10.10.10.5:1337
```

At the end of every run scryer prints a **Next steps** block of copy-paste
commands for what it found, and (with `-o`) writes them to
`<target>.commands.sh` alongside the JSON and Markdown reports.

### Options

| Flag | Description |
|------|-------------|
| `-p, --ports` | `top` (default), `full`, or a list like `22,80,443,8000-8100` |
| `--udp` | Also scan top UDP ports (nmap; needs root for accuracy) |
| `--no-nmap` | Force the pure-python scanner even if nmap is present |
| `-D, --vhost-domain` | Base domain for vhost brute forcing (auto-derived if omitted) |
| `--no-vhost` | Skip virtual-host / subdomain brute forcing |
| `--add-hosts` | Auto-add discovered vhosts (e.g. from an IP→`box.htb` redirect) to `/etc/hosts` so external tools + your browser resolve them |
| `--web-brute` | Full wordlist dir brute (feroxbuster/ffuf + SecLists) per web port |
| `--params` | paramvoid parameter discovery on crawled endpoints (implied by `--web-brute`) |
| `--exploit` | Enable active exploit chains (writable S3 → webshell → RCE; recovered creds → authed SQLi/upload → shell → flag; AD spray → WinRM/psexec) — authorized targets only |
| `--ai` | Ask a locally-hosted LLM (Ollama) to read the recon state and recommend the next step. No API key, no cost, fully offline. `--ai-model NAME` / `$SCRYER_AI_MODEL` picks the model |
| `--agent` | Autonomous execution loop: the local LLM proposes the next command, scryer safety-checks it against an offensive-tool allowlist, runs it, scans the output for flags/creds, and iterates. Confirms each command unless `--agent-auto`; `--agent-steps N` caps iterations. Needs Ollama; authorized targets only |
| `--file PATH` | Analyze a local Jeopardy artifact offline (pcap/pcapng, zip/tar/kdbx, or any file → forensics + layered decode); no network recon |
| `--decode STRING` | Peel encoding layers off a string (base64/32/16/85, hex, URL, gzip, ROT-N, Atbash, single-byte XOR) and print any flag |
| `--connect HOST:PORT` | Interactive nc-style session to a challenge service: relays your terminal, highlights flags on the wire, auto-answers arithmetic/PoW prompts (`--no-auto` for raw relay) |
| `--flag-format PREFIX` | Event flag prefix (e.g. `securewv`) — sharpens ROT/XOR brute filtering |
| `--no-searchsploit` | Skip the searchsploit exploit-lookup phase |
| `-o, --output DIR` | Write JSON + Markdown + `commands.sh` into `DIR` |
| `-t/-w/--nmap-timeout` | Tune python-scan timeout/threads and the nmap phase timeout |
| `-q, --quiet` | Print only the summary + next steps |
| `--no-color` | Disable ANSI colors |
| `--toolcheck [--install]` | Audit (and optionally install) external tools, then exit |

> **Tip:** on Hack The Box, add the box's domain to `/etc/hosts` and pass it
> with `-D` (e.g. `-D nexus.htb`) so scryer can brute-force the virtual hosts
> that usually hide the real foothold.

## External tools

scryer orchestrates these when present and falls back to python when not.
Run `scryer --toolcheck` for the live list. The recommended kit:

`nmap` · `rustscan` · `ffuf` · `feroxbuster` · `whatweb` · `nikto` ·
`paramvoid` · `enum4linux-ng` · `netexec` · `smbclient` · `ldapsearch` ·
`snmpwalk` · `showmount` · `rsync` · `kerbrute` · `impacket` · `searchsploit`
· `seclists`

### Wordlists & paramvoid

- **SecLists** is auto-detected from (first hit wins): `~/Documents/Wordlists/SecLists`,
  `$SCRYER_SECLISTS`, `/usr/share/seclists`, `/usr/share/wordlists/seclists`,
  `~/SecLists`. Override with `SCRYER_SECLISTS=/path scryer …`.
- **Parameter discovery** uses [paramvoid](https://github.com/CypherNova1337/paramvoid)
  (not arjun). It's resolved from `$PATH`, `~/go/bin/paramvoid`, or
  `~/Tools/paramvoid/paramvoid`; install with
  `go install github.com/CypherNova1337/paramvoid@latest`.

## Project layout

```
scryer/
├── __main__.py          # CLI
├── core/
│   ├── engine.py        # adaptive orchestrator + AD methodology inference
│   ├── tooling.py       # external-tool registry + --toolcheck / --install
│   ├── playbook.py      # per-service copy-paste next-step generation
│   ├── report.py        # findings model (confidence-aware) + reporters
│   └── utils.py         # colors, logging, external-tool runner
├── data/
│   └── knowledge.py     # ports, probes, weakness rules, vhost + secret rules
└── modules/
    ├── discovery.py     # resolution + liveness
    ├── ports.py         # pure-python scanner + banner grab
    ├── nmapscan.py      # nmap/rustscan orchestration + NSE ingestion
    ├── fingerprint.py   # active protocol identification
    ├── exploitintel.py  # searchsploit lookups
    └── services/        # http, webcrawl, tls, dns, smb, ldap, vhost, snmp,
                         #   mail, netshares, sqldb, remote, auth_svcs, datastores
```

## Legal / ethics

This tool is for **authorized** security testing and learning only — CTF
platforms, lab machines you own, and engagements you have written permission
for. Scanning systems you do not have permission to test is illegal in most
jurisdictions. You are responsible for how you use it.

## License

MIT
