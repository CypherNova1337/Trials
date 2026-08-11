# voidrecon

**Deep, adaptive recon toolkit for CTF and lab environments** (Hack The Box,
TryHackMe, VulnHub, OSCP-style boxes).

`voidrecon` is a single-shot enumeration tool that goes wide *and* deep on a
target. Point it at a box and it resolves the host, scans ports, fingerprints
every service it finds, and then fires service-specific deep modules that pull
out the kind of information you actually pivot on: banners and versions, web
tech stacks, hidden files, TLS certificate identities, SMB shares, anonymous
logins, unauthenticated datastores, DNS zone transfers, and more.

It is **adaptive**: what it discovers in one phase drives the next. A hostname
found in a TLS certificate is fed back in and re-probed as a virtual host. A
version banner is matched against a knowledge base of well-known weaknesses.
Everything is collected into a single structured report you can read on the
console or export to JSON / Markdown.

---

## Highlights

- **Everything from one command** — no juggling ten tools and copy-pasting IPs.
- **Adaptive dispatch** — deep modules run only for the services that are
  actually open, and re-run when new hostnames surface.
- **Pure standard library core** — the scanner, web, TLS, FTP, SSH and
  datastore modules all run with nothing but Python 3.8+. External tools
  (`nmap`, `smbclient`, `rpcclient`, `dig`, `mongosh`) are used automatically
  *when present* and skipped cleanly when not.
- **Signal over noise** — findings are graded by severity so the interesting
  stuff floats to the top of the summary.
- **Portable reports** — colorized console output plus optional JSON and
  Markdown exports for your notes / write-ups.

## What it collects

| Area        | Information gathered |
|-------------|----------------------|
| Host        | Resolution, reverse DNS, liveness, OS inference from service mix |
| Ports       | Threaded TCP connect scan, banner grabbing, version extraction |
| HTTP(S)     | Status, server/tech headers, page title, generator meta, framework cookies, security-header gaps, login forms, interesting HTML comments, email/username leaks, content discovery on high-signal paths (`.git`, `.env`, backups, `swagger`, `flag.txt`, …), virtual-host re-probing |
| TLS         | Protocol/cipher, subject CN, SANs (fed back as new hostnames), issuer, expiry, weak-protocol flags |
| DNS         | `version.bind`, AXFR zone-transfer attempts |
| SMB         | NetBIOS names, null-session share listing + read checks, RPC user enumeration |
| FTP         | Anonymous login, directory listing, interesting files |
| SSH         | Banner, supported auth methods, password-auth flag |
| Datastores  | Unauthenticated Redis / Elasticsearch / MongoDB / Memcached checks |
| Versions    | Banner matching against a built-in weakness knowledge base |

## Install

No dependencies required for the core.

```bash
git clone https://github.com/CypherNova1337/Trials
cd Trials
python3 -m voidrecon --help
```

Optionally install it as a command:

```bash
pip install .
voidrecon --help
```

## Usage

```bash
# Fast default: curated top-ports scan + full enrichment
python3 -m voidrecon 10.10.10.10

# Specific ports / ranges
python3 -m voidrecon target.htb -p 22,80,443,8000-8100

# Full 65k port sweep
python3 -m voidrecon 10.10.10.10 -p full

# Add nmap -sV service + OS detection when nmap is installed
python3 -m voidrecon 10.10.10.10 --nmap

# Save JSON + Markdown reports
python3 -m voidrecon 10.10.10.10 -o loot/

# Just the summary, no phase chatter
python3 -m voidrecon 10.10.10.10 -q
```

### Options

| Flag | Description |
|------|-------------|
| `-p, --ports` | `top` (default), `full`, or a list like `22,80,443,8000-8100` |
| `-t, --timeout` | Per-port connect timeout (default `1.5s`) |
| `-w, --workers` | Concurrent scan threads (default `200`) |
| `--nmap` | Use `nmap -sV` for service/version + OS detection if installed |
| `--nmap-timeout` | Timeout for the nmap phase (default `300s`) |
| `-o, --output DIR` | Write `<target>.json` and `<target>.md` into `DIR` |
| `-q, --quiet` | Print only the final summary |
| `--no-color` | Disable ANSI colors |

## Optional external tools

`voidrecon` auto-detects and uses these when they are on your `PATH`; none are
required:

`nmap` · `smbclient` · `nmblookup` · `rpcclient` · `dig` / `host` ·
`mongosh` / `mongo` · `ping`

## Project layout

```
voidrecon/
├── __main__.py          # CLI
├── core/
│   ├── engine.py        # adaptive orchestrator
│   ├── report.py        # findings model + console/JSON/Markdown reporters
│   └── utils.py         # colors, logging, external-tool runner
├── data/
│   └── knowledge.py     # port map, probes, version-weakness rules, wordlist
└── modules/
    ├── discovery.py     # resolution + liveness
    ├── ports.py         # scanner + banner grab + optional nmap
    └── services/        # http, tls, dns, smb, auth_svcs, datastores
```

## Legal / ethics

This tool is for **authorized** security testing and learning only — CTF
platforms, lab machines you own, and engagements you have written permission
for. Scanning systems you do not have permission to test is illegal in most
jurisdictions. You are responsible for how you use it.

## License

MIT
