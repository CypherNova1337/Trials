# scryer — Developer Handoff

Automated deep-recon + auto-exploitation for authorized CTF / lab boxes. Goal:
run one command against a target and walk the chain to the flags autonomously.
Pure Python 3 standard library + orchestration of external offensive tools
(nmap, rustscan, netexec, impacket, sqlmap, evil-winrm, tshark, aws, php…).

Entry point: `python -m scryer <target> [flags]` (installed as `scryer`).

---

## 1. Architecture & File Structure

Pipeline: **scan → per-service enrichment → credential recovery → adaptive
convergence → exploitation → reporting.** One `HostReport` is threaded through
every module; modules read learned facts off it and write findings/creds/hosts
back, so later passes benefit from earlier ones.

```
scryer/
  __main__.py            CLI arg parsing + top-level orchestration entry
  core/
    engine.py            THE ORCHESTRATOR. run order + _converge() adaptive loop
    report.py            HostReport + Finding dataclasses; console/JSON/MD output
    brain.py             rules engine -> ranked ATTACK PLAN (next-move suggestions)
    playbook.py          copy-paste "Next steps" generator
    tooling.py           external-tool resolution / availability (`--toolcheck`)
    hostsfile.py         /etc/hosts vhost mapping (--add-hosts)
    utils.py             logging/color, ensure_sudo(), section(), now_iso()
  modules/
    ports.py, nmapscan.py, discovery.py, fingerprint.py   scanning + service ID
    crack.py             looted-doc/file cred + username mining (PDF/OOXML, prose)
    aiadvisor.py         pluggable LLM advisor (Ollama local OR OpenAI-compatible API)
    agent.py             autonomous observe/act loop (LLM-driven, safety allowlist)
    exploitintel.py      searchsploit lookups
    connect.py, crypto.py, pcap.py, artifact.py   Jeopardy/offline artifact tooling
    bruteforce.py, discovery.py …
    services/
      http.py            web recon; harvests emails + role-anchored usernames
      mailloot.py        IMAP/POP3 credential-reuse spray + mailbox mining
      openstamanager.py  OpenSTAManager detect + native CVE-2025-69212 P7M RCE
      olivetin.py        OliveTin CVE-2026-27626 mysqldump-injection root privesc
      roundcube.py       Roundcube version fingerprint + CVE-2025-49113 (gated)
      webexploit.py      authed web exploitation, sqlmap --os-cmd -> shell
      netshares.py       NFS/SMB auto-mount + loot
      adattack.py, winattack.py, ldap.py, smb.py, snmp.py, sqldb.py, tls.py,
      dns.py, vhost.py, webcrawl.py, sshprivesc.py, s3exploit.py, log4shell.py …
  data/
    knowledge.py         regexes + heuristics: flags, doc creds, username_variants,
                         hostnames, port maps, COMMON_VHOSTS, secrets
    gtfobins.py          GTFOBins sudo/SUID privesc data
    filetypes.py         magic-byte / extension identification
    wordlists/           firstnames.txt, passwords.txt, users.txt (bundled)
```

External wordlists (not bundled): SecLists at `~/Documents/Wordlists/SecLists/`,
rockyou at `~/Documents/Wordlists/rockyou.txt`. Param discovery uses `paramvoid`.

### Orchestration order (engine.py `_run_host`)
scan → OS/tech inference → `adattack` → `_credential_reuse` → `mailloot` →
`s3exploit` (if endpoints) → `webexploit` → `roundcube` → `openstamanager` →
`sshprivesc` → **`_converge()`** (up to 2 iterations re-running webexploit /
mailloot / roundcube / openstamanager while new hosts or creds keep appearing) →
`aiadvisor.advise` / `agent.run` (opt-in) → report + playbook.

### The reference chain it drives end-to-end (HTB "Enigma")
NFS onboarding PDF → `kevin:Enigma2024!` → mailbox opens → correspondent
`sarah` harvested from mail → `sarah:Enigma2024!` → her inbox yields
`admin:Ne3s4rtars78s` for `support_001.enigma.htb` (OpenSTAManager 2.9.8) →
native P7M RCE (CVE-2025-69212) → webshell → `user.txt` → OliveTin on
127.0.0.1:1337 (CVE-2026-27626) → SUID bash → `root.txt`.

---

## 2. Key Technical Decisions

- **One mutable `HostReport`, adaptive convergence.** Facts learned mid-run
  (hostnames, creds, usernames) feed back into enumeration + exploitation via
  `engine._converge()`. This is what lets a second mailbox / second credential
  unlock a downstream exploit in the same run.
- **Credential reuse is the primary methodology**, not per-box walkthroughs.
  A recovered password is sprayed across learned usernames (doc logins, mailbox
  correspondents, web-harvested staff names).
- **Exploit natively; never clone/run third-party PoCs.** Standard tools
  (sqlmap, nmap, impacket) are fine; downloading GitHub PoCs is not — they don't
  reliably work and add trust/footprint risk. CVE-2025-69212 is implemented from
  scratch with stdlib (login+CSRF, module discovery, in-memory ZIP, multipart).
- **Only auto-fire access/RCE exploits; never destructive/DoS ones.** E.g. the
  OpenSTAManager time-based-blind DoS CVE (CVE-2026-24417) is reported but never
  run. OliveTin privesc issues only access actions (SUID shell, read flag).
- **Don't assume hidden versions are vulnerable — but do attempt cheap authed
  exploits.** Roundcube "unknown" version is NOT auto-exploited (avoids the
  1.6.16-patched dead end). OpenSTAManager "unknown" IS attempted, because the
  native P7M RCE is authenticated, cheap, and self-confirms by getting exec.
- **Mail spray must not defeat itself.** Blind 300-user IMAP sprays trip Dovecot
  auth-penalty / fail2ban and lock out even valid logins. Mitigations: explicit
  doc login (`Username: kevin`) tried FIRST at low concurrency; web-harvested
  names demoted to a separate low-confidence bucket; broad first-name spray is
  opt-in (`--mail-spray`, else capped at 25); tiered worker counts (2→4→8).
- **Pluggable LLM is optional and off by default.** `aiadvisor` supports local
  Ollama or any OpenAI-compatible API (DeepSeek/OpenAI/OpenRouter/Groq/custom)
  via env keys; the rules `brain` produces the ranked plan without any LLM.
- **Exploitation retries on new intel.** Modules cache *detection* per host:port
  but retry *exploitation* whenever the available credential/login set changes
  (per-host tried-signature), so late-arriving creds still get used.
- **Zero-dependency parsing.** PDF text via zlib FlateDecode + Tj/TJ operators;
  OOXML via zipfile; HTML mail stripped to text keeping `<a href>` links.
- **Repo hygiene:** no AI-tool/vendor names anywhere in code, comments, or
  commits; branch `voidsec-hub/ctf-deep-recon-tool-6xz5ne`; author `VoidSec-Hub`
  <rmpitts94@gmail.com>. Run `grep -rniE "claude|anthropic" scryer` before every
  commit. Run `python -m pyflakes scryer` before every commit.

---

## 3. Data Models / Schemas

`core/report.py` — the two dataclasses everything revolves around.

```python
@dataclass
class Finding:
    title: str
    detail: str = ""
    severity: str = "info"        # critical|high|medium|low|info
    category: str = "general"     # port|service|web|cred|leak|host|vuln|flag|...
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: Optional[str] = None
    confidence: str = "confirmed" # "confirmed" (observed) | "potential" (inferred)
    data: Dict[str, Any] = {}
    def rank() -> int             # severity sort key

@dataclass
class HostReport:
    target: str
    resolved_ip: Optional[str]
    hostnames: List[str]
    os_guess / tech_stack: Optional[str]
    s3_endpoints: List[dict]
    creds: List[str]              # recovered PLAINTEXT passwords (hashes filtered)
    login_urls: List[str]
    open_ports: List[dict]        # {port, proto, service, version, banner, secure?}
    findings: List[Finding]
    started / finished: str (iso)
    # mutation helpers:
    add(Finding)                  # de-dupes by (title,port,severity,detail)
    add_cred(str)                 # skips hash-looking / placeholder values
    add_hostname(str) -> bool     # returns True if newly added
    add_port(port,proto,service,version,banner) -> dict
    to_dict()                     # JSON serialization
```

**Ad-hoc state carried on `host.__dict__`** (dynamic, not dataclass fields) —
modules stash learned intel here and read it in later passes:

| key | type | producer → consumer |
|---|---|---|
| `emails` | `set[str]` | http/crack/mail → mailloot, openstamanager |
| `usernames` | `set[str]` | crack (`username_variants`), mail correspondents → spray |
| `primary_users` | `list[str]` | crack (explicit `Username:` in a doc) → mail (tried first) |
| `web_usernames` | `set[str]` | http staff-page harvest (low-confidence tail) |
| `ad_users` | `list[str]` | adattack |
| `_mail_sig` | tuple | mailloot re-run guard |
| `_opensta_detected/_pwned/_tried` | dict/set/dict | openstamanager retry control |
| `_roundcube_done` | set | roundcube per-host:port dedupe |
| `_uname_pages` | set | http staff-page fetch-once guard |

`knowledge.py` key helpers: `find_flags(text, allow_hex=False)`,
`find_doc_creds(text)`, `find_conn_creds`, `find_windows_creds`,
`extract_secrets`, `username_variants(text)`, `find_hashes`,
`FLAG_PREFIXES`, `HTTP_PORTS`/`HTTPS_PORTS`, `COMMON_VHOSTS`.

Output formats: colored console (default), `report.to_dict()` JSON, Markdown;
loot saved under `./scryer_loot/<ip>/…` (mail bodies, mounted-share files).

---

## 4. Features To Implement Next

Ordered by impact on "run it and get flags".

1. **P7M webroot auto-detection (openstamanager.py).** The native RCE drops a
   webshell into a guessed docroot (`_webroots()` candidate list, self-verified
   via `o.txt`). If the box's docroot isn't listed the channel fails silently.
   Fix: derive the real path — parse the exposed `config.php`/`config.inc.php`,
   read `$_SERVER['DOCUMENT_ROOT']` via the injection itself, or grep the nginx
   config through an early exec probe — instead of relying on a static list.
   (`SCRYER_OSM_WEBROOT` override exists as the manual stopgap.)
2. **End-to-end validate OliveTin privesc (olivetin.py)** against a live box:
   confirm the `StartActionAndWait` action id/arg names (`db_pass`) and the
   SUID-bash payload land root; currently unverified against a real target.
3. **Fix `_harvest_hostnames` false split** — it extracted `001.enigma.htb`
   from `support_001.enigma.htb`. Tighten so subdomain labels aren't sliced into
   bogus vhosts (`knowledge`/`crack`).
4. **Generic CVE auto-runner.** Given a fingerprinted service+version, map to a
   known access/RCE technique and execute it natively (fetch→run→loot pattern),
   with the destructive/DoS exclusion enforced centrally. Generalize the
   per-app modules (roundcube/openstamanager) into a small registry.
5. **Post-RCE auto-privesc generalization.** Once any module yields a `run_cmd`
   channel, run a standard local-privesc sweep (sudo -l/GTFOBins via
   `data/gtfobins.py`, SUID, cron, writable services, localhost-only services
   like OliveTin) and auto-fire the safe wins → root flag.
6. **Flag tracking / submission.** Central flag store with de-dupe + a final
   "FLAGS" summary section; optional HTB/CTFd submission hook.
7. **Mail spray adaptive backoff.** Detect throttling (sudden all-fail after
   successes) and pause/slow instead of burning the budget; surface a clear
   "server is rate-limiting this IP" state (partially done — make it adaptive).
8. **Agent loop hardening (agent.py).** It needs an LLM to drive; expand the
   safety allowlist review, add per-command dry-run diffing, and feed the
   convergence facts (new creds/hosts) into each turn's prompt.
9. **Test fixtures.** No automated tests today. Add offline fixtures (sample
   PDFs/emails/HTTP bodies) so `crack`, `mailloot` harvesting, `knowledge`
   regexes, and `openstamanager` payload encoding can be unit-tested without a
   live box.

### Conventions for any new work
- stdlib-first; shell out only to real offensive tools, never to downloaded PoCs.
- auto-fire access/RCE only — never destructive/DoS actions.
- before commit: `python -m pyflakes scryer` **and**
  `grep -rniE "claude|anthropic" scryer` (must be empty).
- develop on `voidsec-hub/ctf-deep-recon-tool-6xz5ne`, author `VoidSec-Hub`.
