# scryer field notes & cheat sheets

Copy-paste command references for live CTF / HTB / THM / red-team work — the
stuff you reach for the moment scryer hands you a foothold. Everything here is
meant to be grabbed fast during an engagement.

| Sheet | Use it when… |
|-------|--------------|
| [evil-winrm.md](evil-winrm.md) | You have Windows creds and port 5985/5986 is open |
| [hydra.md](hydra.md) | You need to brute a login (ssh/ftp/http-form/rdp/smb) |
| [smb-enum.md](smb-enum.md) | Ports 139/445 are open |
| [active-directory.md](active-directory.md) | It's a domain controller (88/389/445) |
| [impacket.md](impacket.md) | Windows creds in hand: MSSQL xp_cmdshell, psexec, roasting, secretsdump |
| [web-recon.md](web-recon.md) | There's a web app to dig into |
| [reverse-shells.md](reverse-shells.md) | You have code exec and need a shell back |
| [file-transfer.md](file-transfer.md) | You need to move tools/loot on or off the box |
| [linux-privesc.md](linux-privesc.md) | You're a low-priv user on Linux |
| [windows-privesc.md](windows-privesc.md) | You're a low-priv user on Windows |
| [pivoting.md](pivoting.md) | You need to reach an internal network |
| [password-cracking.md](password-cracking.md) | You captured a hash/keyfile |
| [cloud.md](cloud.md) | There are S3/Azure/GCS buckets or cloud metadata |
| [ctf-oneliners.md](ctf-oneliners.md) | Flag hunting, file forensics/stego, PCAP, crypto/encoding |

**Bundled wordlists** live in [`../scryer/data/wordlists/`](../scryer/data/wordlists):
`users.txt` (common CTF accounts) and `passwords.txt` (weak/default creds).
scryer references these automatically when it prints brute-force command
suggestions.

> Reminder: only run these against systems you are explicitly authorised to
> test (your own labs, HTB/THM boxes, sanctioned CTF/engagement scope).
