# Password / hash cracking cheat sheet

## Identify the hash
```bash
hashid '$1$abc...'
nth --text '<hash>'          # name-that-hash → gives hashcat -m mode
```

## hashcat modes you'll actually use
| Mode | Hash |
|------|------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1800 | sha512crypt `$6$` (Linux /etc/shadow) |
| 500 | md5crypt `$1$` |
| 3200 | bcrypt `$2a$` |
| 1000 | NTLM |
| 5600 | NetNTLMv2 (responder captures) |
| 13100 | Kerberoast (TGS-REP) |
| 18200 | AS-REP roast |
| 22000 | WPA-PMKID/handshake |
| 13400 | KeePass (.kdbx) |
| 10000 | Django PBKDF2-SHA256 |

```bash
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 13100 kerb.txt rockyou.txt --force
# John equivalent:
john --format=sha512crypt --wordlist=rockyou.txt hash.txt
john --show hash.txt
```

## Convert files to crackable hashes (`*2john`)
```bash
ssh2john id_rsa > id.hash          # then john -> mode 22921 in hashcat
keepass2john secret.kdbx > kp.hash
zip2john secret.zip > zip.hash
rar2john secret.rar > rar.hash
office2john report.docx > doc.hash
pdf2john locked.pdf > pdf.hash
gpg2john secret.gpg > gpg.hash
# Linux shadow:
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```

## /etc/shadow crack
```bash
john --wordlist=rockyou.txt unshadowed.txt
hashcat -m 1800 shadow-hashes.txt rockyou.txt
```

## Mask / rule tips
```bash
# 8-char, upper+lower+digit:
hashcat -m 1000 hash.txt -a3 '?u?l?l?l?l?l?d?d'
# Best all-round rules:
-r /usr/share/hashcat/rules/best64.rule        # fast
-r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule   # thorough
```

> No GPU on the box? Crack on your own machine — copy the hash out, don't run
> hashcat on the target.
