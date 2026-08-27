# CTF one-liner arsenal

Fast copy-paste commands for flag hunting, file/artifact forensics, PCAP, and
crypto/encoding. Flag format is generic — swap `flag` for `securewv`, `HTB`,
`ctf`, etc.

> **scryer automates the ⚙ items below** on every file it recovers (anonymous
> FTP loot, extracted archives, S3 objects): ASCII + wide-char strings, base64
> flags, data appended after image footers, and (when installed) binwalk +
> exiftool. These one-liners are for the files scryer can't reach on its own.

## Flag hunting ⚙
```bash
# Recursive regex flag finder (text, ignores binary noise, case-insensitive)
grep -EriaoI '(flag|ctf|securewv|htb)\{[^}]+\}' .

# Wide-character / Unicode strings (16-bit LE then BE) — Windows binaries
strings -a -e l target.bin | grep -iE 'flag|ctf|securewv'
strings -a -e b target.bin | grep -iE 'flag|ctf|securewv'

# Base64-encoded flag{ / securewv{ variants (their encoded prefixes)
grep -Eriao '(ZmxhZ[A-Za-z0-9+/=]+|c2VjdXJld[A-Za-z0-9+/=]+|SFRCe[A-Za-z0-9+/=]+)' .

# All strings across every file, then filter
grep -rIaoE '[[:print:]]{6,}' . | grep -iE 'flag|pass|secret|key'
```

## File / artifact inspection ⚙
```bash
# Metadata + hidden comment sweep across a folder
exiftool * 2>/dev/null | grep -Ei 'comment|description|author|keywords'

# Recursive embedded-file carver (pulls out appended zips/images/etc.)
binwalk -Me --dd='.*' suspicious_file

# Data appended after a standard footer (PNG IEND / JPEG FFD9) = classic stego
python3 -c 'import sys; d=open(sys.argv[1],"rb").read(); i=d.rfind(b"\x49\x45\x4e\x44\xae\x42\x60\x82"); print("trailing:",len(d)-(i+8)) if i>0 else print("no PNG footer")' file.png

# Zsteg (PNG/BMP LSB stego) / steghide (JPG/WAV with passphrase)
zsteg -a image.png
steghide extract -sf image.jpg           # try empty + rockyou passphrases
stegseek image.jpg /usr/share/wordlists/rockyou.txt   # fast steghide cracker

# Manual carve of trailing data
binwalk file.png; dd if=file.png of=out bs=1 skip=<offset>
```

## PCAP / network traffic (tshark)
```bash
# Unique HTTP requests (method + host + uri)
tshark -r capture.pcap -Y 'http.request' -T fields \
  -e http.request.method -e http.host -e http.request.uri | sort -u

# All POST bodies / submitted credentials
tshark -r capture.pcap -Y 'http.request.method==POST' -T fields -e http.file_data

# DNS queries (exfil / tunnels show as long random labels)
tshark -r capture.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort -u

# Export every transferred HTTP object to a folder
mkdir loot && tshark -r capture.pcap --export-objects http,loot

# Follow a TCP stream by index
tshark -r capture.pcap -q -z follow,tcp,ascii,0
# Creds in cleartext protocols
tshark -r capture.pcap -Y 'ftp || telnet || http.authorization' -T fields -e text
```

## Crypto / encoding
```bash
# Single-byte XOR brute (first 60 chars per key)
python3 -c 'import sys;d=open(sys.argv[1],"rb").read()
for k in range(256):
    o=bytes(b^k for b in d)
    if b"flag" in o.lower() or b"securewv" in o.lower(): print(k,o[:60])' file.bin

# Nested base64 auto-unwrap
cat encoded.txt | python3 -c 'import sys,base64
d=sys.stdin.read().strip().encode()
while True:
    try: d=base64.b64decode(d)
    except: break
print(d)'

# Identify a hash type
hashid '<hash>' ; nth --text '<hash>'      # name-that-hash -> hashcat -m mode

# XOR against a known key / repeating key (use CyberChef for anything fancy)
python3 -c 'k=b"key";d=open("f","rb").read();print(bytes(c^k[i%len(k)] for i,c in enumerate(d)))'
```
Anything multi-step (ROT/rail-fence/vigenere/magic) → **CyberChef** "Magic" op.

## Fast web triage
```bash
# Headers, cookies, redirects — no browser
curl -iks -L 'http://target:port/' | head -50

# Hidden form fields + HTML comments (creds, next paths hide here)
curl -s 'http://target:port/' | grep -Ei 'type=.hidden|<!--|name=|action='

# Grep a page/JS for endpoints + secrets
curl -s 'http://target/app.js' | grep -Eoi '(/[a-z0-9_./-]+|api[_-]?key|token)[^"]*'

# robots / sitemap / git in one go
for p in robots.txt sitemap.xml .git/HEAD .env; do echo "== $p"; curl -s "http://target/$p" | head; done
```

## Quick loot triage after a shell
```bash
# Find every flag/proof file fast
find / \( -name 'flag*.txt' -o -name 'user.txt' -o -name 'root.txt' \) 2>/dev/null
grep -rIl -- 'flag{' / 2>/dev/null | head
# Creds in web roots / configs
grep -rniE 'password|passwd|secret|api_key|db_pass' /var/www /opt /home 2>/dev/null
```
