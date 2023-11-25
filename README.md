# Recon

### Google Hacking
https://www.exploit-db.com/google-hacking-database
```
site:<domain> -filetype:html
intitle:"index of" "parent directory"
```

### Repositories code
https://github.com/
```
owner:megacorpone path:users
```
https://gist.github.com/starred
https://about.gitlab.com/
https://sourceforge.net/

Herramientas para identificar información expuesta en repositorios
https://github.com/michenriksen/gitrob
https://github.com/gitleaks/gitleaks

### nmap
1. Identificar puertos tcp
```bash
nmap -Pn -sS --open -n <IP> --top-ports 10 --min-rate 1000 --max-retries 2 --reason -oN <IP>-top-ports10
nmap -Pn -sS --open -n <IP> --top-ports 1000 --min-rate 1000 --max-retries 2 --reason -oN <IP>-top-ports1000
nmap -Pn -sS -n <IP> -p- --min-rate 1000 --max-retries 2 --reason -oN <IP>-tcp-all
nmap -Pn -sS -sV -n <IP> -p <port1,port2...> --min-rate 1000 --max-retries 2 --reason -oN <IP>-tcp-sV
nmap -Pn -sS -sV -sC -n <IP> -p <port1,port2...> --min-rate 1000 --max-retries 2 --reason -oN <IP>-tcp-sC
```
2. Identificar puerto udp
```bash
nmap -Pn -sU -sV -n <IP> --top-ports 15 --min-rate 1000 --max-retries 2 --reason -oN <IP>-udp-top-15
nmap -Pn -sU -sV -n <IP> -p <port1,port2...>  --min-rate 1000 --max-retries 2 --reason -oN <IP>-udp-sC
```
3. Filtrar puertos en un formato 80,443,22...
```bash
cat <FILE> | grep -i "^[0-9]" | cut -d '/' -f 1 | xargs | sed 's/\ /,/g'
```

### DNS
https://www.shodan.io/
https://crt.sh/
https://dnsdumpster.com/
https://search.censys.io/
https://certificatedetails.com/
https://searchdns.netcraft.com
#### whois
```bash
whois <ip>
whois <ip> -h <server>
```
#### host
```bash
host <domain>
host -t mx <domain>
host -t txt <domain>
```
1. Ataque de diccionario para identificar dominios DNS
```
for domain in $(cat domains.txt); do host $domain.megacorpone.com; done | grep -vi NXDOMAIN
```
2. Identificar sub dominios de forma invesa, mediante la dirección IP
```
for ip in $(seq 1 254); do host 200.23.91.$ip; done | grep -vE "not found | record"
```
#### dnsrecon
```bash
dnsrecon -d <domain> -t std
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-spanish.txt -t brt
```
#### dnsenum
```bash
dnsenum <domain>
```
#### nslookup
```bash
nslookup mail.<domain>
nslookup -type=TXT info.<domain> <IP-Server-DNS>
```
#### subfinder
```bash
subfinder -d <domain>
subfinder -d <domain> -sources crtsh,dnsdumpster
```
#### amass
```bash
amass enum -list
amass enum -d <domain> -o <output.txt>
```
#### ffuf
```bash
ffuf -u "https://FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

```
/usr/share/seclists/Discovery/DNS/namelist.txt
/usr/share/seclists/Discovery/DNS/subdomains-spanish.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### http
https://securityheaders.com/
https://www.ssllabs.com/ssltest/

#### Web Tecnology
```bash
whatweb 192.168.158.65
```

#### Fuzzing
1. Virtual Host
#### ffuf
```bash
ffuf -t 60 -u "http://<domain>" -H 'Host: FUZZ.<domain>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
2. Directorios y archivos
Wordlist
```
/usr/share/dirb/wordlists/common.txt
/usr/share/dirb/wordlists/small.txt
/usr/share/dirb/wordlists/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/dirb/wordlists/extensions_common.txt
/usr/share/dirb/wordlists/spanish.txt
```
##### nmap
```bash
nmap -Pn -sT -sV --script http-enum -n <IP> -p <PORT> 
nmap -Pn -sT -sV -n <IP> -p 80 --script http-enum --script-args http-enum.basepath="dev/"
```
##### dirsearch
```bash
dirsearch -u <url> -x 404,403,400 --exclude-sizes=0B --random-agent -t 60 
dirsearch -u <url> -e html,txt,asp,aspx -x 404,403,400 --exclude-sizes=0B --random-agent -t 60 -f
dirsearch -u <url> -e html,txt,asp,aspx -x 404,403,400 --exclude-sizes=0B --random-agent -t 60 -w <wordlist-common.txt> -f
```
##### wfuzz
```bash
wfuzz -u http://<IP>/FUZZ --c -t 50 --hc=404,400 --hh=3 -w <wordlist-common.txt,small.txt,big.txt,directory-list-2.3-medium.txt>
```
##### dirb
```bash
dirb <url> -a pen200
dirb <url> -X '.html,.txt' /usr/share/dirb/wordlists/common.txt -a pen200
```

### FTP
```bash
ftp <IP>
wget -m --user=anonymous --password=anonymous ftp://192.168.214.65
```
```bash
for file in $(curl -s -u "anonymous:anonymous" ftp://192.168.214.65/Logs/ | sed 's/\ \{2,3\}/#/g' | cut -d ' ' -f 2); do curl -s  -u "anonymous:anonymous" ftp://192.168.214.65/Logs/$file --output $file && echo $file;  done
```

### RCP
```bash
rpcclient -U "" 192.168.158.65
```
```
>srvinfo /* operating system version */
>netshareenumall /* enumerate all shares and its paths */
>enumdomusers /* rid */*
>enumdomgroups
>querygroupmem 0x200  /* (rid) *rid group */*
>queryuser --> 0x1f4 *rid user
>getdompwinfo # smb password policy configured on the server
```

### SMB
```bash
smbclient -L <IP> -N m SMB2
smbclient -L <IP>.168.158.65 -N
smbclient //<IP>/IPC$ -N -m SMB2
smbclient //<IP>/IPC$ -N
```

```bash
crackmapexec smb <IP> -u '' -p ''
crackmapexec smb <IP> -u '' -p '' --shares
crackmapexec smb <IP> -u 'guest' -p '' --shares
crackmapexec smb <IP> -u 'guest' -p '' --rid-brute 4000 
crackmapexec smb <IP> -u 'guest' -p '' --users
```

```bash
smbmap -H <IP> -u '' -p ''
smbmap -u guest -p '' -H <IP>
smbmap -H <IP> -r carpeta
smbmap -H <IP> --download general/file.txt
```



# Vulns Discovery

#### Explois

##### Exploit DB
https://www.exploit-db.com/
```bash
searchsploit SmarterMail
searchsploit -x 15048
searchsploit -m 15048
```

### http
#### Fuzzing
```bash
/usr/share/dirb/wordlists/vulns/...
/usr/share/dirb/wordlists/vulns/apache.txt
/usr/share/dirb/wordlists/vulns/iis.txt
/usr/share/dirb/wordlists/vulns/jboss.txt
/usr/share/dirb/wordlists/vulns/netware.txt
/usr/share/dirb/wordlists/vulns/oracle.txt
/usr/share/dirb/wordlists/vulns/sap.txt
/usr/share/dirb/wordlists/vulns/sharepoint.txt
/usr/share/dirb/wordlists/vulns/tomcat.txt
/usr/share/dirb/wordlists/vulns/weblogic.txt
/usr/share/dirb/wordlists/vulns/websphere.txt
```


