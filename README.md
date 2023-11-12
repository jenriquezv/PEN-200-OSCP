# Recon
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

### http
comando 1
elian

![[images/1.png]]