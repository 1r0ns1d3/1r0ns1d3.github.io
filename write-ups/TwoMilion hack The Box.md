after connecting to the network thru VPN I start with scanning the machine for open ports.
nmap -A -vv -p- 10.129.203.35

Due to a rather slow connection or pings being blocked the scan does not complete and i have to adjust the command.
nmap -A -vv -p- 10.129.203.35 -Pn

this command on its own takes over 3 hours to complete. so the -T5 argument is given to speed up the process, knowing that detection is not a relevant issue on hack the box.
nmap -A -vv -p- 10.129.203.35 -Pn -T5

The command gave the following output
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-26 04:43 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:43
Completed NSE at 04:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:43
Completed NSE at 04:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:43
Completed NSE at 04:43, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 04:43
Completed Parallel DNS resolution of 1 host. at 04:43, 0.00s elapsed
Initiating SYN Stealth Scan at 04:43
Scanning 10.129.203.35 [65535 ports]
SYN Stealth Scan Timing: About 0.90% done
Discovered open port 22/tcp on 10.129.203.35
Discovered open port 80/tcp on 10.129.203.35
SYN Stealth Scan Timing: About 55.81% done; ETC: 04:45 (0:00:48 remaining)
Completed SYN Stealth Scan at 04:45, 82.21s elapsed (65535 total ports)
Initiating Service scan at 04:45
Scanning 2 services on 10.129.203.35
Completed Service scan at 04:45, 6.30s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.129.203.35
Retrying OS detection (try #2) against 10.129.203.35
Initiating Traceroute at 04:45
Completed Traceroute at 04:45, 0.15s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 04:45
Completed Parallel DNS resolution of 2 hosts. at 04:45, 0.00s elapsed
NSE: Script scanning 10.129.203.35.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:45
Completed NSE at 04:45, 4.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:45
Completed NSE at 04:45, 0.59s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:45
Completed NSE at 04:45, 0.00s elapsed
Nmap scan report for 10.129.203.35
Host is up, received user-set (0.13s latency).
Scanned at 2024-07-26 04:43:51 CDT for 98s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://2million.htb/
OS fingerprint not ideal because: Timing level 5 (Insane) used
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=7/26%OT=22%CT=1%CU=37405%PV=Y%DS=2%DC=T%G=N%TM=66A37039%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 40.924 days (since Sat Jun 15 06:35:33 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 15972/tcp)
HOP RTT       ADDRESS
1   145.25 ms 10.10.14.1
2   145.56 ms 10.129.203.35

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:45
Completed NSE at 04:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:45
Completed NSE at 04:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:45
Completed NSE at 04:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.97 seconds
           Raw packets sent: 67460 (2.970MB) | Rcvd: 66190 (2.651MB)


Port 22 ssh is ignored for now due to the low probability that there is a working exploit for ssh
That means starting with port 80 http starting with accessing the webpage from the browser
![[Pasted image 20240726115133.png]]
as seen the webpage tries to redirect me to http://2million.htb this is not a known DNS query so to resolve this I will add the address in the /etc/hosts file
![[Pasted image 20240726115348.png]]
now the webpage should load correctly
on the login page a register button was found allowing me to go to /invite
![[Pasted image 20240726120153.png]]
this page contained a javascript with the function makeInviteCode this function was called from the console to generate the following data: 
Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr

this message was ROT13 encoded after decoding this message in cyberchef the cleartext message was:
In order to generate the invite code, make a POST request to /api/v1/invite/generate

to do this I used Curl with the following command:
![[Pasted image 20240726120350.png]]
as seen in the image it returned another code:
QU9HRlgtODlHMVctUURKSDctSUlQODM=

This looks base64 encoded, so we will use cyberchef again to decode this message, the cleartext code was:
AOGFX-89G1W-QDJH7-IIP83

this looks like it could be an invite code so let's try using it
![[Pasted image 20240726120549.png]]
it works now we can register an account and continue our enumeration
![[Pasted image 20240726120727.png]]
we are redirected to our homepage and from here we start enumerating again, and on the access page we find two buttons that make an API call
![[Pasted image 20240726120931.png]]
using burpsuite and intercepting the request we adjust the request to probe the API
![[Pasted image 20240726121303.png]]
and as we can see there are a couple of API calls available I will now try what can be achieved using the API calls
![[Pasted image 20240726121616.png]]
we can see that we can update settings however we need to get the correct message content type
as we have seen that the API uses JSON format this will be our first attempt
"Content-Type: application/json"
after tinkering a lot with the message and the formatting i get an update stating that my account is now admin
![[Pasted image 20240726122211.png]]
going back to the API call we could generate a vpn connection for admin, now that we have an admin account we can try generating this file, after some more tinkering the file is generated and send to burp 
![[Pasted image 20240726122505.png]]
unfortunately the openvpn file does not give me a connection, however the generation is a local process, so perhaps we could inject some commands
it appears that the username parameter is vulnerable to a command injection attack
![[Pasted image 20240726122755.png]]
after the first few attempts to get a reverse shell i get no response so I will try encoding the payloads as there may be some filtering mechanism
after base 64 encoding and decoding in the payload i get a shell
![[Pasted image 20240726123310.png]]
![[Pasted image 20240726123254.png]]
after some basic enumeration there appears to be a user named "admin"
in the PWD after getting a shell there appears to be a hidden file that contains credentials for a user also named admin
![[Pasted image 20240726123641.png]]
they should be DB passwords but let's see if password reuse is done
![[Pasted image 20240726123747.png]]
the password is indeed being reused now we have control of the user in an attempt to get a more stable shell i will check to see if this user is allowed a SSH connection
and that is indeed allowed this connection is way more stable and now I can release the old connection
Now we start enumerating for root first checking sudo -l, however this user is not allowed to use sudo.
after further enumeration in the /var/mail we find that admin has got mail
![[Pasted image 20240726124607.png]]
this kernel might be exploitable
![[Pasted image 20240726124631.png]]
it would appear that this kernel is vulnerable to the DirtyPipe exploit so I will try to use this exploit to gain a root shell
afer using the exploit from https://github.com/xkaneiki/CVE-2023-0386 this github we get a root shell
![[Pasted image 20240726131837.png]]
