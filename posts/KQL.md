# Initial Access

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Spearphishing Attachment**

This query detects the execution of malicious attachments delivered via email, focusing on suspicious processes spawned by email clients or opening of files with common phishing extensions.

```kql
// Detect execution of suspicious attachments from email clients
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("outlook.exe", "thunderbird.exe", "winmail.exe")
    // Add other email client executables relevant to your environment
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr" or FileName endswith ".hta"
    // Modify the list of extensions based on common malicious attachment types
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

2. **Drive-by Compromise**

This query detects the execution of scripts or downloads initiated by web browsers, which may indicate a drive-by compromise.

```kql
// Detect execution of scripts or downloads initiated by web browsers
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe", "safari.exe")
    // Add or remove browsers as necessary
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".js" or FileName endswith ".vbs"
    // Include file types that could be maliciously downloaded
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, 
InitiatingProcessParentFileName
| order by Timestamp desc
```

---

3. **Exploit Public-Facing Application**

This query detects suspicious processes or commands executed by public-facing applications, which may indicate exploitation attempts.

```kql
// Detect suspicious commands executed by public-facing applications
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe")
    // Add other public-facing application processes as needed
| where ProcessCommandLine has_any ("cmd.exe", "powershell.exe", "whoami", "net user", "nslookup")
    // Include commands that are uncommon for these applications to execute
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

4. **External Remote Services**

This query identifies successful remote desktop or SSH connections from external IP addresses, which may indicate unauthorized access.

```kql
// Detect successful remote connections from external IPs
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"  // Exclude localhost
| where isnotempty(RemoteIP)
| extend RemoteIPType = iff(ipv4_is_private(RemoteIP), "Private", "Public")
| where RemoteIPType == "Public"
| summarize LogonCount = count() by AccountName, RemoteIP, DeviceName
| order by LogonCount desc
```

---

5. **Valid Accounts**

This query detects the creation of new user accounts or addition of users to privileged groups, which may indicate the use of valid accounts for initial access.

```kql
// Detect creation of new user accounts or privilege escalation
DeviceEvents
| where ActionType in ("UserAccountCreated", "UserAddedToGroup")
| extend ParsedFields = parse_json(AdditionalFields)
| extend GroupName = tostring(ParsedFields.TargetGroupName)
| where ActionType == "UserAddedToGroup" and GroupName in ("Admin", "Remote Desktop Users", "Domain Admins")
    // Adjust group names based on your environment
| project Timestamp, DeviceName, ActionType, AccountName, InitiatingProcessAccountName, GroupName
| order by Timestamp desc
```

# Execution

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect files with known malware hashes**
   ```kql
   // Edit the list of known bad hashes to match the malware you are searching for
   DeviceFileEvents
   | where SHA256 in ("known_hash_1", "known_hash_2", "known_hash_3")
   | project DeviceName, SHA256, FileName, FolderPath, Timestamp
   ```

2. **Detect unusual file executions**
   ```kql
   // Customize "Temp" and "AppData" if malware is known to execute from other directories
   DeviceProcessEvents
   | where ProcessCommandLine contains ".exe" and (InitiatingProcessFolderPath contains "Temp" or InitiatingProcessFolderPath contains "AppData")
   | project DeviceName, ProcessCommandLine, InitiatingProcessFolderPath, Timestamp
   ```

3. **Identify PowerShell script executions**
   ```kql
   // Add specific PowerShell commands you expect attackers to use, if known
   DeviceProcessEvents
   | where ProcessCommandLine contains "powershell"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect suspicious WMI activity**
   ```kql
   // Modify if specific WMI commands are of interest (e.g., suspicious processes)
   DeviceProcessEvents
   | where ProcessCommandLine contains "wmic"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```


# Persistence

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect changes to registry run keys**
   ```kql
   // Adjust the registry key paths to match other areas of interest (e.g., software persistence locations)
   DeviceRegistryEvents
   | where InitiatingProcessFolderPath endswith "Run"
   | project DeviceName, InitiatingProcessFolderPath, RegistryValueName, Timestamp
   ```

2. **Identify new services**
   ```kql
   // Customize if attackers typically use different commands to create services
   DeviceProcessEvents
   | where ProcessCommandLine contains "sc.exe create"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

3. **Detect unusual scheduled tasks**
   ```kql
   // Modify the search to include other command-line tools for task scheduling (e.g., PowerShell)
   DeviceProcessEvents
   | where ProcessCommandLine contains "schtasks"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect auto-start entries in startup folders**
   ```kql
   // Adjust folder paths based on known or suspected locations attackers might use for persistence
   DeviceFileEvents
   | where FolderPath contains "Startup"
   | project DeviceName, FileName, FolderPath, Timestamp
   ```

5. **Detect DLL hijacking attempts**
   ```kql
   // Modify file paths and file types if you suspect DLL hijacking attempts in other directories
   DeviceFileEvents
   | where FileName endswith ".dll" and (FolderPath contains "Windows" or FolderPath contains "System32")
   | project DeviceName, FileName, FolderPath, Timestamp
   ```

# Privilege Escalation

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect suspicious use of `whoami` command**
   ```kql
   // Optionally add other privilege-related commands to the search criteria
   DeviceProcessEvents
   | where ProcessCommandLine contains "whoami"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

2. **Detect new administrative account creation**
   ```kql
   // Adjust "Administrators" group if you have other privileged groups
   IdentityInfo
   | where Type == "User" and AccountDomain == "Administrators"
   | project AccountName, Timestamp
   ```

3. **Unusual process started by `SYSTEM` user**
   ```kql
   // Add more specific filtering for processes you deem suspicious for SYSTEM account usage
   DeviceProcessEvents
   | where InitiatingProcessAccountName == "SYSTEM"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect abnormal group membership changes**
   ```kql
   // Detect users added to the "Administrators" group
   DeviceEvents
   | where ActionType == "UserAddedToGroup"
   | extend ParsedFields = parse_json(AdditionalFields)
   | extend GroupName = tostring(ParsedFields.TargetGroupName)
   | where GroupName == "Administrators"
   | project Timestamp, AccountName, InitiatingProcessAccountName, GroupName
   | order by Timestamp desc
   ```

5. **Detect use of privileged service accounts**
   ```kql
   // Modify "svc" to match naming conventions for service accounts in your environment
   DeviceLogonEvents
   | where AccountName contains "svc" and LogonType == "Interactive"
   | project DeviceName, AccountName, Timestamp
   ```

# Defense Evasion

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect suspicious WMI activity**
   ```kql
   // Modify if specific WMI commands are of interest (e.g., suspicious processes)
   DeviceProcessEvents
   | where ProcessCommandLine contains "wmic"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

# Credential Access

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Identify multiple failed network logon attempts**
   ```kql
   // Customize threshold (e.g., >5) for login failures based on your security policy
   DeviceNetworkEvents
   | where ActionType == "FailedLogin"
   | summarize FailedAttempts = count(), LastAttempt = max(Timestamp) by InitiatingProcessAccountName, RemoteIP
   | where FailedAttempts > 5
   | project LastAttempt, InitiatingProcessAccountName, RemoteIP, FailedAttempts
   ```

2. **Detect possible credential dumping (LSASS access)**
   ```kql
   // Look for suspicious access to LSASS (commonly targeted for credential dumping)
   DeviceProcessEvents
   | where ProcessCommandLine contains "lsass.exe"
   | where InitiatingProcessCommandLine contains "procdump" or InitiatingProcessCommandLine contains "mimikatz"
   | project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine
   ```

3. **Detect suspicious use of `rundll32` for credential access**
   ```kql
   // Monitor for rundll32 being used suspiciously to invoke malicious DLLs for credential theft
   DeviceProcessEvents
   | where ProcessCommandLine contains "rundll32.exe"
   | where ProcessCommandLine contains "samcli.dll" or ProcessCommandLine contains "vaultcli.dll"  // DLLs related to credential theft
   | project Timestamp, DeviceName, AccountName, ProcessCommandLine
   ```

4. **Detect suspicious PowerShell use for credential theft**
   ```kql
   // Monitor for suspicious PowerShell commands that may be related to credential harvesting
   DeviceProcessEvents
   | where ProcessCommandLine contains "powershell.exe"
   | where ProcessCommandLine contains "Get-Credential" or ProcessCommandLine contains "Get-Clipboard"
   | project Timestamp, DeviceName, AccountName, ProcessCommandLine
   ```


# Discovery

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Identify multiple failed network logon attempts**
   ```kql
   // Customize threshold (e.g., >5) for login failures based on your security policy
   DeviceNetworkEvents
   | where ActionType == "FailedLogin"
   | summarize FailedAttempts = count(), LastAttempt = max(Timestamp) by InitiatingProcessAccountName, RemoteIP
   | where FailedAttempts > 5
   | project LastAttempt, InitiatingProcessAccountName, RemoteIP, FailedAttempts
   ```

2. **Detect network scanning activity**
   ```kql
   // Replace RemotePort values to target additional known scanning ports or services
   DeviceNetworkEvents
   | where ActionType == "Scan" and RemotePort < 1024
   | summarize count() by DeviceName, RemoteIP
   ```

# Lateral Movement

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect RDP connections**
   ```kql
   // Adjust the port (3389) if your environment uses a non-standard port for RDP
   DeviceNetworkEvents
   | where RemotePort == 3389
   | project DeviceName, RemoteIP, Timestamp
   ```

2. **Detect abnormal SMB connections**
   ```kql
   // Customize RemotePort (445) if you use other SMB variants
   DeviceNetworkEvents
   | where RemotePort == 445
   | summarize count() by DeviceName, RemoteIP
   ```

3. **Detect use of `PsExec` tool**
   ```kql
   // Adjust based on known PsExec variants or command-line switches specific to your environment
   DeviceProcessEvents
   | where ProcessCommandLine contains "psexec"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect lateral movement via WMI**
   ```kql
   // Add other WMI commands of interest if your environment has variations
   DeviceProcessEvents
   | where ProcessCommandLine contains "wmic" and ProcessCommandLine contains "\\"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

5. **Detect remote service creation**
   ```kql
   // Modify "sc.exe create" if the attacker uses alternative service creation methods
   DeviceProcessEvents
   | where ProcessCommandLine contains "sc.exe" and ProcessCommandLine contains "create"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```


# Collection

## Notes:
- Each script includes a comment on which part should be customized, such as file paths, file types, or specific processes, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect data staging in suspicious directories**
   ```kql
   // Edit the folder paths if attackers are known to use other directories in your environment
   DeviceFileEvents
   | where FolderPath contains "Temp" or FolderPath contains "Downloads" or FolderPath contains "AppData"
   | where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
   | project Timestamp, DeviceName, FolderPath, FileName, FileSize
   ```

2. **Detect large file transfers via Network Shares**
   ```kql
   // Adjust the file size threshold to fit your organization’s definition of "large files"
   DeviceFileEvents
   | where ActionType == "FileCreated" or ActionType == "FileModified"  // Track file creation or modification
   | where FolderPath startswith "\\\\"                                // Look for file access over network shares
   | where FileSize > 100000000  // Threshold set to 100 MB
   | project Timestamp, DeviceName, FileName, FolderPath, FileSize
   ```

3. **Detect screen capture activity**
   ```kql
   // Customize process names if attackers are known to use other screenshot tools in your environment
   DeviceProcessEvents
   | where ProcessCommandLine contains "snippingtool.exe" or ProcessCommandLine contains "mspaint.exe" or ProcessCommandLine contains "screenshot"
   | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
   ```

4. **Detect sensitive file access**
   ```kql
   // Update the file types and folder paths based on the types of sensitive data in your organization
   DeviceFileEvents
   | where FileName endswith ".docx" or FileName endswith ".xlsx" or FileName endswith ".pdf"
   | where FolderPath contains "Documents" or FolderPath contains "Finance"
   | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
   ```

5. **Detect clipboard access for potential data collection**
   ```kql
   // Edit the process names if attackers are known to use specific clipboard tools in your environment
   DeviceProcessEvents
   | where ProcessCommandLine contains "clip.exe" or ProcessCommandLine contains "powershell Get-Clipboard"
   | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
   ```

   # Command and Control (C2)

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect unusual outbound traffic**
   ```kql
   // This query identifies outbound traffic to public IPs on non-standard ports (above 1024). 
   // Adjust RemotePort or RemoteIPType based on your organization's network behavior.
   DeviceNetworkEvents
   | where RemoteIPType == "Public" and RemotePort > 1024
   | summarize count() by RemoteIP
   | sort by count_ desc
   ```

2. **Identify devices communicating with suspicious IPs**
   ```kql
   // Edit the list of known malicious IPs to suit your environment
   DeviceNetworkEvents
   | where RemoteIP in ("known_bad_ip_1", "known_bad_ip_2")
   | project DeviceName, RemoteIP, RemotePort, Timestamp
   ```

3. **Unusual DNS requests**
   ```kql
   // Adjust RemotePort if looking at different DNS services; customize domain TLDs if necessary
   DeviceNetworkEvents
   | where RemotePort == 53 and not (RemoteIP contains ".com" or RemoteIP contains ".org")
   | project DeviceName, RemoteIP, Timestamp
   ```

4. **Detect potential DNS tunneling activity**
   ```kql
   // Adjust the threshold and domain TLDs based on your organization's network behavior
   DnsEvents
   | where QueryType == "A"  // Filter for standard A (IPv4) DNS queries
   | where (Name endswith ".net" or Name endswith ".info" or Name endswith ".xyz")  // Adjust TLDs as necessary
   | summarize count() by ClientIP, Name
   | where count_ > 100  // DNS tunneling often generates a high volume of requests
   | project ClientIP, Name, count_
   ```

5. **Detect external connections to non-standard ports**
   ```kql
   // Replace RemoteIPType and adjust port range if necessary
   DeviceNetworkEvents
   | where RemoteIPType == "Public" and (RemotePort < 1024 or RemotePort > 65535)
   | project Timestamp, DeviceName, RemoteIP, RemotePort, ActionType
   ```


# Exfiltration

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Unusual DNS requests**
   ```kql
   // Adjust RemotePort if looking at different DNS services; customize domain TLDs if necessary
   DeviceNetworkEvents
   | where RemotePort == 53 and not (RemoteIP contains ".com" or RemoteIP contains ".org")
   | project DeviceName, RemoteIP, Timestamp
   ```

2. **Exfiltration Over C2 Channel**

```kql
// Detect unusual outbound connections to external IPs by uncommon processes
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName != "System"  // Exclude system processes; add more if necessary
| where RemoteIPType == "Public"  // Filters for external IP addresses
| summarize ConnectionCount = count() by 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteIP
| where ConnectionCount > 1000  // Adjust this threshold based on normal activity
| order by ConnectionCount desc
```

```kql
// Detect processes making a high number of HTTP POST requests to external IPs
DeviceNetworkEvents
| where ActionType == "HttpPost"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName != "System"
| summarize PostCount = count() by 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteIP, 
    RemoteUrl
| where PostCount > 100  // Adjust this threshold based on normal activity
| order by PostCount desc
```

3. **Exfiltration Over Web Service**

This query looks for HTTP POST requests to popular cloud storage services, which may indicate data exfiltration via web services.

```kql
// Detect high number of HTTP POST requests to cloud storage services
DeviceNetworkEvents
| where ActionType == "HttpPost"
| where InitiatingProcessFileName != "System"  // Exclude system processes; modify as needed
| where RemoteUrl matches regex @"(dropbox\.com|drive\.google\.com|onedrive\.live\.com|box\.com|s3\.amazonaws\.com)"
// Modify the regex above to include or exclude specific cloud services relevant to your environment
| summarize PostCount = count() by 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteUrl
| where PostCount > 50  // Adjust based on typical usage in your organization
| order by PostCount desc
```

4. **Archive Collected Data**

This query detects the creation of archive files by unusual processes, which may signal data being prepared for exfiltration.

```kql
// Detect creation of archive files by unusual processes
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith '.zip' or FileName endswith '.rar' or FileName endswith '.7z' or FileName endswith '.tar.gz'
// Add or remove file extensions above to match archive formats used in your environment
| where InitiatingProcessFileName !in~ ('explorer.exe', 'winrar.exe', '7z.exe', 'tar.exe')  // Exclude known archiving tools; add any others used legitimately
| project Timestamp, 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    FolderPath, 
    FileName
| order by Timestamp desc
```

5. **Obfuscated Files or Information**

This query searches for the use of encryption tools or commands, potentially indicating data encryption before exfiltration.

```kql
// Detect usage of encryption tools and commands
DeviceProcessEvents
| where ProcessCommandLine has_any ("gpg", "openssl", "certutil", "encrypt", "gpg.exe", "openssl.exe", "certutil.exe")
// Modify the list above to include or exclude encryption tools and keywords relevant to your environment
| project Timestamp, 
    DeviceName, 
    FileName, 
    ProcessCommandLine, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine
| order by Timestamp desc

```


# Impact

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Data Encrypted for Impact**

This query detects processes that are encrypting multiple files, which may indicate ransomware activity.

```kql
// Detect potential ransomware file encryption activity
DeviceFileEvents
| where ActionType == "FileModified"
| where FileName endswith ".encrypted" or FileName matches regex @".*\.(lock|crypt|cry)$"
    // Add or modify file extensions and patterns relevant to known ransomware in your environment
| where InitiatingProcessFileName != "explorer.exe"  // Exclude legitimate processes; add more if necessary
| summarize FileCount = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where FileCount > 100  // Adjust threshold based on normal activity
| order by FileCount desc
```

2. **Inhibit System Recovery**

This query identifies attempts to delete or modify system recovery configurations or shadow copies, which can inhibit system recovery.

```kql
// Detect deletion of shadow copies and modifications to system recovery settings
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete", "diskshadow")
    or ProcessCommandLine has_any ("bcdedit /set", "wbadmin delete", "Remove-Item")
    // Add or adjust commands based on methods used to inhibit system recovery
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

3. **Service Stop**

This query detects attempts to stop or disable services, which can impact system functionality or security.

```kql
// Detect attempts to stop or disable services
DeviceProcessEvents
| where ProcessCommandLine has_any ("net stop", "sc stop", "Set-Service -Status Stopped", "Stop-Service")
    // Modify the list above to include other commands used to stop services
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

4. **System Shutdown/Reboot**

This query identifies processes initiating a system shutdown or reboot, which could be malicious if unexpected.

```kql
// Detect processes initiating system shutdown or reboot
DeviceProcessEvents
| where ProcessCommandLine has_any ("shutdown /s", "shutdown /r", "Restart-Computer", "Stop-Computer")
    // Add other commands or scripts used to shutdown or reboot systems in your environment
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

5. **Defacement**

This query detects modifications to web server content directories, which may indicate defacement activities.

```kql
// Detect modifications to web server content directories
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified", "FileDeleted")
| where FolderPath startswith @"C:\inetpub\wwwroot" or FolderPath startswith @"/var/www/html"
    // Adjust the paths above to match web content directories in your environment
| where InitiatingProcessFileName !in~ ("w3wp.exe", "httpd.exe", "nginx.exe")
    // Exclude legitimate web server processes; add more if necessary
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```


