# Proactive Threat Hunt: Signals Before the Noise — PHTG

**Analyst:** Tiernan Falcon\
**Date Completed:** 25 April 2026 JST\
**Environment Investigated:** PHTG (`azwks-phtg-02`)\
**Timeframe:** 9 December 2025 – 23 December 2025 (UTC)\
**Platform:** Microsoft Defender for Endpoint (MDE) + Microsoft Sentinel — KQL / Log Analytics Workspace\
**Source:** Cyber Range (Intermediate Difficulty)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Key Findings](#key-findings)
3. [Environment & Hunt Scope](#environment--hunt-scope)
4. [All Flags Quick Reference](#all-flags-quick-reference)
5. [Attack Timeline](#attack-timeline)
6. [Hunt Narrative](#hunt-narrative)
7. [Conclusion](#conclusion)
8. [Remediation Recommendations](#remediation-recommendations)
9. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
10. [Final Thoughts & What I Learned](#final-thoughts--what-i-learned)
11. [Credits](#credits)
12. [Disclaimer](#disclaimer)

---

## Executive Summary

Signals Before the Noise documents a proactive threat hunt initiated not by an alert, but by an OSINT observation. A PHTG cloud engineer posted a photo to LinkedIn. The photo showed a workstation, an Azure portal session, and enough infrastructure detail to hand a threat actor a target. The exposed asset was `azwks-phtg-02`, a Windows workstation with a public IP address, RDP open to the internet, and its full VM configuration visible in the background of a social media post. There was no incident ticket. There was no SOC escalation. There was no suspected compromise. There was just a photo that should not have been posted, and a question: did anyone act on it?

They did.

The investigation unfolded across five MDE tables over a 14-day window. RDP scanning from public IP ranges began almost immediately after the LinkedIn post provided the target. 173 unique source IPs were observed making inbound connection attempts against port 3389. Of those, 57 IPs showed both a `ConnectionAttempt` and an `InboundConnectionAccepted` record, representing a broad automated brute-force campaign with meaningful reach. The scanning drew from 11 distinct countries. The authentication telemetry told the same story: 667 failed logon attempts against the exposed service before a successful `RemoteInteractive` logon landed from Uruguay, a country with no connection to PHTG's operations or workforce.

The account used in the successful authentication was `vmadminusername`. Twenty-three successful RDP sessions were established from two Uruguayan IP addresses across a three-day window. Operator activity within those sessions followed a recognizable pattern of reconnaissance: browser-based enumeration of Azure documentation, SharePoint, and Azure AD roles; repeated opening of internal PHTG documents; and systematic survey of the file system. The attacker read `notes_sarah.txt`, a file containing internal security-relevant content that reduced their operational effort without requiring any active discovery tooling.

The payload, initially staged on the workstation as `Sarah_Chen_Notes.exe.Txt`, was renamed into executable form using a double-extension evasion technique and then executed. Microsoft Defender detected it three times as `Trojan:Win32/Meterpreter.RPZ!MTB`, but Defender was operating in passive mode, which meant detections were logged and not acted upon. The payload ran freely. It subsequently moved through two further rename cycles, ending as `PHTG.exe` inside `C:\ProgramData\PHTG\HealthCloud\`, a directory belonging to a legitimate internal service PHTG had rolled out just one week before the attack. The attacker placed their final persistence payload inside the baseline noise of a brand-new internal tool, then wrapped its execution in a scheduled batch file to survive reboots.

The C2 callback destination was `173.244.55.130:4444`, a Meterpreter listener hosted in Uruguay — the same `/24` subnet as the successful RDP source IPs. The connection failed on all three observed attempts, indicating the C2 infrastructure may have been taken down or rotated, but the intent and the tooling were unambiguous.

This investigation was conducted exclusively through MDE and Sentinel telemetry using KQL in Log Analytics Workspace. No endpoint shell access, memory forensics, or packet capture was available. All findings were reconstructed through behavioral correlation of process execution, file system, network, and logon event data.

---

## Key Findings

- OSINT trigger confirmed: the exposed LinkedIn post revealed `azwks-phtg-02` with its public IP address `74.249.82.162` and full VM configuration detail, providing a threat actor with a ready-made external RDP target
- 194 total inbound network events recorded against port 3389 from public source IPs; 173 unique source IPs; 57 IPs showed both connection attempt and accepted connection records across 11 distinct countries
- 667 external RDP authentication failures recorded; `InvalidUserNameOrPassword` was the dominant failure reason, consistent with automated credential stuffing
- Successful RDP authentication confirmed from Uruguay (2 source IPs: `173.244.55.131` and `173.244.55.128`), using the `vmadminusername` account across 23 sessions spanning 12–13 December 2025
- Payload `Sarah_Chen_Notes.exe.Txt` delivered to the workstation, renamed using double-extension evasion to `Sarah_Chen_Notes.exe`, detected three times by Defender as `Trojan:Win32/Meterpreter.RPZ!MTB` with SHA256 `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`; Defender operating in passive mode prevented blocking
- Payload progressed through a second rename cycle, ultimately deployed as `PHTG.exe` inside `C:\ProgramData\PHTG\HealthCloud\`, deliberately blending into the legitimate HealthCloud service directory
- Execution persisted via `C:\ProgramData\PHTG\HealthCloud\Launch.bat`, wrapped by `cmd.exe` to provide a scheduled launch mechanism
- C2 callback to `173.244.55.130:4444` confirmed via `DeviceNetworkEvents` filtered to the payload SHA256; three connection attempts all returned `ConnectionFailed`, suggesting the listener was down or rotated
- C2 infrastructure geolocated to Uruguay, consistent with the RDP intrusion source, indicating the same actor controlled both the initial access and the post-exploitation infrastructure

---

## Environment & Hunt Scope

| Property | Detail |
|---|---|
| Target Company | PHTG |
| Target Asset | `azwks-phtg-02` |
| Public IP | `74.249.82.162` |
| Hunt Type | Proactive / Hypothesis-Driven |
| Trigger | OSINT review of employee LinkedIn post |
| Investigation Window | 9 December 2025 – 23 December 2025 UTC |
| SIEM | Microsoft Sentinel |
| Workspace | `law-cyber-range` |
| Tables Used | `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents` |
| Baseline Noise | HealthCloud internal service (rolled out 11 Dec 2025): PowerShell tasks, diagnostic cache directories, and periodic check-ins from private IP ranges |

The HealthCloud rollout is the critical context for this hunt. PHTG deployed it on 11 December 2025, one day before the confirmed intrusion began. The service created scheduled PowerShell tasks, background executables, and diagnostic cache directories under `C:\ProgramData\PHTG\HealthCloud\`. The attacker was aware of this baseline and deliberately placed their final payload inside it, counting on the new service noise to absorb their footprint.

---

## All Flags Quick Reference

| Flag | Question | Answer |
|---|---|---|
| Q00 | Fictional company name | PHTG |
| Q01 | Exposed virtual machine name | `azwks-phtg-02` |
| Q02 | Public IP address of the VM | `74.249.82.162` |
| Q03 | Clearest indicator for a threat actor | D — Visible public IP address |
| Q04 | Activity type shown in LinkedIn photo | C — Managing cloud infrastructure resources |
| Q05 | Primary telemetry source for scanning review | D — Azure network or platform analytics related to inbound connections |
| Q06 | Local port showing broad automated scanning | `3389` |
| Q07 | Total network events from public IPs on port 3389 | `194` |
| Q08 | Unique public source IPs on port 3389 | `173` |
| Q09 | Unique source IPs with both attempt and accepted connection | `57` |
| Q10 | Distinct countries associated with RDP connection activity | `11` |
| Q11 | Total external authentication events | 693 |
| Q12 | RDP-related authentication events | `675` |
| Q13 | Dominant authentication outcome | `LogonFailed` |
| Q14 | Most common failure reason | `InvalidUserNameOrPassword` |
| Q15 | Unique countries in RDP auth events | `17` |
| Q16 | Countries with at least one successful auth event | `2` |
| Q17 | Countries with successful RDP authentication | `United States, Uruguay` |
| Q18 | Country outside PHTG's expected operating region | `Uruguay` |
| Q19 | Account used in successful auth from Uruguay | `vmadminusername` |
| Q20 | Successful RDP auth events from Uruguay | `23` |
| Q21 | First RemoteIP from Uruguay | `173.244.55.131` |
| Q22 | Second RemoteIP from Uruguay | `173.244.55.128` |
| Q23 | First notable process after Uruguay logon | `notepad.exe` |
| Q24 | Sensitive text file opened during session | `notes_sarah.txt` |
| Q25 | First renamed filename with executable extension | `Sarah_Chen_Notes.exe` |
| Q26 | Double-extension evasion filename | `Sarah_Chen_Notes.exe.Txt` |
| Q27 | SHA256 of payload file | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` |
| Q28 | Final observed filename for this hash | `PHTG.exe` |
| Q29 | Malware family classification | `Trojan:Win32/Meterpreter.RPZ!MTB` |
| Q30 | Defender operating mode that allowed execution | `Passive mode` |
| Q31 | Payload filename during first execution phase | `Sarah_Chen_Notes.exe` |
| Q32 | Process initiating later payload executions | `cmd.exe` |
| Q33 | Full path of batch file wrapper | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` |
| Q34 | C2 IP address | `173.244.55.130` |
| Q35 | C2 infrastructure location | `Uruguay, South America` |
| Q36 | C2 remote port | `4444` |
| Q37 | Legitimate service directory used for payload persistence | `HealthCloud` |

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| Pre-9 Dec 2025 | PHTG cloud engineer posts LinkedIn photo exposing `azwks-phtg-02` and its public IP |
| 11 Dec 2025 | PHTG rolls out HealthCloud internally; `C:\ProgramData\PHTG\HealthCloud\` becomes established baseline |
| 11 Dec 2025, ~02:38 | First `InboundConnectionAccepted` event on port 3389 recorded |
| 11–14 Dec 2025 | Broad automated RDP scanning from 173 public IPs; 667 failed authentication attempts logged |
| 12 Dec 2025, 05:47 | First successful RDP logon from Uruguay (`173.244.55.131`), account `vmadminusername` |
| 12 Dec 2025, 13:32 | Second Uruguay session begins (`173.244.55.128`); operator opens Explorer, launches Edge, begins document enumeration |
| 12 Dec 2025, 13:35 | `powershell.exe` launched interactively; `notepad.exe` opened; operator begins file survey |
| 12 Dec 2025, 13:46 | Operator opens internal PHTG documents including `notes_sarah.txt` |
| 12 Dec 2025, 14:18 | `Sarah_Chen_Notes.exe.Txt` renamed to `Sarah_Chen_Notes.exe`; double-extension evasion complete |
| 12 Dec 2025, 14:18 | Defender detects `Trojan:Win32/Meterpreter.RPZ!MTB` (passive mode — no block) |
| 12 Dec 2025, 14:18–14:22 | `Sarah_Chen_Notes.exe` executes three times; Defender fires three detections, all passive |
| 12 Dec 2025, 14:19 | First C2 callback attempt to `173.244.55.130:4444` — `ConnectionFailed` |
| 13 Dec 2025, 09:34 | Operator opens `_.ps1` from Documents; PowerShell executes the script |
| 13 Dec 2025, 09:35 | `attrib.exe +h +s` applied to HealthCloud cache directories and FLAG files |
| 13 Dec 2025, 10:13 | `Sarah_Chen_Notes.exe` renamed to `PHTG.exe` inside `C:\ProgramData\PHTG\HealthCloud\` |
| 13 Dec 2025, 10:21 | `cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat"` executes `PHTG.exe` |
| 13 Dec 2025, 10:13 | Second C2 callback attempt to `173.244.55.130:4444` — `ConnectionFailed` |
| 13 Dec 2025, 10:22 | Third C2 callback attempt — `ConnectionFailed`; C2 listener appears down |
| 16–17 Dec 2025 | Further operator RDP sessions observed; reconnaissance activity continues |
| 22 Dec 2025 | Final session observed; operator reviews HealthCloud logs, internal scripts, and staging files |

---

## Hunt Narrative

**Phase 01–02: Public Exposure and Scanning**

The hunt started with the image. The LinkedIn post showed enough: a visible Azure portal session, a VM details pane, and a public IP address. `azwks-phtg-02` at `74.249.82.162` with RDP exposed to the internet, handed to anyone who saw it. The first question was whether the exposure had been acted on.

Querying `DeviceNetworkEvents` for inbound traffic on port 3389 from public IPs produced 194 events from 173 unique source IPs across the 14-day window. 57 IPs showed evidence of both attempting and successfully connecting. Geographic enrichment through the GeoTable CSV placed those 57 IPs across 11 countries, confirming a distributed, automated scan campaign rather than a targeted single-source effort.

**Phase 03: Authentication Baseline**

The authentication picture built on top of the network picture. Querying `DeviceLogonEvents` for external source IPs confirmed 675 RDP-related authentication events (combining `Network` and `RemoteInteractive` logon types). `LogonFailed` was the dominant outcome at 646 events, with `InvalidUserNameOrPassword` as the uniform failure reason. This was credential stuffing at scale against an openly exposed RDP service with no lockout mechanism visible in the telemetry.

Of the 17 countries contributing auth traffic, two had successful logons. The United States was expected. Uruguay was not. PHTG operates exclusively in the United States with no international workforce, no remote contractors, and no documented external access arrangements. A successful `RemoteInteractive` logon from Uruguay using `vmadminusername` was anomalous from the first event and only became more so as the session volume accumulated.

**Phase 04: Operator Activity**

Twenty-three successful logons from two Uruguayan IPs across a three-day window is not a scanner. That is an operator. The first session arrived at `2025-12-12T05:47:45Z` from `173.244.55.131` and was brief. The second wave began at `13:32Z` the same day from `173.244.55.128` and was not.

Pulling `DeviceProcessEvents` from the first Uruguayan logon timestamp forward and scoping to `vmadminusername` produced a dense but readable timeline. The early session scaffolding (`userinit.exe`, `SecurityHealthSystray.exe`, Edge startup, OneDrive background) gave way quickly. `notepad.exe` was the first process the operator opened with deliberate intent, launched from `explorer.exe` at `13:46Z`. From that point the document enumeration was methodical: `Notes 12122025.txt`, `notes_sarah.txt`, `PHTG_Project_Notes_azwks-phtg-02.txt`, `PHTG_ToDo_azwks-phtg-02.txt`, `TeamMeetingNotes.docx`. Each opened sequentially. The operator was reading.

`notes_sarah.txt` was the file that mattered. Among all the documents opened across the session, it was the one containing internal security-relevant content that would meaningfully reduce an attacker's effort. The filename pattern and the context of what surrounded it in the session made it stand out as the intelligence-gathering moment rather than general orientation.

Repeated Edge browser navigations reinforced the reconnaissance picture: `login.microsoftonline.com`, `company.sharepoint.com/sites/TeamHub`, `company.sharepoint.com/sites/HR`, and Azure AD roles documentation were all browsed in the same windows. The operator was mapping the environment's identity and access structure without running a single discovery tool.

**Phase 05: Payload Delivery and Evasion**

`Sarah_Chen_Notes.exe.Txt` arrived during the session and sat on the filesystem in its disguised form. The double-extension technique exploits a Windows default: with file extensions hidden, the file appears to be a text document. The rename to `Sarah_Chen_Notes.exe` at `14:18:38Z` was the moment it became an executable.

Defender fired within fourteen seconds. `Trojan:Win32/Meterpreter.RPZ!MTB` was the classification. The `ReportSource` field told the rest of the story: `Windows Defender Antivirus passive mode`. In passive mode, Defender reports but does not remediate. The file was flagged three times across four minutes and ran freely through all three detections. The C2 callback to `173.244.55.130:4444` fired during the first execution and returned `ConnectionFailed`. The infrastructure was down, or had already been rotated.

**Phase 06: Persistence via HealthCloud**

The attacker's response to a dead C2 listener was not to abandon the host. On 13 December, the operator returned. A PowerShell script named `_.ps1` was executed from the Documents directory, and `attrib.exe` was used to apply hidden and system attributes to HealthCloud cache paths and a sequence of flag-named text files, suggesting pre-staged content in the HealthCloud directory structure.

At `10:13:41Z`, `Sarah_Chen_Notes.exe` was renamed one final time to `PHTG.exe` inside `C:\ProgramData\PHTG\HealthCloud\`. Eight minutes later, `cmd.exe` launched it via `C:\ProgramData\PHTG\HealthCloud\Launch.bat`. The payload was now named after the company itself, sitting inside a directory belonging to a service deployed the previous week, and launched by a batch file that could be scheduled without raising obvious suspicion.

The C2 callback attempted twice more from `PHTG.exe` and failed both times. The listener was gone. The persistence mechanism was in place regardless.

---

## Conclusion

The intrusion into `azwks-phtg-02` began with a photograph. An employee disclosed enough infrastructure detail in a public social media post to hand a threat actor a target IP, a confirmed service port, and a hostname. The attack that followed was not sophisticated: it was opportunistic and patient. Automated scanning, credential stuffing, and eventually a successful brute-force logon. From there the operator worked methodically: reading internal documents, surveying the directory structure, establishing their payload inside the one directory least likely to attract attention, and attempting to phone home.

The C2 infrastructure failing does not reduce the severity of what was achieved. The attacker had authenticated access to a PHTG workstation for multiple days. They read internal documents. They staged a Meterpreter payload inside a legitimate service directory. They wrapped it in a batch file for persistent execution. The only thing that prevented the full post-exploitation chain from completing was an infrastructure failure on the attacker's side, not a defensive control on PHTG's side.

Defender was present on the host. It detected the payload correctly. It was in passive mode, so it did nothing about it.

The exposure was not an edge case or a technical misconfiguration deep in a cloud console. It was a photograph on LinkedIn. The entire attack surface of this intrusion was created by one post.

---

## Remediation Recommendations

### Immediate Actions

- Rotate all credentials associated with `vmadminusername` and audit all accounts that authenticated successfully from external IPs during the investigation window
- Remove or quarantine `PHTG.exe` from `C:\ProgramData\PHTG\HealthCloud\` and audit the full contents of the HealthCloud directory for attacker-staged files
- Review and remove `C:\ProgramData\PHTG\HealthCloud\Launch.bat` and any associated scheduled tasks
- Block `173.244.55.128`, `173.244.55.130`, and `173.244.55.131` at the network perimeter and review for any additional Uruguayan source IPs in authentication logs

### Defender Configuration

- Disable passive mode on all production endpoints; Defender must be running in active mode to block detected threats rather than only reporting them
- Enable Tamper Protection to prevent unauthorized mode changes
- Alert on `AntivirusDetectionActionType` events where `ReportSource` contains `passive mode`; detections in passive mode should generate immediate analyst review, not silent logs

### RDP Exposure

- Remove port 3389 from public exposure entirely; RDP should never be reachable directly from the internet
- Where remote access is operationally required, enforce it through a VPN or Azure Bastion with MFA
- Implement account lockout policy and alerting on repeated `InvalidUserNameOrPassword` failures from external IPs

### OSINT and Social Media Policy

- Establish and enforce a policy prohibiting the publication of infrastructure details in any form on social media, including screenshots, photos, and conference presentations
- Brief cloud engineering teams specifically on the risk of ambient disclosure: console sessions, VM details panes, and terminal windows visible in background photos
- Conduct periodic OSINT reviews of employee social media for inadvertent infrastructure exposure

### Detection Rules

- Alert on successful `RemoteInteractive` logons from geographies inconsistent with PHTG's operating region
- Alert on file rename events where the resulting filename carries an executable extension and the previous filename did not
- Alert on `attrib.exe +h +s` applied to paths under `C:\ProgramData\`
- Alert on outbound connections to port 4444 from any process, particularly from paths under `C:\ProgramData\`

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Confidence |
|---|---|---|---|
| Reconnaissance | T1593.001 | Search Open Websites/Domains: Social Media | 🔴 High |
| Initial Access | T1110.001 | Brute Force: Password Guessing | 🔴 High |
| Initial Access | T1021.001 | Remote Services: Remote Desktop Protocol | 🔴 High |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | 🔴 High |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | 🔴 High |
| Execution | T1204.002 | User Execution: Malicious File | 🔴 High |
| Defense Evasion | T1036.007 | Masquerading: Double File Extension | 🔴 High |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | 🔴 High |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | 🔴 High |
| Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | 🔴 High |
| Discovery | T1087 | Account Discovery | 🟠 Medium |
| Discovery | T1083 | File and Directory Discovery | 🔴 High |
| Discovery | T1518.001 | Software Discovery: Security Software Discovery | 🟠 Medium |
| Collection | T1005 | Data from Local System | 🔴 High |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | 🟠 Medium |
| Command and Control | T1571 | Non-Standard Port | 🔴 High |
| Command and Control | T1219 | Remote Access Software | 🔴 High |

> 🔴 **High** — Directly observed in telemetry and confirmed through flag output\
> 🟠 **Medium** — Strongly supported by correlated behavior; outcome partially confirmed or inferred from surrounding evidence

The ATT&CK coverage for this hunt is anchored in **Initial Access**, **Defense Evasion**, and **Discovery**, which reflects where the attacker invested the most deliberate effort. The double-extension masquerade, the HealthCloud directory blending, and the hidden-attribute application all point to an operator who understood the defensive landscape and worked within it rather than against it. The passive mode Defender configuration handed them the rest.

---

## Final Thoughts


The Defender passive mode finding was the sharpest moment in the investigation. The detection was accurate. The classification was correct. The hash was flagged three times in four minutes, each one tied to the same Meterpreter binary running in plain sight. And it did not matter, because passive mode turns Defender into a logging service with strong opinions. Knowing that a host is running Defender is not the same as knowing a host is protected by Defender. The mode matters as much as the presence.

The HealthCloud persistence story was the most instructive piece of attacker tradecraft in the hunt. The payload was not hidden in a temp directory or dropped under a suspicious username path. It was placed inside a directory belonging to a legitimate service that PHTG had deployed one week earlier. The attacker likely identified HealthCloud from the file system reconnaissance during the early sessions, recognised that a new internal service directory would have an established baseline with minimal analyst familiarity, and chose it deliberately. Defenders tend to trust new infrastructure because it has not yet generated noise worth investigating. That trust is the attack surface. Anything that was not present in the environment before an intrusion window opened is worth auditing afterward, regardless of how legitimate the directory name looks.

The C2 infrastructure failing on all three callback attempts was operationally lucky for PHTG but analytically interesting. The failure did not limit the investigation: the SHA256-based network query surfaced all three attempts cleanly, and the Uruguayan subnet overlap between the RDP source IPs and the C2 destination IP was enough to attribute the full chain to a single actor. What the failure did demonstrate is that infrastructure availability is the attacker's problem, not the defender's. A dead C2 listener does not mean the compromise did not happen. It means the attacker did not get what they came for on that attempt. The persistence mechanism was still in place, and the actor returned across multiple sessions trying to re-establish it.

The hunt started with a photograph. That framing stayed with me throughout. Technical hygiene matters: RDP should not be exposed to the internet, Defender should not run in passive mode, and accounts with weak credentials should not be the only barrier on a public-facing service. But none of those controls failed because of a configuration error buried in a cloud console. They failed because someone shared a photo that contained just enough information for an adversary to know where to look.

---

## Credits

Thanks to Josh Madakor and Steven Cruz for the scenario design and Cyber Range environment.

---

## Disclaimer

This report is based on a controlled Cyber Range scenario. All systems, users, files, IP addresses, and hashes are simulated for training and investigation practice.
