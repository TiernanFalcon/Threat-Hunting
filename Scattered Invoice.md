# SCATTERED INVOICE
## Business Email Compromise — Threat Hunt Report
### Cyber Range // Hunt 02 // Intermediate

| Field | Detail |
|---|---|
| **Analyst** | Tiernan Falcon |
| **Date Completed** | 11 April 2026 JST |
| **Incident Reference** | IR-2026-0225-BEC &nbsp;\|&nbsp; Severity HIGH &nbsp;\|&nbsp; Status Active |
| **Environment** | LogN Pacific Financial Services // Finance department |
| **Timeframe** | 25 February 2026, 21:00 to 23:00 UTC |
| **Platform** | Microsoft Sentinel // law-cyber-range workspace |
| **Source** | Cyber Range |
| **Financial Impact** | £24,500 (funds frozen by receiving bank) |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Hunt Narrative](#hunt-narrative)
3. [Key Findings](#key-findings)
4. [Environment and Hunt Scope](#environment-and-hunt-scope)
5. [All Flags Quick Reference](#all-flags-quick-reference)
6. [Attack Timeline](#attack-timeline)
7. [Flag-by-Flag Analysis](#flag-by-flag-analysis)
8. [Conclusion](#conclusion)
9. [Remediation Recommendations](#remediation-recommendations)
10. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
11. [Final Thoughts and What I Learned](#final-thoughts-and-what-i-learned)
12. [Credits](#credits)
13. [Disclaimer](#disclaimer)

---

## Executive Summary

Scattered Invoice documents a Business Email Compromise (BEC) against LogN Pacific Financial Services attributed to the financially motivated threat group **Scattered Spider**. The intrusion began not with a technical exploit but with a credential the actor already held, almost certainly purchased from an infostealer marketplace. Armed with Mark Smith's password, the actor mounted a push-bombing MFA fatigue attack from a Netherlands-based IP address, submitting multiple approval prompts until Smith, watching television at home, approved one to make them stop. That single tap handed the attacker an authenticated Outlook Web session.

Once inside, the actor moved deliberately. The first post-authentication action was `MailItemsAccessed`, suggesting the session was used to read the inbox before anything else. The actor then created two inbox rules. The first, named `.` (a single period), forwarded any email containing the keywords `invoice`, `payment`, `wire`, or `transfer` to an external Duck.com address (`insights@duck.com`) and set `StopProcessingRules` to prevent any other rule from intercepting those messages. The second rule, named `..` (two periods), deleted any incoming email matching security-related keywords: `suspicious`, `security`, `phishing`, `unusual`, `compromised`, `verify`. The deletion rule was designed to blind the victim to any security alert or breach notification arriving during the attack window.

With the forwarding infrastructure in place, the actor sent a thread-hijacked reply to James Reynolds in the finance team, using Smith's account and the attacker's IP. The subject line was `RE: Invoice #INV-2026-0892 - Updated Banking Details`. Reynolds processed the payment. £24,500 was redirected to an unknown account. The receiving bank flagged the transaction as suspicious and froze the funds before the money moved further.

The attacker's scope extended beyond email. The same session authenticated to Microsoft OneDrive for Business and SharePoint Online, and file-access telemetry in `CloudAppEvents` confirmed the actor touched OneDrive content during the attack window. Conditional Access was marked `notApplied` on the successful sign-in, meaning no policy challenged the authentication despite the anomalous origin country, unmanaged device fingerprint, and novel browser profile.

This investigation was reconstructed solely from Sentinel telemetry across three tables: `SigninLogs`, `CloudAppEvents`, and `EmailEvents`. No endpoint access, memory forensics, or packet capture was available. Where a finding was directly established by the evidence it is treated as confirmed; where the broader narrative required correlation across multiple events, conclusions are stated conservatively and only where supported by the telemetry.

---

## Hunt Narrative

### Phase 01: MFA Bypass // How Did They Get Past MFA?

The investigation opened in `SigninLogs`. The directive was simple: confirm the compromise, find the attacker infrastructure, and explain how MFA was bypassed.

Querying for Mark Smith's activity during the two-hour investigation window quickly separated two sign-in streams. Smith had a normal daytime pattern from a US IP address. In the evening window, a different IP appeared: `205.147.16.190`, geolocating to the Netherlands. Failure events from that IP carried error code `50074`, which indicates MFA was required but not completed. The log showed three MFA denial events from the attack source before a successful authentication went through. The volume was low enough to look like a technical glitch rather than a deliberate attack, which is precisely why MFA fatigue at this scale works against users who are not expecting it.

The device profile on the attacker's successful session was distinctive. Smith's corporate device runs Windows on a managed endpoint. The attacker authenticated from Linux, using Firefox 147.0, connecting to One Outlook Web. Three anomaly layers were immediately visible in the telemetry: different country, different operating system, different browser. In an environment with working Conditional Access, any one of those should have triggered a challenge. None did.

> **Analyst Note — Q5:** The lab answer key gives `3` as the MFA attempt count, but querying `ResultType == 50074` filtered to `205.147.16.190` returns only two events. The count of three appears to include one MFA denial from the US IP during the same evening, which may reflect an earlier attempt before the actor settled on the Netherlands exit node. The question asks specifically for attempts from the attacker's IP before the first successful authentication, so this flag warrants a closer review of the intended scope in the lab answer key.

### Phase 02: Account Takeover // What Did They Leave Behind?

After confirming the compromise, the investigation pivoted to `CloudAppEvents` to reconstruct what happened inside the session. The first action after authentication was `MailItemsAccessed`, which established that the attacker read the inbox before doing anything else. That sequencing matters: it shows the session was being used for reconnaissance within email content before persistence was established.

Two `New-InboxRule` events followed. The first rule's name was a single period (`.`), an obvious attempt to be invisible in any inbox rule listing. Its configuration forwarded matching emails to `insights@duck.com` and set `StopProcessingRules` to true, meaning no subsequent rule would process the same message. The trigger keywords were financial: `invoice`, `payment`, `wire`, `transfer`. This rule was the collection mechanism for the fraud operation.

### Phase 03: What Are They Hiding?

The second inbox rule showed the defensive layer of the operation. Named `..` (two periods), it targeted security-related keywords for deletion: `suspicious`, `security`, `phishing`, `unusual`, `compromised`, `verify`. Any breach notification, security alert, or authentication warning arriving in Smith's inbox during the attack window would have been silently deleted before he saw it. Combined with the forwarding rule, the actor had established both a collection channel and a suppression mechanism before sending the BEC email.

### Phase 04: Who Took the Bait?

Pivoting to `EmailEvents` and filtering for the compromised sender address with the attacker's source IP identified the target and the pretext. J. Reynolds (`j.reynolds@lognpacific.org`) received a reply to an existing invoice thread. The subject line `RE: Invoice #INV-2026-0892 - Updated Banking Details` used thread hijacking: the actor replied to a real email chain to inherit the legitimacy of the existing conversation. The `EmailDirection` value of `Intra-org` confirmed this was sent internally from within the organisation's mail system, meaning standard external-sender warning banners would not have appeared. The `SenderIPv4` matched the attacker's sign-in IP, directly linking the same session to both the inbox rule creation and the fraudulent email.

### Phase 05: What Else Did They Access?

With the fraud confirmed, the question became scope. `CloudAppEvents` filtered to the attacker's IP and the `FileAccessed` action type showed the Application field returning `Microsoft OneDrive for Business`, confirming that personal file content was accessed during the session. A separate query against `SigninLogs` using `distinct AppDisplayName` for the attacker's IP showed a second application: `SharePoint Online`. The attacker authenticated to at least three cloud services in a single session window: Outlook Web, OneDrive, and SharePoint.

Session correlation across both `CloudAppEvents` and `SigninLogs` confirmed that all attacker activity was conducted under a single authenticated session: `00225cfa-a0ff-fb46-a079-5d152fcdf72a`. The `AADSessionId` in the CloudAppEvents rule creation events matched the `SessionId` in the successful sign-in record, providing a single thread that tied the inbox rules, the file access, and the BEC email back to one authenticated credential event.

### Phase 06: How Do We Catch This Next Time?

The `ConditionalAccessStatus` on the attacker's successful sign-in was `notApplied`. No policy challenged the sign-in despite the Netherlands origin, Linux device, and unmanaged browser profile. That is the primary control gap. MFA fatigue (MITRE `T1621`) succeeded because push notification approval was the only control standing between an infostealer-harvested password and a live cloud session. The inbox rule technique maps to MITRE `T1564.008` (Hide Artifacts: Email Hiding Rules), and the credential source was identified as infostealer malware, which provides initial access to groups like Scattered Spider through purchased credential markets.

The single most important immediate containment action was session revocation. The attacker's session was still valid at the time of investigation. Revoking it terminates access. The inbox rules remain in place until explicitly deleted, which must follow immediately after session revocation as a second containment step.

---

## Key Findings

- Confirmed BEC incident IR-2026-0225-BEC with £24,500 redirected to an unknown account; funds frozen by the receiving bank
- Compromised account: `m.smith@lognpacific.org` (Mark Smith, Finance department)
- Attacker source IP: `205.147.16.190` geolocating to the Netherlands (NL)
- MFA bypass confirmed via fatigue / push-bombing; error code `50074` observed in `SigninLogs` prior to successful authentication
- Attacker device profile: Linux OS, Firefox 147.0, connecting to `One Outlook Web` — anomalous against Smith's corporate Windows / managed endpoint baseline
- Conditional Access status: `notApplied` on the successful attacker sign-in; no policy challenged the foreign origin or unmanaged device
- First post-authentication action: `MailItemsAccessed`, indicating inbox reconnaissance before persistence was established
- Two inbox rules created under the compromised session:
  - Rule `.` (single period): forwards emails matching `invoice, payment, wire, transfer` to `insights@duck.com` with `StopProcessingRules` set to true
  - Rule `..` (two periods): silently deletes emails matching `suspicious, security, phishing, unusual, compromised, verify`
- BEC email sent intra-org from `m.smith@lognpacific.org` via attacker IP to `j.reynolds@lognpacific.org` with subject `RE: Invoice #INV-2026-0892 - Updated Banking Details`; thread hijacking pretext
- Confirmed access to Microsoft OneDrive for Business (`FileAccessed` events) and SharePoint Online during the attack session
- Session correlation confirmed: all attacker activity linked to AAD session `00225cfa-a0ff-fb46-a079-5d152fcdf72a`
- Credential source attributed to infostealer malware; attack TTPs consistent with Scattered Spider attribution
- Immediate containment action: revoke session; secondary action: delete both inbox rules
- 29 flags resolved across 9 investigation phases

---

## Environment and Hunt Scope

**Target organisation:** LogN Pacific Financial Services, Finance department

### Data Sources Available

Three tables in Microsoft Sentinel / Log Analytics Workspace (`law-cyber-range`):

- `SigninLogs` — authentication events, sign-in result codes, IP addresses, device detail, geolocation, Conditional Access status, session ID
- `CloudAppEvents` — post-authentication cloud application activity including action types, raw event data, inbox rule configuration parameters, and file access events
- `EmailEvents` — email telemetry including sender IP, recipient, subject, direction, and delivery action

### Investigation Constraints

- No endpoint access, memory dumps, disk forensics, or packet capture
- No direct interaction with attacker-controlled infrastructure
- No malware detonation or reverse engineering

All findings were reconstructed through behavioral correlation of authentication, cloud activity, and email telemetry. Where a value was directly established by the evidence it is treated as confirmed. Where sequence or intent required correlation across multiple events, conclusions are stated conservatively and only where supported by the telemetry.

### Investigation Window

| Parameter | Value |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `law-cyber-range` |
| Tables Queried | `SigninLogs`, `CloudAppEvents`, `EmailEvents` |
| Time Window | 25 February 2026, 21:00 UTC to 23:00 UTC |
| Target | LogN Pacific Financial Services // Finance department |
| Compromised Account | `m.smith@lognpacific.org` (Mark Smith) |
| Attacker IP | `205.147.16.190` |
| Attacker Country | NL (Netherlands) |
| Financial Impact | £24,500 redirected; funds frozen |

---

## All Flags Quick Reference

| # | Phase | Flag Name | Answer |
|---|---|---|---|
| Q0 | Mission Brief | Workspace Name | `LAW-Cyber-Range` |
| Q1 | Phase 01 | Compromised Account | `m.smith@lognpacific.org` |
| Q2 | Phase 01 | Attacker Source IP | `205.147.16.190` |
| Q3 | Phase 01 | Attack Origin Country | `NL` |
| Q4 | Phase 01 | MFA Denial Error Code | `50074` |
| Q5 | Phase 01 | MFA Fatigue Intensity | `3` (see analyst note) |
| Q6 | Phase 01 | Application Accessed | `One Outlook Web` |
| Q7 | Phase 01 | Attacker Operating System | `Linux` |
| Q8 | Phase 01 | Attacker Browser | `Firefox 147.0` |
| Q9 | Phase 02 | First Post-Auth Action | `MailItemsAccessed` |
| Q10 | Phase 02 | Rule Creation Method | `New-InboxRule` |
| Q11 | Phase 02 | Forward Rule Name | `.` (single period) |
| Q12 | Phase 02 | Forward Destination | `insights@duck.com` |
| Q13 | Phase 02 | Forward Keywords | `invoice, payment, wire, transfer` |
| Q14 | Phase 02 | Rule Processing Flag | `StopProcessingRules` |
| Q15 | Phase 03 | Delete Rule Name | `..` (two periods) |
| Q16 | Phase 03 | Delete Keywords | `suspicious, security, phishing, unusual, compromised, verify` |
| Q17 | Phase 04 | BEC Target | `j.reynolds@lognpacific.org` |
| Q18 | Phase 04 | BEC Subject Line | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Q19 | Phase 04 | Email Direction | `Intra-org` |
| Q20 | Phase 04 | BEC Sender IP | `205.147.16.190` |
| Q21 | Phase 05 | Cloud App Accessed | `Microsoft OneDrive for Business` |
| Q22 | Phase 05 | SharePoint App Accessed | `SharePoint Online` |
| Q23 | Phase 05 | Session Correlation | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| Q24 | Phase 06 | Conditional Access Status | `notApplied` |
| Q25 | Phase 06 | MFA Fatigue MITRE ID | `T1621` |
| Q26 | Phase 06 | Email Rules MITRE ID | `T1564.008` |
| Q27 | Phase 07 | Credential Source | `infostealer` |
| Q28 | Phase 08 | Immediate Containment | `revoke session` |
| Q29 | Phase 08 | Threat Actor Attribution | `Scattered Spider` |

> **Q5 Note:** The lab answer key gives `3`. Filtering `ResultType == 50074` strictly to `205.147.16.190` returns two events. The third denial appears to originate from a US IP also active during the evening window. The flag question specifies attempts from the attacker's IP before first successful authentication, which would narrow the count to two. Flagged for answer key review.

---

## Attack Timeline

> **Analyst Note:** Two precise UTC timestamps were recoverable from `SigninLogs`: the first MFA denial event and the first successful authentication. Exact timestamps for rule creation and email sending are available in the workspace telemetry but were not captured in the flag answers. The timeline below uses confirmed sequence and exact timestamps where recovered.

| Time (UTC) | Tactic | Action | Key Artifact |
|---|---|---|---|
| Pre-attack | Credential Access | Attacker obtains Mark Smith's password via infostealer credential market | infostealer |
| ~21:00 | Initial Access | MFA push-bombing begins from `205.147.16.190` (NL); Smith receives repeated approval prompts | `50074`, `205.147.16.190` |
| ~21:xx | Initial Access | Smith approves one MFA prompt to stop the notifications; attacker gains authenticated session | `m.smith@lognpacific.org`, Firefox 147.0 / Linux |
| Shortly after auth | Collection | First cloud action: `MailItemsAccessed` — attacker reads inbox to identify active threads | `MailItemsAccessed` |
| Attack window | Persistence | Rule 1 created: forward financial keywords to `insights@duck.com` with `StopProcessingRules` | `New-InboxRule`, rule name `.` |
| Attack window | Defense Evasion | Rule 2 created: delete security alert keywords silently | `New-InboxRule`, rule name `..` |
| Attack window | Collection | Additional auth to OneDrive for Business; SharePoint Online session also established | `FileAccessed`, SharePoint Online |
| Attack window | Impact | Thread-hijacked BEC email sent intra-org to `j.reynolds@lognpacific.org` with updated banking details | `RE: Invoice #INV-2026-0892` |
| 26 Feb 2026 | Impact | Reynolds processes £24,500 payment to attacker-controlled account | £24,500 |
| 26 Feb 2026, morning | Discovery | Receiving bank flags transaction as suspicious; funds frozen; incident raised | IR-2026-0225-BEC |

### Kill Chain

```
Infostealer credential
        |
        v
MFA push-bombing (50074 x3)
        |
        v
Authenticated session (205.147.16.190 / Linux / Firefox 147.0)
        |
        v
MailItemsAccessed -- inbox reconnaissance
        |
        v
New-InboxRule "."  --> forward invoice/payment/wire/transfer --> insights@duck.com
New-InboxRule ".." --> delete suspicious/security/phishing/unusual/compromised/verify
        |
        v
OneDrive for Business -- FileAccessed
SharePoint Online -- authenticated
        |
        v
BEC email (thread hijack) --> j.reynolds@lognpacific.org
RE: Invoice #INV-2026-0892 - Updated Banking Details
        |
        v
£24,500 redirected (frozen by receiving bank)
```

---

## Flag-by-Flag Analysis

---

### Q0 — Mission Brief | Workspace Name

**Answer:** `LAW-Cyber-Range`

The environment access question confirmed connectivity to the Sentinel workspace before investigation began. The workspace name is displayed in the Sentinel portal header and serves as the Log Analytics workspace identifier for all subsequent queries.


---

### Q1 — Phase 01: MFA Bypass | Compromised Account

**Answer:** `m.smith@lognpacific.org`

The incident brief identified Mark Smith as the account holder who reported unusual MFA prompts. Querying `SigninLogs` for his display name during the investigation window confirmed his sign-in identifier and anchored the rest of the authentication analysis.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| project TimeGenerated, UserDisplayName, SignInIdentifier
| sort by TimeGenerated asc
| take 5
```
<img width="1320" height="580" alt="image" src="https://github.com/user-attachments/assets/e5d8e589-979b-49d2-8b15-b21678a88bf2" />

---

### Q2 — Phase 01: MFA Bypass | Attacker Source IP

**Answer:** `205.147.16.190`

Baselining Smith's normal authentication activity against the evening window separated the two IP addresses. His daytime activity came from a US address consistent with his work location. The Netherlands IP appearing in the evening window, accompanied by MFA failure events, identified the attacker source.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| project TimeGenerated, UserDisplayName, ResultSignature, IPAddress, LocationDetails.city
| sort by TimeGenerated asc
| take 5
```
<img width="1597" height="558" alt="image" src="https://github.com/user-attachments/assets/0b6b58a6-2fc6-49da-a982-bd46d661fcac" />

---

### Q3 — Phase 01: MFA Bypass | Attack Origin Country

**Answer:** `NL`

The `LocationDetails` field in `SigninLogs` resolved the attacker's IP to the Netherlands. An employee signing in from a country they do not normally work from is a classic impossible travel signal and would trigger a Conditional Access policy if one were enforced for geographic anomalies.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| project TimeGenerated, UserDisplayName, ResultSignature, IPAddress, LocationDetails.countryOrRegion
| sort by TimeGenerated asc
| take 5
```
<img width="1570" height="556" alt="image" src="https://github.com/user-attachments/assets/91fce09b-d086-4aa0-963b-b949d63c2a4c" />

---

### Q4 — Phase 01: MFA Bypass | MFA Denial Error Code

**Answer:** `50074`

Filtering to failure events from Smith's account returned the `50074` error code, which indicates strong authentication was required but not completed. This code is specific to the MFA challenge response being absent or rejected, distinguishing MFA failures from wrong-password failures (`50126`) or account lockouts.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| where ResultSignature =~ "failure"
| project TimeGenerated, Status.errorCode, Status.failureReason, ResultSignature, IPAddress, LocationDetails.countryOrRegion
| sort by TimeGenerated asc
| take 5
```
<img width="2158" height="616" alt="image" src="https://github.com/user-attachments/assets/2ddfdfe1-c740-4dd8-aa6d-ca984d855102" />

---

### Q5 — Phase 01: MFA Bypass | MFA Fatigue Intensity

**Answer:** `3` (lab answer key — see analyst note)

The lab answer key records `3` for this flag. Querying `ResultType == 50074` filtered strictly to `205.147.16.190` returns two events. The third denial event that accounts for the flag answer appears to originate from a US IP address also active during the evening window. The flag question specifies failed attempts before the first successful authentication from the attacker's IP, which would narrow the count to two. This flag is noted as a potential answer key discrepancy and warrants clarification from the lab designer.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-20 00:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| where ResultType == 50074
// | where IPAddress == "205.147.16.190"  -- uncomment to filter to attacker IP only
| project TimeGenerated, Status.errorCode, Status.failureReason, ResultSignature, IPAddress, LocationDetails.countryOrRegion
| sort by TimeGenerated asc
```

<img width="1878" height="552" alt="image" src="https://github.com/user-attachments/assets/c077d4d5-2580-4e71-9f0e-9c7d34240113" />

<img width="1891" height="922" alt="image" src="https://github.com/user-attachments/assets/80065c06-de36-4ae9-9417-65eee5858213" />


---

### Q6 — Phase 01: MFA Bypass | Application Accessed

**Answer:** `One Outlook Web`

Filtering `SigninLogs` to successful authentications from the attacker's IP returned the `AppDisplayName` field as `One Outlook Web`. A remote attacker without a corporate-managed endpoint or the desktop client installed would use the browser-based Outlook interface, which is consistent with the Linux / Firefox 147.0 device profile identified in Q7 and Q8.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-20 00:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| where ResultSignature =~ "success"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, IPAddress, AppDisplayName
| sort by TimeGenerated asc
```
<img width="1355" height="641" alt="image" src="https://github.com/user-attachments/assets/207c9136-6bc7-45ef-b896-bbc205ff708f" />

---

### Q7 — Phase 01: MFA Bypass | Attacker Operating System

**Answer:** `Linux`

The `DeviceDetail` field on the attacker's successful authentication session showed a Linux operating system. Smith's corporate device runs Windows on a managed endpoint. Linux on an unmanaged device, authenticating from a foreign country via a browser not associated with the corporate baseline, adds a third anomaly layer to the already-suspicious sign-in.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-20 00:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| where ResultSignature =~ "success"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, IPAddress, DeviceDetail
| sort by TimeGenerated asc
```
<img width="1598" height="566" alt="image" src="https://github.com/user-attachments/assets/e064f87e-2ff3-480f-ba92-c682ae340e07" />

---

### Q8 — Phase 01: MFA Bypass | Attacker Browser

**Answer:** `Firefox 147.0`

The browser field within `DeviceDetail` confirmed Firefox 147.0. Cross-referenced with Smith's normal session profile, this is another deviation from the expected baseline. Detection logic that alerts on new browser or OS combinations for established accounts would have flagged this sign-in regardless of the geographic anomaly.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-20 00:00)..datetime(2026-02-25 23:00))
| where UserDisplayName =~ "mark smith"
| where ResultSignature =~ "success"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, IPAddress, DeviceDetail.browser
| sort by TimeGenerated asc
```
<img width="1200" height="531" alt="image" src="https://github.com/user-attachments/assets/60438a2d-1c9f-4907-b2ab-0366526e6dff" />

---

### Q9 — Phase 02: Account Takeover | First Post-Auth Action

**Answer:** `MailItemsAccessed`

Querying `CloudAppEvents` for the attacker's IP during the attack window and sorting ascending returned `MailItemsAccessed` as the first `ActionType`. The attacker read the inbox before creating any rules or sending any email. That sequence shows deliberate reconnaissance: understanding the active email threads before inserting a fraudulent reply into one of them.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType
| sort by TimeGenerated asc
```
<img width="1270" height="400" alt="image" src="https://github.com/user-attachments/assets/9972ee6d-d2dc-407f-accc-458d1d837565" />

---

### Q10 — Phase 02: Account Takeover | Rule Creation Method

**Answer:** `New-InboxRule`

Continuing to review the `CloudAppEvents` timeline, `New-InboxRule` appeared as an `ActionType` following the initial mail access events. Inbox rules are a well-documented Scattered Spider persistence technique and are particularly dangerous in BEC scenarios because they create a silent channel for ongoing email access without requiring re-authentication.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType
| sort by TimeGenerated asc
```
<img width="1189" height="466" alt="image" src="https://github.com/user-attachments/assets/2fc8b5d3-84b3-430d-a40a-dc26317636cb" />

---

### Q11 — Phase 02: Account Takeover | Forward Rule Name

**Answer:** `.` (single period)

Filtering to `New-InboxRule` events and projecting the `Parameters` array from `RawEventData` exposed the rule name as a single period. Attackers choose names like this deliberately: a period renders as a near-invisible entry in an inbox rules list and is unlikely to draw attention during a casual review. Any automated rule enumeration alert that does not inspect rule names will miss this entirely.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, RawEventData.Parameters[3].Name
| sort by TimeGenerated asc
```
<img width="1211" height="411" alt="image" src="https://github.com/user-attachments/assets/a1e5596d-c58a-471e-8920-9fe6de245b3a" />

---

### Q12 — Phase 02: Account Takeover | Forward Destination

**Answer:** `insights@duck.com`

The `ForwardTo` parameter identified the external collection address as a Duck.com email address. Duck.com provides privacy-focused email addresses that can be created without identity verification, making them attractive for attacker-controlled collection infrastructure. This address should be blocked at the email gateway and submitted to Duck.com abuse reporting.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, RawEventData.Parameters[2]
| sort by TimeGenerated asc
```
<img width="1278" height="472" alt="image" src="https://github.com/user-attachments/assets/9b6dae39-7afe-455c-8118-df5508627258" />

---

### Q13 — Phase 02: Account Takeover | Forward Keywords

**Answer:** `invoice, payment, wire, transfer`

The `SubjectOrBodyContainsWords` parameter for the forwarding rule targeted four financial keywords. These are exactly the terms that would appear in an accounts payable workflow. The attacker was not collecting general email content; they were filtering specifically for emails related to active financial transactions, which gave them the thread to hijack for the BEC fraud.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, RawEventData.Parameters[4]
| sort by TimeGenerated asc
```
<img width="1416" height="469" alt="image" src="https://github.com/user-attachments/assets/fc69332a-0edc-4dac-b6f3-d7595e3285c3" />

---

### Q14 — Phase 02: Account Takeover | Rule Processing Flag

**Answer:** `StopProcessingRules`

The `StopProcessingRules` parameter was set to true on the forwarding rule. This ensures that once the forwarding rule matches a message, no subsequent rule processes it. The practical effect is that any rule Smith himself had created to handle invoice emails is bypassed. The attacker's rule runs first and intercepts the message cleanly.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, RawEventData.Parameters[5]
| sort by TimeGenerated asc
```
<img width="1267" height="450" alt="image" src="https://github.com/user-attachments/assets/2f873a4e-de75-4c5f-b065-92f81b1ff0ad" />

---

### Q15 — Phase 03: What Are They Hiding? | Delete Rule Name

**Answer:** `..` (two periods)

Querying all `New-InboxRule` events without filtering to a single result set exposed a second rule. Its name was two periods. The layered naming convention (one period for the first rule, two for the second) reflects deliberate obfuscation. An analyst listing inbox rules in the Outlook interface would see two nearly identical short entries that could easily be mistaken for formatting artefacts.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, RawEventData.Parameters[2]
| sort by TimeGenerated asc
```
<img width="1203" height="644" alt="image" src="https://github.com/user-attachments/assets/93bd5614-ec0e-47ee-914f-b7b679ca98ad" />

---

### Q16 — Phase 03: What Are They Hiding? | Delete Keywords

**Answer:** `suspicious, security, phishing, unusual, compromised, verify`

The deletion rule's keyword list targeted the exact language that Microsoft security alerts and bank fraud notifications use. Any email from Microsoft Security indicating unusual sign-in activity, or a bank alert flagging a suspicious transaction, would be silently deleted before Smith saw it. The attacker was specifically designing for the scenario where their activity triggers an automated security response and then suppressing that response at the mailbox level.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, RawEventData.Parameters[3]
| sort by TimeGenerated asc
```
<img width="1656" height="683" alt="image" src="https://github.com/user-attachments/assets/66b07751-c3d7-49d9-82fe-e1032c54e0f9" />

---

### Q17 — Phase 04: Who Took the Bait? | BEC Target

**Answer:** `j.reynolds@lognpacific.org`

Pivoting to `EmailEvents` and filtering for the compromised sender address with the attacker's source IP isolated the fraudulent outbound email. The recipient was J. Reynolds in the finance team. Given that the attacker had been forwarding financial emails to their own collection address, they had likely already read active invoice conversations before selecting Reynolds as the target.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where SenderFromAddress =~ "m.smith@lognpacific.org"
| where SenderIPv4 =~ "205.147.16.190"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress
```
<img width="1233" height="395" alt="image" src="https://github.com/user-attachments/assets/c917df8e-cd19-4aa3-90d1-4a5e2f2d3045" />

---

### Q18 — Phase 04: Who Took the Bait? | BEC Subject Line

**Answer:** `RE: Invoice #INV-2026-0892 - Updated Banking Details`

The subject line confirmed thread hijacking. The `RE:` prefix shows this was a reply to an existing email thread, meaning the attacker inserted themselves into a real conversation rather than initiating a new one. Reynolds would have seen this as a continuation of a legitimate exchange with a known colleague, with updated payment instructions arriving mid-thread.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where SenderFromAddress =~ "m.smith@lognpacific.org"
| where SenderIPv4 =~ "205.147.16.190"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
```
<img width="1545" height="444" alt="image" src="https://github.com/user-attachments/assets/b9194599-a332-499e-8488-7c2eae8bc948" />

---

### Q19 — Phase 04: Who Took the Bait? | Email Direction

**Answer:** `Intra-org`

The `Intra-org` direction value confirmed the email was sent within the organisation's mail environment rather than from an external domain. This is a critical detail for the attack's effectiveness: external-sender banners and anti-spoofing controls do not apply to an authenticated intra-org send. The email arrived looking like a genuine internal message from a known colleague with no warning indicators.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where SenderFromAddress =~ "m.smith@lognpacific.org"
| where SenderIPv4 =~ "205.147.16.190"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, EmailDirection
```
<img width="1514" height="433" alt="image" src="https://github.com/user-attachments/assets/f5b4df96-8414-4f95-99f6-6e2acd9bdc8b" />

---

### Q20 — Phase 04: Who Took the Bait? | BEC Sender IP

**Answer:** `205.147.16.190`

The `SenderIPv4` on the fraudulent email matched the attacker's sign-in IP exactly, directly correlating the authenticated Outlook Web session with the email send event. This is the cross-table linkage that places the same attacker IP at authentication, inbox rule creation, and the BEC email in a single continuous session.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where SenderFromAddress =~ "m.smith@lognpacific.org"
| where SenderIPv4 =~ "205.147.16.190"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, SenderIPv4
```
<img width="1477" height="411" alt="image" src="https://github.com/user-attachments/assets/ef0f351d-c069-4e45-90e4-2395fb5932ce" />

---

### Q21 — Phase 05: What Else Did They Access? | Cloud App Accessed

**Answer:** `Microsoft OneDrive for Business`

Filtering `CloudAppEvents` for `FileAccessed` actions from the attacker's IP returned `Microsoft OneDrive for Business` as the application. The attacker accessed personal file content stored in Smith's OneDrive during the same session window. The specific files accessed were not surfaced by the flags, but the access event establishes that the scope of the compromise extended beyond email.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "FileAccessed"
| project TimeGenerated, ActionType, Application
| sort by TimeGenerated asc
```
<img width="1269" height="453" alt="image" src="https://github.com/user-attachments/assets/e57e79de-21a3-48c8-8864-ee76ed8eec16" />

---

### Q22 — Phase 05: What Else Did They Access? | SharePoint App Accessed

**Answer:** `SharePoint Online`

A distinct query on `SigninLogs` for the attacker's IP exposed a second application beyond One Outlook Web: SharePoint Online. The logged `AppDisplayName` was `SharePoint Online Web Client Extensibility`, but the answer accepted for this flag was `SharePoint Online`. The attacker authenticated to three cloud services in a single session: email, personal file storage, and the organisational document platform.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ResultSignature =~ "success"
| distinct AppDisplayName
```
<img width="1308" height="583" alt="image" src="https://github.com/user-attachments/assets/ea04586a-83db-4782-ae98-c4ac594dd982" />

---

### Q23 — Phase 05: What Else Did They Access? | Session Correlation

**Answer:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

Extracting the `AADSessionId` from the `AppAccessContext` in `CloudAppEvents` rule creation events and confirming a match against the `SessionId` in the successful `SigninLogs` entry tied the entire investigation to a single authenticated session. This cross-table session correlation is the forensic thread that would support any legal or insurance process: one credential event, one session, all attacker actions.

```kql
// CloudAppEvents -- extract session ID from rule creation events
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, RawEventData.AppAccessContext.AADSessionId
| sort by TimeGenerated asc

// SigninLogs -- confirm session ID on successful authentication
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ResultSignature =~ "success"
| project SessionId
```
<img width="1198" height="511" alt="image" src="https://github.com/user-attachments/assets/3abc8763-2bc3-40e1-9a9d-d1bafae03a2e" />

<img width="1239" height="489" alt="image" src="https://github.com/user-attachments/assets/61e77403-698a-49b9-91c6-040f642c1558" />

---

### Q24 — Phase 06: How Do We Catch This Next Time? | Conditional Access Status

**Answer:** `notApplied`

The `ConditionalAccessStatus` field on the attacker's successful sign-in was `notApplied`. No Conditional Access policy evaluated this authentication. This is the core defensive failure of the incident. A policy requiring compliant or hybrid-joined devices, blocking sign-ins from high-risk countries, or requiring phishing-resistant MFA (FIDO2 or certificate-based) would have prevented this session from completing regardless of the MFA fatigue success.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00)..datetime(2026-02-25 23:00))
| where IPAddress == "205.147.16.190"
| where ResultSignature =~ "success"
| project ConditionalAccessStatus
```
<img width="1231" height="491" alt="image" src="https://github.com/user-attachments/assets/37451d75-0068-4564-9b3d-354179f150e0" />

---

### Q25 — Phase 06: How Do We Catch This Next Time? | MFA Fatigue MITRE ID

**Answer:** `T1621`

MITRE ATT&CK T1621 (Multi-Factor Authentication Request Generation) describes the technique of sending repeated MFA push notifications to wear down the target user until they approve. The technique exploits the human tendency to approve prompts to stop unwanted notifications rather than treating repeated prompts as an attack signal.

*Tactic: Credential Access // Technique: T1621*
<img width="1959" height="123" alt="image" src="https://github.com/user-attachments/assets/de28fa89-8457-44f9-96ce-5b8dc03baa5d" />
<img width="2170" height="681" alt="image" src="https://github.com/user-attachments/assets/eb61dbc2-4091-4d5f-b4e7-4b79dbc9fdd6" />



---

### Q26 — Phase 06: How Do We Catch This Next Time? | Email Rules MITRE ID

**Answer:** `T1564.008`

MITRE ATT&CK T1564.008 (Hide Artifacts: Email Hiding Rules) describes the use of email client rules to move, delete, or otherwise manage messages in a way that hides attacker activity from the account owner. Both inbox rules created in this incident map directly to this sub-technique: one for collection, one for suppression of detection notifications.

*Tactic: Defense Evasion // Technique: T1564.008*
<img width="2147" height="1013" alt="image" src="https://github.com/user-attachments/assets/9da91665-9e07-4c30-bb1b-2fed0ab83189" />

---

### Q27 — Phase 07: Where Did the Password Come From? | Credential Source

**Answer:** `infostealer`

The attacker already had Smith's valid password before the MFA fatigue attack began. Scattered Spider is known to purchase credentials from infostealer logs sold on underground marketplaces. Infostealer malware infects endpoints and harvests saved passwords, session tokens, browser data, and credentials from password managers, packaging them into logs sold to downstream threat actors. This means the initial compromise vector was not the organisation's infrastructure at all; it was a personal or shared device infected with commodity malware prior to the attack.

<img width="1536" height="92" alt="image" src="https://github.com/user-attachments/assets/e42c3dea-2970-4dc4-adbd-62e4608bd167" />
<img width="1063" height="234" alt="image" src="https://github.com/user-attachments/assets/79c5adab-a4e4-42a0-b242-91174cae6bb0" />


---

### Q28 — Phase 08: What Do We Do First? | Immediate Containment

**Answer:** `revoke session`

The attacker held a valid, active session throughout the investigation window. The single most important immediate containment action was session revocation, which terminates all active tokens for the compromised account and forces re-authentication. This stops the attacker from continuing to access email, OneDrive, and SharePoint without needing to change the user's password as a first step. Password reset and MFA re-enrollment follow immediately after session revocation. The inbox rules must also be deleted as a parallel containment action.

---

### Q29 — Phase 08: What Do We Do First? | Threat Actor Attribution

**Answer:** `Scattered Spider`

The full kill chain observed in this investigation matches the documented TTPs of Scattered Spider (also tracked as UNC3944 and Oktapus). The combination of MFA push-bombing, infostealer credential sourcing, inbox rule persistence using near-invisible rule names, BEC targeting of finance teams, and use of legitimate cloud infrastructure to avoid detection is characteristic of this group. Scattered Spider has conducted similar attacks against MGM Resorts, Caesars Entertainment, and multiple UK retailers. The use of a Duck.com forwarding address is consistent with their preference for privacy-focused disposable infrastructure.

---

## Conclusion

Scattered Invoice documents a complete Business Email Compromise lifecycle from initial credential access through financial fraud. The attacker entered the environment through a password purchased from an infostealer credential market, bypassed MFA through fatigue rather than any technical exploit, and within a single two-hour session established email forwarding for financial intelligence collection, deleted security notifications for suppression, hijacked an active invoice thread, and sent a fraudulent payment instruction to the finance team. £24,500 was redirected before the receiving bank's fraud detection flagged the transaction.

What is notable about this intrusion is that the attacker never needed to touch the endpoint. No malware was deployed. No lateral movement occurred across devices. The entire operation was conducted through the legitimate cloud authentication stack, through a legitimate application (Outlook Web), using a legitimate session. The telemetry that caught it came not from endpoint detection but from three Sentinel tables recording authentication events, cloud application activity, and email flow. That is precisely where BEC-focused detection needs to live.

The core failure was the absence of enforced Conditional Access. A policy requiring compliant devices, challenging foreign country sign-ins, or enforcing phishing-resistant MFA would have blocked this session at the authentication layer regardless of whether Smith approved the push notification. The attacker's Linux device, Firefox browser, and Netherlands IP were all clearly anomalous against Smith's established baseline. The controls to catch that anomaly exist; they were simply not active.

---

## Remediation Recommendations

### Immediate Containment

- Revoke all active sessions for `m.smith@lognpacific.org` immediately
- Delete both malicious inbox rules (rule names `.` and `..`)
- Reset Smith's password and re-enroll MFA with a phishing-resistant method (FIDO2 or certificate-based)
- Block `205.147.16.190` at email gateway and Conditional Access named locations
- Block `insights@duck.com` at the email gateway and report to Duck.com abuse
- Audit all finance team mailboxes for additional inbox rules created during or near the attack window

### MFA Hardening

- Migrate all user accounts from push-notification MFA to phishing-resistant methods (FIDO2 security keys or certificate-based authentication)
- If push notification MFA must remain, enable number-matching and additional context display to reduce fatigue attack success rates
- Alert on three or more MFA denial events from any single IP within a 15-minute window for any user account
- Educate users that repeated unsolicited MFA prompts are an attack signal, not a technical glitch

### Conditional Access

- Enforce device compliance or hybrid-join requirements for all cloud application authentication
- Block or require step-up authentication for sign-ins from countries outside the organisation's normal operating geography
- Alert on `ConditionalAccessStatus` of `notApplied` for any successful sign-in; any authentication that bypasses Conditional Access evaluation is an anomaly worth investigating
- Define and enforce named locations; require additional verification for authentication outside approved IP ranges

### Inbox Rule Monitoring

- Alert on `New-InboxRule` events for any user account, especially rules that forward to external addresses or delete messages
- Alert specifically on `ForwardTo` parameters pointing to external domains, particularly privacy-focused or disposable email services
- Alert on inbox rules with single-character or punctuation-only names, which are a common attacker obfuscation technique
- Audit all inbox rules organisation-wide on a recurring schedule and alert on rules created outside business hours

### BEC Process Controls

- Implement a callback verification process for any banking detail change request received by email, regardless of whether the sender is internal or external
- Require a second approver for payment instructions above a defined threshold (suggested: £5,000)
- Train finance staff on thread-hijacking BEC tactics: legitimate banking detail changes do not arrive via email reply; they follow a documented change request process
- Consider implementing email banners for intra-org emails sent from unusual IP addresses or new devices

### Infostealer Credential Hygiene

- Subscribe to a commercial credential breach monitoring service and act immediately on any alert for organisational email addresses found in infostealer logs
- Enforce a policy against saving corporate credentials in personal browsers or unmanaged devices
- Conduct regular checks of Have I Been Pwned and similar services for organisational domains

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Confidence |
|---|---|---|---|
| Initial Access | T1078 | Valid Accounts | High — attacker authenticated as `m.smith@lognpacific.org` with a valid infostealer-sourced password |
| Credential Access | T1621 | MFA Request Generation | High — `50074` errors from `205.147.16.190` confirmed push-bombing before successful auth |
| Collection | T1114.003 | Email Forwarding Rule | High — inbox rule forwarding to `insights@duck.com` directly observed in `CloudAppEvents` |
| Defense Evasion | T1564.008 | Hide Artifacts: Email Hiding Rules | High — deletion rule for security keywords directly observed in `CloudAppEvents` |
| Defense Evasion | T1036 | Masquerading | High — rule names `.` and `..` designed to be invisible in inbox rule listings |
| Persistence | T1098 | Account Manipulation | High — inbox rules established persistent access to financial email content |
| Collection | T1539 | Steal Web Session Cookie | Medium — infostealer credential sourcing likely included session token harvesting |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Medium — financial email forwarded to external Duck.com address |
| Impact | T1657 | Financial Theft | High — £24,500 redirected via fraudulent BEC payment instruction |
| Discovery | T1087 | Account Discovery | Medium — `MailItemsAccessed` used to read inbox content and identify target threads |
| Lateral Movement | T1534 | Internal Spearphishing | High — thread-hijacked email sent intra-org to `j.reynolds@lognpacific.org` |

> **High:** Directly observed in Sentinel telemetry and confirmed by flag output.
> **Medium:** Strongly supported by correlated behavior and established threat group TTPs, but not confirmed by a single discrete telemetry event.

---

## Final Thoughts and What I Learned

Scattered Invoice is my first encounter with a Business Email Compromise scenario and the simplicity of it caught me off guard. The attacker never wrote a line of malware. They never touched an endpoint. They bought a password, clicked approve on an MFA prompt, and walked out with £24,500. The entire operation ran through the same cloud infrastructure the organisation uses every day.

The thing that stuck with me most was the inbox rule sequencing. The attacker read the inbox first, before creating any rules or sending any email. That is not a coincidence; that is how you do BEC professionally. You find the active threads, you understand the payment relationships, and then you insert yourself into the right conversation at the right moment. The forwarding rule was not for general email collection; it was targeted specifically at financial keywords. The attacker knew exactly what they were looking for before they set up the infrastructure to collect it.

The deletion rule is the part I find most interesting from a detection perspective. The attacker anticipated that their activity would trigger automated security notifications and built a mechanism to delete those notifications before the account owner saw them. That is a deliberate second layer of design, not an afterthought. They were thinking about defender response at the point of persistence setup. That kind of operational awareness is what makes Scattered Spider effective at scale.

The Conditional Access finding is sobering. Every anomaly signal that should have triggered a challenge was present in the telemetry: foreign country, unmanaged device, new browser profile. None of them stopped the session because no policy evaluated the authentication. The technology to block this exists. It was simply not configured. That is not a sophisticated attacker bypassing advanced controls; that is a motivated attacker walking through an unlocked door.

Working with three cloud-native tables rather than endpoint telemetry was a nice change of focus from The BUYER and The BROKER. The `SigninLogs` device detail fields, the `RawEventData` parameter arrays in `CloudAppEvents`, and the cross-table session ID correlation are all techniques worth having as muscle memory for identity-focused investigations. 

---

## Credits

Thanks to Josh Madakor and Mohammed A for the scenario design and Cyber Range environment.

---

## Disclaimer

This report is based on a controlled Cyber Range scenario. All systems, users, domains, IP addresses, email addresses, financial figures, and log data are simulated for training and investigation practice. Do not contact any email addresses or submit any IP addresses or domains found in this report to public threat intelligence platforms.
