 # 🎯 Threat-Hunting-Scenario-The-Great-Admin-Heist

<img width="400" src="https://github.com/user-attachments/assets/1f05cb00-e1af-40f1-a4e1-8f24f6528a57" alt="computer login screen"/>

# 🕵️ **Scenario: APT Threat Alert** 🚨  
**Date**: 7 May 2025
**Target User**: Bubba Rockerfeatherman III (anthony-001)
**Scenario**: Acme Corp - Phantom Hackers APT Intrusion

## Platforms and Languages Leveraged
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Executive Summary

Acme Corp has experienced a targeted attack by the advanced persistent threat (APT) group known as The Phantom Hackers. Through stealthy delivery, deceptive tools, and persistent mechanisms, the attackers successfully infiltrated a privileged system used by the IT administrator Bubba Rockerfeatherman III.

This investigation, conducted using MDE telemetry and KQL queries, uncovered a multi-stage attack that began with a fake antivirus binary and progressed into system modification, keylogging, and long-term persistence through scheduled tasks and registry manipulation. All malicious behaviors were traced back to the execution of a single binary: BitSentinelCore.exe.

## Threat Timeline

**Timestamp(UTC)**            |   **Event Description**  
2025-05-07T02:00:36.794406Z    |   File BitSentinelCore.exe was created (Fake Antivirus)  
2025-05-07T02:02:14.9669902Z  |   Registry key modified in HKCU\...\Run for persistence  
2025-05-07T02:02:15.2599627Z  |   cmd.exe spawns and creates Scheduled Task UpdateHealthTelemetry  
2025-05-07T02:06:51.3594039Z  |   File systemreport.lnk was dropped to serve as a keylogger  

---

## 🧠 Your mission:
Hunt through Microsoft Defender for Endpoint (MDE) telemetry, analyze signals, query using KQL, and follow the breadcrumbs before the keys to Bubba’s empire vanish forever.

### High-Level Related IoC Discovery Plan
- **Check `DeviceProcessEvents`** for any new processes.
- **Check `DeviceRegistryEvents`** for any modified keys.
- **Check `DeviceFileEvents`** for any file changes.

---

### 🕵️ **Flag 1: Identify the Fake Antivirus Program Name** 🔍  

I looked for the answer under DeviceFileEvents with the user anthony-001. With the help of the hint of the program's name starting with either A, B or C and assuming it's an executable (exe) file i used the following KQL to find the answer

```
DeviceFileEvents
| where DeviceName == "anthony-001"
| where ActionType == "FileCreated"
| where FileName startswith "A" or FileName startswith "B" or FileName startswith "C"
| where FileName contains ".exe"
```
<img width="400" src="https://github.com/user-attachments/assets/b5424ba6-a943-4e48-8f67-3cb820fac499"/>

**Answer**: BitSentinelCore.exe

Details: Disguised as an antivirus tool, this executable initiated the malicious chain of events.

Flag 2: Dropper Identification

Answer: csc.exe

Details: Used to compile and drop BitSentinelCore.exe into the C:\ProgramData directory.

Flag 3: Execution Source

Answer: BitSentinelCore.exe

Details: Manually executed by the user (Bubba), confirming attacker deception and delivery success.

Flag 4: Keylogger Artifact

Answer: systemreport.lnk

Details: A disguised .lnk file written to the user’s recent documents folder, consistent with keylogging tactics.

Flag 5: Registry Persistence

Answer: HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Details: Entry created here causes the malware to execute at every user login, achieving persistence.

Flag 6: Scheduled Task Persistence

Answer: UpdateHealthTelemetry

Details: Task created using schtasks.exe, scheduled to execute BitSentinelCore.exe daily at 14:00.

Flag 7: Process Chain (Persistence Creation)

Answer: BitSentinelCore.exe -> cmd.exe -> schtasks.exe

Details: Clear parent-child-grandchild relationship showing malware initiated persistence setup.

Flag 8: Root Cause Timestamp

Answer: 2025-05-07T04:00:36.794406Z

Details: The timestamp at which BitSentinelCore.exe was executed, triggering the full attack chain.

Observed MITRE ATT&CK Techniques

Technique ID

Name

Description

T1059.003

Command and Scripting Interpreter

Usage of cmd.exe and PowerShell

T1547.001

Registry Run Keys/Startup Folder

Registry-based persistence in Run key

T1053.005

Scheduled Task/Job: Scheduled Task

Daily execution of malware via schtasks.exe

T1204.002

User Execution: Malicious File

User manually executed BitSentinelCore.exe

T1027

Obfuscated Files or Information

.lnk keylogger disguised as systemreport

Conclusion

This threat hunt successfully uncovered a stealthy and multi-layered intrusion orchestrated by The Phantom Hackers. Every malicious behavior—from initial execution, to keylogger deployment, to persistent access—was definitively linked to the execution of the fake antivirus BitSentinelCore.exe. The attack leveraged common techniques in a clever way to maintain long-term access while avoiding detection.

All infected systems must be reimaged, credentials reset, and defensive controls updated to prevent recurrence.

Recommendations

Remove Scheduled Task UpdateHealthTelemetry

Delete Registry Entry under HKCU\...\Run

Purge Malware File BitSentinelCore.exe

Review LNK files and disable recent document execution via GPO if possible

Monitor for misuse of csc.exe, PowerShell, and schtasks.exe in telemetry

Appendix

Device Name: anthony-001

Primary User: 4nth0ny!

Investigation Timeline Range: 2025-05-07 03:00 to 2025-05-07 05:00 UTC

Tools Used: Microsoft Defender for Endpoint, KQL, Process Explorer

Report Compiled by: [Your Name]Scenario: Operation Jackal Spear

Primary User: 4nth0ny!

Investigation Timeline Range: 2025-05-07 03:00 to 2025-05-07 05:00 UTC

Tools Used: Microsoft Defender for Endpoint, KQL, Process Explorer

Report Compiled by: [Your Name]Scenario: Operation Jackal Spear
