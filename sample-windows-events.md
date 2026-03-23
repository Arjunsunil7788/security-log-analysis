# Sample Windows Security Event Log Entries (Sanitized)

These are representative log entries used during analysis. All IPs and hostnames are from a lab environment.

---

## Scenario: SSH/RDP Brute-Force Followed by Successful Login

### Failed Login Attempts (Event ID 4625)

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4625
Task Category: Logon
Level:         Information
Keywords:      Audit Failure

An account failed to log on.

Subject:
  Security ID:    NULL SID
  Account Name:   -
  Account Domain: -

Logon Type:       10  (RemoteInteractive / RDP)
Account For Which Logon Failed:
  Account Name:   Administrator
  Account Domain: WORKSTATION-01

Failure Reason:   Unknown user name or bad password

Network Information:
  Source IP:      192.168.1.50
  Source Port:    51234

[Repeated 23 times between 02:14:05 and 02:14:52]
```

**Analyst Note:** 23 failed RDP logon attempts for the Administrator account from 192.168.1.50 within 47 seconds. Classic brute-force pattern.

---

### Successful Login After Failures (Event ID 4624)

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4624
Task Category: Logon
Level:         Information
Keywords:      Audit Success

An account was successfully logged on.

Subject:
  Security ID:    SYSTEM

Logon Type:       10  (RemoteInteractive / RDP)
New Logon:
  Account Name:   Administrator
  Account Domain: WORKSTATION-01

Network Information:
  Source IP:      192.168.1.50
  Source Port:    51289

Logon Time:     02:15:01
```

**Analyst Note:** Successful login at 02:15:01, 9 seconds after the last failed attempt. Strong indicator of credential compromise. Escalated as High severity incident.

---

## Scenario: New Local Admin Account Created (Event ID 4720 + 4732)

```
Log Name:      Security
Event ID:      4720

A user account was created.

New Account:
  Account Name:   svcbackup01
  Account Domain: WORKSTATION-01

Created By:
  Account Name:   Administrator
  Account Domain: WORKSTATION-01

Time:           02:16:44
```

```
Log Name:      Security
Event ID:      4732

A member was added to a security-enabled local group.

Member Added:
  Account Name:   svcbackup01

Group:
  Group Name:     Administrators

Time:           02:16:45
```

**Analyst Note:** New account `svcbackup01` created and immediately added to local Administrators group at 02:16 — 1 minute after the successful RDP login. Likely a persistence mechanism. Critical finding. Account disabled and system isolated.

---

## Scenario: Suspicious Process Execution (Sysmon Event ID 1)

```
Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1 (Process Create)

Image:         C:\Windows\System32\cmd.exe
CommandLine:   cmd.exe /c powershell -EncodedCommand <base64_string>
ParentImage:   C:\Windows\System32\mstsc.exe
User:          WORKSTATION-01\Administrator
UtcTime:       2024-01-15 02:17:03

Hashes:        SHA256=<hash>
```

**Analyst Note:** `cmd.exe` spawned by `mstsc.exe` (RDP client) executing an encoded PowerShell command. This is a well-known lateral movement/execution pattern. Encoded command decoded to a reverse shell attempt.

---

## Triage Summary for This Scenario

| Time | Event | Event ID | Classification |
|------|-------|----------|---------------|
| 02:14:05–02:14:52 | 23x Failed RDP login | 4625 | True Positive (Brute-force) |
| 02:15:01 | Successful RDP login | 4624 | True Positive (Compromise) |
| 02:16:44 | New account created | 4720 | True Positive (Persistence) |
| 02:16:45 | Account added to Admins | 4732 | True Positive (Privilege escalation) |
| 02:17:03 | Encoded PowerShell via cmd | Sysmon 1 | True Positive (Execution) |

**Overall Severity: CRITICAL — Active compromise with persistence established.**
