# Security Log Analysis — Reference Notes

---

## Windows Key Event IDs

### Authentication
| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4624 | Successful logon | Baseline; watch for off-hours or unusual logon types |
| 4625 | Failed logon | Brute-force detection |
| 4634 | Logoff | Session duration analysis |
| 4648 | Logon with explicit credentials | Pass-the-hash / credential relay |
| 4768 | Kerberos TGT request | Kerberoasting pre-cursor |
| 4771 | Kerberos pre-auth failure | Brute-force against AD |

### Privilege & Account
| Event ID | Description |
|----------|-------------|
| 4672 | Special privileges assigned to logon |
| 4720 | User account created |
| 4728 | User added to security group |
| 4732 | User added to local Administrators group |
| 4756 | Member added to universal security group |

### Process & Execution
| Event ID | Description |
|----------|-------------|
| 4688 | New process created (enable command line logging) |
| 4689 | Process terminated |
| 1 (Sysmon) | Process creation with full command line |
| 3 (Sysmon) | Network connection by process |
| 11 (Sysmon) | File created |

### Persistence
| Event ID | Description |
|----------|-------------|
| 4698 | Scheduled task created |
| 7045 | New service installed |
| 4657 | Registry value modified |

---

## Linux Key Log Locations

| Log File | Contents |
|----------|---------|
| `/var/log/auth.log` | SSH logins, sudo, su, PAM |
| `/var/log/syslog` | General system messages |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/faillog` | Failed login records |
| `/var/log/wtmp` | Login/logout history (`last` command) |
| `/var/log/btmp` | Failed login history (`lastb` command) |
| `journalctl -xe` | Systemd journal (current session) |

---

## Linux Log Commands

```bash
# View failed SSH logins
grep "Failed password" /var/log/auth.log

# View successful logins
grep "Accepted password" /var/log/auth.log

# Count failed logins by IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# View sudo usage
grep "sudo" /var/log/auth.log

# View recent logins
last -n 20

# View failed login attempts
lastb -n 20

# Check for new user accounts
grep "useradd" /var/log/auth.log

# Real-time log monitoring
tail -f /var/log/auth.log
```

---

## Splunk Queries

```spl
-- Brute-force detection (Windows)
index=windows EventCode=4625
| bucket _time span=1m
| stats count by _time, src_ip, user
| where count > 5
| sort -count

-- Successful logins after failures (possible compromise)
index=windows (EventCode=4625 OR EventCode=4624)
| transaction user maxspan=10m
| where EventCode=4625 AND EventCode=4624

-- Off-hours login detection
index=windows EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, user, src_ip, ComputerName

-- New user account created
index=windows EventCode=4720
| table _time, user, SubjectUserName, ComputerName

-- Privilege escalation — special privileges
index=windows EventCode=4672
| table _time, user, PrivilegeList, ComputerName

-- New service installed
index=windows EventCode=7045
| table _time, ServiceName, ServiceFileName, ComputerName

-- Linux brute-force (if syslog forwarded to Splunk)
index=linux "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 10
| sort -count
```

---

## Wazuh Key Rule Groups

| Rule Group | Description |
|------------|-------------|
| `authentication_failed` | Failed login attempts |
| `authentication_success` | Successful logins (for baselining) |
| `syscheck` | File integrity monitoring alerts |
| `rootcheck` | Rootkit detection |
| `web` | Web attack patterns |
| `attack` | Known attack signatures |
| `pci_dss` | PCI DSS compliance alerts |

---

## Alert Triage Decision Flow

```
Alert received
     │
     ▼
Is the source IP known/internal?
     │
   Yes → Is this activity expected for this user/host?
              │
            Yes → Benign / False Positive → Close with note
              │
             No → True Positive → Escalate + Document
     │
    No → External/Unknown → True Positive → Escalate + Block IP
```

---

## Severity Rating Guide

| Severity | Criteria |
|----------|---------|
| Critical | Active compromise, data exfiltration, ransomware |
| High | Brute-force success, privilege escalation, malware detected |
| Medium | Repeated failed logins, suspicious process, policy violation |
| Low | Single failed login, unusual time activity, minor anomaly |
| Info | Baseline event, no immediate threat |
