# Security Incident Report

**Incident ID:** INC-YYYY-001  
**Date/Time Detected:** YYYY-MM-DD HH:MM  
**Analyst:** Arjun S  
**Severity:** Critical / High / Medium / Low  
**Status:** Open / Investigating / Closed  

---

## 1. Incident Summary

> One paragraph describing what happened, how it was detected, and the initial assessment.

---

## 2. Timeline of Events

| Time (UTC) | Event |
|-----------|-------|
| HH:MM | First failed login attempt detected from 192.168.x.x |
| HH:MM | 15 consecutive failed logins — brute-force threshold triggered |
| HH:MM | Successful login recorded — possible credential compromise |
| HH:MM | Unusual process spawned post-login (e.g., cmd.exe → powershell.exe) |
| HH:MM | Alert escalated for investigation |

---

## 3. Detection Source

| Field | Detail |
|-------|--------|
| **Tool** | Splunk / Wazuh / Windows Event Log |
| **Alert Name** | e.g., "Multiple Failed Logins — Brute Force Detected" |
| **Rule/Query** | e.g., Event ID 4625 count > 10 in 5 min |
| **Log Source** | Windows Security Log / /var/log/auth.log |

---

## 4. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Source IP | 192.168.x.x |
| Username Targeted | administrator |
| Hostname | WORKSTATION-01 |
| Process (if applicable) | powershell.exe (PID: xxxx) |
| Hash (if applicable) | N/A |

---

## 5. Affected Assets

| Asset | Type | Criticality |
|-------|------|-------------|
| 192.168.x.10 | Windows Workstation | Medium |

---

## 6. Analysis

### What Happened?
Detailed description of the sequence of events based on log evidence.

### Evidence
```
# Sample Splunk output or log snippet
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 10

Results:
src_ip=192.168.x.50  user=administrator  count=23
```

### Classification
- [x] True Positive
- [ ] False Positive
- [ ] Benign / Informational

### Severity Justification
Explain why this severity was assigned (impact, likelihood, asset value).

---

## 7. Response Actions Taken

- [ ] Source IP blocked at firewall
- [ ] Account locked pending investigation
- [ ] System isolated from network
- [ ] Escalated to senior analyst / SOC lead
- [ ] Notified affected user/team

---

## 8. Recommendations

1. Implement account lockout after 5 failed login attempts
2. Enable MFA on all remote access accounts
3. Review firewall rules — restrict RDP/SSH to authorised IPs only
4. Monitor the affected account for further suspicious activity

---

## 9. Lessons Learned

> What can be improved in detection, response, or prevention based on this incident?

---

*Report prepared by: Arjun S | Cybersecurity Analyst*
