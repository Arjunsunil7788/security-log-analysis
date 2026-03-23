 Security Log Analysis & SIEM Monitoring
A blue team project focused on analyzing Windows Event Logs and Linux syslogs to detect security anomalies, perform alert triage, and document incidents using SIEM platforms (Splunk and Wazuh).
---
🎯 Objectives
Ingest and analyze Windows and Linux logs in a SIEM environment
Detect threats including failed logins, brute-force, privilege escalation, and unauthorized processes
Perform structured alert triage — classify True Positives, False Positives, and Benign events
Create professional incident reports with timeline, IOCs, and recommended response actions
---
🛠️ Tools Used
Tool	Purpose
Splunk	Log ingestion, correlation searches, dashboards
Wazuh	Agent-based threat detection and alerting
Windows Event Viewer	Native Windows log review
Linux syslog / journalctl	Linux log analysis
Sysmon	Enhanced Windows endpoint telemetry
---
📋 Methodology
1. Log Collection
Configured Splunk Universal Forwarder on Windows and Linux hosts
Enabled Wazuh agents for real-time alerting
Key log sources: Windows Security Event Log, Sysmon, `/var/log/auth.log`, `/var/log/syslog`
2. Detection Rules Applied
Brute-force: >5 failed logins in 1 minute from same source
Privilege escalation: `sudo` usage outside normal hours; new local admin accounts created
Lateral movement: RDP/SMB connections between internal hosts
Persistence: New services created, scheduled tasks added, registry run key modification
3. Alert Triage Process
For each alert:
Identify source — IP, hostname, user account
Check timing — business hours vs. off-hours
Review correlated events across log sources
Classify: True Positive / False Positive / Benign
Escalate TP with full documentation
4. Incident Documentation
Timeline of events
IOCs (IP, username, process name, file hash)
Severity rating
Recommended response and remediation
---
📁 Repository Structure
```
security-log-analysis/
├── README.md
├── reports/
│   └── incident-report-template.md    # Standard incident report format
├── notes/
│   └── log-analysis-notes.md          # Key event IDs, log locations, Splunk queries
└── samples/
    └── sample-windows-events.md       # Sanitized sample Windows log entries
```
---
📌 Key Windows Event IDs
Event ID	Description	Relevance
4624	Successful logon	Baseline / lateral movement
4625	Failed logon	Brute-force detection
4648	Logon using explicit credentials	Pass-the-hash indicator
4672	Special privileges assigned	Privilege escalation
4688	New process created	Malicious process execution
4698	Scheduled task created	Persistence mechanism
4720	User account created	Unauthorized account creation
7045	New service installed	Persistence / malware
---
🧠 Skills Demonstrated
Windows and Linux log analysis
SIEM configuration and use (Splunk, Wazuh)
Threat detection logic and correlation rules
Alert triage and classification
Incident report writing
---
📄 Reports & Notes
`/reports` — Incident report template
`/notes` — Event IDs, log paths, Splunk queries reference
`/samples` — Sanitized sample log entries for reference
---
All analysis was performed in a controlled lab environment using simulated log data.
