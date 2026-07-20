# NetFusion SOC Analyst Guide

## Overview
This guide equips Security Operations Center (SOC) analysts, incident responders, and threat hunters with operational procedures for conducting end-to-end cyber investigations using NetFusion Phase v1.0 RC1.

---

## Investigation Lifecycle Workflow

```
+-----------+    +-----------+    +-------------+    +-------------+    +------------+
|  1. NEW   | -> | 2. TRIAGE | -> | 3. IN_PROGRESS | -> | 4. CONTAIN | -> | 5. CLOSED  |
+-----------+    +-----------+    +-------------+    +-------------+    +------------+
```

1. **New**: Automated alert or collector event ingests into NetFusion.
2. **Triage**: Analyst evaluates initial severity, affected assets, and assigns investigation ownership.
3. **In Progress**: Analyst collects evidence artifacts (PCAP, EVTX, Nmap XML, Threat Intel), builds timeline, and runs AI copilot queries.
4. **Containment**: Analyst executes containment tasks (host isolation, credential revocation, IP blocking).
5. **Closed**: Final verdict, root cause analysis, and multi-section executive report are generated.

---

## Operational Runbooks for Real-World Threat Scenarios

### 1. Spear Phishing Campaign
- **Symptoms**: Executive user received suspicious email with embedded URL.
- **Actions**:
  1. Export `.eml` artifact into Investigation Evidence.
  2. Query Threat Intelligence collector for domain reputation.
  3. Run AI Assistant `analyze_ioc` on extracted URLs.
  4. Perform user password reset and firewall URL block.

### 2. LockBit Ransomware Attack
- **Symptoms**: `vssadmin.exe delete shadows` detected via Sysmon Event ID 1 followed by mass file renaming.
- **Actions**:
  1. Trigger immediate host isolation task (`Isolate Host`).
  2. Preserve Sysmon EVTX log artifact and calculate SHA-256 evidence checksum.
  3. Map MITRE ATT&CK techniques: `T1490` (Inhibit System Recovery), `T1486` (Data Encrypted for Impact).
  4. Restore system from immutable offsite backup.

### 3. Insider Threat IP Theft
- **Symptoms**: Mass file download to unauthorized USB removable storage media.
- **Actions**:
  1. Analyze Sysmon Event ID 11 / Windows Event 20001 USB mount event.
  2. Map MITRE `T1052.001` (Exfiltration Over Physical Medium).
  3. Coordinate with HR/Legal and revoke active Active Directory credentials.

### 4. Domain Pass-The-Hash Lateral Movement
- **Symptoms**: Remote execution via PsExec / WMI from workstation to Domain Controller.
- **Actions**:
  1. Inspect Sysmon Event ID 3 (Network Conn) & Event ID 10 (Process Access to LSASS).
  2. Map MITRE `T1021.002` (SMB/Windows Admin Shares) and `T1550.002` (Pass the Hash).
  3. Purge Kerberos ticket cache and isolate compromised source host.

### 5. Cobalt Strike C2 Malware Beaconing
- **Symptoms**: Periodic outbound HTTP/DNS requests to suspicious external IP every 60 seconds.
- **Actions**:
  1. Ingest TShark PCAP capture into timeline.
  2. Map MITRE `T1071.001` (Application Layer Protocol: Web Protocols).
  3. Add C2 IP to perimeter firewall blocklist and re-image endpoint.

### 6. High Volume Data Exfiltration
- **Symptoms**: 50GB transferred over HTTPS port 443 to cloud storage domain.
- **Actions**:
  1. Ingest NetFlow / Nmap summary into investigation.
  2. Map MITRE `T1048.002` (Exfiltration Over Asymmetric Encrypted Channel).
  3. Rotate database service account credentials and enforce egress bandwidth throttling.

---

## AI Assistant Copilot Guidance
Analysts can query the AI Assistant at any point during investigation:
- **Hypothesis Generation**: Ask "What are the most likely threat actor TTPs given current evidence?"
- **MITRE Mapping**: Ask "Identify all applicable MITRE ATT&CK techniques in this session."
- **Executive Summary**: Ask "Draft an executive summary suitable for C-level leadership."
