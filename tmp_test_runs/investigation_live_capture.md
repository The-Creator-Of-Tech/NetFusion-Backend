# AI Investigation Report

## Executive Summary
- **Investigation Status**: COMPLETED
- **Overall Risk**: MEDIUM (65/100)
- **Capture Overview**: Analyzed traffic containing 3 packets over 0.0 seconds.
- **Network Activity**: Identified 3 protocols (HTTP, SMB, TCP) across 2 unique endpoints and 1 conversations.
- **Open Services**: No open services detected.
- **Key Findings**: Triggered 2 correlation rules: Exposed SMB Service (Port 445), Unencrypted HTTP Communication
- **Recommendations**: Block external access to Port 445 (SMB) immediately.; Ensure SMBv1 is disabled and require SMB signing on internal networks.; Isolate systems exposing SMB services if they cannot be patched.
- **Conclusion**: Immediate remediation is recommended to secure exposed ports/protocols.

## Risk Score & Severity
- **Risk Score**: 65 / 100
- **Severity**: Medium

## Findings
### 1. Exposed SMB Service (Port 445) (Critical)
- **Confidence**: 95%
- **Description**: Server Message Block (SMB) protocol is exposed to the network. This is a high-risk service frequently targeted for lateral movement, credential harvesting (e.g., via NTLM relaying), and exploit execution (e.g., EternalBlue).
- **Evidence**:
  - SMB protocol detected in traffic: ['HTTP', 'SMB', 'TCP']

### 2. Unencrypted HTTP Communication (Medium)
- **Confidence**: 85%
- **Description**: Unencrypted HTTP traffic was observed in the network capture. Transmitting sensitive data over unencrypted channels makes it vulnerable to eavesdropping, sniffing, and man-in-the-middle (MitM) attacks.
- **Evidence**:
  - HTTP protocol detected in traffic.
  - HTTP hosts queried: ['unencrypted-host.net']



## Evidence
### DNS Queries
- `malicious-dns.com`
### HTTP Hosts
- `unencrypted-host.net`


## Network Statistics
- **Total Packets**: 3
- **File Size Bytes**: 9
- **Duration Seconds**: 0.0
- **Protocols Count**: 3
- **Dns Queries Count**: 1
- **Http Hosts Count**: 1
- **Tls Sessions Count**: 0
- **Conversations Count**: 1
- **Endpoints Count**: 2


## Open Ports & Services
*No open ports or services detected.*


## Recommendations
- Block external access to Port 445 (SMB) immediately.
- Ensure SMBv1 is disabled and require SMB signing on internal networks.
- Isolate systems exposing SMB services if they cannot be patched.
- Enforce HTTPS/TLS (Port 443) across all web assets and client devices.
- Implement HTTP Strict Transport Security (HSTS) headers.
- Configure automatic HTTP-to-HTTPS redirection rules.

## Investigation Timeline
- **[2026-07-17T08:21:58.932201Z] Execution Started: E2E NetFusion Investigation**: Playbook 'E2E NetFusion Investigation' execution has started.
- **[2026-07-17T08:21:59.294840Z] Step Started: Analyze PCAP**: Step of type 'AUTOMATED' started.
- **[2026-07-17T08:21:59.357418Z] PCAP Analysis Started**: Analyzing capture file: live_capture.pcapng
- **[2026-07-17T08:21:59.792672Z] PCAP Analysis Completed**: Analysis completed successfully in 0.44s.
- **[2026-07-17T08:21:59.823436Z] Step Completed: Analyze PCAP**: Step completed successfully. Summary: PCAP Analysis completed for live_capture.pcapng. Analyzed 3 packets over 0.0s. Found 3 protocols (HTTP, SMB, TCP), 1 DNS queries, 1 HTTP hosts, 0 TLS sessions, and 1 conversations.
- **[2026-07-17T08:22:00.445392Z] Step Started: AI Indicator Threat Analysis**: Step of type 'AUTOMATED' started.

