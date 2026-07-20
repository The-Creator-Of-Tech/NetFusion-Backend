# Security Policy

## Supported Versions

The following table indicates the security patch support status for NetFusion releases:

| Version | Supported | Notes |
|---|---|---|
| 1.0.0-rc1 | Yes | Current Release Candidate (Active Maintenance) |
| < 1.0.0 | No | Pre-release development snapshots |

---

## Reporting a Vulnerability

The NetFusion Engineering Team takes platform security seriously. If you discover a potential security vulnerability in NetFusion, please report it immediately by following these guidelines:

### Preferred Reporting Method
- **Email**: Send a private report to `security@netfusion.io` or open a confidential Security Advisory on GitHub.
- **Encrypted Communication**: GPG key available upon request.

### What to Include in Your Report
1. **Description**: Detailed description of the vulnerability and potential impact.
2. **Reproduction Steps**: Step-by-step instructions or proof-of-concept (PoC) code.
3. **Affected Components**: Specific package, module, API endpoint, or file.
4. **Environment**: Operating System, Python version, and deployment mode.

### Our Security Response Process
1. **Acknowledgement**: We will acknowledge receipt of your report within 24 hours.
2. **Assessment**: Our security team will validate the issue and assess risk within 72 hours.
3. **Patch & Disclosure**: We will develop a fix, issue a CVE if appropriate, and publish a patch release within 14 days.

---

## Security Hardening Principles in NetFusion

- **Secret Masking**: `SecretLogMasker` dynamically redacts API keys and credentials from console and file logs.
- **Path Traversal Protection**: `validate_safe_path` prevents directory traversal attacks across file operations.
- **SQLi & Command Injection**: All database operations use parameter bindings via Prisma/SQLite, and subprocess calls avoid `shell=True`.
- **JWT & RBAC**: Strong cryptographic signatures for tokens and granular permission verification on REST API routes.
