# NetFusion Platform Deployment & Administrator Guide

## Overview
This document provides complete instructions for system administrators to deploy, configure, secure, monitor, and maintain the NetFusion Cyber Investigation Platform in production environments.

---

## Prerequisites & System Requirements

### Hardware Minimum Specifications
- **CPU**: 4 vCPUs (x86_64 / ARM64)
- **RAM**: 8 GB System Memory (16 GB Recommended for large PCAP parsing)
- **Disk**: 50 GB SSD storage space for session logs and database

### Software Prerequisites
- **Operating System**: Linux (Ubuntu 22.04 LTS / RHEL 9), Windows Server 2022, or macOS
- **Runtime**: Python 3.11+ / Node.js 18+ (for API gateway if applicable)
- **System Binaries**: `tshark` (v4.0+), `nmap` (v7.90+)

---

## Deployment Architectures

### Option A: Standalone Host Execution
```bash
# Clone Repository
git clone https://github.com/netfusion/netfusion-agent.git
cd netfusion-agent

# Install Dependencies
python -m pip install -r requirements.txt

# Launch Backend Server
python main.py
```

### Option B: Docker Compose Enterprise Stack
```bash
# Navigate to deployment directory
cd deployment

# Copy & configure production environment
cp .env.production .env

# Launch platform services
sh start.sh
```

---

## Configuration & Environment Variables

Key configuration variables stored in `.env`:

| Variable | Description | Default | Security Level |
|---|---|---|---|
| `NETFUSION_ENV` | Environment mode (`production`, `development`) | `production` | High |
| `NETFUSION_JWT_SECRET` | Secret key for signing JWT tokens | `<RANDOM_SECRET>` | CRITICAL |
| `NETFUSION_PORT` | HTTP REST API listening port | `8000` | Medium |
| `OPENAI_API_KEY` | Optional key for OpenAI AI Assistant provider | `""` | CRITICAL |
| `VIRUSTOTAL_API_KEY` | Optional key for VirusTotal Threat Intel collector | `""` | High |

---

## Operational Health & Diagnostics

NetFusion provides structured health check endpoints for load balancers and container orchestrators:

- **Liveness Probe**: `GET http://localhost:8000/health/liveness` (Returns `200 OK` if process is responsive)
- **Readiness Probe**: `GET http://localhost:8000/health/readiness` (Returns `200 OK` if DB & Collectors are initialized)
- **Aggregated Health Status**: `GET http://localhost:8000/health` (Provides per-collector status report)

---

## Backup & Disaster Recovery

### Database Backup Procedure
```bash
# SQLite DB Snapshot
cp dev.db dev.db.bak_$(date +%Y%m%d_%H%M%S)
```

### Incident Data Export
To export all case data and investigation timelines for archival:
```bash
python -m utils.export_investigation --all --output-dir /backup/investigations/
```
