# NetFusion Operational Runbooks

## Runbook 1: Installation & Initial Provisioning
1. Clone NetFusion repository into target server path.
2. Ensure Docker engine and Python 3.11 environment are available.
3. Configure environment variables in `.env`.
4. Run `sh deployment/start.sh`.
5. Verify `/health` API endpoint returns `{"status": "HEALTHY"}`.

## Runbook 2: Configuration & Feature Flag Tuning
1. Open `netfusion.yaml` or set environment variables with prefix `NETFUSION_`.
2. Hot-reload configuration dynamically via `ConfigurationManager.reload()`.

## Runbook 3: Backup & Restoration
### Database Snapshot Backup
```python
from netfusion_platform.backup.manager import BackupManager
bm = BackupManager()
backup_file = bm.backup_database("dev.db")
```

### Database Restore Procedure
```python
bm.restore_database(str(backup_file), "dev.db")
```

## Runbook 4: Troubleshooting & Diagnostics
- **Symptom: Collector execution failing or timing out.**
  - Action: Inspect `/health` endpoint to check collector health probe. Verify binaries (`tshark`, `nmap`) are present in PATH.
- **Symptom: AI provider requests fast-failing.**
  - Action: Check if Circuit Breaker `ai_provider` is OPEN. Verify network connectivity to API provider endpoint.

## Runbook 5: Incident Response & Emergency Shutdown
1. Execute emergency platform shutdown via `PlatformOrchestrator.shutdown()`.
2. Export affected investigation bundle using `BackupManager.export_investigation(workflow_service, case_id)`.
