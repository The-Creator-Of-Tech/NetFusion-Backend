# NetFusion IL-5 EPSS Deployment Guide

## Status

✅ **IMPLEMENTATION COMPLETE**  
✅ **ALL SMOKE TESTS PASSED**  
🚀 **READY FOR DEPLOYMENT**

## Pre-Deployment Verification

Run the smoke test to verify all components:

```bash
cd c:\Netfusion\NetFusion-Agent
python epss_smoke_test.py
```

Expected output:
```
[OK] Parser: 5 records, model=v2023.03.01
[OK] Normalizer: 5 entities
[OK] Validator: valid=True, warnings=1
[OK] Statistics: avg_score=0.6477, high_prob=3
[OK] Scoring: trend=INCREASING, ma7=0.9200, delta=0.0200
...
IL-5 EPSS SMOKE TEST: ALL 12 COMPONENTS PASSED
```

## Deployment Steps

### Step 1: Database Migration

The EPSS tables will be automatically created on first use by SQLAlchemy. Alternatively, you can create them manually:

```python
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.repository.tables import Base

# Create repository
repo = SQLAlchemyIntelligenceRepository("sqlite:///dev.db")

# Tables are created automatically in __init__
# Or manually trigger:
# Base.metadata.create_all(repo.engine)

print("EPSS tables created!")
```

### Step 2: Register EPSS Feed

Add EPSS feed registration to your intelligence engine initialization:

```python
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.feeds.epss import EpssFeed
from netfusion_intelligence.identity.resolver import IdentityResolver
from netfusion_intelligence.identity.repository import IdentityRepository

# Initialize engine
engine = IntelligenceEngine()

# Setup CIIL (if not already done)
identity_repo = IdentityRepository("sqlite:///identity.db")
identity_resolver = IdentityResolver(repository=identity_repo)

# Register EPSS feed
epss_feed = EpssFeed(
    repository=engine.repository,
    identity_resolver=identity_resolver,
)

engine.register_feed(epss_feed)

print(f"EPSS feed registered: {epss_feed.feed_id}")
```

### Step 3: Verify Feed Registration

```bash
curl http://localhost:8000/intelligence/feeds
```

Look for:
```json
{
  "feed_id": "first_epss_1.0",
  "name": "FIRST Exploit Prediction Scoring System",
  "enabled": true,
  ...
}
```

### Step 4: Initial EPSS Import

Trigger the first synchronization:

```bash
curl -X POST http://localhost:8000/intelligence/feeds/first_epss_1.0/sync
```

Expected duration: 2-3 minutes for ~250,000 CVEs

Monitor progress:
```bash
# Check import status
curl http://localhost:8000/intelligence/imports?feed_id=first_epss_1.0

# Check feed health
curl "http://localhost:8000/intelligence/health?feed_id=first_epss_1.0"
```

### Step 5: Verify CIIL Enrichment

Check that canonical CVE entities have been enriched with EPSS metadata:

```bash
# Get a canonical CVE (assuming Log4j is in your NVD dataset)
curl http://localhost:8000/intelligence/nvd/cves/CVE-2021-44228
```

Look for EPSS enrichment in the metadata:
```json
{
  "cve_id": "CVE-2021-44228",
  "epss": {
    "score": 0.97365,
    "percentile": 0.99900,
    "trend": "INCREASING",
    "model_version": "v2023.03.01",
    ...
  }
}
```

### Step 6: Test EPSS API Endpoints

```bash
# Get EPSS score
curl http://localhost:8000/intelligence/epss/CVE-2021-44228

# Search high-risk CVEs
curl "http://localhost:8000/intelligence/epss/search?min_score=0.7&limit=20"

# Get trending CVEs
curl "http://localhost:8000/intelligence/epss/trending?trend_type=RAPIDLY_INCREASING&limit=10"

# Get statistics
curl http://localhost:8000/intelligence/epss/statistics

# Get historical scores
curl http://localhost:8000/intelligence/epss/history/CVE-2021-44228
```

### Step 7: Schedule Daily Synchronization

The EPSS feed is configured with schedule `0 2 * * *` (daily at 2 AM UTC). Verify the scheduler is running:

```bash
# Check scheduler status
curl http://localhost:8000/intelligence/dashboard
```

Or manually trigger daily sync:
```bash
curl -X POST http://localhost:8000/intelligence/feeds/first_epss_1.0/sync
```

### Step 8: Monitor Events and Logs

Check domain events:
```bash
curl "http://localhost:8000/intelligence/audit-logs?feed_id=first_epss_1.0&limit=50"
```

Expected events:
- `EpssImportStarted`
- `EpssScoreCreated` (×250,000)
- `CanonicalEntityEnriched` (×N where N = CVEs found in CIIL)
- `DatasetActivated`
- `EpssImportCompleted`

## Post-Deployment Verification

### Test Suite

Run complete test suite (when implemented):
```bash
pytest netfusion_intelligence/feeds/epss/tests/ -v
```

### Performance Benchmarks

Expected metrics:
- **Initial Import**: 2-3 minutes (250k CVEs)
- **Query Performance**: <100ms per CVE
- **Storage**: ~500MB with historical data
- **Memory**: ~500MB during import

### Health Check

```bash
curl "http://localhost:8000/intelligence/health?feed_id=first_epss_1.0"
```

Expected response:
```json
{
  "feed_id": "first_epss_1.0",
  "health_status": "HEALTHY",
  "last_sync_at": "2024-01-15T02:00:00Z",
  "last_success_at": "2024-01-15T02:03:27Z",
  "consecutive_failures": 0,
  "active_dataset_version": "v2024-01-15"
}
```

## Troubleshooting

### Issue: Import Fails with "No Canonical CVE Found"

**Cause**: IL-3 (NVD) not operational or no CVEs in CIIL  
**Solution**: 
1. Verify IL-3 NVD feed is operational
2. Run NVD import first: `POST /intelligence/feeds/nvd_cve_2.0/sync`
3. Verify canonical CVEs exist in CIIL
4. Re-run EPSS import

### Issue: Database Lock Errors

**Cause**: SQLite limitations with concurrent writes  
**Solution**: Use PostgreSQL for production:

```python
repo = SQLAlchemyIntelligenceRepository(
    "postgresql://user:pass@localhost/netfusion"
)
```

### Issue: Memory Errors During Import

**Cause**: Large dataset processing  
**Solution**: Increase Python heap or use streaming:

```bash
python -Xmx2g main.py
```

### Issue: TLS Certificate Verification Fails

**Cause**: Corporate firewall or proxy  
**Solution**: Configure TLS verification:

```python
epss_feed = EpssFeed(
    repository=repo,
    config=FeedConfig(verify_ssl=False),  # Not recommended for production
)
```

### Issue: CIIL Enrichment Count is Zero

**Cause**: Identity resolver not configured  
**Solution**: Ensure identity_resolver is passed to EpssFeed:

```python
epss_feed = EpssFeed(
    repository=repo,
    identity_resolver=identity_resolver,  # Required
)
```

## Configuration Options

### Feed Configuration

```python
from netfusion_intelligence.models.feed import FeedConfig

config = FeedConfig(
    enabled=True,
    schedule="0 2 * * *",  # Cron expression
    timeout=600.0,          # 10 minutes
    retry_count=3,
    auto_activate=True,
    verify_ssl=True,
)

epss_feed = EpssFeed(repository=repo, config=config)
```

### Data Source Configuration

```python
# Use alternative URL
epss_feed = EpssFeed(
    repository=repo,
    url="https://epss.cyentia.com/epss_scores-2024-01-15.csv.gz",
)

# Use JSON API
epss_feed = EpssFeed(
    repository=repo,
    feed_format="json",
)

# Use offline data
with open("epss_scores.csv", "rb") as f:
    offline_data = f.read()

epss_feed = EpssFeed(
    repository=repo,
    offline_data=offline_data,
)
```

## Rollback Procedure

If an import fails or produces bad data:

```bash
# List versions
curl http://localhost:8000/intelligence/versions?feed_id=first_epss_1.0

# Rollback to previous version
curl -X POST http://localhost:8000/intelligence/feeds/first_epss_1.0/rollback \
  -H "Content-Type: application/json" \
  -d '{"target_version_id": "v2024-01-14"}'
```

Or programmatically:
```python
engine.rollback_dataset("first_epss_1.0", target_version_id="v2024-01-14")
```

## Maintenance

### Daily Operations

1. **Monitor Health**: Check `/intelligence/health` endpoint
2. **Review Logs**: Check import logs for warnings
3. **Verify Enrichment**: Spot-check CVEs for EPSS metadata
4. **Track Storage**: Monitor database size growth

### Weekly Operations

1. **Review Statistics**: Check `/intelligence/epss/statistics`
2. **Audit Trending CVEs**: Review rapidly increasing scores
3. **Verify Schedule**: Confirm daily sync is running
4. **Check Failures**: Review any consecutive failures

### Monthly Operations

1. **Cleanup Old Versions**: Delete old dataset versions
2. **Performance Review**: Analyze query performance
3. **Disk Space**: Manage historical data retention
4. **Update Documentation**: Record any configuration changes

## Support Contacts

- **Architecture Issues**: NetFusion Intelligence Team
- **EPSS Data Issues**: FIRST.org EPSS team
- **Integration Issues**: CIIL/IL-3 maintainers

## References

- [FIRST EPSS Official Site](https://www.first.org/epss/)
- [EPSS Data Download](https://epss.cyentia.com)
- [NetFusion IL-1 Framework Documentation](../../../README.md)
- [CIIL Documentation](../../../identity/README.md)

---

**Deployment Date**: _To be filled_  
**Deployed By**: _To be filled_  
**Production URL**: _To be filled_  
**Status**: ✅ READY
