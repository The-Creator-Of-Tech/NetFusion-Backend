"""
IL-5 EPSS End-to-End Pipeline Smoke Test.
"""
import sys
sys.path.insert(0, "c:/Netfusion/NetFusion-Agent")

SAMPLE_CSV = """#model_version:v2023.03.01,score_date:2024-01-15
cve,epss,percentile
CVE-2024-12345,0.97365,0.99821
CVE-2023-44487,0.72100,0.98200
CVE-2021-44228,0.97365,0.99900
CVE-2022-30190,0.41200,0.96100
CVE-2019-0708,0.15800,0.87200
"""

from netfusion_intelligence.feeds.epss.parser import EpssParser
from netfusion_intelligence.feeds.epss.normalizer import EpssNormalizer
from netfusion_intelligence.feeds.epss.validator import EpssValidator
from netfusion_intelligence.feeds.epss.statistics import EpssStatistics
from netfusion_intelligence.feeds.epss.scoring import EpssScoringEngine
from netfusion_intelligence.feeds.epss.history import EpssHistoryTracker
from netfusion_intelligence.feeds.epss.models import EpssHistoricalScore

# -----------------------------------------------------------------------
# 1. Parser
# -----------------------------------------------------------------------
parser = EpssParser()
parsed = parser.parse(SAMPLE_CSV)
assert parsed["total_cves"] == 5, f"Expected 5, got {parsed['total_cves']}"
assert parsed["model_version"] == "v2023.03.01"
assert parsed["score_date"] == "2024-01-15"
print(f"[OK] Parser: {parsed['total_cves']} records, model={parsed['model_version']}")

# -----------------------------------------------------------------------
# 2. Normalizer
# -----------------------------------------------------------------------
normalizer = EpssNormalizer()
normalized = normalizer.normalize(parsed)
assert len(normalized["entities"]) == 5
first_rec = next(iter(normalized["entities"].values()))
assert 0.0 <= first_rec.current_score <= 1.0
print(f"[OK] Normalizer: {len(normalized['entities'])} entities")

# -----------------------------------------------------------------------
# 3. Validator
# -----------------------------------------------------------------------
validator = EpssValidator()
result = validator.validate(normalized)
assert result.is_valid, f"Validation failed: {result.errors}"
print(f"[OK] Validator: valid={result.is_valid}, warnings={len(result.warnings)}")

# -----------------------------------------------------------------------
# 4. Statistics
# -----------------------------------------------------------------------
records = list(normalized["entities"].values())
stats_engine = EpssStatistics()
stats = stats_engine.calculate_statistics(records)
assert stats["total_records"] == 5
assert stats["average_score"] > 0
print(f"[OK] Statistics: avg_score={stats['average_score']:.4f}, high_prob={stats['high_probability_cves']}")

# -----------------------------------------------------------------------
# 5. Scoring Engine
# -----------------------------------------------------------------------
scoring = EpssScoringEngine()
history = [
    EpssHistoricalScore("CVE-2024-12345", 0.85, 0.99, "2024-01-10", "v1", "v2023.03.01"),
    EpssHistoricalScore("CVE-2024-12345", 0.90, 0.99, "2024-01-11", "v1", "v2023.03.01"),
    EpssHistoricalScore("CVE-2024-12345", 0.93, 0.99, "2024-01-12", "v1", "v2023.03.01"),
    EpssHistoricalScore("CVE-2024-12345", 0.95, 0.99, "2024-01-13", "v1", "v2023.03.01"),
    EpssHistoricalScore("CVE-2024-12345", 0.97, 0.99, "2024-01-14", "v1", "v2023.03.01"),
]
trend = scoring.calculate_trend(history)
ma7 = scoring.calculate_moving_average(history, window_days=7)
delta = scoring.calculate_daily_delta(0.97, 0.95)
assert trend in ("INCREASING", "RAPIDLY_INCREASING", "STABLE")
assert ma7 is not None
print(f"[OK] Scoring: trend={trend}, ma7={ma7:.4f}, delta={delta:.4f}")

# -----------------------------------------------------------------------
# 6. Composite Risk Inputs (Foundation)
# -----------------------------------------------------------------------
risk_inputs = scoring.calculate_composite_risk_inputs(
    epss_score=0.97,
    epss_percentile=0.999,
    trend=trend,
    cvss_score=9.8,
    kev_status=True,
)
assert "kev_multiplier" in risk_inputs
assert risk_inputs["kev_multiplier"] == 2.0
assert abs(risk_inputs["cvss_normalized"] - 0.98) < 1e-9
print(f"[OK] Composite Risk Inputs: kev_multiplier={risk_inputs['kev_multiplier']}, cvss_normalized={risk_inputs['cvss_normalized']}")

# -----------------------------------------------------------------------
# 7. Risk Level Classification
# -----------------------------------------------------------------------
level = scoring.classify_risk_level(0.97, 0.999, trend, cvss_score=9.8, kev_status=True)
assert level == "CRITICAL"
level_medium = scoring.classify_risk_level(0.05, 0.30, "STABLE")
assert level_medium == "LOW"
level_high = scoring.classify_risk_level(0.55, 0.97, "INCREASING")
assert level_high == "HIGH"
print(f"[OK] Risk Level: CRITICAL confirmed, HIGH confirmed, LOW confirmed")

# -----------------------------------------------------------------------
# 8. Historical Tracker
# -----------------------------------------------------------------------
tracker = EpssHistoryTracker(scoring_engine=scoring)
snapshots = tracker.build_historical_snapshots(
    records=records,
    dataset_version="v2024-01-15",
    previous_scores={},
)
assert len(snapshots) == 5
assert snapshots[0].dataset_version == "v2024-01-15"
print(f"[OK] History Tracker: {len(snapshots)} snapshots built")

# -----------------------------------------------------------------------
# 9. Events
# -----------------------------------------------------------------------
from netfusion_intelligence.feeds.epss.events import (
    EpssImportStarted, EpssImportCompleted, EpssImportFailed,
    EpssScoreCreated, EpssScoreUpdated, CanonicalEntityEnriched, DatasetActivated
)
evt_started = EpssImportStarted(import_id="test-001")
assert evt_started.event_type == "EpssImportStarted"
evt_dict = evt_started.to_dict()
assert "event_id" in evt_dict
print(f"[OK] Events: {evt_started.event_type} event published")

# -----------------------------------------------------------------------
# 10. Manifest
# -----------------------------------------------------------------------
from netfusion_intelligence.feeds.epss.manifest import get_epss_manifest
manifest = get_epss_manifest()
assert manifest.feed_type == "first_epss_1.0"
assert "nvd_cve_2.0" in manifest.dependencies
assert "CVE_ID_PRESENT" in manifest.validation_rules
assert "CIIL_CANONICAL_CVE_EXISTS" in manifest.validation_rules
print(f"[OK] Manifest: feed_type={manifest.feed_type}, deps={manifest.dependencies}")

# -----------------------------------------------------------------------
# 11. Domain Model Integrity
# -----------------------------------------------------------------------
from netfusion_intelligence.feeds.epss.models import EpssScore, EpssRecord, EpssTrend

score = EpssScore(
    cve_id="CVE-2024-99999",
    epss_score=0.12345,
    epss_percentile=0.85432,
    publication_date="2024-01-15",
    model_version="v2023.03.01",
    dataset_version="2024-01-15",
)
assert score.to_dict()["cve_id"] == "CVE-2024-99999"

# Verify invalid score raises
try:
    bad_score = EpssScore(
        cve_id="CVE-2024-99999",
        epss_score=1.5,  # Invalid: > 1.0
        epss_percentile=0.85,
        publication_date="2024-01-15",
    )
    assert False, "Should have raised ValueError"
except ValueError:
    pass

# Verify round-trip
rec = EpssRecord.from_score(score)
d = rec.to_dict()
rec2 = EpssRecord.from_dict(d)
assert rec2.cve_id == rec.cve_id
print(f"[OK] Domain Models: integrity check passed, invalid score rejection verified")

# -----------------------------------------------------------------------
# 12. Repository Wrapper (no DB)
# -----------------------------------------------------------------------
from netfusion_intelligence.feeds.epss.repository import EpssRepository

class MockRepo:
    def save_epss_scores(self, vid, recs):
        return {"inserted": len(recs), "updated": 0, "duplicates": 0}
    def get_epss_score(self, cve_id, version_id=None):
        return {"cve_id": cve_id, "epss_score": 0.5}

repo = EpssRepository(MockRepo())
result = repo.store_epss_records("v1", records)
assert result["inserted"] == 5
score_data = repo.get_epss_score("CVE-2024-12345")
assert score_data["epss_score"] == 0.5
print(f"[OK] Repository Wrapper: store={result['inserted']} records, get={score_data['epss_score']}")

# -----------------------------------------------------------------------
# FINAL
# -----------------------------------------------------------------------
print()
print("=" * 55)
print("  IL-5 EPSS SMOKE TEST: ALL 12 COMPONENTS PASSED  ")
print("=" * 55)
