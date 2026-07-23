# IL-5.1 — Architecture Walkthrough
## Time-Aware EPSS Analytics Engine

---

## 1. Design Principles

IL-5.1 is built on four non-negotiable constraints:

1. **Read-only extension** — zero modifications to any IL-1 through IL-5 pipeline file
2. **No new database tables** — operates entirely on `epss_score` and `epss_history` tables created by IL-5
3. **SOLID throughout** — each class has one responsibility; nothing is a God object
4. **No ML** — pure mathematical indicators only; ML is a future IL phase

---

## 2. Layer Map

```
┌─────────────────────────────────────────────────────────────────┐
│                     REST API Layer                              │
│  api.py — FastAPI router, endpoint definitions, HTTP contracts  │
└─────────────────────────────┬───────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                   Analytics Engine                              │
│  engine.py — central orchestrator, public API surface           │
│  Coordinates all sub-engines; no business logic of its own      │
└──┬────────────┬────────────┬────────────┬────────────┬──────────┘
   │            │            │            │            │
   ▼            ▼            ▼            ▼            ▼
trend_       ranking.py  statistics.py  forecasting.py  repository.py
analyzer.py
   │            │            │            │            │
   └────────────┴────────────┴────────────┴────────────┘
                              │
                    (all read through)
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│              EpssAnalyticsRepository (repository.py)            │
│  Read-only adapter over IntelligenceRepositoryInterface         │
│  Converts raw dicts → typed EpssScoreSnapshot domain objects    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ delegates via existing interface
┌─────────────────────────────▼───────────────────────────────────┐
│         IL-5 SQLAlchemy Repository (existing, unchanged)        │
│  epss_score table        epss_history table                     │
│  (written by IL-5 feed)  (written by IL-5 feed)                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Module-by-Module Walkthrough

### 3.1 `models.py` — Domain Contracts

Pure Python dataclasses and enums. Zero I/O. Zero dependencies on DB or FastAPI.

Key types:

| Type | Purpose |
|---|---|
| `TrendClassification` (11-value enum) | Categorises CVE movement |
| `TimeWindow` (enum) | 24h / 7d / 14d / 30d / 90d / custom |
| `RankingCriteria` (9-value enum) | Nine ranking dimensions |
| `HighRiskCategory` (5-value enum) | High-risk alert categories |
| `EpssScoreSnapshot` | One historical data point |
| `EpssTrendAnalysis` | Full per-CVE analysis result |
| `EpssRankedEntry` | One ranked CVE with position + value |
| `EpssHighRiskAlert` | A high-risk detection result |
| `EpssAnalyticsSummary` | Global statistics snapshot |
| `EpssHistoryView` | Time-series data for dashboards |
| `TrendThresholds` | Configurable classification thresholds |

All models expose `to_dict()` for JSON serialisation. Trend is always serialised as a plain string, never as an enum object.

---

### 3.2 `repository.py` — Read-Only Data Adapter

`EpssAnalyticsRepository` wraps `IntelligenceRepositoryInterface` and adds analytics-specific read methods:

```
get_current_score(cve_id)           → dict | None
get_current_scores_bulk(cve_ids)    → dict[cve_id → dict]
list_current_scores(filters…)       → list[dict]
get_history(cve_id, limit)          → list[EpssScoreSnapshot]   ← typed conversion
get_history_in_window(cve_id, days) → list[EpssScoreSnapshot]
get_score_at_date(cve_id, date)     → EpssScoreSnapshot | None
get_top_rising_in_window(days)      → list[dict]   ← delta computed live
get_top_falling_in_window(days)     → list[dict]
get_new_high_risk_cves(days, thr)   → list[dict]
get_scores_above_delta_threshold()  → list[dict]
get_daily_delta_statistics()        → dict
resolve_canonical_uuid(cve_id)      → str | None   ← CIIL integration
```

The key design decision: `get_history()` converts raw DB dicts into typed `EpssScoreSnapshot` objects at the repository boundary. Everything above the repo works with typed objects only.

**Why not query the tables directly?**  
The analytics layer must stay decoupled from the ORM. If the repository implementation changes (e.g., from SQLite to PostgreSQL), analytics code is unaffected.

---

### 3.3 `trend_analyzer.py` — Per-CVE Trend Analysis

`EpssTrendAnalyzer` takes a list of `EpssScoreSnapshot` objects (newest-first) and returns a fully populated `EpssTrendAnalysis`. It has zero database access.

**Computation steps in order:**

```
1. Reference scores   → score at yesterday, −7d, −30d, −90d (date-tolerant ±2d)
2. Deltas             → daily, weekly, monthly (current − reference)
3. Moving averages    → SMA over last 7, 30, 90 observations
4. Historical extremes → max, min, mean of all observations
5. Forecasting maths   → slope, std-dev, growth-rate, momentum, confidence
6. Classification      → 11-rule priority chain (see §4)
```

The date-tolerance in step 1 handles sparse history gracefully — if day N has no snapshot, it looks back up to 2 days further. This prevents false nulls on weekends or missed ingestion runs.

---

### 3.4 `trend_analyzer.py` — Classification Priority Chain

Rules are evaluated **top-to-bottom**. The first matching rule wins.

```python
if observation_count < 2:          → INSUFFICIENT_DATA
elif current > historical_high:    → NEW_HIGH
elif current < historical_low:     → NEW_LOW
elif avg >= 0.50 and cur >= 0.50:  → CONSISTENTLY_HIGH
elif avg <= 0.05:                  → CONSISTENTLY_LOW
elif is_recovery(history):         → RECOVERY_TREND
elif daily_delta >= +0.10:         → RAPIDLY_INCREASING
elif daily_delta >= +0.01:         → INCREASING
elif daily_delta <= -0.10:         → RAPIDLY_DECREASING
elif daily_delta <= -0.01:         → DECREASING
else:                              → STABLE
```

All six thresholds are configurable via `TrendThresholds`. The entire chain can be retuned without touching engine code.

---

### 3.5 `ranking.py` — Nine-Dimension Ranking Engine

`EpssRankingEngine` dispatches to nine private methods via a `dict` dispatcher. This avoids a giant `if/elif` chain and makes adding a new criterion a one-line change.

```python
dispatch = {
    LARGEST_DAILY_INCREASE:     _rank_largest_increase(days=1),
    LARGEST_WEEKLY_INCREASE:    _rank_largest_increase(days=7),
    LARGEST_MONTHLY_INCREASE:   _rank_largest_increase(days=30),
    HIGHEST_CURRENT_SCORE:      _rank_by_current_score(),
    HIGHEST_PERCENTILE:         _rank_by_percentile(),
    FASTEST_RISING:             _rank_fastest_moving("rising"),
    FASTEST_FALLING:            _rank_fastest_moving("falling"),
    RECENTLY_ENTERED_HIGH_RISK: _rank_recently_entered_high_risk(),
    RECENTLY_LEFT_HIGH_RISK:    _rank_recently_left_high_risk(),
}
```

All methods return `List[EpssRankedEntry]` with sequential 1-based rank numbers. The `ranking_value` field always holds the value that determined the rank, making results self-documenting.

---

### 3.6 `statistics.py` — Statistics Engine

`EpssStatisticsEngine` computes global analytics over the active dataset. No external libraries — pure stdlib maths.

Private helpers exposed as `@staticmethod` so they are independently testable:

```
_mean(values)          → float
_median(values)        → float
_std_dev(values)       → float   (population std-dev)
_slope(values)         → float   (linear regression via closed-form)
_growth_rate(old, new) → float | None
```

`get_global_statistics()` is intentionally sampled on large datasets (default cap 5,000 CVEs) to keep response time under 1 second in production. The cap is a parameter, not a hardcoded constant.

---

### 3.7 `forecasting.py` — Forecasting Foundation

`EpssForecastingFoundation` prepares the feature layer for a future ML model. It delegates computation to `EpssTrendAnalyzer` to avoid duplication, then adds three derived indicators:

| Indicator | Formula | Purpose |
|---|---|---|
| `range_utilization` | `(current − min) / (max − min)` | Position within history range |
| `score_percentile_ratio` | `score / percentile` | Concentrated spike detector |
| `recent_acceleration` | 2nd derivative of last N scores | Rate of change acceleration |

The `ml_ready` flag is `True` when `observation_count >= 7`. A downstream ML pipeline can filter on this flag before attempting to use the features.

`feature_version = "il5.1-v1"` is stamped on every response. When the forecasting algorithm changes in a future IL phase, bump this version so stale cached features can be identified.

---

### 3.8 `engine.py` — Central Orchestrator

`EpssAnalyticsEngine` is the single entry point for all analytics workflows. It owns no computation logic — it creates and coordinates the sub-engines.

Constructor wiring:

```python
def __init__(self, repository, thresholds=None):
    self._analytics_repo = EpssAnalyticsRepository(repository)
    self._trend_analyzer  = EpssTrendAnalyzer(thresholds)
    self._ranking_engine  = EpssRankingEngine(self._analytics_repo)
    self._stats_engine    = EpssStatisticsEngine(self._analytics_repo)
    self._forecasting     = EpssForecastingFoundation(self._trend_analyzer)
```

All five sub-engines receive their dependencies via constructor injection. There is no global state inside the engine.

---

### 3.9 `api.py` — REST Layer

`EpssAnalyticsEngine` is a FastAPI router with `prefix="/intelligence/epss"`. It is integrated into the existing `netfusion_intelligence/api/routes.py` via `router.include_router()` at the bottom of that file — additive only.

The engine is wired lazily:

```python
def _get_or_init_epss_analytics_engine():
    global _epss_analytics_engine_instance
    if _epss_analytics_engine_instance is None:
        eng = get_intelligence_engine()
        _epss_analytics_engine_instance = EpssAnalyticsEngine(eng.repository)
        set_analytics_engine(_epss_analytics_engine_instance)
    return _epss_analytics_engine_instance
```

This means analytics becomes available the moment the first request arrives, with no startup-time side effects on the existing framework.

---

## 4. CIIL Integration

Every `EpssTrendAnalysis`, `EpssRankedEntry`, and `EpssHighRiskAlert` carries a `canonical_uuid` field. This is resolved via:

```
EpssAnalyticsRepository.resolve_canonical_uuid(cve_id)
  → identity_repo.find_by_identifier_value(cve_id)
  → filter entity_type == "CVE" and active == True
  → return canonical_uuid or None
```

When CIIL is not wired (e.g., in tests or standalone deployments), the field is `null` and the analytics layer continues without error. No duplicate entities are ever created — analytics is read-only with respect to CIIL.

---

## 5. Data Flow for a Single API Request

`GET /intelligence/epss/history/CVE-2024-1234`

```
HTTP Request
    │
    ▼
api.py:get_epss_history_view()
    │
    ▼
engine.py:get_history_view(cve_id)
    ├─► analytics_repo.get_current_score(cve_id)
    │       └─► sqlalchemy_repo.get_epss_score(cve_id)   [epss_score table]
    ├─► analytics_repo.get_history(cve_id, limit=365)
    │       └─► sqlalchemy_repo.get_epss_history(cve_id)  [epss_history table]
    │           └─► converts dicts → EpssScoreSnapshot[]
    ├─► trend_analyzer.analyze(cve_id, history, current_score, current_pct)
    │       ├─ computes reference scores (−1d, −7d, −30d, −90d)
    │       ├─ computes deltas
    │       ├─ computes moving averages (7d, 30d, 90d)
    │       ├─ computes extremes + average
    │       ├─ computes forecasting indicators
    │       └─ classifies trend (11-rule chain)
    ├─► builds EpssTimeSeriesPoint[] with per-point moving averages
    ├─► analytics_repo.resolve_canonical_uuid(cve_id)   [CIIL lookup]
    └─► returns EpssHistoryView
            │
            ▼
    .to_dict() → JSON response
```

Total DB calls: 2 (`get_epss_score` + `get_epss_history`). All computation is in Python.

---

## 6. Query Complexity and Performance

| Operation | DB Calls | Notes |
|---|---|---|
| Single CVE trend analysis | 2 | 1 score + 1 history |
| Top-N rising (7d window) | 1 + N | 1 list + N date lookups |
| Global statistics | 1 + sample | 1 list + sampled deltas |
| Bulk trend analysis (N CVEs) | 2N | Parallelisable in future |
| New high-risk detection | 1 + N | 1 filtered list + N past scores |

The current implementation is designed for correctness and maintainability first. For datasets with millions of CVEs, the per-CVE history lookups inside `get_top_rising_in_window()` would benefit from a batch SQL query — this is a known optimization path for a future IL-5.2 phase.

---

## 7. Extension Points

| Extension | Where to add |
|---|---|
| New trend classification | Add rule to `_classify_trend()` priority chain in `trend_analyzer.py` |
| New ranking criterion | Add entry to `dispatch` dict in `ranking.py` |
| New high-risk category | Add method to `engine.py`, add `HighRiskCategory` enum value |
| New API endpoint | Add route to `api.py` |
| ML forecasting model | Consume `EpssForecastingFoundation.prepare_forecast_indicators()` output |
| Asset correlation | Add `internet_facing` field lookup in `engine.get_high_risk_internet_facing_alerts()` |
| Custom time windows | Pass `start_date`/`end_date` in `EpssQueryFilter` |
| New statistics metric | Add to `EpssStatisticsEngine.get_global_statistics()` |

---

## 8. Backward Compatibility Contract

The following are guaranteed unchanged:

- `netfusion_intelligence/feeds/epss/` — zero modifications
- `netfusion_intelligence/repository/tables.py` — zero modifications  
- `netfusion_intelligence/repository/sqlalchemy_repository.py` — zero modifications
- `netfusion_intelligence/api/routes.py` — one additive block at the end only
- All existing IL-1 through IL-5 endpoints — unaffected
- `EpssTrend` enum in `feeds/epss/models.py` — unaffected
- `EpssScoringEngine` in `feeds/epss/scoring.py` — unaffected

IL-5.1 is a strict superset of IL-5. Removing IL-5.1 restores the exact IL-5 state.
