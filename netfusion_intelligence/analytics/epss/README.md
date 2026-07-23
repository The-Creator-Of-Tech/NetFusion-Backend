# IL-5.1 — Time-Aware EPSS Analytics Engine

## Overview

IL-5.1 extends the completed IL-5 EPSS pipeline with **historical intelligence analytics**.  
It operates entirely on historical EPSS records already stored by the IL-5 ingestion pipeline.  
No ingestion code is modified. No new tables are required.

---

## Architecture

```
netfusion_intelligence/analytics/epss/
├── __init__.py
├── models.py          ← Pure domain models (enums, dataclasses, no I/O)
├── repository.py      ← Read-only analytics repository over existing tables
├── trend_analyzer.py  ← Per-CVE trend analysis and classification engine
├── ranking.py         ← Nine-dimension ranking engine
├── statistics.py      ← Global and per-CVE statistics engine
├── forecasting.py     ← Mathematical forecasting indicators foundation
├── engine.py          ← Central analytics engine orchestrator
├── api.py             ← FastAPI REST endpoints
└── tests/
    ├── conftest.py
    ├── test_analytics.py
    ├── test_api.py
    ├── test_forecasting.py
    ├── test_models.py
    ├── test_ranking.py
    ├── test_repository.py
    ├── test_statistics.py
    └── test_trend_analyzer.py
```

---

## Data Flow

```
epss_history table (IL-5)
        │
        ▼
EpssAnalyticsRepository   ← read-only, delegates to IntelligenceRepositoryInterface
        │
        ├──► EpssTrendAnalyzer     → EpssTrendAnalysis
        ├──► EpssRankingEngine     → EpssRankedEntry[]
        ├──► EpssStatisticsEngine  → EpssAnalyticsSummary
        └──► EpssForecastingFoundation → forecast indicators dict
                │
                ▼
        EpssAnalyticsEngine  (central orchestrator)
                │
                ▼
        FastAPI REST API  (api.py)
```

---

## Trend Analysis

Per-CVE analysis produces `EpssTrendAnalysis` with:

| Field | Description |
|---|---|
| `current_score` | Live EPSS score |
| `yesterday_score` | Score from 1 day ago |
| `score_7d / 30d / 90d` | Historical reference scores |
| `daily_delta` | current − yesterday |
| `weekly_delta` | current − 7d_ago |
| `monthly_delta` | current − 30d_ago |
| `historical_high / low / average` | All-time extremes |
| `moving_avg_7d / 30d / 90d` | Simple moving averages |
| `trend` | `TrendClassification` enum (11 values) |
| `trend_slope` | Linear regression slope |
| `volatility` | Std-deviation of recent scores |
| `growth_rate` | % change over observation window |
| `momentum` | Exponentially weighted recent delta |
| `prediction_confidence` | 0.0–1.0 placeholder for future ML |

### Trend Classification Priority Order

1. INSUFFICIENT_DATA — < 2 observations
2. NEW_HIGH — current > all-time high
3. NEW_LOW — current < all-time low
4. CONSISTENTLY_HIGH — avg ≥ 0.50 and current ≥ 0.50
5. CONSISTENTLY_LOW — avg ≤ 0.05
6. RECOVERY_TREND — recent avg > older avg + 0.05 and current rising
7. RAPIDLY_INCREASING — daily_delta ≥ +0.10
8. INCREASING — daily_delta in [+0.01, +0.10)
9. RAPIDLY_DECREASING — daily_delta ≤ −0.10
10. DECREASING — daily_delta in (−0.10, −0.01]
11. STABLE — |daily_delta| < 0.01

All thresholds are configurable via `TrendThresholds`.

---

## Ranking Engine

Nine ranking dimensions via `RankingCriteria`:

| Criterion | Description |
|---|---|
| `largest_daily_increase` | Biggest 1-day score gain |
| `largest_weekly_increase` | Biggest 7-day score gain |
| `largest_monthly_increase` | Biggest 30-day score gain |
| `highest_current_score` | Highest live EPSS score |
| `highest_percentile` | Highest live EPSS percentile |
| `fastest_rising` | RAPIDLY_INCREASING trend CVEs |
| `fastest_falling` | RAPIDLY_DECREASING trend CVEs |
| `recently_entered_high_risk` | Crossed ≥0.50 in last N days |
| `recently_left_high_risk` | Dropped below 0.50 from prior high |

---

## High-Risk Detection

| Category | Trigger |
|---|---|
| `NEW_HIGH_RISK` | Crossed high-risk threshold within lookback window |
| `RAPIDLY_INCREASING` | Delta > threshold over time window |
| `HIGH_SCORE_KEV` | High EPSS + in CISA KEV catalog |
| `HIGH_SCORE_HIGH_CVSS` | High EPSS + CVSS ≥ threshold |
| `HIGH_SCORE_INTERNET_FACING` | Foundation only (future asset correlation) |

---

## REST API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/intelligence/epss/analytics` | Global analytics summary |
| GET | `/intelligence/epss/trends` | CVE trend analyses |
| GET | `/intelligence/epss/history/{cve_id}` | Full history view with time-series |
| GET | `/intelligence/epss/top-rising` | Top fastest-rising CVEs |
| GET | `/intelligence/epss/top-falling` | Top fastest-falling CVEs |
| GET | `/intelligence/epss/new-high-risk` | Newly high-risk CVEs |
| GET | `/intelligence/epss/forecast` | Forecasting indicators for a CVE |
| GET | `/intelligence/epss/statistics` | Global statistics |
| GET | `/intelligence/epss/ranked` | Ranked list by any criterion |
| GET | `/intelligence/epss/cve/{cve_id}/statistics` | Per-CVE statistics |
| GET | `/intelligence/epss/alerts/rapidly-increasing` | Rapid increase alerts |

### Common Query Parameters

| Parameter | Description |
|---|---|
| `time_window` | `24h`, `7d`, `14d`, `30d`, `90d` |
| `min_score` | Minimum EPSS score filter |
| `min_percentile` | Minimum percentile filter |
| `trend_type` | `TrendClassification` value |
| `limit` | Result count cap |

---

## Forecasting Foundation

`EpssForecastingFoundation` computes mathematical indicators for future ML integration:

- `trend_slope` — linear regression slope
- `volatility` — std-deviation
- `growth_rate` — % change over window
- `momentum` — exponentially weighted recent delta
- `prediction_confidence` — observation count × (1 − volatility) proxy
- `range_utilization` — position within historical range [0,1]
- `score_percentile_ratio` — ratio indicator for concentrated spikes
- `recent_acceleration` — second derivative of recent scores
- `ml_ready` — True when ≥ 7 observations available
- `feature_version` — `il5.1-v1` (bump when algorithm changes)

No machine learning is implemented. These fields are the feature input layer for a future forecasting model.

---

## CIIL Integration

Every analytics result includes `canonical_uuid` — resolved via the CIIL layer when available.  
If CIIL is not wired or the CVE has no canonical entity, the field is `null`.  
No duplicate entities are created. Analytics is read-only with respect to CIIL.

---

## Statistics

Global `EpssAnalyticsSummary` includes:

- Trend distribution across all CVEs
- Risk distribution: CRITICAL / HIGH / MEDIUM / LOW
- Average daily and weekly change
- Largest daily / weekly / monthly increase (with CVE ID)
- Most stable CVEs (lowest volatility)
- Most volatile CVEs (highest volatility)
- New high-risk count and CVE list

---

## Wiring

The analytics engine is lazily initialised and wired to the IL-5 repository in `api/routes.py`:

```python
from netfusion_intelligence.analytics.epss.engine import EpssAnalyticsEngine
from netfusion_intelligence.analytics.epss.api import set_analytics_engine

engine = EpssAnalyticsEngine(intelligence_engine.repository)
set_analytics_engine(engine)
```

Or via the lazy init in `routes.py` which does this automatically on first request.

---

## Running Tests

```bash
# Full analytics suite
python -m pytest netfusion_intelligence/analytics/epss/tests/ -v

# Smoke test (no pytest required)
python epss_analytics_smoke_test.py
```

---

## Backward Compatibility

- Zero changes to any IL-1 through IL-5 module
- No new DB tables required
- No changes to EPSS ingestion pipeline
- The analytics router is additive — all existing endpoints are unaffected
- `IntelligenceRepositoryInterface` is consumed read-only
