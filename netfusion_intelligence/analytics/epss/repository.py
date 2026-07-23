"""
IL-5.1 EPSS Analytics Repository.

Reads from existing epss_score and epss_history tables (created by IL-5)
without modifying any ingestion logic.  All methods are read-only queries
over the data that the pipeline already stores.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from netfusion_intelligence.analytics.epss.models import (
    EpssQueryFilter,
    EpssScoreSnapshot,
    TimeWindow,
)
from netfusion_intelligence.interfaces.repository import IntelligenceRepositoryInterface

logger = logging.getLogger(__name__)


class EpssAnalyticsRepository:
    """
    Read-only analytics repository that operates on historical EPSS records
    already stored by the IL-5 ingestion pipeline.

    Delegates all DB operations to IntelligenceRepositoryInterface so the
    analytics layer never touches storage tables directly.
    """

    def __init__(self, repository: IntelligenceRepositoryInterface) -> None:
        self._repo = repository

    # ------------------------------------------------------------------
    # Current Score Lookups
    # ------------------------------------------------------------------

    def get_current_score(
        self,
        cve_id: str,
        version_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Returns the current EPSS score record for a CVE.
        Delegates to the existing get_epss_score() repo method.
        """
        if not hasattr(self._repo, "get_epss_score"):
            return None
        return self._repo.get_epss_score(cve_id.upper(), version_id=version_id)

    def get_current_scores_bulk(
        self,
        cve_ids: List[str],
        version_id: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Returns current score records for multiple CVEs.
        Returns dict: cve_id → score_record.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for cve_id in cve_ids:
            rec = self.get_current_score(cve_id, version_id)
            if rec:
                result[cve_id.upper()] = rec
        return result

    def list_current_scores(
        self,
        min_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        trend: Optional[str] = None,
        version_id: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Lists current EPSS score records with optional filters.
        """
        if not hasattr(self._repo, "list_epss_scores"):
            return []
        return self._repo.list_epss_scores(
            min_score=min_score,
            min_percentile=min_percentile,
            trend=trend,
            version_id=version_id,
            limit=limit,
            offset=offset,
        )

    # ------------------------------------------------------------------
    # Historical Data Access
    # ------------------------------------------------------------------

    def get_history(
        self,
        cve_id: str,
        limit: int = 365,
    ) -> List[EpssScoreSnapshot]:
        """
        Returns historical snapshots for a CVE ordered by date descending.
        Converts raw dicts from the existing get_epss_history() into
        typed EpssScoreSnapshot objects.
        """
        if not hasattr(self._repo, "get_epss_history"):
            return []

        raw_records = self._repo.get_epss_history(cve_id.upper(), limit=limit)
        snapshots: List[EpssScoreSnapshot] = []

        for r in raw_records:
            try:
                snapshots.append(
                    EpssScoreSnapshot(
                        cve_id=r.get("cve_id", cve_id).upper(),
                        score=float(r.get("epss_score", 0.0)),
                        percentile=float(r.get("epss_percentile", 0.0)),
                        date=str(r.get("date", r.get("score_date", ""))),
                        daily_delta_score=float(r.get("daily_delta_score", 0.0)),
                        daily_delta_percentile=float(r.get("daily_delta_percentile", 0.0)),
                        dataset_version_id=str(r.get("dataset_version_id", "")),
                        model_version=str(r.get("model_version", "")),
                    )
                )
            except (ValueError, TypeError) as exc:
                logger.warning(f"Skipping malformed history record for {cve_id}: {exc}")

        return snapshots

    def get_history_in_window(
        self,
        cve_id: str,
        days: int,
        reference_date: Optional[datetime] = None,
    ) -> List[EpssScoreSnapshot]:
        """
        Returns history snapshots within the last `days` days.
        """
        all_history = self.get_history(cve_id, limit=days + 10)
        if not all_history:
            return []

        cutoff = (reference_date or datetime.now(timezone.utc)) - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d")

        return [s for s in all_history if s.date >= cutoff_str]

    def get_score_at_date(
        self,
        cve_id: str,
        target_date: str,
    ) -> Optional[EpssScoreSnapshot]:
        """
        Returns the closest historical snapshot at or before target_date (YYYY-MM-DD).
        """
        history = self.get_history(cve_id, limit=365)
        candidates = [s for s in history if s.date <= target_date]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.date)

    # ------------------------------------------------------------------
    # Bulk Historical Analysis Queries
    # ------------------------------------------------------------------

    def get_top_rising_in_window(
        self,
        days: int,
        limit: int = 50,
        min_score: Optional[float] = None,
        reference_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns CVEs with the largest score increase over `days`.

        Strategy: for every CVE in the active dataset, compute
        delta = current_score − score_N_days_ago.
        Returns top-N sorted by delta descending.
        """
        now = reference_date or datetime.now(timezone.utc)
        past_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")

        all_scores = self.list_current_scores(
            min_score=min_score,
            limit=50_000,  # full dataset
        )

        results: List[Dict[str, Any]] = []
        for rec in all_scores:
            cve_id = rec.get("cve_id", "")
            current = float(rec.get("epss_score", 0.0))

            past_snap = self.get_score_at_date(cve_id, past_date)
            if past_snap is None:
                continue

            delta = round(current - past_snap.score, 6)
            if delta <= 0:
                continue

            results.append(
                {
                    "cve_id": cve_id,
                    "current_score": current,
                    "past_score": past_snap.score,
                    "delta": delta,
                    "days": days,
                    "past_date": past_date,
                    "current_percentile": float(rec.get("epss_percentile", 0.0)),
                    "trend": rec.get("trend", "INSUFFICIENT_DATA"),
                }
            )

        results.sort(key=lambda x: x["delta"], reverse=True)
        return results[:limit]

    def get_top_falling_in_window(
        self,
        days: int,
        limit: int = 50,
        reference_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns CVEs with the largest score decrease over `days`.
        """
        now = reference_date or datetime.now(timezone.utc)
        past_date = (now - timedelta(days=days)).strftime("%Y-%m-%d")

        all_scores = self.list_current_scores(limit=50_000)

        results: List[Dict[str, Any]] = []
        for rec in all_scores:
            cve_id = rec.get("cve_id", "")
            current = float(rec.get("epss_score", 0.0))

            past_snap = self.get_score_at_date(cve_id, past_date)
            if past_snap is None:
                continue

            delta = round(current - past_snap.score, 6)
            if delta >= 0:
                continue

            results.append(
                {
                    "cve_id": cve_id,
                    "current_score": current,
                    "past_score": past_snap.score,
                    "delta": delta,
                    "days": days,
                    "past_date": past_date,
                    "current_percentile": float(rec.get("epss_percentile", 0.0)),
                    "trend": rec.get("trend", "INSUFFICIENT_DATA"),
                }
            )

        results.sort(key=lambda x: x["delta"])
        return results[:limit]

    def get_new_high_risk_cves(
        self,
        lookback_days: int = 7,
        high_risk_threshold: float = 0.50,
        reference_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns CVEs that recently crossed the high-risk threshold.
        A CVE qualifies if: current_score >= threshold AND score N days ago < threshold.
        """
        now = reference_date or datetime.now(timezone.utc)
        past_date = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%d")

        high_risk_now = self.list_current_scores(
            min_score=high_risk_threshold,
            limit=50_000,
        )

        results: List[Dict[str, Any]] = []
        for rec in high_risk_now:
            cve_id = rec.get("cve_id", "")
            current = float(rec.get("epss_score", 0.0))

            past_snap = self.get_score_at_date(cve_id, past_date)
            if past_snap and past_snap.score >= high_risk_threshold:
                continue  # Was already high-risk before window

            results.append(
                {
                    "cve_id": cve_id,
                    "current_score": current,
                    "past_score": past_snap.score if past_snap else None,
                    "current_percentile": float(rec.get("epss_percentile", 0.0)),
                    "trend": rec.get("trend", "INSUFFICIENT_DATA"),
                    "crossed_threshold": high_risk_threshold,
                    "lookback_days": lookback_days,
                }
            )

        results.sort(key=lambda x: x["current_score"], reverse=True)
        return results

    def get_scores_above_delta_threshold(
        self,
        delta_threshold: float,
        days: int,
        limit: int = 200,
        reference_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns CVEs whose score increased by more than delta_threshold over `days`.
        E.g. delta > 0.20 over 7 days, or delta > 0.40 over 30 days.
        """
        rising = self.get_top_rising_in_window(days=days, limit=limit * 2, reference_date=reference_date)
        return [r for r in rising if r["delta"] >= delta_threshold][:limit]

    # ------------------------------------------------------------------
    # Delta Statistics
    # ------------------------------------------------------------------

    def get_daily_delta_statistics(
        self,
        limit_cves: int = 10_000,
    ) -> Dict[str, Any]:
        """
        Computes average daily change statistics across the active dataset.
        Uses the daily_delta_score values stored in epss_history.
        """
        all_scores = self.list_current_scores(limit=limit_cves)

        all_daily_deltas: List[float] = []
        largest_increase = 0.0
        largest_increase_cve: Optional[str] = None
        largest_decrease = 0.0
        largest_decrease_cve: Optional[str] = None

        for rec in all_scores:
            cve_id = rec.get("cve_id", "")
            history = self.get_history(cve_id, limit=2)
            if len(history) < 1:
                continue

            # Most recent daily delta
            delta = history[0].daily_delta_score
            all_daily_deltas.append(delta)

            if delta > largest_increase:
                largest_increase = delta
                largest_increase_cve = cve_id
            if delta < largest_decrease:
                largest_decrease = delta
                largest_decrease_cve = cve_id

        avg_daily = (
            round(sum(all_daily_deltas) / len(all_daily_deltas), 6)
            if all_daily_deltas
            else 0.0
        )

        return {
            "average_daily_change": avg_daily,
            "largest_daily_increase": round(largest_increase, 6),
            "largest_daily_increase_cve": largest_increase_cve,
            "largest_daily_decrease": round(largest_decrease, 6),
            "largest_daily_decrease_cve": largest_decrease_cve,
            "sample_size": len(all_daily_deltas),
        }

    # ------------------------------------------------------------------
    # CIIL Integration
    # ------------------------------------------------------------------

    def resolve_canonical_uuid(self, cve_id: str) -> Optional[str]:
        """
        Attempts to look up the canonical UUID for a CVE from the CIIL layer.
        Returns None if CIIL is not wired or the CVE is not found.
        """
        if not hasattr(self._repo, "_identity_repository"):
            return None
        try:
            identity_repo = self._repo._identity_repository
            entities = identity_repo.find_by_identifier_value(cve_id)
            cve_entities = [e for e in entities if e.entity_type.upper() == "CVE" and e.active]
            return cve_entities[0].canonical_uuid if cve_entities else None
        except Exception as exc:
            logger.debug(f"CIIL lookup failed for {cve_id}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_epss_version_id(self) -> Optional[str]:
        """Returns the active EPSS dataset version ID."""
        try:
            active = self._repo.get_active_dataset_version("first_epss_1.0")
            return active.version_id if active else None
        except Exception:
            return None
