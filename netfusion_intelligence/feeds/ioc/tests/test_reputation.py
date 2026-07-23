"""Tests for IL-7 IocReputationEngine and IocConfidenceEngine."""

import uuid
import pytest
from netfusion_intelligence.feeds.ioc.reputation import IocReputationEngine
from netfusion_intelligence.feeds.ioc.confidence import IocConfidenceEngine
from netfusion_intelligence.feeds.ioc.models import IocEntity, IocSeverity


def make_entity(**kwargs) -> IocEntity:
    defaults = dict(
        ioc_id=str(uuid.uuid4()), ioc_type="ipv4", value="1.2.3.4",
        confidence=0.8, severity="high", provider="test", source_count=1,
        false_positive_score=0.0,
    )
    defaults.update(kwargs)
    return IocEntity(**defaults)


class TestIocReputationEngine:

    def setup_method(self):
        self.engine = IocReputationEngine()

    def test_initial_reputation_computed(self):
        ent = make_entity(confidence=0.9, severity="critical")
        rep = self.engine.compute_initial_reputation(ent)
        assert rep.ioc_id == ent.ioc_id
        assert 0.0 <= rep.reputation_score <= 10.0

    def test_critical_severity_has_higher_score_than_low(self):
        ent_crit = make_entity(confidence=0.8, severity="critical")
        ent_low = make_entity(confidence=0.8, severity="low")
        rep_crit = self.engine.compute_initial_reputation(ent_crit)
        rep_low = self.engine.compute_initial_reputation(ent_low)
        assert rep_crit.reputation_score > rep_low.reputation_score

    def test_false_positive_reduces_score(self):
        ent_clean = make_entity(confidence=0.8, false_positive_score=0.0)
        ent_fp = make_entity(confidence=0.8, false_positive_score=0.8)
        rep_clean = self.engine.compute_initial_reputation(ent_clean)
        rep_fp = self.engine.compute_initial_reputation(ent_fp)
        assert rep_clean.reputation_score > rep_fp.reputation_score

    def test_reputation_update_increases_source_count(self):
        ent = make_entity()
        rep = self.engine.compute_initial_reputation(ent)
        updated = self.engine.update_reputation(rep, new_confidence=0.9, new_source="misp")
        assert updated.source_count == 2
        assert "misp" in updated.contributing_sources

    def test_reputation_update_merges_confidence(self):
        ent = make_entity(confidence=0.5)
        rep = self.engine.compute_initial_reputation(ent)
        updated = self.engine.update_reputation(rep, new_confidence=1.0)
        assert updated.confidence > rep.confidence

    def test_bulk_compute_all_entities(self):
        entities = {f"fp{i}": make_entity(ioc_id=str(uuid.uuid4())) for i in range(5)}
        reputations = self.engine.bulk_compute(entities)
        assert len(reputations) == 5
        for rep in reputations.values():
            assert 0.0 <= rep.reputation_score <= 10.0

    def test_score_clamped_to_ten(self):
        """No score should exceed 10.0 regardless of inputs."""
        ent = make_entity(confidence=1.0, severity="critical", source_count=100)
        rep = self.engine.compute_initial_reputation(ent)
        assert rep.reputation_score <= 10.0

    def test_score_never_negative(self):
        ent = make_entity(confidence=0.0, false_positive_score=1.0)
        rep = self.engine.compute_initial_reputation(ent)
        assert rep.reputation_score >= 0.0


class TestIocConfidenceEngine:

    def setup_method(self):
        self.engine = IocConfidenceEngine()

    def test_basic_confidence_in_range(self):
        score = self.engine.compute(0.7, provider_type="misp")
        assert 0.0 <= score <= 1.0

    def test_misp_higher_trust_than_csv(self):
        misp = self.engine.compute(0.7, provider_type="misp")
        csv_ = self.engine.compute(0.7, provider_type="csv")
        assert misp > csv_

    def test_multi_source_boost(self):
        single = self.engine.compute(0.7, source_count=1)
        multi = self.engine.compute(0.7, source_count=10)
        assert multi > single

    def test_sighting_boost(self):
        no_sight = self.engine.compute(0.7, sighting_count=0)
        sighted = self.engine.compute(0.7, sighting_count=20)
        assert sighted > no_sight

    def test_temporal_decay_applied(self):
        fresh = self.engine.compute(0.8, age_days=5)
        stale = self.engine.compute(0.8, age_days=180)
        assert fresh > stale

    def test_false_positive_reduces_confidence(self):
        clean = self.engine.compute(0.8, false_positive_score=0.0)
        suspect = self.engine.compute(0.8, false_positive_score=0.8)
        assert clean > suspect

    def test_tlp_red_boost(self):
        no_tlp = self.engine.compute(0.7)
        red = self.engine.compute(0.7, tlp="TLP:RED")
        assert red >= no_tlp

    def test_merge_confidences_single(self):
        result = self.engine.merge_confidences([0.8])
        assert result == 0.8

    def test_merge_confidences_consensus(self):
        result = self.engine.merge_confidences([0.8, 0.9, 0.85])
        assert 0.8 <= result <= 1.0

    def test_merge_empty_returns_zero(self):
        assert self.engine.merge_confidences([]) == 0.0

    def test_confidence_clamped(self):
        result = self.engine.compute(1.0, provider_type="misp", source_count=100, sighting_count=50)
        assert result <= 1.0

    def test_age_days_calculation(self):
        from datetime import datetime, timezone, timedelta
        first_seen = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        days = self.engine.age_days(first_seen)
        assert 44 <= days <= 46

    def test_age_days_none_for_invalid(self):
        assert self.engine.age_days("not-a-date") is None

    def test_age_days_none_for_empty(self):
        assert self.engine.age_days(None) is None
