"""
Tests for CapecStatistics — coverage metrics, distribution counts, quality indicators.
"""

import pytest

from netfusion_intelligence.feeds.capec.statistics import CapecStatistics


class TestCapecStatisticsBasic:

    def test_returns_dict(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert isinstance(stats, dict)

    def test_total_attack_patterns(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_attack_patterns"] == 2

    def test_total_relationships(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_relationships"] == 1

    def test_total_cwe_mappings(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_cwe_mappings"] == 1

    def test_empty_dataset_returns_empty(self):
        stats = CapecStatistics.calculate_statistics("not a dict")
        assert stats == {}


class TestCapecStatisticsDistributions:

    def test_by_abstraction_counts(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        by_abs = stats["by_abstraction"]
        assert "Standard" in by_abs
        assert by_abs["Standard"] == 1
        assert "Detailed" in by_abs
        assert by_abs["Detailed"] == 1

    def test_by_status_counts(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert "Stable" in stats["by_status"]
        assert stats["by_status"]["Stable"] == 1
        assert "Draft" in stats["by_status"]

    def test_by_likelihood_counts(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert "High" in stats["by_likelihood_of_attack"]
        assert stats["by_likelihood_of_attack"]["High"] == 2

    def test_by_severity_counts(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert "High" in stats["by_typical_severity"]
        assert "Medium" in stats["by_typical_severity"]

    def test_by_relationship_nature_counts(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        nature_counts = stats["by_relationship_nature"]
        assert "ChildOf" in nature_counts
        assert nature_counts["ChildOf"] == 1


class TestCapecStatisticsCoverage:

    def test_patterns_with_execution_flow(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        # Only CAPEC-66 has execution flow
        assert stats["patterns_with_execution_flow"] == 1

    def test_patterns_with_mitigations(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["patterns_with_mitigations"] == 1

    def test_patterns_with_detection(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["patterns_with_detection"] == 1

    def test_patterns_with_cwe_references(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        # Both CAPEC-66 and CAPEC-86 have CWE references
        assert stats["patterns_with_cwe_references"] == 2

    def test_patterns_with_prerequisites(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["patterns_with_prerequisites"] == 1

    def test_execution_flow_coverage_pct(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        # 1 of 2 → 50%
        assert stats["execution_flow_coverage_pct"] == 50.0

    def test_mitigation_coverage_pct(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["mitigation_coverage_pct"] == 50.0

    def test_cwe_coverage_pct(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        # Both have CWE refs → 100%
        assert stats["cwe_coverage_pct"] == 100.0

    def test_patterns_with_attack_references(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        # CAPEC-66 has ATT&CK taxonomy mapping
        assert stats["patterns_with_attack_references"] == 1

    def test_attack_coverage_pct(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["attack_coverage_pct"] == 50.0

    def test_total_execution_steps_counted(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        # CAPEC-66 has 2 steps
        assert stats["total_execution_steps"] == 2

    def test_total_mitigations_counted(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_mitigations"] >= 1


class TestCapecStatisticsMostReferenced:

    def test_most_referenced_is_list(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert isinstance(stats["most_referenced_attack_patterns"], list)

    def test_most_referenced_has_entries(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        assert len(stats["most_referenced_attack_patterns"]) > 0

    def test_most_referenced_schema(self, sample_normalized_data):
        stats = CapecStatistics.calculate_statistics(sample_normalized_data)
        entry = stats["most_referenced_attack_patterns"][0]
        assert "capec_id" in entry
        assert "name" in entry
        assert "cwe_count" in entry


class TestCapecStatisticsEdgeCases:

    def test_zero_entities_returns_zero_coverage(self):
        data = {"entities": {}, "relationships": [], "cwe_mappings": []}
        stats = CapecStatistics.calculate_statistics(data)
        assert stats["total_attack_patterns"] == 0
        assert stats["execution_flow_coverage_pct"] == 0.0
        assert stats["mitigation_coverage_pct"] == 0.0
