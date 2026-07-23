"""
Tests for CweStatistics — coverage metrics, distribution counts, quality indicators.
"""

import pytest

from netfusion_intelligence.feeds.cwe.statistics import CweStatistics


class TestCweStatisticsBasic:

    def test_returns_dict(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert isinstance(stats, dict)

    def test_total_weaknesses(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_weaknesses"] == 2

    def test_total_relationships(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_relationships"] == 1

    def test_empty_dataset_returns_empty(self):
        stats = CweStatistics.calculate_statistics("not a dict")
        assert stats == {}


class TestCweStatisticsDistributions:

    def test_by_abstraction_counts(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        by_abs = stats["by_abstraction"]
        assert "Base" in by_abs
        assert by_abs["Base"] == 2

    def test_by_structure_counts(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert "Simple" in stats["by_structure"]
        assert stats["by_structure"]["Simple"] == 2

    def test_by_status_counts(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert "Stable" in stats["by_status"]
        assert stats["by_status"]["Stable"] == 2

    def test_by_likelihood_counts(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert "High" in stats["by_likelihood_of_exploit"]

    def test_by_relationship_nature_counts(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        nature_counts = stats["by_relationship_nature"]
        assert "ChildOf" in nature_counts
        assert nature_counts["ChildOf"] == 1


class TestCweStatisticsCoverage:

    def test_weaknesses_with_mitigations(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        # Only CWE-79 has mitigations
        assert stats["weaknesses_with_mitigations"] == 1

    def test_weaknesses_with_detection_methods(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["weaknesses_with_detection_methods"] == 1

    def test_weaknesses_with_capec_references(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        # CWE-79 has CAPEC references
        assert stats["weaknesses_with_capec_references"] == 1

    def test_weaknesses_with_platform_data(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["weaknesses_with_platform_data"] == 1

    def test_mitigation_coverage_percentage(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        # 1 of 2 have mitigations → 50%
        assert stats["mitigation_coverage_pct"] == 50.0

    def test_detection_coverage_percentage(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["detection_coverage_pct"] == 50.0

    def test_capec_coverage_percentage(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["capec_coverage_pct"] == 50.0

    def test_total_mitigations_counted(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_mitigations"] >= 1

    def test_total_detection_methods_counted(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert stats["total_detection_methods"] >= 1


class TestCweStatisticsMostConnected:

    def test_most_connected_weaknesses_is_list(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert isinstance(stats["most_connected_weaknesses"], list)

    def test_most_connected_weaknesses_has_entries(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        assert len(stats["most_connected_weaknesses"]) > 0

    def test_most_connected_weakness_schema(self, sample_normalized_data):
        stats = CweStatistics.calculate_statistics(sample_normalized_data)
        entry = stats["most_connected_weaknesses"][0]
        assert "cwe_id" in entry
        assert "name" in entry
        assert "related_count" in entry


class TestCweStatisticsEdgeCases:

    def test_zero_entities_returns_zero_coverage(self):
        data = {
            "entities": {},
            "relationships": [],
        }
        stats = CweStatistics.calculate_statistics(data)
        assert stats["total_weaknesses"] == 0
        assert stats["mitigation_coverage_pct"] == 0.0
        assert stats["detection_coverage_pct"] == 0.0
