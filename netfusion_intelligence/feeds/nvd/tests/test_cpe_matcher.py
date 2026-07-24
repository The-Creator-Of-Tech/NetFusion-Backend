"""
Unit tests for CPE Matcher Engine (cpe_matcher.py).
"""

from netfusion_intelligence.feeds.nvd.cpe_matcher import CpeMatcher, CpeParser, VersionComparer
from netfusion_intelligence.feeds.nvd.models import ConfigurationNode, CpeMatchItem


def test_cpe_parser():
    cpe_str = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    cpe = CpeParser.parse(cpe_str)

    assert cpe.part == "a"
    assert cpe.vendor == "apache"
    assert cpe.product == "http_server"
    assert cpe.version == "2.4.41"


def test_version_comparer():
    assert VersionComparer.compare("2.4.41", "2.4.40") > 0
    assert VersionComparer.compare("1.0.0", "1.0.0") == 0
    assert VersionComparer.compare("2.0.1", "2.0.5") < 0


def test_cpe_matcher_string_match():
    matcher = CpeMatcher()
    asset_cpe = "cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*"
    target_cpe = "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"

    assert matcher.match_cpe_string(asset_cpe, target_cpe) is True


def test_cpe_matcher_version_ranges():
    matcher = CpeMatcher()
    asset_cpe = "cpe:2.3:a:example:product:2.0.3:*:*:*:*:*:*:*"

    item = CpeMatchItem(
        vulnerable=True,
        criteria="cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
        version_start_including="2.0",
        version_end_including="2.0.5",
    )

    assert matcher.match_item(asset_cpe, item) is True

    out_of_range_asset = "cpe:2.3:a:example:product:2.1.0:*:*:*:*:*:*:*"
    assert matcher.match_item(out_of_range_asset, item) is False


def test_configuration_node_evaluator():
    matcher = CpeMatcher()
    asset_cpe = "cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*"

    node = ConfigurationNode(
        operator="OR",
        cpe_matches=(
            CpeMatchItem(vulnerable=True, criteria="cpe:2.3:a:example:product:2.0:*:*:*:*:*:*:*"),
        ),
    )

    assert matcher.evaluate_node(asset_cpe, node) is True
