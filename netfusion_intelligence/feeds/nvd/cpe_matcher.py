"""
Production CPE 2.3 / 2.2 Parser & Matcher Engine for NetFusion IL-3 NVD Pipeline.
Supports vendor, product, version, edition, language, architecture, platform, OS,
wildcard matching (*, ANY, -, NA), version ranges, and configuration node evaluation.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Union
from netfusion_intelligence.feeds.nvd.models import ConfigurationNode, CpeMatchItem


@dataclass(frozen=True)
class Cpe23:
    """
    Decomposed CPE 2.3 Formatted String representation.
    """
    part: str = "*"  # 'a' (application), 'o' (operating system), 'h' (hardware)
    vendor: str = "*"
    product: str = "*"
    version: str = "*"
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def to_formatted_string(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:{self.update}:{self.edition}:{self.language}:{self.sw_edition}:{self.target_sw}:{self.target_hw}:{self.other}"


class CpeParser:
    """
    Parses CPE 2.3 formatted strings and CPE 2.2 URIs into Cpe23 instances.
    """

    @classmethod
    def parse(cls, cpe_str: str) -> Cpe23:
        if not cpe_str or not isinstance(cpe_str, str):
            return Cpe23()

        clean = cpe_str.strip()

        # Handle CPE 2.3 Formatted String
        if clean.startswith("cpe:2.3:"):
            parts = clean.split(":")
            # Pad parts to 13 elements if shorter
            parts = parts + ["*"] * (13 - len(parts))
            return Cpe23(
                part=parts[2].lower() or "*",
                vendor=parts[3].lower() or "*",
                product=parts[4].lower() or "*",
                version=parts[5].lower() or "*",
                update=parts[6].lower() or "*",
                edition=parts[7].lower() or "*",
                language=parts[8].lower() or "*",
                sw_edition=parts[9].lower() or "*",
                target_sw=parts[10].lower() or "*",
                target_hw=parts[11].lower() or "*",
                other=parts[12].lower() or "*",
            )

        # Handle CPE 2.2 URI format: cpe:/part:vendor:product:version:update:edition:language
        if clean.startswith("cpe:/"):
            uri_body = clean[5:]
            parts = uri_body.split(":")
            part = "*"
            if parts and parts[0] in ("a", "o", "h"):
                part = parts[0]
                parts = parts[1:]
            elif parts and parts[0].startswith("/"):
                part = parts[0].replace("/", "")
                parts = parts[1:]

            parts = parts + ["*"] * (10 - len(parts))
            return Cpe23(
                part=part.lower() or "*",
                vendor=parts[0].lower() or "*",
                product=parts[1].lower() or "*",
                version=parts[2].lower() or "*",
                update=parts[3].lower() or "*",
                edition=parts[4].lower() or "*",
                language=parts[5].lower() or "*",
            )

        return Cpe23()


class VersionComparer:
    """
    Semantic and alphanumeric version comparison engine for CPE version ranges.
    """

    @classmethod
    def parse_version_tuple(cls, ver_str: str) -> Tuple[List[Union[int, str]], bool]:
        """
        Parses version string into list of numerical and string tokens for comparison.
        """
        if not ver_str or ver_str in ("*", "-", "ANY", "NA"):
            return ([], True)

        tokens = re.split(r"[-_.\s]+", ver_str.lower().strip())
        parsed = []
        for t in tokens:
            if t.isdigit():
                parsed.append(int(t))
            else:
                parsed.append(t)
        return (parsed, False)

    @classmethod
    def compare(cls, ver1: str, ver2: str) -> int:
        """
        Compares ver1 and ver2.
        Returns >0 if ver1 > ver2, 0 if equal, <0 if ver1 < ver2.
        """
        t1, wild1 = cls.parse_version_tuple(ver1)
        t2, wild2 = cls.parse_version_tuple(ver2)

        if wild1 or wild2:
            return 0

        min_len = min(len(t1), len(t2))
        for i in range(min_len):
            e1, e2 = t1[i], t2[i]
            if type(e1) is type(e2):
                if e1 != e2:
                    return 1 if e1 > e2 else -1
            else:
                # Int comes before string
                return -1 if isinstance(e1, int) else 1

        if len(t1) != len(t2):
            return 1 if len(t1) > len(t2) else -1

        return 0


class CpeMatcher:
    """
    Production CPE Matching Engine.
    Matches asset CPEs against NVD cpeMatch criteria items and configuration trees.
    """

    def __init__(self, parser: Optional[CpeParser] = None):
        self.parser = parser or CpeParser()

    @staticmethod
    def _match_attribute(asset_val: str, criteria_val: str) -> bool:
        """
        Matches individual attribute field taking wildcards into account.
        """
        a = asset_val.lower().strip()
        c = criteria_val.lower().strip()

        if c in ("*", "any") or a in ("*", "any"):
            return True
        if c in ("-", "na") or a in ("-", "na"):
            return c == a

        if "*" in c or "?" in c:
            # Convert CPE wildcard pattern to regex
            pattern = "^" + re.escape(c).replace(r"\*", ".*").replace(r"\?", ".") + "$"
            return bool(re.match(pattern, a))

        return a == c

    def match_cpe_string(self, asset_cpe_str: str, target_cpe_str: str) -> bool:
        """
        Checks if asset CPE string matches target CPE criteria string.
        """
        asset = self.parser.parse(asset_cpe_str)
        target = self.parser.parse(target_cpe_str)

        return (
            self._match_attribute(asset.part, target.part)
            and self._match_attribute(asset.vendor, target.vendor)
            and self._match_attribute(asset.product, target.product)
            and self._match_attribute(asset.version, target.version)
            and self._match_attribute(asset.update, target.update)
            and self._match_attribute(asset.edition, target.edition)
            and self._match_attribute(asset.language, target.language)
            and self._match_attribute(asset.sw_edition, target.sw_edition)
            and self._match_attribute(asset.target_sw, target.target_sw)
            and self._match_attribute(asset.target_hw, target.target_hw)
            and self._match_attribute(asset.other, target.other)
        )

    def match_item(self, asset_cpe_str: str, match_item: CpeMatchItem) -> bool:
        """
        Checks if an asset CPE matches a CpeMatchItem including version range boundaries.
        """
        if not self.match_cpe_string(asset_cpe_str, match_item.criteria):
            return False

        asset = self.parser.parse(asset_cpe_str)
        asset_ver = asset.version

        if asset_ver in ("*", "-", "ANY", "NA"):
            return True

        # Check versionStartIncluding (>=)
        if match_item.version_start_including:
            if VersionComparer.compare(asset_ver, match_item.version_start_including) < 0:
                return False

        # Check versionStartExcluding (>)
        if match_item.version_start_excluding:
            if VersionComparer.compare(asset_ver, match_item.version_start_excluding) <= 0:
                return False

        # Check versionEndIncluding (<=)
        if match_item.version_end_including:
            if VersionComparer.compare(asset_ver, match_item.version_end_including) > 0:
                return False

        # Check versionEndExcluding (<)
        if match_item.version_end_excluding:
            if VersionComparer.compare(asset_ver, match_item.version_end_excluding) >= 0:
                return False

        return True

    def evaluate_node(self, asset_cpe_str: str, node: ConfigurationNode) -> bool:
        """
        Evaluates a logical configuration node (AND/OR, negate, cpe_matches, children).
        """
        op = node.operator.upper()
        results = []

        for match_item in node.cpe_matches:
            results.append(self.match_item(asset_cpe_str, match_item))

        for child in node.children:
            results.append(self.evaluate_node(asset_cpe_str, child))

        if not results:
            res = True
        elif op == "AND":
            res = all(results)
        else:  # OR
            res = any(results)

        return not res if node.negate else res

    def evaluate_configurations(self, asset_cpe_str: str, configurations: List[ConfigurationNode]) -> bool:
        """
        Evaluates an asset CPE against a list of top-level configuration nodes (OR logic across top-level nodes).
        """
        if not configurations:
            return False
        return any(self.evaluate_node(asset_cpe_str, node) for node in configurations)
