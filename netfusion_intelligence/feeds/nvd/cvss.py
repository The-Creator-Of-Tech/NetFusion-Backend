"""
Dedicated CVSS Parser and Calculator Engine for NetFusion IL-3 NVD Pipeline.
Supports CVSS v2, v3.0, v3.1, and v4.0 vector strings and JSON metric objects.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
from netfusion_intelligence.feeds.nvd.models import CvssMetric


SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "UNKNOWN": 1,
    "NONE": 0,
}


class CvssParser:
    """
    Dedicated CVSS parser supporting CVSS v2, v3.0, v3.1, and v4.0.
    Normalizes metrics, validates vector strings, compares scores, and computes risk levels.
    """

    @staticmethod
    def parse_vector_string(vector_str: str) -> Dict[str, Any]:
        """
        Parses a CVSS vector string into a key-value dictionary.
        Example v3.1: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        Example v2: 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
        """
        if not vector_str:
            return {}

        metrics = {}
        clean_str = vector_str.strip()
        
        # Check prefix
        if clean_str.startswith("CVSS:"):
            parts = clean_str.split("/")
            version_part = parts[0]
            metrics["version"] = version_part.replace("CVSS:", "").strip()
            parts = parts[1:]
        else:
            parts = clean_str.split("/")
            metrics["version"] = "2.0"

        for part in parts:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k.strip()] = v.strip()

        return metrics

    @staticmethod
    def derive_severity_v3(base_score: float) -> str:
        """Derives CVSS v3.x / v4.0 Qualitative Severity Rating."""
        if base_score >= 9.0:
            return "CRITICAL"
        elif base_score >= 7.0:
            return "HIGH"
        elif base_score >= 4.0:
            return "MEDIUM"
        elif base_score > 0.0:
            return "LOW"
        else:
            return "NONE"

    @staticmethod
    def derive_severity_v2(base_score: float) -> str:
        """Derives CVSS v2 Qualitative Severity Rating."""
        if base_score >= 7.0:
            return "HIGH"
        elif base_score >= 4.0:
            return "MEDIUM"
        elif base_score > 0.0:
            return "LOW"
        else:
            return "NONE"

    def parse_cvss_metric(self, raw_metric_dict: Dict[str, Any], version: str = "3.1") -> CvssMetric:
        """
        Parses an NVD JSON 2.0 metric object (e.g. item inside cvssMetricV31, cvssMetricV30, cvssMetricV2, cvssMetricV40).
        """
        if not isinstance(raw_metric_dict, dict):
            return CvssMetric(version=version, vector_string="", base_score=0.0, severity="UNKNOWN")

        source = raw_metric_dict.get("source")
        m_type = raw_metric_dict.get("type")
        exploitability = raw_metric_dict.get("exploitabilityScore")
        impact = raw_metric_dict.get("impactScore")

        cvss_data = raw_metric_dict.get("cvssData", {})
        if not isinstance(cvss_data, dict):
            cvss_data = {}

        ver = str(cvss_data.get("version", version))
        vector_str = str(cvss_data.get("vectorString", raw_metric_dict.get("vectorString", "")))
        base_score = float(cvss_data.get("baseScore", raw_metric_dict.get("baseScore", 0.0)))
        
        # Severity
        base_severity = cvss_data.get("baseSeverity", raw_metric_dict.get("baseSeverity"))
        if not base_severity:
            base_severity = self.derive_severity_v3(base_score) if ver != "2.0" else self.derive_severity_v2(base_score)
        else:
            base_severity = str(base_severity).upper()

        # Vector metric components
        attack_vector = cvss_data.get("attackVector") or cvss_data.get("accessVector")
        attack_complexity = cvss_data.get("attackComplexity") or cvss_data.get("accessComplexity")
        privileges_required = cvss_data.get("privilegesRequired") or cvss_data.get("authentication")
        user_interaction = cvss_data.get("userInteraction")
        scope = cvss_data.get("scope")
        c_impact = cvss_data.get("confidentialityImpact")
        i_impact = cvss_data.get("integrityImpact")
        a_impact = cvss_data.get("availabilityImpact")

        temp_score = cvss_data.get("temporalScore")
        env_score = cvss_data.get("environmentalScore")

        return CvssMetric(
            version=ver,
            vector_string=vector_str,
            base_score=base_score,
            source=source,
            metric_type=m_type,
            severity=base_severity,
            exploitability_score=float(exploitability) if exploitability is not None else None,
            impact_score=float(impact) if impact is not None else None,
            attack_vector=str(attack_vector) if attack_vector else None,
            attack_complexity=str(attack_complexity) if attack_complexity else None,
            privileges_required=str(privileges_required) if privileges_required else None,
            user_interaction=str(user_interaction) if user_interaction else None,
            scope=str(scope) if scope else None,
            confidentiality_impact=str(c_impact) if c_impact else None,
            integrity_impact=str(i_impact) if i_impact else None,
            availability_impact=str(a_impact) if a_impact else None,
            temporal_score=float(temp_score) if temp_score is not None else None,
            environmental_score=float(env_score) if env_score is not None else None,
            access_vector=str(cvss_data.get("accessVector")) if cvss_data.get("accessVector") else None,
            access_complexity=str(cvss_data.get("accessComplexity")) if cvss_data.get("accessComplexity") else None,
            authentication=str(cvss_data.get("authentication")) if cvss_data.get("authentication") else None,
            raw_metric=raw_metric_dict,
        )

    @staticmethod
    def compare_severity(severity1: str, severity2: str) -> int:
        """
        Compares two severity ratings.
        Returns >0 if severity1 > severity2, 0 if equal, <0 if severity1 < severity2.
        """
        w1 = SEVERITY_WEIGHTS.get(severity1.upper(), 0)
        w2 = SEVERITY_WEIGHTS.get(severity2.upper(), 0)
        return w1 - w2

    @staticmethod
    def calculate_risk_score(cvss_metric: Optional[CvssMetric], epss_score: float = 0.0, is_kev: bool = False) -> float:
        """
        Calculates an integrated risk score for future risk prioritization engine.
        Combines CVSS base score, EPSS probability, and CISA KEV status.
        """
        if not cvss_metric:
            base = 0.0
        else:
            base = cvss_metric.base_score

        multiplier = 1.0
        if is_kev:
            multiplier += 0.5
        if epss_score > 0.0:
            multiplier += epss_score * 0.5

        return round(min(10.0, base * multiplier), 2)
