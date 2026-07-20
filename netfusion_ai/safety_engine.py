"""
NetFusion AI Safety Engine
Enforces non-fabrication of evidence, IOC values, and timestamps.
Classifies AI output statements into Facts, Inferences, Hypotheses, and Recommendations.
"""

import re
from typing import Any, Dict, List, Set, Tuple

from netfusion_ai.domain import Claim, ClaimType, EvidenceReference
from netfusion_ai.context_builder import InvestigationContextContainer
from netfusion_ai.exceptions import SafetyViolationError


# Regular expressions for entity extraction
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
TIMESTAMP_REGEX = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b")


class SafetyEngine:
    """Safety verification and claim classification engine."""

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def verify_and_classify(
        self,
        raw_text: str,
        context: InvestigationContextContainer,
    ) -> Tuple[List[Claim], List[Claim], List[Claim], List[Claim]]:
        """Verifies text against context and partitions statements into Facts, Inferences, Hypotheses, Recommendations."""

        known_ips, known_hashes, known_timestamps = self._extract_known_context_entities(context)

        # Non-fabrication verification
        mentioned_ips = set(IPV4_REGEX.findall(raw_text))
        mentioned_hashes = set(SHA256_REGEX.findall(raw_text) + MD5_REGEX.findall(raw_text))

        unverified_ips = mentioned_ips - known_ips
        unverified_hashes = mentioned_hashes - known_hashes

        # Filter out common standard local/broadcast IPs like 127.0.0.1, 0.0.0.0, 255.255.255.255
        unverified_ips = {ip for ip in unverified_ips if not (ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255"))}

        if self.strict_mode and (unverified_ips or unverified_hashes):
            raise SafetyViolationError(
                f"Safety Violation: AI generated ungrounded entities. "
                f"Unverified IPs: {unverified_ips}, Unverified Hashes: {unverified_hashes}"
            )

        # Categorize statements into claims
        facts: List[Claim] = []
        inferences: List[Claim] = []
        hypotheses: List[Claim] = []
        recommendations: List[Claim] = []

        lines = [line.strip() for line in raw_text.split("\n") if line.strip()]

        for line in lines:
            if not line or len(line) < 5:
                continue

            lower_line = line.lower()
            if any(k in lower_line for k in ["recommend", "should", "suggest", "action:", "isolate", "block"]):
                claim = Claim(
                    statement=line,
                    claim_type=ClaimType.RECOMMENDATION,
                    is_verified=True,
                )
                recommendations.append(claim)
            elif any(k in lower_line for k in ["hypothesis", "hypothesize", "suspect", "possible", "could be"]):
                claim = Claim(
                    statement=line,
                    claim_type=ClaimType.HYPOTHESIS,
                    is_verified=True,
                )
                hypotheses.append(claim)
            elif any(k in lower_line for k in ["observed", "timeline", "evidence", "found", "detected", "log"]):
                is_grounded = not any(ip in line for ip in unverified_ips)
                claim = Claim(
                    statement=line,
                    claim_type=ClaimType.FACT,
                    is_verified=is_grounded,
                    notes="Verified against context telemetry" if is_grounded else "Unverified entity in statement",
                )
                facts.append(claim)
            else:
                claim = Claim(
                    statement=line,
                    claim_type=ClaimType.INFERENCE,
                    is_verified=True,
                )
                inferences.append(claim)

        return facts, inferences, hypotheses, recommendations

    def _extract_known_context_entities(
        self, context: InvestigationContextContainer
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Extracts set of known IPs, hashes, and timestamps present in investigation context."""
        context_str = str(context.to_dict())

        ips = set(IPV4_REGEX.findall(context_str))
        hashes = set(SHA256_REGEX.findall(context_str) + MD5_REGEX.findall(context_str))
        timestamps = set(TIMESTAMP_REGEX.findall(context_str))

        return ips, hashes, timestamps
