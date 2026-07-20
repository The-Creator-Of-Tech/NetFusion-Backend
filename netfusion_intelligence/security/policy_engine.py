"""
Trust Policy Engine for NetFusion Intelligence feeds.
Evaluates trust profile, TLS certificates, payload signatures, checksums, and download authenticity.
Renders final trust decisions: TRUSTED, PARTIALLY_TRUSTED, UNTRUSTED, BLOCKED.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from netfusion_intelligence.core.exceptions import (
    ChecksumVerificationError,
    DownloadAuthenticityError,
    SignatureVerificationError,
    TransportSecurityError,
    TrustPolicyViolationError,
)
from netfusion_intelligence.security.checksum_verifier import ChecksumVerifier
from netfusion_intelligence.security.download_verifier import DownloadVerifier
from netfusion_intelligence.security.signature_verifier import SignatureVerifier
from netfusion_intelligence.security.transport_verifier import TransportVerifier
from netfusion_intelligence.security.trust_model import TrustLevel, TrustProfile
from netfusion_intelligence.utils.logging import get_structured_logger

logger = get_structured_logger(__name__)


class TrustDecision(str, Enum):
    TRUSTED = "TRUSTED"
    PARTIALLY_TRUSTED = "PARTIALLY_TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    BLOCKED = "BLOCKED"


@dataclass
class TrustEvaluationResult:
    """
    Detailed evaluation output produced by TrustPolicyEngine.
    """
    feed_id: str
    decision: TrustDecision
    overall_trust: str
    trust_score: float  # 0.0 to 100.0
    publisher: str
    organization: str
    trust_level: str
    transport_status: str
    certificate_status: str
    signature_status: str
    checksum_status: str
    domain_verification: str
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value if isinstance(self.decision, TrustDecision) else self.decision
        return data


class TrustPolicyEngine:
    """
    Core security evaluation engine that enforces trust policies across all intelligence feeds.
    """

    def __init__(
        self,
        transport_verifier: Optional[TransportVerifier] = None,
        signature_verifier: Optional[SignatureVerifier] = None,
        checksum_verifier: Optional[ChecksumVerifier] = None,
        download_verifier: Optional[DownloadVerifier] = None,
        strict_mode: bool = True,
    ):
        self.transport_verifier = transport_verifier or TransportVerifier()
        self.signature_verifier = signature_verifier or SignatureVerifier()
        self.checksum_verifier = checksum_verifier or ChecksumVerifier()
        self.download_verifier = download_verifier or DownloadVerifier()
        self.strict_mode = strict_mode

    def evaluate(
        self,
        feed_id: str,
        trust_profile: TrustProfile,
        raw_data: Optional[Union[str, bytes]] = None,
        url: Optional[str] = None,
        cert_info: Optional[Dict[str, Any]] = None,
        signature: Optional[Union[str, bytes]] = None,
        manifest: Optional[Dict[str, Any]] = None,
        expected_checksum: Optional[str] = None,
        redirect_chain: Optional[List[str]] = None,
    ) -> TrustEvaluationResult:
        """
        Evaluates feed authenticity across all security dimensions and computes final TrustDecision.
        """
        reasons: List[str] = []
        details: Dict[str, Any] = {}
        score: float = 100.0

        transport_status = "PASSED"
        cert_status = "PASSED"
        sig_status = "PASSED"
        checksum_status = "PASSED"
        domain_status = "PASSED"

        target_url = url or trust_profile.official_url

        # -------------------------------------------------------------
        # 1. Transport & Hostname Verification
        # -------------------------------------------------------------
        if target_url:
            try:
                transport_report = self.transport_verifier.verify_transport(target_url, trust_profile, cert_info)
                details["transport"] = transport_report
            except TransportSecurityError as tse:
                transport_status = "FAILED"
                if "Insecure transport" in str(tse):
                    cert_status = "FAILED"
                reasons.append(f"Transport security error: {tse}")
                score -= 40.0

        # -------------------------------------------------------------
        # 2. Download Authenticity & Redirect Safety
        # -------------------------------------------------------------
        if target_url:
            try:
                domain_report = self.download_verifier.verify_source(target_url, trust_profile)
                details["download_source"] = domain_report
            except DownloadAuthenticityError as dae:
                domain_status = "FAILED"
                reasons.append(f"Domain authenticity error: {dae}")
                score -= 30.0

        if target_url and redirect_chain:
            try:
                redirect_report = self.download_verifier.verify_redirects(target_url, redirect_chain, trust_profile)
                details["redirects"] = redirect_report
            except (DownloadAuthenticityError, Exception) as re:
                domain_status = "FAILED"
                reasons.append(f"Redirect security error: {re}")
                score -= 30.0

        # -------------------------------------------------------------
        # 3. Signature Verification
        # -------------------------------------------------------------
        if raw_data is not None:
            try:
                sig_report = self.signature_verifier.verify_signature(
                    raw_data=raw_data,
                    signature=signature,
                    trust_profile=trust_profile,
                    manifest=manifest,
                )
                details["signature"] = sig_report
                if not sig_report.get("verified", False):
                    sig_status = "FAILED"
                    reasons.append("Payload signature verification failed")
                    score -= 30.0
            except SignatureVerificationError as sve:
                sig_status = "FAILED"
                reasons.append(f"Signature verification error: {sve}")
                score -= 30.0
        elif trust_profile.verification_requirements.require_signature:
            sig_status = "FAILED"
            reasons.append("Signature required by trust profile but payload missing")
            score -= 30.0

        # -------------------------------------------------------------
        # 4. Checksum Verification
        # -------------------------------------------------------------
        if raw_data is not None:
            try:
                chk_report = self.checksum_verifier.verify_checksum(
                    feed_id=feed_id,
                    raw_data=raw_data,
                    expected_checksum=expected_checksum,
                    algorithm=trust_profile.verification_requirements.checksum_algorithm,
                    required=trust_profile.verification_requirements.require_checksum,
                )
                details["checksum"] = chk_report
            except ChecksumVerificationError as cve:
                checksum_status = "FAILED"
                reasons.append(f"Checksum verification error: {cve}")
                score -= 40.0

        # -------------------------------------------------------------
        # 5. Evaluate Final Decision & Trust Level Policy
        # -------------------------------------------------------------
        # Factor in base trust level of profile
        if trust_profile.trust_level == TrustLevel.LOW:
            score -= 15.0

        score = max(0.0, min(100.0, score))

        if transport_status == "FAILED" or domain_status == "FAILED" or checksum_status == "FAILED":
            decision = TrustDecision.BLOCKED
        elif sig_status == "FAILED" and trust_profile.verification_requirements.require_signature:
            decision = TrustDecision.BLOCKED
        elif sig_status == "FAILED" or trust_profile.trust_level == TrustLevel.LOW or score < 70.0:
            decision = TrustDecision.UNTRUSTED if score < 50.0 else TrustDecision.PARTIALLY_TRUSTED
        else:
            decision = TrustDecision.TRUSTED

        if not reasons:
            reasons.append("All authenticity, transport, signature, and checksum verification requirements satisfied")

        result = TrustEvaluationResult(
            feed_id=feed_id,
            decision=decision,
            overall_trust=decision.value,
            trust_score=round(score, 2),
            publisher=trust_profile.publisher,
            organization=trust_profile.organization,
            trust_level=trust_profile.trust_level.value,
            transport_status=transport_status,
            certificate_status=cert_status,
            signature_status=sig_status,
            checksum_status=checksum_status,
            domain_verification=domain_status,
            reasons=reasons,
            details=details,
        )

        logger.info(
            f"Trust policy evaluation completed for feed '{feed_id}': decision={decision.value}, score={result.trust_score}"
        )

        if self.strict_mode and decision in (TrustDecision.BLOCKED, TrustDecision.UNTRUSTED):
            err_msg = f"Feed '{feed_id}' failed TrustPolicyEngine evaluation (decision={decision.value}): {'; '.join(reasons)}"
            raise TrustPolicyViolationError(err_msg)

        return result
