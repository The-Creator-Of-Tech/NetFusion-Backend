"""
Comprehensive Security & Trust Verification Framework Test Suite.
Tests certificate validation, signature verification, checksum mismatch, redirect attacks, trust policy engine, audit trail, 13-step lifecycle execution, and FastAPI endpoints.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from netfusion_intelligence.api.routes import router, set_intelligence_engine
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.events import (
    CertificateValidated,
    ChecksumVerified,
    SignatureVerified,
    TrustFailed,
    TrustVerified,
)
from netfusion_intelligence.core.exceptions import (
    CertificateValidationError,
    ChecksumVerificationError,
    DownloadAuthenticityError,
    ExpiredCertificateError,
    HostnameMismatchError,
    InsecureTransportError,
    RedirectSecurityError,
    SignatureVerificationError,
    TrustPolicyViolationError,
)
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.interfaces.validator import ValidationResult
from netfusion_intelligence.models.dataset import DatasetVersion
from netfusion_intelligence.models.feed import FeedConfig, FeedMetadata
from netfusion_intelligence.models.import_result import ImportResult
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.security.audit import TrustAuditEntry, TrustAuditRepository
from netfusion_intelligence.security.checksum_verifier import ChecksumVerifier
from netfusion_intelligence.security.download_verifier import DownloadVerifier
from netfusion_intelligence.security.policy_engine import TrustDecision, TrustPolicyEngine
from netfusion_intelligence.security.signature_verifier import SignatureVerifier
from netfusion_intelligence.security.transport_verifier import TransportVerifier
from netfusion_intelligence.security.trust_model import (
    TransportRequirements,
    TrustLevel,
    TrustProfile,
    VerificationRequirements,
)


class MockSecurityFeed(FeedInterface):
    def __init__(
        self,
        feed_id: str = "security_test_feed",
        raw_data: str = '{"items": [{"id": 1}]}',
        url: str = "https://intelligence.netfusion.io/feed.json",
        expected_domain: str = "intelligence.netfusion.io",
    ):
        self._feed_id = feed_id
        self.raw_payload = raw_data
        self.url = url
        self._config = FeedConfig(enabled=True, checksum_required=True)
        self._meta = FeedMetadata(
            feed_id=feed_id,
            feed_name="Security Test Feed",
            description="Mock security feed",
            author="Security Lead",
        )
        self.trust_profile = TrustProfile(
            publisher="NetFusion Threat Lab",
            organization="NetFusion Enterprise",
            official_url=url,
            expected_domain=expected_domain,
            trust_level=TrustLevel.HIGH,
            verification_requirements=VerificationRequirements(
                require_signature=False,
                require_checksum=True,
                checksum_algorithm="SHA256",
            ),
            transport_requirements=TransportRequirements(
                require_https=True,
                allowed_domains=[expected_domain],
            ),
        )

    @property
    def metadata(self) -> FeedMetadata:
        return self._meta

    @property
    def config(self) -> FeedConfig:
        return self._config

    @config.setter
    def config(self, new_config: FeedConfig) -> None:
        self._config = new_config

    def fetch_raw_data(self):
        return self.raw_payload

    def verify_checksum(self, raw_data):
        return True

    def parse(self, raw_data):
        return [{"id": 1, "indicator": "192.168.1.100"}]

    def normalize(self, parsed_data):
        return parsed_data

    def validate(self, normalized_data):
        return ValidationResult(is_valid=True, total_checked=1)

    def store(self, dataset_version, normalized_data):
        return ImportResult(records_inserted=1)

    def build_relationships(self, dataset_version):
        return 1

    def on_activate(self, dataset_version):
        pass

    def on_rollback(self, dataset_version):
        pass


# -------------------------------------------------------------------------
# 1. Transport & Certificate Verification Tests
# -------------------------------------------------------------------------

def test_transport_verifier_https_enforcement():
    verifier = TransportVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="http://insecure.netfusion.io/feed",
        expected_domain="insecure.netfusion.io",
        transport_requirements=TransportRequirements(require_https=True),
    )
    with pytest.raises(InsecureTransportError):
        verifier.verify_transport("http://insecure.netfusion.io/feed", profile)


def test_transport_verifier_hostname_mismatch():
    verifier = TransportVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://legit.netfusion.io/feed",
        expected_domain="legit.netfusion.io",
    )
    with pytest.raises(HostnameMismatchError):
        verifier.verify_transport("https://malicious-mirror.com/feed", profile)


def test_transport_verifier_expired_certificate():
    verifier = TransportVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://feed.netfusion.io",
        expected_domain="feed.netfusion.io",
    )
    cert_info = {"is_expired": True, "subject_cn": "feed.netfusion.io"}
    with pytest.raises(ExpiredCertificateError):
        verifier.verify_transport("https://feed.netfusion.io", profile, cert_info)


# -------------------------------------------------------------------------
# 2. Signature Verification Tests
# -------------------------------------------------------------------------

def test_signature_verifier_gpg_success():
    verifier = SignatureVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://feed.netfusion.io",
        expected_domain="feed.netfusion.io",
        verification_requirements=VerificationRequirements(require_signature=True),
    )
    sig_block = "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2\n... Hash ...\n-----END PGP SIGNATURE-----"
    res = verifier.verify_signature(
        raw_data="payload_data",
        signature=sig_block,
        trust_profile=profile,
        algorithm="GPG",
    )
    assert res["verified"] is True
    assert res["algorithm"] == "PGP/GPG"


def test_signature_verifier_manifest_hash_match():
    verifier = SignatureVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://feed.netfusion.io",
        expected_domain="feed.netfusion.io",
    )
    payload = "hello world payload"
    import hashlib
    expected_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    res = verifier.verify_signature(
        raw_data=payload,
        signature=expected_sha256,
        trust_profile=profile,
        algorithm="SHA256_MANIFEST",
    )
    assert res["verified"] is True


def test_signature_verifier_missing_required_signature():
    verifier = SignatureVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://feed.netfusion.io",
        expected_domain="feed.netfusion.io",
        verification_requirements=VerificationRequirements(require_signature=True),
    )
    with pytest.raises(SignatureVerificationError):
        verifier.verify_signature(raw_data="data", signature=None, trust_profile=profile)


# -------------------------------------------------------------------------
# 3. Checksum Verification Tests
# -------------------------------------------------------------------------

def test_checksum_verifier_mismatch():
    verifier = ChecksumVerifier()
    raw_data = "actual payload"
    with pytest.raises(ChecksumVerificationError):
        verifier.verify_checksum("feed1", raw_data, expected_checksum="incorrect_hash", algorithm="SHA256")

    history = verifier.get_history(feed_id="feed1")
    assert len(history) == 1
    assert history[0]["verified"] is False


def test_checksum_verifier_sha512_success():
    verifier = ChecksumVerifier()
    raw_data = "test data sha512"
    computed = verifier.compute_hash(raw_data, algorithm="SHA512")
    res = verifier.verify_checksum("feed1", raw_data, expected_checksum=computed, algorithm="SHA512")
    assert res["verified"] is True


# -------------------------------------------------------------------------
# 4. Download Authenticity & Redirect Safety Tests
# -------------------------------------------------------------------------

def test_download_verifier_redirect_downgrade():
    verifier = DownloadVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://secure.netfusion.io",
        expected_domain="secure.netfusion.io",
    )
    chain = ["http://insecure-http-target.com/feed"]
    with pytest.raises(RedirectSecurityError):
        verifier.verify_redirects("https://secure.netfusion.io", chain, profile)


def test_download_verifier_unauthorized_mirror():
    verifier = DownloadVerifier()
    profile = TrustProfile(
        publisher="Test",
        organization="Test",
        official_url="https://official.netfusion.io",
        expected_domain="official.netfusion.io",
    )
    chain = ["https://unauthorized-mirror.com/feed"]
    with pytest.raises(DownloadAuthenticityError):
        verifier.verify_redirects("https://official.netfusion.io", chain, profile)


# -------------------------------------------------------------------------
# 5. Trust Policy Engine Evaluation Tests
# -------------------------------------------------------------------------

def test_trust_policy_engine_trusted_evaluation():
    engine = TrustPolicyEngine(strict_mode=False)
    payload = "payload content"
    import hashlib
    expected_chk = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    profile = TrustProfile(
        publisher="NetFusion Security",
        organization="NetFusion",
        official_url="https://feed.netfusion.io",
        expected_domain="feed.netfusion.io",
        trust_level=TrustLevel.HIGH,
    )
    res = engine.evaluate(
        feed_id="feed1",
        trust_profile=profile,
        raw_data=payload,
        url="https://feed.netfusion.io",
        expected_checksum=expected_chk,
    )
    assert res.decision == TrustDecision.TRUSTED
    assert res.overall_trust == "TRUSTED"
    assert res.trust_score >= 80.0


def test_trust_policy_engine_blocked_on_insecure_transport():
    engine = TrustPolicyEngine(strict_mode=False)
    profile = TrustProfile(
        publisher="NetFusion Security",
        organization="NetFusion",
        official_url="http://insecure.netfusion.io",
        expected_domain="insecure.netfusion.io",
        transport_requirements=TransportRequirements(require_https=True),
    )
    res = engine.evaluate(
        feed_id="feed1",
        trust_profile=profile,
        raw_data="payload",
        url="http://insecure.netfusion.io",
    )
    assert res.decision == TrustDecision.BLOCKED


# -------------------------------------------------------------------------
# 6. Audit Trail Persistence Tests
# -------------------------------------------------------------------------

def test_trust_audit_repository_recording():
    repo = TrustAuditRepository()
    entry = TrustAuditEntry(
        feed_id="test_feed",
        publisher="Publisher X",
        overall_trust="TRUSTED",
        reason="Verification passed",
    )
    repo.record(entry)
    history = repo.get_history(feed_id="test_feed")
    assert len(history) == 1
    assert history[0].overall_trust == "TRUSTED"


# -------------------------------------------------------------------------
# 7. 13-Step Lifecycle Pipeline & Domain Events Integration Test
# -------------------------------------------------------------------------

def test_full_13_step_lifecycle_execution():
    repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)
    feed = MockSecurityFeed()
    engine.register_feed(feed)

    events_captured = []
    engine.event_bus.subscribe_all(lambda e: events_captured.append(e))

    result = engine.sync_feed(feed.feed_id)
    assert result.status.value == "COMPLETED"

    # Verify security events were published
    event_types = [e.event_type() for e in events_captured]
    assert "TrustVerified" in event_types
    assert "CertificateValidated" in event_types
    assert "ChecksumVerified" in event_types

    # Verify audit entries were persisted
    history = engine.get_trust_history(feed_id=feed.feed_id)
    assert len(history) >= 1
    assert history[0]["overall_trust"] == "TRUSTED"


# -------------------------------------------------------------------------
# 8. Security API Endpoints Tests
# -------------------------------------------------------------------------

def test_security_api_endpoints():
    repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    engine = IntelligenceEngine(repository=repo)
    set_intelligence_engine(engine)
    feed = MockSecurityFeed()
    engine.register_feed(feed)
    engine.sync_feed(feed.feed_id)

    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    # 1. GET /intelligence/trust
    r1 = client.get("/intelligence/trust")
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["status"] == "success"
    assert "trust_summary" in data1

    # 2. GET /intelligence/trust/history
    r2 = client.get("/intelligence/trust/history")
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["status"] == "success"
    assert data2["count"] >= 1

    # 3. GET /intelligence/trust/{feed}
    r3 = client.get(f"/intelligence/trust/{feed.feed_id}")
    assert r3.status_code == 200
    data3 = r3.json()
    assert data3["status"] == "success"
    assert data3["trust"]["feed_id"] == feed.feed_id
