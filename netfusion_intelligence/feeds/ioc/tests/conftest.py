"""
IL-7 IOC Test Suite — Shared Fixtures.
"""

import pytest
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.config import EngineConfig
from netfusion_intelligence.feeds.ioc.feed import IocFeed
from netfusion_intelligence.feeds.ioc.providers import OfflineImportProvider


# ---------------------------------------------------------------------------
# Minimal indicator datasets for testing
# ---------------------------------------------------------------------------

SAMPLE_INDICATORS = [
    {"type": "ipv4", "value": "1.2.3.4", "confidence": 0.9, "severity": "high",
     "provider": "test", "provider_indicator_id": "evt-001",
     "malware_families": ["AgentTesla"], "campaigns": ["PhishWave"],
     "threat_actors": ["Lazarus"], "attack_technique_ids": ["T1059"],
     "tags": ["c2", "botnet"]},
    {"type": "domain", "value": "evil.example.com", "confidence": 0.8, "severity": "medium",
     "provider": "test", "provider_indicator_id": "evt-001",
     "malware_families": ["AgentTesla"]},
    {"type": "sha256",
     "value": "a" * 64,
     "confidence": 0.95, "severity": "critical",
     "provider": "test"},
    {"type": "url", "value": "https://malicious.example.com/payload.exe",
     "confidence": 0.7, "provider": "test"},
    {"type": "email", "value": "attacker@evil.com", "confidence": 0.6, "provider": "test"},
    {"type": "md5", "value": "b" * 32, "confidence": 0.85, "provider": "test"},
]

SAMPLE_JSON_PAYLOAD = {"indicators": SAMPLE_INDICATORS}


@pytest.fixture(scope="function")
def in_memory_repo():
    return SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")


@pytest.fixture(scope="function")
def engine_with_repo(in_memory_repo):
    cfg = EngineConfig(db_url="sqlite:///:memory:")
    eng = IntelligenceEngine(config=cfg, repository=in_memory_repo)
    return eng


@pytest.fixture(scope="function")
def ioc_feed(in_memory_repo):
    provider = OfflineImportProvider(data=SAMPLE_JSON_PAYLOAD, name="TestOffline")
    feed = IocFeed(repository=in_memory_repo, providers=[provider])
    return feed


@pytest.fixture(scope="function")
def ioc_feed_no_repo():
    provider = OfflineImportProvider(data=SAMPLE_JSON_PAYLOAD, name="TestOffline")
    return IocFeed(providers=[provider])


@pytest.fixture(scope="function")
def normalized_dataset(ioc_feed):
    raw = ioc_feed.fetch_raw_data()
    parsed = ioc_feed.parse(raw)
    return ioc_feed.normalize(parsed)
