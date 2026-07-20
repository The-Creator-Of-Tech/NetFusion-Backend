import tempfile
import os
import shutil
import pytest
from netfusion_collector_sdk import CollectorContext
from netfusion_collectors.threat_intelligence import ThreatIntelConfig, ThreatIntelCollector, ThreatIntelCache


@pytest.fixture
def temp_cache_dir():
    dir_path = tempfile.mkdtemp()
    yield dir_path
    shutil.rmtree(dir_path, ignore_errors=True)


@pytest.fixture
def sample_context():
    return CollectorContext(
        investigation_id="test-inv-999",
        correlation_id="test-corr-888",
        tenant_id="test-tenant",
    )


@pytest.fixture
def sample_config(temp_cache_dir):
    return ThreatIntelConfig(
        cache_dir=temp_cache_dir,
        iocs=[
            {"value": "1.1.1.1", "type": "IPv4"},
            {"value": "8.8.8.8", "type": "IPv4"},
            {"value": "malicious.org", "type": "Domain"},
            {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "FileHash"},
        ],
        abuseipdb={"enabled": True, "api_key": "test_abuse_key"},
        virustotal={"enabled": True, "api_key": "test_vt_key"},
        alienvault_otx={"enabled": True, "api_key": "test_otx_key"},
        urlhaus={"enabled": True},
        misp={"enabled": False},
        opencti={"enabled": False},
    )
