import pytest
from netfusion_collectors.threat_intelligence.config import ThreatIntelConfig
from netfusion_collectors.threat_intelligence.health import ThreatIntelHealthChecker


def test_health_checker_probes(temp_cache_dir):
    cfg = ThreatIntelConfig(
        cache_dir=temp_cache_dir,
        abuseipdb={"enabled": True, "api_key": "test_key"},
        virustotal={"enabled": True, "api_key": "test_key"},
    )
    checker = ThreatIntelHealthChecker(cfg)
    report = checker.run_all()

    assert report.status in ("HEALTHY", "DEGRADED")
    assert report.provider_status["abuseipdb"] == "CONFIGURED"
    assert report.provider_status["virustotal"] == "CONFIGURED"
    assert "network_connectivity" in report.checks


def test_health_checker_unconfigured_providers(temp_cache_dir):
    cfg = ThreatIntelConfig(
        cache_dir=temp_cache_dir,
        abuseipdb={"enabled": True, "api_key": None},
        virustotal={"enabled": True, "api_key": None},
        urlhaus={"enabled": False},
        misp={"enabled": False},
        opencti={"enabled": False},
    )
    checker = ThreatIntelHealthChecker(cfg)
    report = checker.run_all()

    assert report.status == "DEGRADED"
    assert len(report.errors) > 0
