import pytest
from netfusion_collector_sdk import CollectorContext
from netfusion_canonical.value_objects import Severity
from netfusion_collectors.threat_intelligence.correlator import ThreatCorrelator
from netfusion_collectors.threat_intelligence.providers import ProviderResponse
from netfusion_collectors.threat_intelligence.canonical import (
    IOCObserved,
    ThreatIntelMatched,
    RelationshipObserved,
    MalwareObserved,
    ExploitObserved,
    MITREMappingObserved,
    ThreatActorObserved,
)


def test_correlator_ip_and_domain():
    correlator = ThreatCorrelator()
    ctx = CollectorContext(investigation_id="inv-123")

    resp = ProviderResponse(
        provider_name="abuseipdb",
        ioc_value="1.2.3.4",
        ioc_type="IPv4",
        is_threat=True,
        confidence=80.0,
        severity=Severity.HIGH,
        threat_name="Malicious IP",
        metadata={"domain": "bad-domain.com"},
    )

    objs = correlator.correlate_provider_response(resp, ctx)
    types = [o.canonical_type for o in objs]

    assert "netfusion.canonical.threat.IOCObserved" in types
    assert "netfusion.canonical.threat.ThreatIntelMatched" in types
    assert "netfusion.canonical.threat.RelationshipObserved" in types

    rel_obj = next(o for o in objs if isinstance(o, RelationshipObserved))
    assert rel_obj.source_id == "1.2.3.4"
    assert rel_obj.target_id == "bad-domain.com"
    assert rel_obj.relationship_type == "RESOLVES_TO"


def test_correlator_hash_and_malware():
    correlator = ThreatCorrelator()
    ctx = CollectorContext(investigation_id="inv-456")

    resp = ProviderResponse(
        provider_name="virustotal",
        ioc_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ioc_type="FileHash",
        is_threat=True,
        confidence=95.0,
        severity=Severity.CRITICAL,
        threat_name="Trojan.Generic",
        metadata={"malware_family": "WannaCry"},
    )

    objs = correlator.correlate_provider_response(resp, ctx)

    malware_obj = next(o for o in objs if isinstance(o, MalwareObserved))
    assert malware_obj.malware_name == "WannaCry"
    assert "filehash" in malware_obj.hashes


def test_correlator_cve_and_mitre():
    correlator = ThreatCorrelator()
    ctx = CollectorContext(investigation_id="inv-789")

    resp = ProviderResponse(
        provider_name="otx",
        ioc_value="CVE-2023-1234",
        ioc_type="CVE",
        is_threat=True,
        confidence=90.0,
        severity=Severity.CRITICAL,
        threat_name="Vulnerability CVE-2023-1234 in T1059",
        categories=["T1059.001", "Execution"],
    )

    objs = correlator.correlate_provider_response(resp, ctx)

    exploit_obj = next(o for o in objs if isinstance(o, ExploitObserved))
    assert exploit_obj.cve_id == "CVE-2023-1234"

    mitre_obj = next(o for o in objs if isinstance(o, MITREMappingObserved))
    assert mitre_obj.technique_id in ("T1059", "T1059.001")
