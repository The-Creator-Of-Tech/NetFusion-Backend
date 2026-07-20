import pytest
from unittest.mock import patch, MagicMock
from netfusion_collector_sdk import CollectorContext, EventPublisher
from netfusion_canonical import NormalizationPipeline, DeadLetterQueue, CanonicalValidator
from netfusion_collectors.threat_intelligence import (
    ThreatIntelCollector,
    ThreatIntelConfig,
)


def test_collector_full_execution_flow(temp_cache_dir):
    context = CollectorContext(
        investigation_id="inv-e2e-001",
        correlation_id="corr-e2e-001",
        tenant_id="default-tenant",
    )

    collector = ThreatIntelCollector(context=context)

    dlq = DeadLetterQueue()
    validator = CanonicalValidator()
    pipeline = NormalizationPipeline(dlq=dlq)
    publisher = EventPublisher()

    collector.initialize_runtime(
        event_publisher=publisher,
        pipeline=pipeline,
    )

    config = ThreatIntelConfig(
        cache_dir=temp_cache_dir,
        batch_size=10,
        iocs=[
            {"value": "1.1.1.1", "type": "IPv4"},
            {"value": "malware.download/exe", "type": "URL"},
        ],
        abuseipdb={"enabled": True, "api_key": "test_abuse_key"},
        virustotal={"enabled": True, "api_key": "test_vt_key"},
        urlhaus={"enabled": True},
        misp={"enabled": False},
        opencti={"enabled": False},
    )

    collector.configure(config.model_dump())
    collector.on_pre_execute()

    # Mock provider responses
    with patch("urllib.request.urlopen") as mock_url:
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value.read.return_value = b'{"data": {"abuseConfidenceScore": 90, "totalReports": 10}, "query_status": "ok", "threat": "malware_download"}'
        mock_url.return_value = mock_cm

        result = collector.execute_collection()

        assert result.status.value == "COMPLETED"
        assert result.packets_captured == 2
        assert result.objects_generated > 0

        # Check published events
        event_types = [e.event_type for e in publisher.published_events]
        assert "CollectorStartedEvent" in event_types
        assert "CanonicalObjectEvent" in event_types
        assert "CompletedEvent" in event_types

    collector.on_post_execute(result)
    collector.on_cleanup()
