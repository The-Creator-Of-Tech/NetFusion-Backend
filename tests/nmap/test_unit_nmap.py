import pytest
from netfusion_collectors.nmap import (
    NmapConfig,
    NmapScanType,
    NmapTimingTemplate,
    NmapOutputFormat,
    NmapDNSResolution,
    NmapProcessRunner,
    NmapHealthChecker,
    NmapCollector,
)


def test_nmap_config_defaults():
    config = NmapConfig()
    assert config.targets == ["127.0.0.1"]
    assert config.scan_type == NmapScanType.SYN
    assert config.timing_template == NmapTimingTemplate.T3
    assert config.output_format == NmapOutputFormat.XML
    assert config.binary_path == "nmap"


def test_nmap_runner_build_command():
    config = NmapConfig(
        targets=["192.168.1.1", "192.168.1.2"],
        scan_type=NmapScanType.SYN,
        ports="80,443",
        timing_template=NmapTimingTemplate.T4,
        skip_host_discovery=True,
        service_version_detection=True,
        os_detection=True,
        script_categories=["default", "vuln"],
        output_format=NmapOutputFormat.XML,
        ipv6=True,
        dns_resolution=NmapDNSResolution.NEVER,
    )
    runner = NmapProcessRunner(config)
    cmd = runner.build_command()

    assert cmd[0] == "nmap"
    assert "-sS" in cmd
    assert "-Pn" in cmd
    assert "-p" in cmd
    assert "80,443" in cmd
    assert "-T4" in cmd
    assert "-sV" in cmd
    assert "-O" in cmd
    assert "--script=default,vuln" in cmd
    assert "-6" in cmd
    assert "-n" in cmd
    assert "-oX" in cmd
    assert "-" in cmd
    assert "192.168.1.1" in cmd
    assert "192.168.1.2" in cmd


def test_nmap_health_checker():
    checker = NmapHealthChecker(binary_path="non_existent_nmap_path_12345")
    report = checker.run_all(collector_id="test-coll")
    assert report.xml_parser_ok is True
    assert report.binary_available is False
    assert report.status == "UNHEALTHY"
    assert len(report.errors) > 0


def test_nmap_collector_initialization():
    collector = NmapCollector()
    collector.configure({"targets": ["10.0.0.1"], "scan_type": "CONNECT"})
    assert collector.nmap_config.scan_type == NmapScanType.CONNECT
    assert collector.context.collector_type == "NmapCollector"
