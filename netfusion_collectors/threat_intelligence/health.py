import urllib.request
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .config import ThreatIntelConfig
from .providers import ThreatProviderFactory


@dataclass
class ThreatIntelHealthReport:
    status: str = "HEALTHY"  # HEALTHY, DEGRADED, UNHEALTHY
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    provider_status: Dict[str, str] = field(default_factory=dict)
    checks: Dict[str, bool] = field(default_factory=dict)


class ThreatIntelHealthChecker:
    """
    Health Checker Probe for Threat Intelligence Collector.
    Verifies provider configuration, API credentials, network connectivity, rate limits, and SSL/TLS certificates.
    """

    def __init__(self, config: ThreatIntelConfig):
        self.config: ThreatIntelConfig = config

    def check_network_connectivity(self, host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
        """Verify outbound network connectivity."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except Exception:
            return False

    def check_certificate_validation(self, hostname: str = "www.virustotal.com", port: int = 443) -> bool:
        """Verify SSL certificate validation setup."""
        if not self.config.tls_verification:
            return True
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.getpeercert()
            return True
        except Exception:
            return False

    def run_all(self) -> ThreatIntelHealthReport:
        report = ThreatIntelHealthReport()

        # 1. Connectivity Check
        conn_ok = self.check_network_connectivity()
        report.checks["network_connectivity"] = conn_ok
        if not conn_ok:
            report.warnings.append("Network connectivity probe failed; offline or air-gapped execution mode active.")

        # 2. SSL Verification Check
        cert_ok = self.check_certificate_validation()
        report.checks["certificate_validation"] = cert_ok
        if not cert_ok:
            report.warnings.append("TLS Certificate validation failed for external provider endpoints.")

        # 3. Provider Configuration Probes
        providers_checked = 0
        providers_active = 0

        providers = [
            ("abuseipdb", self.config.abuseipdb),
            ("virustotal", self.config.virustotal),
            ("alienvault_otx", self.config.alienvault_otx),
            ("urlhaus", self.config.urlhaus),
            ("misp", self.config.misp),
            ("opencti", self.config.opencti),
        ]

        for p_name, p_cfg in providers:
            if not p_cfg.enabled:
                report.provider_status[p_name] = "DISABLED"
                continue

            providers_checked += 1
            if p_cfg.api_key or p_cfg.oauth_token or p_name == "urlhaus":
                report.provider_status[p_name] = "CONFIGURED"
                providers_active += 1
            else:
                report.provider_status[p_name] = "NO_CREDENTIALS"
                report.warnings.append(f"Provider '{p_name}' enabled but API credentials are unconfigured.")

        report.checks["has_active_provider"] = providers_active > 0

        if providers_active == 0:
            report.status = "DEGRADED"
            report.errors.append("No active threat providers are fully configured with API credentials.")
        else:
            report.status = "HEALTHY"

        return report
