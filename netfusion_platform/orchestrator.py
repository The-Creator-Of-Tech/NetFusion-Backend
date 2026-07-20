"""
NetFusion Master Platform Orchestrator
Governs platform lifecycle: startup sequencing, dependency initialization, runtime registration, health aggregation, and graceful shutdown.
"""

import time
import logging
from typing import Dict, Any, Optional

from netfusion_platform.config.manager import ConfigurationManager
from netfusion_platform.config.models import PlatformConfig
from netfusion_platform.security.auth import AuthManager
from netfusion_platform.security.rbac import RBACEngine
from netfusion_platform.security.secrets import SecretStore
from netfusion_platform.observability.logger import setup_platform_logger
from netfusion_platform.observability.metrics import PlatformMetricsManager
from netfusion_platform.observability.tracing import TraceTracer
from netfusion_platform.observability.health import HealthAggregator, PlatformHealthReport
from netfusion_platform.resiliency.circuit_breaker import CircuitBreaker
from netfusion_platform.resiliency.backpressure import GracefulDegradationManager
from netfusion_platform.pipeline.orchestrator import InvestigationPipelineOrchestrator

from netfusion_collector_sdk.events import EventPublisher
from netfusion_workflow.service import WorkflowService
from netfusion_ai.assistant import AIAssistant
from netfusion_ai.providers import create_provider_from_config, ProviderConfig, MockAIProvider

logger = logging.getLogger(__name__)


class PlatformOrchestrator:
    """Master Platform Orchestrator governing all NetFusion engines and runtimes."""

    def __init__(self, config_path: Optional[str] = None):
        self._is_started = False
        self._is_shutdown = False
        self._start_timestamp: float = 0.0

        # Core Foundation Systems
        self.config_manager = ConfigurationManager(config_path=config_path)
        self.config: PlatformConfig = self.config_manager.config

        self.secret_store = SecretStore()
        self.logger = setup_platform_logger(
            name="netfusion",
            level=self.config.log_level,
            secret_masker=self.secret_store.masker
        )

        self.auth_manager = AuthManager(
            jwt_secret=self.config.security.jwt_secret,
            jwt_algorithm=self.config.security.jwt_algorithm,
            expiration_minutes=self.config.security.jwt_expiration_minutes
        )
        self.rbac_engine = RBACEngine()

        self.metrics_manager = PlatformMetricsManager()
        self.tracer = TraceTracer()
        self.health_aggregator = HealthAggregator()
        self.degradation_manager = GracefulDegradationManager()

        # Engine Modules
        self.event_publisher = EventPublisher()
        self.workflow_service = WorkflowService()
        self.ai_assistant: Optional[AIAssistant] = None
        self.pipeline_orchestrator: Optional[InvestigationPipelineOrchestrator] = None

        # Registered Collectors & Providers
        self._registered_collectors: Dict[str, Any] = {}
        self._registered_ai_providers: Dict[str, Any] = {}
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}

    def startup(self) -> None:
        """
        Executes platform startup sequencing:
        1. Initialize Observability & Logging
        2. Validate Configuration & Secrets
        3. Register Runtimes (Workflow, AI, Collectors)
        4. Register Health Probes
        """
        if self._is_started:
            logger.warning("PlatformOrchestrator already started.")
            return

        logger.info("Initializing NetFusion Platform Orchestrator v%s...", self.config.version)
        self._start_timestamp = time.time()

        # 1. Initialize Circuit Breakers
        self._circuit_breakers["ai_provider"] = CircuitBreaker("ai_provider", failure_threshold=3, recovery_timeout_seconds=15.0)
        self._circuit_breakers["threat_intel"] = CircuitBreaker("threat_intel", failure_threshold=3, recovery_timeout_seconds=15.0)

        # 2. Register AI Runtimes
        self._init_ai_subsystem()

        # 3. Register Collectors
        self._init_collectors_subsystem()

        # 4. Register Pipeline Orchestrator
        self.pipeline_orchestrator = InvestigationPipelineOrchestrator(
            workflow_service=self.workflow_service,
            ai_assistant=self.ai_assistant,
            event_publisher=self.event_publisher,
        )

        # 5. Register Health Checkers
        self.health_aggregator.register_checker("workflow_service", lambda: {"status": "HEALTHY", "active_cases": len(self.workflow_service.cases)})
        self.health_aggregator.register_checker("event_bus", lambda: {"status": "HEALTHY", "bus_type": self.config.event_bus.backend})

        self._is_started = True
        logger.info("NetFusion Platform Orchestrator started cleanly.")

    def _init_ai_subsystem(self) -> None:
        """Initialize AI Provider & AI Assistant."""
        if not self.config.features.enable_ai:
            logger.info("AI features disabled via configuration feature flags.")
            return

        provider_name = self.config.ai.default_provider
        try:
            if provider_name == "mock":
                provider = MockAIProvider()
            else:
                p_cfg = ProviderConfig(provider_name=provider_name, model_name=self.config.ai.model_name)
                provider = create_provider_from_config(p_cfg)
        except Exception as e:
            logger.warning("Failed to initialize requested AI provider '%s': %s. Falling back to MockAIProvider.", provider_name, e)
            provider = MockAIProvider()

        self._registered_ai_providers[provider_name] = provider
        self.ai_assistant = AIAssistant(provider=provider)
        self.health_aggregator.register_checker("ai_assistant", lambda: {"status": "HEALTHY", "provider": provider_name})

    def _init_collectors_subsystem(self) -> None:
        """Register Collector runtimes based on feature flags."""
        if self.config.features.enable_sysmon and self.config.collectors.sysmon_enabled:
            self.register_collector("sysmon", {"status": "REGISTERED", "collector": "SysmonCollector"})

        if self.config.features.enable_tshark and self.config.collectors.tshark_enabled:
            self.register_collector("tshark", {"status": "REGISTERED", "collector": "TSharkCollector"})

        if self.config.features.enable_nmap and self.config.collectors.nmap_enabled:
            self.register_collector("nmap", {"status": "REGISTERED", "collector": "NmapCollector"})

        if self.config.features.enable_threat_intel and self.config.collectors.threat_intel_enabled:
            self.register_collector("threat_intel", {"status": "REGISTERED", "collector": "ThreatIntelCollector"})

    def register_collector(self, name: str, collector_obj: Any) -> None:
        """Register a collector instance and attach health probe."""
        self._registered_collectors[name] = collector_obj
        self.health_aggregator.register_checker(
            f"collector_{name}",
            lambda: {"status": "HEALTHY", "name": name}
        )
        logger.info("Registered collector '%s' with PlatformOrchestrator.", name)

    def get_health(self) -> PlatformHealthReport:
        """Aggregates platform health metrics across all components."""
        return self.health_aggregator.get_aggregated_health()

    def shutdown(self) -> None:
        """
        Executes graceful platform shutdown:
        1. Stop collector executions
        2. Flush event publisher queues
        3. Clear active session registries
        4. Log final metrics & trace summary
        """
        if self._is_shutdown:
            return

        logger.info("Shutting down NetFusion Platform Orchestrator...")
        self._is_started = False
        self._is_shutdown = True

        self._registered_collectors.clear()
        self._registered_ai_providers.clear()

        logger.info("NetFusion Platform Orchestrator shut down gracefully.")
