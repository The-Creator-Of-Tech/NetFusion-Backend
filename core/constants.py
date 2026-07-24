"""Shared application constants."""

AI_MODEL_LIGHT = "llama-3.1-8b-instant"
AI_MODEL_HEAVY = "llama-3.3-70b-versatile"

DEFAULT_VENDOR = "Unknown"
DEFAULT_RISK_LEVEL = "LOW"

RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_LOW = "LOW"

RISK_SCORE_SSL = 30
RISK_SCORE_INSECURE_PROTOCOLS = 20
RISK_SCORE_DNS_THRESHOLD = 15
RISK_SCORE_HIGH_TRAFFIC = 10
DNS_PACKET_THRESHOLD = 50
HIGH_TRAFFIC_PACKET_THRESHOLD = 100

INSECURE_PROTOCOLS = ("FTP", "TELNET", "SMB", "HTTP")
HIGH_RISK_PROTOCOLS = ("TELNET", "FTP", "SMB")
LEGACY_SSL_PROTOCOL = "SSL"
DNS_PROTOCOL = "DNS"

RISK_HOST_SCORE_HIGH = 60
RISK_HOST_SCORE_MEDIUM = 30

OUI_VENDOR_MAP = {
    "00:1A:2B": "Dell",
    "00:1C:B3": "Apple",
    "00:1E:C2": "Samsung",
    "00:1B:21": "Cisco",
    "00:1B:63": "Cisco",
    "00:14:22": "HP",
    "00:1B:44": "Intel",
    "00:0C:29": "VMware",
    "00:16:3E": "Xen",
    "00:50:56": "VMware",
    "00:15:5D": "Microsoft",
    "28:6C:07": "Apple",
    "3C:07:54": "Apple",
    "F8:1A:67": "Dell",
}

CLOUD_PROVIDER_KEYWORDS = (
    "azure",
    "microsoft",
    "amazon",
    "aws",
    "google",
    "oracle",
    "digitalocean",
    "linode",
)

CDN_KEYWORDS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cdn77",
)

IDENTITY_CONFIDENCE = {
    "manual": 100,
    "dhcp_hostname": 95,
    "bootp_hostname": 92,
    "http_host": 85,
    "nbns_name": 80,
    "nbns_netbios_name": 80,
    "mdns_name": 75,
    "dns_ptr": 72,
    "nmap_name": 70,
    "llmnr_name": 70,
    "reverse_dns": 65,
    "dns_query": 60,
}

HOSTNAME_IDENTITY_SOURCES = (
    "dhcp_hostname",
    "bootp_hostname",
    "nbns_name",
    "nbns_netbios_name",
    "mdns_name",
    "llmnr_name",
    "reverse_dns",
    "dns_query",
)

# ---------------------------------------------------------------------------
# Phase A.2.2.2 — Identity Confidence Engine constants
# ---------------------------------------------------------------------------

# Base confidence score assigned to each signal SOURCE TYPE.
# These are the authoritative values used by identity_confidence_service.py.
# Do NOT hardcode these values in any service — always import from here.
#
# Semantics: how much do we trust that a value from this source is CORRECT
# and uniquely identifies the asset?  Scale: 0–100.
SIGNAL_SOURCE_CONFIDENCE: dict = {
    "manual":        100,  # analyst-entered override — absolute authority
    "mac_frame":     100,  # Ethernet MAC observed directly in a frame
    "dhcp":          100,  # DHCP hostname/option — device self-declares
    "arp":           100,  # ARP — MAC/IP binding observed at layer-2
    "mdns":           95,  # mDNS / Bonjour — device self-announces
    "dns_ptr":        90,  # Reverse DNS PTR record
    "nmap":           85,  # Nmap active scan result
    "nbns":           80,  # NetBIOS Name Service
    "http_host":      75,  # HTTP Host header
    "tls_sni":        75,  # TLS SNI field
    "user_agent":     70,  # HTTP User-Agent string
    "llmnr":          70,  # Link-Local Multicast Name Resolution
    "dns_query":      60,  # DNS query (querier, not answerer)
    "pcap":           60,  # Generic pcap observation (IP/MAC seen in frame)
    "inference":      50,  # Derived / computed value (no direct observation)
    "unknown":         0,  # Source is unknown or unclassified
}

# Map SourceType enum values (from identity_signal_service) → base confidence.
# Keys match SourceType.value strings so no import cycle is needed.
SOURCE_TYPE_CONFIDENCE: dict = {
    "manual":    SIGNAL_SOURCE_CONFIDENCE["manual"],
    "pcap":      SIGNAL_SOURCE_CONFIDENCE["pcap"],
    "dhcp":      SIGNAL_SOURCE_CONFIDENCE["dhcp"],
    "arp":       SIGNAL_SOURCE_CONFIDENCE["arp"],
    "mdns":      SIGNAL_SOURCE_CONFIDENCE["mdns"],
    "dns":       SIGNAL_SOURCE_CONFIDENCE["dns_ptr"],
    "nbns":      SIGNAL_SOURCE_CONFIDENCE["nbns"],
    "llmnr":     SIGNAL_SOURCE_CONFIDENCE["llmnr"],
    "nmap":      SIGNAL_SOURCE_CONFIDENCE["nmap"],
    "zeek":      SIGNAL_SOURCE_CONFIDENCE["inference"],
    "sysmon":    SIGNAL_SOURCE_CONFIDENCE["inference"],
    "suricata":  SIGNAL_SOURCE_CONFIDENCE["inference"],
    "windows":   SIGNAL_SOURCE_CONFIDENCE["inference"],
}

# Multi-source agreement bonus.
# When N independent sources agree on the same value, add this many points
# per additional confirming source (capped at MAX_AGREEMENT_BONUS).
CONFIDENCE_AGREEMENT_BONUS_PER_SOURCE: int = 5
CONFIDENCE_AGREEMENT_MAX_BONUS:        int = 15   # hard cap regardless of N

# Conflict penalty applied per conflicting value when sources disagree.
CONFIDENCE_CONFLICT_PENALTY: int = 20

# Overall confidence → ConfidenceLevel thresholds (inclusive lower bounds).
CONFIDENCE_LEVEL_THRESHOLDS: dict = {
    "VERIFIED":   100,
    "VERY_HIGH":   90,
    "HIGH":        75,
    "MEDIUM":      55,
    "LOW":         35,
    "WEAK":        15,
    "UNKNOWN":      0,
}

# Engine version — bump this whenever the confidence algorithm changes.
# Stored in IdentityConfidence.metadata so old evidence can be re-evaluated.
IDENTITY_CONFIDENCE_ENGINE_VERSION: str = "identity-confidence-v1"

# ---------------------------------------------------------------------------
# Phase A.2.2.3 — Identity Resolution Engine constants
# ---------------------------------------------------------------------------

# Per-field match weights used by the Resolution Engine.
# Higher weight = field match contributes more to a candidate's total score.
# Do NOT hardcode these in any service — always import from here.
#
# Scale: 0–100 (raw points added per matching field).
# A candidate's total score is the SUM of weights for all matched fields,
# normalised to 0–100 by dividing by RESOLUTION_MAX_POSSIBLE_SCORE.
RESOLUTION_FIELD_WEIGHTS: dict = {
    "macAddress"      : 100,  # exact hardware match — highest priority
    "hostname"        : 80,   # device self-declared name
    "currentIp"       : 70,   # IP currently assigned to asset
    "previousIp"      : 40,   # IP previously seen on asset (rotated)
    "ssid"            : 20,   # WiFi SSID association
    "vendor"          : 15,   # OUI-resolved hardware vendor
    "operatingSystem" : 15,   # OS fingerprint
}

# Sum of all possible weights — used to normalise total score to 0–100.
RESOLUTION_MAX_POSSIBLE_SCORE: int = sum(RESOLUTION_FIELD_WEIGHTS.values())

# Score thresholds that map a candidate's normalised score → DecisionLevel.
# Inclusive lower bounds (score >= threshold → that level).
#
# Calibration note: RESOLUTION_MAX_POSSIBLE_SCORE is the sum of ALL field
# weights (MAC+hostname+IP+prevIP+SSID+vendor+OS = 355).  In practice, pcap
# data rarely provides all seven fields simultaneously. Thresholds are set
# against realistic multi-field combinations:
#   MAC alone           = 100/355 = 28%
#   MAC + hostname      = 180/355 = 51%
#   MAC + hostname + IP = 250/355 = 70%
#   MAC + hn + IP + v   = 265/355 = 75%
#   All fields present  = 355/355 = 100%
RESOLUTION_DECISION_THRESHOLDS: dict = {
    "MATCH"          : 70,   # MAC + hostname + IP or equivalent strong set
    "LIKELY_MATCH"   : 45,   # MAC + hostname, or hostname + IP
    "POSSIBLE_MATCH" : 25,   # MAC alone, or hostname alone
    "MANUAL_REVIEW"  : 10,   # weak signal, ambiguous candidates
    "CREATE_NEW"     :  0,   # no plausible match
}

# Engine version — bump when algorithm changes.
IDENTITY_RESOLUTION_ENGINE_VERSION: str = "identity-resolution-v1"

# ---------------------------------------------------------------------------
# Phase A.2.2.6 — Evidence Engine constants
# ---------------------------------------------------------------------------

# Schema version for EvidenceRecord.
# Bump when the field set of EvidenceRecord changes in a breaking way.
EVIDENCE_SCHEMA_VERSION: str = "1.0"

# Engine version for the Evidence Service.
# Bump when builder logic changes.
EVIDENCE_ENGINE_VERSION: str = "evidence-engine-v1"

# ---------------------------------------------------------------------------
# Phase A.2.2.6.3 — Evidence History Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Evidence History Service.
# Bump when history builder logic changes.
HISTORY_ENGINE_VERSION: str = "history-engine-v1"

# ---------------------------------------------------------------------------
# Phase A.3.1 — Relationship Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Relationship Service.
# Bump when relationship builder logic changes.
RELATIONSHIP_ENGINE_VERSION: str = "relationship-engine-v1"

# Base confidence score contributed per observed packet for a relationship.
# Caps at RELATIONSHIP_MAX_PACKET_CONFIDENCE regardless of packet count.
RELATIONSHIP_CONFIDENCE_PER_PACKET: int = 1
RELATIONSHIP_MAX_PACKET_CONFIDENCE: int = 40   # 40 pts max from packet volume

# Per-protocol confidence bonus — reward for well-known, structured protocols.
RELATIONSHIP_PROTOCOL_BONUS: dict = {
    "DNS"   : 15,
    "DHCP"  : 20,
    "ARP"   : 20,
    "HTTP"  : 10,
    "HTTPS" : 15,
    "TLS"   : 15,
    "SSH"   : 15,
    "SMB"   : 10,
    "RDP"   : 10,
    "FTP"   : 10,
    "ICMP"  : 5,
}

# Bonus per linked EvidenceRecord (caps at RELATIONSHIP_MAX_EVIDENCE_BONUS).
RELATIONSHIP_EVIDENCE_BONUS_PER_RECORD: int = 5
RELATIONSHIP_MAX_EVIDENCE_BONUS: int = 20

# ---------------------------------------------------------------------------
# Phase A.3.1 — Relationship History Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Relationship History Service.
# Bump when history builder logic changes.
RELATIONSHIP_HISTORY_ENGINE_VERSION: str = "relationship-history-engine-v1"

# Known changeReason values — used by builders and validated downstream.
# AI Copilot uses these as explanations; keep them stable across versions.
RELATIONSHIP_CHANGE_REASON_NEW_PACKET    : str = "New packet observed"
RELATIONSHIP_CHANGE_REASON_NEW_EVIDENCE  : str = "New evidence linked"
RELATIONSHIP_CHANGE_REASON_RECALCULATED  : str = "Confidence recalculated"
RELATIONSHIP_CHANGE_REASON_MERGED        : str = "Relationship merged"
RELATIONSHIP_CHANGE_REASON_ANALYST       : str = "Manual analyst update"
RELATIONSHIP_CHANGE_REASON_STATE_CHANGE  : str = "State transition"
RELATIONSHIP_CHANGE_REASON_INITIAL       : str = "Initial relationship creation"

# ---------------------------------------------------------------------------
# Phase A4.0.1 — Attack Graph Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Attack Graph Service.
# Bump when graph builder logic or model schema changes.
ATTACK_GRAPH_ENGINE_VERSION: str = "attack-graph-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.2 — Attack Graph Query Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Attack Graph Query Service.
# Bump when query logic, traversal algorithms, or model schema changes.
ATTACK_GRAPH_QUERY_ENGINE_VERSION: str = "attack-graph-query-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.4 — Attack Graph Intelligence Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Attack Graph Intelligence Service.
# Bump when intelligence algorithms, pattern detection rules, or model schema changes.
ATTACK_GRAPH_INTELLIGENCE_ENGINE_VERSION: str = "attack-graph-intelligence-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.5 — Timeline Intelligence Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Timeline Intelligence Service.
# Bump when event builders, sorting logic, or model schema changes.
TIMELINE_INTELLIGENCE_ENGINE_VERSION: str = "timeline-intelligence-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.6 — Investigation Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Investigation Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
INVESTIGATION_ENGINE_VERSION: str = "investigation-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.7 — Findings Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Finding Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
FINDING_ENGINE_VERSION: str = "finding-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.8 — Alert Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Alert Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
ALERT_ENGINE_VERSION: str = "alert-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.0.9 — MITRE ATT&CK Engine constants
# ---------------------------------------------------------------------------

# Engine version for the MITRE Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
MITRE_ENGINE_VERSION: str = "mitre-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.1.0 — AI Copilot Context Engine constants
# ---------------------------------------------------------------------------

# Engine version for the AI Context Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
AI_COPILOT_CONTEXT_ENGINE_VERSION: str = "ai-context-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.1.1 — Reasoning Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Reasoning Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
REASONING_ENGINE_VERSION: str = "reasoning-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.1.2 — Prompt Assembly Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Prompt Assembly Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
PROMPT_ASSEMBLY_ENGINE_VERSION: str = "prompt-assembly-v1"

# ---------------------------------------------------------------------------
# Phase A4.1.3 — Investigation Narrative Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Investigation Narrative Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
INVESTIGATION_NARRATIVE_ENGINE_VERSION: str = "investigation-narrative-v1"

# ---------------------------------------------------------------------------
# Phase A4.1.4 — Copilot Orchestrator Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Copilot Orchestrator Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
COPILOT_ORCHESTRATOR_ENGINE_VERSION: str = "copilot-orchestrator-v1"

# ---------------------------------------------------------------------------
# Phase A4.2.3 — Tool Calling Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Tool Calling Service.
TOOL_CALLING_ENGINE_VERSION: str = "tool-calling-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.2.2 — Groq Streaming Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Groq Streaming Service.
GROQ_STREAMING_ENGINE_VERSION: str = "groq-streaming-v1"

# ---------------------------------------------------------------------------
# Phase A4.2.1 — Groq HTTP Client Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Groq HTTP Client.
GROQ_HTTP_CLIENT_ENGINE_VERSION: str = "groq-http-client-v1"

# Default HTTP timeout (seconds)
GROQ_HTTP_DEFAULT_TIMEOUT_SECONDS: int = 60

# Default max retries
GROQ_HTTP_DEFAULT_MAX_RETRIES: int = 3

# Default retry delay (milliseconds)
GROQ_HTTP_DEFAULT_RETRY_DELAY_MS: int = 1000

# HTTP status codes that are retryable
GROQ_HTTP_RETRYABLE_STATUS_CODES: tuple = (429, 500, 502, 503, 504)

# HTTP status codes that must NOT be retried
GROQ_HTTP_NON_RETRYABLE_STATUS_CODES: tuple = (400, 401, 403, 404)

# Default User-Agent header value
GROQ_HTTP_DEFAULT_USER_AGENT: str = "NetFusion-Agent/2.0 groq-http-client-v1"

# ---------------------------------------------------------------------------
# Phase A4.3.0 — Provider Registry Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Provider Registry Service.
PROVIDER_REGISTRY_ENGINE_VERSION: str = "provider-registry-v1"

# ---------------------------------------------------------------------------
# Phase A4.3.1 — AI Execution Engine constants
# ---------------------------------------------------------------------------

# Engine version for the AI Execution Service.
AI_EXECUTION_ENGINE_VERSION: str = "ai-execution-v1"

# ---------------------------------------------------------------------------
# Phase A4.4.0 — Conversation Manager Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Conversation Manager Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
CONVERSATION_MANAGER_ENGINE_VERSION: str = "conversation-manager-v1"

# Content-Type header value for Groq requests
GROQ_HTTP_CONTENT_TYPE: str = "application/json"

# Accept header value
GROQ_HTTP_ACCEPT: str = "application/json"

# ---------------------------------------------------------------------------
# Phase A4.1.5 — Groq Provider Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Groq Provider Service.
GROQ_PROVIDER_ENGINE_VERSION: str = "groq-provider-v1"

# Groq API version and endpoint
GROQ_API_VERSION:  str = "2024-01-01"
GROQ_API_ENDPOINT: str = "https://api.groq.com/openai/v1/chat/completions"

# Supported Groq models — canonical lowercase names
GROQ_SUPPORTED_MODELS: tuple = (
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "openai/gpt-oss-120b",
)

# Model alias normalisation map  alias → canonical
GROQ_MODEL_ALIASES: dict = {
    "llama3.3-70b":          "llama-3.3-70b-versatile",
    "llama-3.3-70b":         "llama-3.3-70b-versatile",
    "llama3-70b-versatile":  "llama-3.3-70b-versatile",
    "llama3.1-8b":           "llama-3.1-8b-instant",
    "llama-3.1-8b":          "llama-3.1-8b-instant",
    "llama3-8b-instant":     "llama-3.1-8b-instant",
    "gpt-oss-120b":          "openai/gpt-oss-120b",
    "openai-gpt-oss-120b":   "openai/gpt-oss-120b",
}

# Per-model capabilities
GROQ_MODEL_CAPABILITIES: dict = {
    "llama-3.3-70b-versatile": {
        "supportsStreaming": True,
        "supportsTools":     True,
        "supportsJsonMode":  True,
        "maxTokens":         8192,
    },
    "llama-3.1-8b-instant": {
        "supportsStreaming": True,
        "supportsTools":     True,
        "supportsJsonMode":  True,
        "maxTokens":         8192,
    },
    "openai/gpt-oss-120b": {
        "supportsStreaming": True,
        "supportsTools":     True,
        "supportsJsonMode":  True,
        "maxTokens":         8192,
    },
}

# Pricing: cost per 1 million tokens (USD) — prompt / completion
# Configurable; update when Groq changes pricing.
GROQ_PRICING_PER_MILLION: dict = {
    "llama-3.3-70b-versatile": {"prompt": 0.59,  "completion": 0.79},
    "llama-3.1-8b-instant":    {"prompt": 0.05,  "completion": 0.08},
    "openai/gpt-oss-120b":     {"prompt": 5.00,  "completion": 15.00},
}

# Valid message roles
GROQ_VALID_ROLES: tuple = ("system", "user", "assistant", "tool")

# Temperature bounds
GROQ_TEMPERATURE_MIN: float = 0.0
GROQ_TEMPERATURE_MAX: float = 2.0

# top_p bounds
GROQ_TOP_P_MIN: float = 0.0
GROQ_TOP_P_MAX: float = 1.0

# Max tokens bounds
GROQ_MAX_TOKENS_MIN: int = 1
GROQ_MAX_TOKENS_MAX: int = 131072

# ---------------------------------------------------------------------------
# Phase A4.5.0 — Session Memory Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Session Memory Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
SESSION_MEMORY_ENGINE_VERSION: str = "session-memory-v1"

# ---------------------------------------------------------------------------
# Phase A4.5.1 — Context Window Manager Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Context Window Manager Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
CONTEXT_WINDOW_ENGINE_VERSION: str = "context-window-v1"

# ---------------------------------------------------------------------------
# Phase A4.5.2 — Token Budget Manager Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Token Budget Manager Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
TOKEN_BUDGET_ENGINE_VERSION: str = "token-budget-v1"

# ---------------------------------------------------------------------------
# Phase A4.5.3 — Retry & Failover Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Retry & Failover Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
RETRY_FAILOVER_ENGINE_VERSION: str = "retry-failover-v1"

# ---------------------------------------------------------------------------
# Phase A4.3.6 — Chat Runtime Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Chat Runtime Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
CHAT_RUNTIME_ENGINE_VERSION: str = "chat-runtime-v1"

# ---------------------------------------------------------------------------
# Phase A4.3.7 — MITRE ATT&CK Attack Service constants
# ---------------------------------------------------------------------------

# Engine version for the MITRE ATT&CK Attack Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
MITRE_ATTACK_ENGINE_VERSION: str = "mitre-attack-v1"

# ---------------------------------------------------------------------------
# Phase A4.3.8 — CVE Intelligence Engine constants
# ---------------------------------------------------------------------------

# Engine version for the CVE Intelligence Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
CVE_INTELLIGENCE_ENGINE_VERSION: str = "cve-intelligence-v1"

# ---------------------------------------------------------------------------
# Phase A4.4.3 — IOC Intelligence Engine constants
# ---------------------------------------------------------------------------

# Engine version for the IOC Intelligence Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
IOC_INTELLIGENCE_ENGINE_VERSION: str = "ioc-intelligence-v1"

# ---------------------------------------------------------------------------
# Phase A4.4.4 — Threat Intelligence Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Threat Intelligence Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
THREAT_INTELLIGENCE_ENGINE_VERSION: str = "threat-intelligence-v1"

# ---------------------------------------------------------------------------
# Phase A4.4.5 — Playbook Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Playbook Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
PLAYBOOK_ENGINE_VERSION: str = "playbook-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.5.1 — Rules Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Rules Engine Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
RULES_ENGINE_VERSION: str = "rules-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.5.2 — Automation Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Automation Engine Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
AUTOMATION_ENGINE_VERSION: str = "automation-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.5.3 — Case Flow Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Case Flow Engine Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
CASE_FLOW_ENGINE_VERSION: str = "case-flow-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.6.1 — Report Engine constants
# ---------------------------------------------------------------------------

# Engine version for the Report Engine Service.
# Bump when builder logic, model schema, or fingerprint algorithm changes.
REPORT_ENGINE_VERSION: str = "report-engine-v1"

# ---------------------------------------------------------------------------
# Phase A4.7.1 — API Layer constants
# ---------------------------------------------------------------------------

# Version for the API layer.
# Bump when the API contract, response shapes, or error codes change.
API_LAYER_VERSION: str = "api-layer-v1"

# ---------------------------------------------------------------------------
# IL-8 — Unified Threat Knowledge Graph constants
# ---------------------------------------------------------------------------

# Engine version — bump when graph algorithms, node/edge schema, or fusion
# logic changes in a breaking way.
UTKG_ENGINE_VERSION: str = "utkg-engine-v1"

# Default max traversal depth for BFS/DFS operations.
UTKG_DEFAULT_MAX_DEPTH: int = 3

# Default node limit for traversal / subgraph queries.
UTKG_DEFAULT_NODE_LIMIT: int = 500

# Confidence decay factor applied per hop during confidence propagation.
UTKG_CONFIDENCE_DECAY: float = 0.8

# Maximum number of nodes used for statistics sample (degree dist, APL, etc.)
UTKG_STATS_SAMPLE_SIZE: int = 5000

# Maximum cached path entries retained in the path table.
UTKG_PATH_CACHE_LIMIT: int = 10000
