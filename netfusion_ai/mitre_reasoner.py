"""
NetFusion MITRE Reasoner Engine
Infers MITRE ATT&CK:
- Techniques (Txxxx)
- Sub-techniques (Txxxx.xxx)
- Tactics (Reconnaissance to Impact)
- Kill Chain Progression
- Confidence & Supporting Evidence
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.domain import MITREInference, EvidenceReference
from netfusion_ai.enums import TacticalPhase, ConfidenceLevel
from netfusion_ai.context_builder import InvestigationContextContainer


KILL_CHAIN_STAGES: Dict[TacticalPhase, int] = {
    TacticalPhase.RECONNAISSANCE: 1,
    TacticalPhase.RESOURCE_DEVELOPMENT: 1,
    TacticalPhase.INITIAL_ACCESS: 2,
    TacticalPhase.EXECUTION: 3,
    TacticalPhase.PERSISTENCE: 4,
    TacticalPhase.PRIVILEGE_ESCALATION: 4,
    TacticalPhase.DEFENSE_EVASION: 5,
    TacticalPhase.CREDENTIAL_ACCESS: 5,
    TacticalPhase.DISCOVERY: 5,
    TacticalPhase.LATERAL_MOVEMENT: 6,
    TacticalPhase.COLLECTION: 6,
    TacticalPhase.COMMAND_AND_CONTROL: 6,
    TacticalPhase.EXFILTRATION: 7,
    TacticalPhase.IMPACT: 7,
}


KNOWN_TACTICAL_MAP = [
    {
        "keywords": ["nmap", "scan", "port scan", "syn scan", "recon"],
        "tactic": TacticalPhase.RECONNAISSANCE,
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "sub_technique_id": "T1595.002",
        "sub_technique_name": "Vulnerability Scanning",
    },
    {
        "keywords": ["phishing", "spearphishing", "email attachment", "malicious attachment"],
        "tactic": TacticalPhase.INITIAL_ACCESS,
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "sub_technique_id": "T1566.001",
        "sub_technique_name": "Spearphishing Attachment",
    },
    {
        "keywords": ["powershell", "cmd.exe", "wmic", "execution", "sysmon eventid 1"],
        "tactic": TacticalPhase.EXECUTION,
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "sub_technique_id": "T1059.001",
        "sub_technique_name": "PowerShell",
    },
    {
        "keywords": ["registry", "run key", "startup", "scheduled task", "service creation"],
        "tactic": TacticalPhase.PERSISTENCE,
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "sub_technique_id": "T1053.005",
        "sub_technique_name": "Scheduled Task",
    },
    {
        "keywords": ["lsass", "mimikatz", "dump credentials", "sam hive", "hashdump"],
        "tactic": TacticalPhase.CREDENTIAL_ACCESS,
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "sub_technique_id": "T1003.001",
        "sub_technique_name": "LSASS Memory",
    },
    {
        "keywords": ["pssexec", "smb", "winrm", "rdp", "lateral movement", "tshark flow"],
        "tactic": TacticalPhase.LATERAL_MOVEMENT,
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "sub_technique_id": "T1021.002",
        "sub_technique_name": "SMB/Windows Admin Shares",
    },
    {
        "keywords": ["c2", "beacon", "dns tunnel", "http request", "cobalt strike"],
        "tactic": TacticalPhase.COMMAND_AND_CONTROL,
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "sub_technique_id": "T1071.001",
        "sub_technique_name": "Web Protocols",
    },
]


class MITREReasoner:
    """Reasoning engine inferring MITRE ATT&CK tactics and techniques."""

    def infer_mitre_tactics(
        self, context: InvestigationContextContainer
    ) -> List[MITREInference]:
        """Analyzes investigation context to infer ATT&CK mappings."""
        inferences: List[MITREInference] = []
        context_text = str(context.to_dict()).lower()

        # Match against known tactical map
        for entry in KNOWN_TACTICAL_MAP:
            matched_kw = [kw for kw in entry["keywords"] if kw in context_text]
            if matched_kw:
                tactic = entry["tactic"]
                stage = KILL_CHAIN_STAGES.get(tactic, 3)

                evidence_ref = EvidenceReference(
                    evidence_id="mitre-telemetry-match",
                    source_type="context_analysis",
                    summary=f"Matched telemetry keywords: {matched_kw}",
                    relevance_score=0.85,
                )

                inference = MITREInference(
                    tactic=tactic,
                    technique_id=entry["technique_id"],
                    technique_name=entry["technique_name"],
                    sub_technique_id=entry.get("sub_technique_id"),
                    sub_technique_name=entry.get("sub_technique_name"),
                    kill_chain_progression_stage=stage,
                    confidence=ConfidenceLevel.HIGH if len(matched_kw) > 1 else ConfidenceLevel.MEDIUM,
                    confidence_score=0.85 if len(matched_kw) > 1 else 0.65,
                    supporting_evidence=[evidence_ref],
                    description=f"Inferred {entry['technique_name']} under {tactic.value} phase based on observed telemetry.",
                )
                inferences.append(inference)

        # Include explicit workflow MITRE mappings if present
        for m in context.mitre_mappings:
            inf = MITREInference(
                tactic=TacticalPhase.EXECUTION,
                technique_id=m.get("technique_id", "T1059"),
                technique_name=m.get("technique_name", "Inferred Technique"),
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                description="Explicit workflow MITRE mapping.",
            )
            inferences.append(inf)

        # Fallback if no matching keywords found
        if not inferences:
            inferences.append(
                MITREInference(
                    tactic=TacticalPhase.INITIAL_ACCESS,
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    kill_chain_progression_stage=2,
                    confidence=ConfidenceLevel.LOW,
                    confidence_score=0.40,
                    description="Default baseline initial access technique inference.",
                )
            )

        return inferences
