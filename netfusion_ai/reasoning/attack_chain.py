"""
ATRE Attack Chain Engine — NetFusion IL-9
==========================================
Reconstructs multi-stage attack chains mapped to MITRE ATT&CK, CAPEC, CWE, CVE, and graph evidence.
"""

from typing import Any, Dict, List
from netfusion_ai.reasoning.graph_reasoner import AttackChainBuilder
from netfusion_ai.reasoning.models import AttackChain, GraphEvidence


class AttackChainEngine:
    """
    Dedicated facade for attack chain reconstruction across all 11 ATT&CK tactical phases.
    """

    def __init__(self):
        self.builder = AttackChainBuilder()

    def reconstruct_attack_chain(
        self, evidence: List[GraphEvidence], expanded_subgraph: Dict[str, Any]
    ) -> AttackChain:
        return self.builder.build_chain(evidence, expanded_subgraph)
