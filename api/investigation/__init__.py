"""
Investigation API — Phase A4.7.2+
==================================
Sub-package that exposes the Asset, Evidence, Attack Graph, Finding,
and Alert Engines through a REST interface.

Routers
-------
asset_router         — GET/POST/PUT/DELETE /api/v2/assets
evidence_router      — GET/POST/PUT/DELETE /api/v2/evidence
attack_graph_router  — GET/POST/PUT/DELETE /api/v2/attack-graph
finding_router       — GET/POST/PUT/DELETE /api/v2/findings
alert_router         — GET/POST/PUT/DELETE /api/v2/alerts

This package contains only API orchestration.  All business logic lives
in services.  Nothing here duplicates service logic.
"""

from api.investigation.alert_router import alert_router
from api.investigation.asset_router import asset_router
from api.investigation.attack_graph_router import attack_graph_router
from api.investigation.evidence_router import evidence_router
from api.investigation.finding_router import finding_router

__all__ = ["alert_router", "asset_router", "evidence_router", "attack_graph_router", "finding_router"]
