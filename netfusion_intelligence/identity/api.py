"""
FastAPI REST API Routes for NetFusion CIIL (Canonical Intelligence Identity Layer).
Exposes REST endpoints for identity resolution, lookup, search, relationships, provenance, and statistics.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Path, Body
from pydantic import BaseModel, Field

from netfusion_intelligence.identity.models import ExternalIdentifier
from netfusion_intelligence.identity.service import IdentityService

# Global singleton or dependency instance for identity service
_identity_service_instance: Optional[IdentityService] = None


def set_identity_service(service: IdentityService) -> None:
    global _identity_service_instance
    _identity_service_instance = service


def get_identity_service() -> IdentityService:
    global _identity_service_instance
    if _identity_service_instance is None:
        _identity_service_instance = IdentityService()
    return _identity_service_instance


router = APIRouter(prefix="/intelligence/identity", tags=["Identity Subsystem"])


class ResolveRequest(BaseModel):
    entity_type: str = Field(..., description="Canonical entity type, e.g. ATTACK_TECHNIQUE, CVE, MALWARE")
    display_name: str = Field(..., description="Display name for entity")
    external_identifiers: List[Dict[str, Any]] = Field(default_factory=list, description="External identifiers list")
    aliases: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    feed_source: str = "REST_API"
    dataset_version: str = "1.0"
    original_object_id: Optional[str] = None
    confidence: float = 1.0


class MergeRequest(BaseModel):
    primary_uuid: str = Field(..., description="Target primary canonical UUID")
    secondary_uuid: str = Field(..., description="Secondary canonical UUID to be merged and deactivated")
    reason: str = "Manual API request"


@router.get("/statistics")
def get_identity_statistics() -> Dict[str, Any]:
    """
    GET /intelligence/identity/statistics
    Get overall Canonical Identity statistics and source coverage metrics.
    """
    service = get_identity_service()
    stats = service.get_statistics()
    return {"status": "success", "statistics": stats.to_dict()}


@router.get("/search")
def search_identities(
    q: Optional[str] = Query(None, description="Search query string"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type"),
    source: Optional[str] = Query(None, description="Filter by feed source"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/identity/search
    Search canonical entities by keyword query, type, or feed source.
    """
    service = get_identity_service()
    results = service.search(query=q, entity_type=entity_type, feed_source=source, limit=limit)
    return {
        "status": "success",
        "count": len(results),
        "entities": [e.to_dict() for e in results],
    }


@router.get("/external/{source}/{id:path}")
def get_by_external_id(
    source: str = Path(..., description="External source name (e.g., MITRE, NVD)"),
    id: str = Path(..., description="External identifier value"),
) -> Dict[str, Any]:
    """
    GET /intelligence/identity/external/{source}/{id}
    Look up canonical entities matching an external identifier.
    """
    service = get_identity_service()
    entities = service.find_by_external_id(source=source, identifier=id)
    if not entities:
        raise HTTPException(status_code=404, detail=f"No entity found for external identifier '{source}:{id}'")
    return {
        "status": "success",
        "count": len(entities),
        "entities": [e.to_dict() for e in entities],
    }


@router.get("/relationships/{uuid}")
def get_entity_relationships(
    uuid: str = Path(..., description="Canonical UUID"),
    direction: str = Query("both", description="'source', 'target', or 'both'"),
    relationship_type: Optional[str] = Query(None, description="Filter relationship type"),
) -> Dict[str, Any]:
    """
    GET /intelligence/identity/relationships/{uuid}
    Get relationships for a canonical entity.
    """
    service = get_identity_service()
    rel_list = service.list_relationships(canonical_uuid=uuid, direction=direction, relationship_type=relationship_type)
    return {
        "status": "success",
        "canonical_uuid": uuid,
        "count": len(rel_list),
        "relationships": [r.to_dict() for r in rel_list],
    }


@router.get("/provenance/{uuid}")
def get_entity_provenance(
    uuid: str = Path(..., description="Canonical UUID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/identity/provenance/{uuid}
    Get provenance history for a canonical entity.
    """
    service = get_identity_service()
    prov_list = service.get_provenance(canonical_uuid=uuid)
    return {
        "status": "success",
        "canonical_uuid": uuid,
        "count": len(prov_list),
        "provenance": [p.to_dict() for p in prov_list],
    }


@router.get("/{uuid}")
def get_identity_by_uuid(
    uuid: str = Path(..., description="Canonical entity UUID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/identity/{uuid}
    Get canonical entity details by UUID.
    """
    service = get_identity_service()
    entity = service.find_by_uuid(uuid)
    if not entity:
        raise HTTPException(status_code=404, detail=f"Canonical entity not found: {uuid}")
    return {"status": "success", "entity": entity.to_dict()}


@router.post("/resolve")
def resolve_identity(req: ResolveRequest) -> Dict[str, Any]:
    """
    POST /intelligence/identity/resolve
    Resolve or create a canonical entity.
    """
    service = get_identity_service()

    ext_ids = [
        ExternalIdentifier.from_dict(item) if isinstance(item, dict) else item
        for item in req.external_identifiers
    ]

    entity = service.resolve_entity(
        entity_type=req.entity_type,
        display_name=req.display_name,
        external_identifiers=ext_ids,
        aliases=req.aliases,
        description=req.description,
        tags=req.tags,
        metadata=req.metadata,
        feed_source=req.feed_source,
        dataset_version=req.dataset_version,
        original_object_id=req.original_object_id,
        confidence=req.confidence,
    )
    return {"status": "success", "entity": entity.to_dict()}


@router.post("/merge")
def merge_identity(req: MergeRequest) -> Dict[str, Any]:
    """
    POST /intelligence/identity/merge
    Merge two canonical entities into one.
    """
    service = get_identity_service()
    try:
        merged_entity = service.merge_entity(
            primary_uuid=req.primary_uuid,
            secondary_uuid=req.secondary_uuid,
            reason=req.reason,
        )
        return {"status": "success", "entity": merged_entity.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
