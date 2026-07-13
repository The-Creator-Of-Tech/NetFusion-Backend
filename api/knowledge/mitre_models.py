"""
MITRE ATT&CK API Models — Phase A4.9.1
======================================
Immutable Pydantic models for MITRE ATT&CK API request and response contracts.

Design rules
------------
- All models are frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns.
- Response models are plain typed structures for FastAPI / OpenAPI schema generation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateTechniqueRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/mitre.
    """
    mitreId     : str
    name        : str
    tactic      : str
    description : Optional[str] = ""
    platforms   : Optional[List[str]] = Field(default_factory=list)
    detection   : Optional[str] = ""
    mitigations : Optional[List[str]] = Field(default_factory=list)
    references  : Optional[List[str]] = Field(default_factory=list)
    createdAt   : str
    severity    : Optional[str] = "MEDIUM"
    dataSource  : Optional[str] = ""
    revoked     : Optional[bool] = False
    deprecated  : Optional[bool] = False

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Validate request data on the API layer.
        """
        errors: List[str] = []
        if not self.mitreId or not self.mitreId.strip():
            errors.append("mitreId must not be empty.")
        elif not self.mitreId.strip().upper().startswith("T"):
            errors.append(f"mitreId='{self.mitreId}' must start with 'T' (ATT&CK ID pattern).")
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if not self.tactic or not self.tactic.strip():
            errors.append("tactic must not be empty.")
        else:
            from services.mitre_attack_service import TacticEnum
            try:
                # Validate enum member
                TacticEnum(self.tactic.strip().upper())
            except ValueError:
                errors.append(f"tactic must be a valid TacticEnum member; got {self.tactic!r}.")
        return errors


class UpdateTechniqueRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/mitre/{techniqueId}.
    """
    name        : Optional[str] = None
    tactic      : Optional[str] = None
    description : Optional[str] = None
    platforms   : Optional[List[str]] = None
    detection   : Optional[str] = None
    mitigations : Optional[List[str]] = None
    references  : Optional[List[str]] = None
    severity    : Optional[str] = None
    dataSource  : Optional[str] = None
    revoked     : Optional[bool] = None
    deprecated  : Optional[bool] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """
        Check if at least one field is provided.
        """
        return any(
            v is not None
            for k, v in self.model_dump().items()
        )

    def validate_request(self) -> List[str]:
        """
        Validate update fields.
        """
        errors: List[str] = []
        if self.tactic is not None:
            if not self.tactic.strip():
                errors.append("tactic must not be empty.")
            else:
                from services.mitre_attack_service import TacticEnum
                try:
                    TacticEnum(self.tactic.strip().upper())
                except ValueError:
                    errors.append(f"tactic must be a valid TacticEnum member; got {self.tactic!r}.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class TechniqueResponse(BaseModel):
    """
    Response model representing a single MITRE ATT&CK technique.
    """
    techniqueId  : str
    techniqueKey : str
    mitreId      : str
    name         : str
    tactic       : str
    description  : str
    platforms    : List[str]
    detection    : str
    mitigations  : List[str]
    references   : List[str]
    createdAt    : str
    severity     : str
    dataSource   : str
    revoked      : bool
    deprecated   : bool
    tacticCount  : int = 1

    class Config:
        frozen = True


class TechniqueListResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/mitre.
    """
    techniques : List[TechniqueResponse]
    total      : int

    class Config:
        frozen = True


class TechniqueStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/mitre/statistics.
    """
    totalTechniques     : int
    revokedTechniques     : int
    deprecatedTechniques  : int
    averageTactics        : float
    tacticCounts          : Dict[str, int]
    platformCounts        : Dict[str, int]

    class Config:
        frozen = True


class TechniqueSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/mitre/search.
    """
    techniques : List[TechniqueResponse]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int
    query      : str
    sortBy     : str
    sortOrder  : str

    class Config:
        frozen = True


class MitreTacticResponse(BaseModel):
    """
    Payload representing a tactic associated with a technique.
    """
    tactic      : str
    name        : str
    description : str
    order       : int = 0
    shortName   : Optional[str] = None

    class Config:
        frozen = True


class MitreMitigationResponse(BaseModel):
    """
    Payload representing a mitigation associated with a technique.
    """
    mitigation   : str
    mitigationId : str

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateTechniquesRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/mitre/bulk/create.
    """
    techniques : List[CreateTechniqueRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.techniques:
            errors.append("techniques list must not be empty.")
        for i, t in enumerate(self.techniques):
            sub = t.validate_request()
            for e in sub:
                errors.append(f"techniques[{i}]: {e}")
        return errors


class BulkUpdateTechniquesRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/mitre/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        techniqueId : str
        update      : UpdateTechniqueRequest

        class Config:
            frozen = True

    items : List[BulkUpdateItem] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.items:
            errors.append("items list must not be empty.")
        for i, item in enumerate(self.items):
            if not item.techniqueId or not item.techniqueId.strip():
                errors.append(f"items[{i}]: techniqueId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteTechniquesRequest(BaseModel):
    """
    Request body for DELETE /api/v2/knowledge/mitre/bulk/delete.
    """
    techniqueIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.techniqueIds:
            errors.append("techniqueIds list must not be empty.")
        for i, tid in enumerate(self.techniqueIds):
            if not tid or not tid.strip():
                errors.append(f"techniqueIds[{i}]: techniqueId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
