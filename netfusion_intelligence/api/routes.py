"""
FastAPI Management Endpoints for netfusion_intelligence.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Path

from netfusion_intelligence.core.engine import IntelligenceEngine
from netfusion_intelligence.core.exceptions import FeedNotFoundError, IntelligenceException

# Global singleton or injected engine instance
_engine_instance: Optional[IntelligenceEngine] = None


def set_intelligence_engine(engine: IntelligenceEngine) -> None:
    global _engine_instance
    _engine_instance = engine


def get_intelligence_engine() -> IntelligenceEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = IntelligenceEngine()
    return _engine_instance


router = APIRouter(prefix="/intelligence", tags=["Intelligence Subsystem"])


@router.get("/feeds")
def list_feeds() -> Dict[str, Any]:
    """
    GET /intelligence/feeds
    List all registered intelligence feeds, their configs, and declared manifests.
    """
    engine = get_intelligence_engine()
    feeds = engine.list_feeds()
    return {
        "status": "success",
        "count": len(feeds),
        "feeds": [
            {
                "feed_id": f.feed_id,
                "name": f.feed_name,
                "description": f.description,
                "enabled": f.config.enabled,
                "config": f.config.to_dict(),
                "manifest": f.manifest.to_dict() if f.manifest else None,
            }
            for f in feeds
        ],
    }


@router.get("/health")
def get_health(feed_id: Optional[str] = Query(None, description="Optional feed ID filter")) -> Dict[str, Any]:
    """
    GET /intelligence/health
    Get platform or feed-specific health state.
    """
    engine = get_intelligence_engine()
    if feed_id:
        health = engine.get_health(feed_id)
        if not health:
            raise HTTPException(status_code=404, detail=f"Feed health for '{feed_id}' not found")
        return {"status": "success", "health": health.to_dict()}
    
    summary = engine.get_health()
    return {"status": "success", "summary": summary.to_dict()}


@router.get("/dashboard")
def get_dashboard() -> Dict[str, Any]:
    """
    GET /intelligence/dashboard
    Get comprehensive Framework Health Dashboard.
    """
    engine = get_intelligence_engine()
    summary = engine.get_health()
    metrics = engine.get_metrics()
    return {
        "status": "success",
        "dashboard": {
            "health_summary": summary.to_dict(),
            "metrics": metrics.to_dict(),
            "execution_order": engine.get_execution_order(),
        },
    }


@router.get("/versions")
def list_versions(feed_id: Optional[str] = Query(None, description="Filter dataset versions by feed ID")) -> Dict[str, Any]:
    """
    GET /intelligence/versions
    List dataset versions managed by the framework.
    """
    engine = get_intelligence_engine()
    versions = engine.get_dataset_versions(feed_id=feed_id)
    return {
        "status": "success",
        "count": len(versions),
        "versions": [v.to_dict() for v in versions],
    }


@router.get("/imports")
def list_imports(
    feed_id: Optional[str] = Query(None, description="Filter import history by feed ID"),
    status: Optional[str] = Query(None, description="Filter import history by status"),
    trigger: Optional[str] = Query(None, description="Filter import history by trigger (manual/scheduled)"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/imports
    List permanent synchronization import history and statistics.
    """
    engine = get_intelligence_engine()
    imports = engine.get_import_history(feed_id=feed_id, status=status, trigger=trigger, limit=limit)
    return {
        "status": "success",
        "count": len(imports),
        "imports": [i.to_dict() for i in imports],
    }


@router.post("/feeds/{feed_id}/sync")
def sync_feed(feed_id: str = Path(..., description="ID of feed to synchronize")) -> Dict[str, Any]:
    """
    POST /intelligence/feeds/{feed_id}/sync
    Triggers manual synchronization execution for a registered feed.
    """
    engine = get_intelligence_engine()
    try:
        result = engine.sync_feed(feed_id)
        return {
            "status": "success",
            "message": f"Synchronization for feed '{feed_id}' completed",
            "result": result.to_dict(),
        }
    except FeedNotFoundError as fnf:
        raise HTTPException(status_code=404, detail=str(fnf))
    except IntelligenceException as ie:
        raise HTTPException(status_code=500, detail=str(ie))
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Unexpected error during sync: {ex}")


@router.get("/statistics")
def get_statistics() -> Dict[str, Any]:
    """
    GET /intelligence/statistics
    Expose global intelligence ingestion & dataset statistics.
    """
    engine = get_intelligence_engine()
    stats = engine.get_statistics()
    return {
        "status": "success",
        "statistics": stats.to_dict(),
    }


@router.get("/metrics")
def get_metrics() -> Dict[str, Any]:
    """
    GET /intelligence/metrics
    Expose structured operational metrics.
    """
    engine = get_intelligence_engine()
    metrics = engine.get_metrics()
    return {
        "status": "success",
        "metrics": metrics.to_dict(),
    }


@router.get("/audit-logs")
def get_audit_logs(
    event_type: Optional[str] = Query(None, description="Filter audit logs by event type"),
    feed_id: Optional[str] = Query(None, description="Filter audit logs by feed ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/audit-logs
    Expose domain event audit log history.
    """
    engine = get_intelligence_engine()
    logs = engine.get_audit_logs(event_type=event_type, feed_id=feed_id, limit=limit)
    return {
        "status": "success",
        "count": len(logs),
        "audit_logs": [l.to_dict() for l in logs],
    }


@router.get("/dependencies")
def get_dependencies() -> Dict[str, Any]:
    """
    GET /intelligence/dependencies
    Expose feed dependency graph and topological execution order.
    """
    engine = get_intelligence_engine()
    order = engine.get_execution_order()
    return {
        "status": "success",
        "execution_order": order,
    }


# -------------------------------------------------------------------------
# Security & Trust Verification Framework API Endpoints
# -------------------------------------------------------------------------

@router.get("/trust")
def get_trust_summary() -> Dict[str, Any]:
    """
    GET /intelligence/trust
    Expose overall trust framework summary across all feeds.
    """
    engine = get_intelligence_engine()
    summary = engine.get_trust_summary()
    return {
        "status": "success",
        "trust_summary": summary,
    }


@router.get("/trust/history")
def get_trust_history(
    feed_id: Optional[str] = Query(None, description="Filter trust history by feed ID"),
    overall_trust: Optional[str] = Query(None, description="Filter trust history by decision (TRUSTED, BLOCKED, etc)"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/trust/history
    Expose persistent trust audit history log.
    """
    engine = get_intelligence_engine()
    history = engine.get_trust_history(feed_id=feed_id, overall_trust=overall_trust, limit=limit)
    return {
        "status": "success",
        "count": len(history),
        "history": history,
    }


@router.get("/trust/{feed}")
def get_feed_trust(feed: str = Path(..., description="Feed ID to retrieve trust evaluation for")) -> Dict[str, Any]:
    """
    GET /intelligence/trust/{feed}
    Expose TrustProfile and latest verification results for a specific feed.
    """
    engine = get_intelligence_engine()
    try:
        data = engine.get_feed_trust(feed)
        return {
            "status": "success",
            "trust": data,
        }
    except Exception as ex:
        raise HTTPException(status_code=404, detail=f"Trust profile for feed '{feed}' not found or invalid: {ex}")


# -------------------------------------------------------------------------
# MITRE ATT&CK Enterprise STIX 2.1 Domain API Endpoints
# -------------------------------------------------------------------------

@router.get("/mitre/techniques")
def list_mitre_techniques(
    tactic: Optional[str] = Query(None, description="Filter techniques by tactic (e.g., execution, persistence)"),
    platform: Optional[str] = Query(None, description="Filter techniques by platform (e.g., Windows, Linux)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/techniques
    List MITRE ATT&CK Techniques & Sub-techniques.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "search_mitre_objects"):
        records = repo.search_mitre_objects(tactic=tactic, platform=platform, entity_type="attack-pattern", version_id=version_id, limit=limit)
    else:
        records = []
    return {"status": "success", "count": len(records), "techniques": records}


@router.get("/mitre/techniques/{technique_id}")
def get_mitre_technique(
    technique_id: str = Path(..., description="ATT&CK ID (e.g. T1059) or STIX ID"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/techniques/{technique_id}
    Get detailed MITRE ATT&CK Technique or Sub-technique object.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_mitre_object"):
        obj = repo.get_mitre_object(technique_id, version_id=version_id)
        if obj:
            return {"status": "success", "technique": obj}
    raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")


@router.get("/mitre/techniques/{technique_id}/relationships")
def get_mitre_technique_relationships(
    technique_id: str = Path(..., description="ATT&CK ID (e.g. T1059) or STIX ID"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/techniques/{technique_id}/relationships
    Get STIX relationships associated with a technique (uses, mitigates, detects, subtechnique-of).
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_mitre_relationships"):
        rels_src = repo.list_mitre_relationships(source_ref=technique_id, version_id=version_id, limit=limit)
        rels_tgt = repo.list_mitre_relationships(target_ref=technique_id, version_id=version_id, limit=limit)
        
        # Deduplicate relationships by stix_id
        seen = set()
        combined = []
        for r in rels_src + rels_tgt:
            sid = r.get("stix_id")
            if sid not in seen:
                seen.add(sid)
                combined.append(r)

        return {"status": "success", "count": len(combined), "relationships": combined}
    return {"status": "success", "count": 0, "relationships": []}


@router.get("/mitre/groups")
def list_mitre_groups(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/groups
    List MITRE ATT&CK Intrusion Set Threat Groups.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_mitre_objects"):
        groups = repo.list_mitre_objects(type="intrusion-set", version_id=version_id, limit=limit)
        return {"status": "success", "count": len(groups), "groups": groups}
    return {"status": "success", "count": 0, "groups": []}


@router.get("/mitre/groups/{group_id}")
def get_mitre_group(
    group_id: str = Path(..., description="ATT&CK Group ID (e.g. G0007) or STIX ID"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/groups/{group_id}
    Get detailed MITRE ATT&CK Group object.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_mitre_object"):
        obj = repo.get_mitre_object(group_id, version_id=version_id)
        if obj and obj.get("type") == "intrusion-set":
            return {"status": "success", "group": obj}
    raise HTTPException(status_code=404, detail=f"Group '{group_id}' not found")


@router.get("/mitre/campaigns")
def list_mitre_campaigns(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/campaigns
    List MITRE ATT&CK Campaigns.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_mitre_objects"):
        camps = repo.list_mitre_objects(type="campaign", version_id=version_id, limit=limit)
        return {"status": "success", "count": len(camps), "campaigns": camps}
    return {"status": "success", "count": 0, "campaigns": []}


@router.get("/mitre/software")
def list_mitre_software(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/software
    List MITRE ATT&CK Software (Malware & Tools).
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_mitre_objects"):
        malware = repo.list_mitre_objects(type="malware", version_id=version_id, limit=limit)
        tools = repo.list_mitre_objects(type="tool", version_id=version_id, limit=limit)
        software = malware + tools
        return {"status": "success", "count": len(software), "software": software}
    return {"status": "success", "count": 0, "software": []}


@router.get("/mitre/mitigations")
def list_mitre_mitigations(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/mitigations
    List MITRE ATT&CK Mitigations (course-of-action).
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_mitre_objects"):
        mits = repo.list_mitre_objects(type="course-of-action", version_id=version_id, limit=limit)
        return {"status": "success", "count": len(mits), "mitigations": mits}
    return {"status": "success", "count": 0, "mitigations": []}


@router.get("/mitre/data-sources")
def list_mitre_data_sources(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(1000, ge=1, le=5000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/data-sources
    List MITRE ATT&CK Data Sources.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_mitre_objects"):
        ds = repo.list_mitre_objects(type="x-mitre-data-source", version_id=version_id, limit=limit)
        return {"status": "success", "count": len(ds), "data_sources": ds}
    return {"status": "success", "count": 0, "data_sources": []}


@router.get("/mitre/search")
def search_mitre(
    query: str = Query("", description="Keyword search query"),
    technique_id: Optional[str] = Query(None, description="ATT&CK Technique ID"),
    tactic: Optional[str] = Query(None, description="Tactic filter"),
    platform: Optional[str] = Query(None, description="Platform filter"),
    alias: Optional[str] = Query(None, description="Group or Software Alias filter"),
    type: Optional[str] = Query(None, description="STIX entity type filter"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/search
    Search MITRE ATT&CK Enterprise Intelligence objects across technique ID, name, alias, tactic, platform, or keyword.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "search_mitre_objects"):
        results = repo.search_mitre_objects(
            query=query,
            technique_id=technique_id,
            tactic=tactic,
            platform=platform,
            alias=alias,
            entity_type=type,
            version_id=version_id,
            limit=limit,
        )
        return {"status": "success", "count": len(results), "results": results}
    return {"status": "success", "count": 0, "results": []}


@router.get("/mitre/version")
def get_mitre_active_version() -> Dict[str, Any]:
    """
    GET /intelligence/mitre/version
    Get current active MITRE ATT&CK Enterprise dataset version.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    active_ver = repo.get_active_dataset_version("mitre_attack_enterprise")
    if active_ver:
        return {"status": "success", "active_version": active_ver.to_dict()}
    return {"status": "success", "active_version": None}


@router.get("/mitre/statistics")
def get_mitre_statistics(
    version_id: Optional[str] = Query(None, description="Optional dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/mitre/statistics
    Get object and relationship breakdown statistics for MITRE ATT&CK Enterprise dataset.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_mitre_statistics_for_version"):
        stats = repo.get_mitre_statistics_for_version(version_id)
        return {"status": "success", "statistics": stats}
    return {"status": "success", "statistics": {}}


# -------------------------------------------------------------------------
# NVD Enterprise CVE JSON 2.0 Domain API Endpoints
# -------------------------------------------------------------------------

@router.get("/nvd/cves")
def list_nvd_cves(
    severity: Optional[str] = Query(None, description="Severity filter (CRITICAL, HIGH, MEDIUM, LOW)"),
    vendor: Optional[str] = Query(None, description="Vendor filter (e.g. microsoft, apache)"),
    product: Optional[str] = Query(None, description="Product filter (e.g. windows_10, log4j)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/cves
    List NVD CVE vulnerability records.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_nvd_cves"):
        records = repo.list_nvd_cves(severity=severity, vendor=vendor, product=product, version_id=version_id, limit=limit, offset=offset)
        return {"status": "success", "count": len(records), "cves": records}
    return {"status": "success", "count": 0, "cves": []}


@router.get("/nvd/cves/{cve_id}")
def get_nvd_cve(
    cve_id: str = Path(..., description="CVE ID (e.g., CVE-2024-1234)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/cves/{cve_id}
    Get detailed NVD CVE vulnerability object by CVE ID.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_nvd_cve"):
        obj = repo.get_nvd_cve(cve_id, version_id=version_id)
        if obj:
            return {"status": "success", "cve": obj}
    raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found")


@router.get("/nvd/vendors")
def list_nvd_vendors(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/vendors
    List distinct affected vendors in NVD dataset.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_nvd_vendors"):
        vendors = repo.list_nvd_vendors(version_id=version_id)
        return {"status": "success", "count": len(vendors), "vendors": vendors}
    return {"status": "success", "count": 0, "vendors": []}


@router.get("/nvd/products")
def list_nvd_products(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/products
    List distinct affected products in NVD dataset.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_nvd_products"):
        products = repo.list_nvd_products(version_id=version_id)
        return {"status": "success", "count": len(products), "products": products}
    return {"status": "success", "count": 0, "products": []}


@router.get("/nvd/cwes")
def list_nvd_cwes(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/cwes
    List distinct associated CWE weakness IDs in NVD dataset.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_nvd_cwes"):
        cwes = repo.list_nvd_cwes(version_id=version_id)
        return {"status": "success", "count": len(cwes), "cwes": cwes}
    return {"status": "success", "count": 0, "cwes": []}


@router.get("/nvd/search")
def search_nvd(
    query: str = Query("", description="Keyword search query"),
    cve_id: Optional[str] = Query(None, description="CVE ID filter"),
    vendor: Optional[str] = Query(None, description="Vendor filter"),
    product: Optional[str] = Query(None, description="Product filter"),
    cwe: Optional[str] = Query(None, description="CWE ID filter (e.g. CWE-79)"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    min_cvss: Optional[float] = Query(None, description="Minimum CVSS base score"),
    max_cvss: Optional[float] = Query(None, description="Maximum CVSS base score"),
    pub_start: Optional[str] = Query(None, description="Published date start filter (ISO string)"),
    pub_end: Optional[str] = Query(None, description="Published date end filter (ISO string)"),
    mod_start: Optional[str] = Query(None, description="Modified date start filter (ISO string)"),
    mod_end: Optional[str] = Query(None, description="Modified date end filter (ISO string)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/search
    Multi-parameter search across CVE ID, vendor, product, CWE, severity, CVSS scores, dates, or keywords.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "search_nvd_cves"):
        results = repo.search_nvd_cves(
            query=query,
            cve_id=cve_id,
            vendor=vendor,
            product=product,
            cwe=cwe,
            severity=severity,
            min_cvss=min_cvss,
            max_cvss=max_cvss,
            pub_start=pub_start,
            pub_end=pub_end,
            mod_start=mod_start,
            mod_end=mod_end,
            version_id=version_id,
            limit=limit,
        )
        return {"status": "success", "count": len(results), "results": results}
    return {"status": "success", "count": 0, "results": []}


@router.get("/nvd/version")
def get_nvd_active_version() -> Dict[str, Any]:
    """
    GET /intelligence/nvd/version
    Get current active NVD Enterprise dataset version.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    active_ver = repo.get_active_dataset_version("nvd_cve_2.0")
    if active_ver:
        return {"status": "success", "active_version": active_ver.to_dict()}
    return {"status": "success", "active_version": None}


@router.get("/nvd/statistics")
def get_nvd_statistics(
    version_id: Optional[str] = Query(None, description="Optional dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/nvd/statistics
    Get NVD dataset breakdown statistics.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_nvd_statistics_for_version"):
        stats = repo.get_nvd_statistics_for_version(version_id)
        return {"status": "success", "statistics": stats}
    return {"status": "success", "statistics": {}}


# -------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV) Domain API Endpoints
# -------------------------------------------------------------------------

@router.get("/kev")
def list_kev_records(
    vendor: Optional[str] = Query(None, description="Vendor filter"),
    product: Optional[str] = Query(None, description="Product filter"),
    ransomware: Optional[str] = Query(None, description="Known ransomware campaign use filter"),
    due_date: Optional[str] = Query(None, description="Remediation due date filter"),
    date_added: Optional[str] = Query(None, description="Date added filter"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    GET /intelligence/kev
    List CISA KEV entries with filtering by vendor, product, ransomware, due date, date added.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_kev_records"):
        records = repo.list_kev_records(
            vendor=vendor,
            product=product,
            ransomware=ransomware,
            due_date=due_date,
            date_added=date_added,
            version_id=version_id,
            limit=limit,
            offset=offset,
        )
        return {"status": "success", "count": len(records), "kev_records": records}
    return {"status": "success", "count": 0, "kev_records": []}


@router.get("/kev/vendors")
def list_kev_vendors(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/kev/vendors
    List distinct vendors in CISA KEV dataset.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_kev_vendors"):
        vendors = repo.list_kev_vendors(version_id=version_id)
        return {"status": "success", "count": len(vendors), "vendors": vendors}
    return {"status": "success", "count": 0, "vendors": []}


@router.get("/kev/products")
def list_kev_products(
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/kev/products
    List distinct products in CISA KEV dataset.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_kev_products"):
        products = repo.list_kev_products(version_id=version_id)
        return {"status": "success", "count": len(products), "products": products}
    return {"status": "success", "count": 0, "products": []}


@router.get("/kev/search")
def search_kev(
    query: str = Query("", description="Keyword search query"),
    cve_id: Optional[str] = Query(None, description="CVE ID filter"),
    vendor: Optional[str] = Query(None, description="Vendor filter"),
    product: Optional[str] = Query(None, description="Product filter"),
    due_date: Optional[str] = Query(None, description="Due date filter"),
    ransomware: Optional[str] = Query(None, description="Ransomware campaign filter"),
    exploitation_status: Optional[str] = Query(None, description="Exploitation status filter"),
    date_added: Optional[str] = Query(None, description="Date added filter"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/kev/search
    Multi-parameter search across KEV entries by CVE, vendor, product, due date, ransomware, status, dates, or keywords.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "search_kev_records"):
        results = repo.search_kev_records(
            query=query,
            cve_id=cve_id,
            vendor=vendor,
            product=product,
            due_date=due_date,
            ransomware=ransomware,
            exploitation_status=exploitation_status,
            date_added=date_added,
            version_id=version_id,
            limit=limit,
        )
        return {"status": "success", "count": len(results), "results": results}
    return {"status": "success", "count": 0, "results": []}


@router.get("/kev/statistics")
def get_kev_statistics(
    version_id: Optional[str] = Query(None, description="Optional dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/kev/statistics
    Get CISA KEV dataset breakdown statistics.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_kev_statistics_for_version"):
        stats = repo.get_kev_statistics_for_version(version_id)
        return {"status": "success", "statistics": stats}
    return {"status": "success", "statistics": {}}


@router.get("/kev/version")
def get_kev_active_version() -> Dict[str, Any]:
    """
    GET /intelligence/kev/version
    Get current active CISA KEV dataset version.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    active_ver = repo.get_active_dataset_version("cisa_kev_1.0")
    if active_ver:
        return {"status": "success", "active_version": active_ver.to_dict()}
    return {"status": "success", "active_version": None}


@router.get("/kev/{cve}")
def get_kev_record(
    cve: str = Path(..., description="CVE ID (e.g., CVE-2021-44228)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/kev/{cve}
    Get detailed CISA KEV entry for a specific CVE.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_kev_record"):
        obj = repo.get_kev_record(cve, version_id=version_id)
        if obj:
            return {"status": "success", "kev_record": obj}
    raise HTTPException(status_code=404, detail=f"KEV record for '{cve}' not found")


# -------------------------------------------------------------------------
# FIRST EPSS (Exploit Prediction Scoring System) Domain API Endpoints
# -------------------------------------------------------------------------

@router.get("/epss")
def list_epss_scores(
    min_score: Optional[float] = Query(None, description="Minimum EPSS score (0.0-1.0)", ge=0.0, le=1.0),
    max_score: Optional[float] = Query(None, description="Maximum EPSS score (0.0-1.0)", ge=0.0, le=1.0),
    min_percentile: Optional[float] = Query(None, description="Minimum EPSS percentile (0.0-1.0)", ge=0.0, le=1.0),
    max_percentile: Optional[float] = Query(None, description="Maximum EPSS percentile (0.0-1.0)", ge=0.0, le=1.0),
    trend: Optional[str] = Query(None, description="Trend filter (RAPIDLY_INCREASING, INCREASING, STABLE, DECREASING, RAPIDLY_DECREASING)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss
    List EPSS exploit probability scores with filtering by score, percentile, and trend.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "list_epss_scores"):
        records = repo.list_epss_scores(
            min_score=min_score,
            max_score=max_score,
            min_percentile=min_percentile,
            max_percentile=max_percentile,
            trend=trend,
            version_id=version_id,
            limit=limit,
            offset=offset,
        )
        return {"status": "success", "count": len(records), "epss_scores": records}
    return {"status": "success", "count": 0, "epss_scores": []}


@router.get("/epss/{cve_id}")
def get_epss_score(
    cve_id: str = Path(..., description="CVE ID (e.g., CVE-2024-1234)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/{cve_id}
    Get current EPSS exploit probability score for a specific CVE.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_epss_score"):
        obj = repo.get_epss_score(cve_id, version_id=version_id)
        if obj:
            return {"status": "success", "epss_score": obj}
    raise HTTPException(status_code=404, detail=f"EPSS score for '{cve_id}' not found")


@router.get("/epss/history/{cve_id}")
def get_epss_history(
    cve_id: str = Path(..., description="CVE ID (e.g., CVE-2024-1234)"),
    limit: int = Query(100, ge=1, le=365),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/history/{cve_id}
    Get historical EPSS score snapshots for a specific CVE (ordered by date descending).
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_epss_history"):
        history = repo.get_epss_history(cve_id, limit=limit)
        return {"status": "success", "count": len(history), "history": history}
    return {"status": "success", "count": 0, "history": []}


@router.get("/epss/search")
def search_epss(
    cve_id: Optional[str] = Query(None, description="CVE ID filter"),
    min_score: Optional[float] = Query(None, description="Minimum EPSS score", ge=0.0, le=1.0),
    max_score: Optional[float] = Query(None, description="Maximum EPSS score", ge=0.0, le=1.0),
    min_percentile: Optional[float] = Query(None, description="Minimum EPSS percentile", ge=0.0, le=1.0),
    max_percentile: Optional[float] = Query(None, description="Maximum EPSS percentile", ge=0.0, le=1.0),
    trend: Optional[str] = Query(None, description="Trend classification filter"),
    publication_date: Optional[str] = Query(None, description="Publication date filter (YYYY-MM-DD)"),
    model_version: Optional[str] = Query(None, description="EPSS model version filter (e.g., v2023.03.01)"),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/search
    Multi-parameter search across EPSS scores by CVE, score range, percentile, trend, date, or model version.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "search_epss_scores"):
        results = repo.search_epss_scores(
            cve_id=cve_id,
            min_score=min_score,
            max_score=max_score,
            min_percentile=min_percentile,
            max_percentile=max_percentile,
            trend=trend,
            publication_date=publication_date,
            model_version=model_version,
            version_id=version_id,
            limit=limit,
        )
        return {"status": "success", "count": len(results), "results": results}
    return {"status": "success", "count": 0, "results": []}


@router.get("/epss/trending")
def get_trending_epss(
    trend_type: str = Query("INCREASING", description="Trend type: RAPIDLY_INCREASING, INCREASING, DECREASING, RAPIDLY_DECREASING"),
    limit: int = Query(100, ge=1, le=1000),
    version_id: Optional[str] = Query(None, description="Dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/trending
    Get CVEs with specific EPSS score trend classifications.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_trending_epss_cves"):
        records = repo.get_trending_epss_cves(
            trend_type=trend_type,
            limit=limit,
            version_id=version_id,
        )
        return {"status": "success", "count": len(records), "trending_cves": records}
    return {"status": "success", "count": 0, "trending_cves": []}


@router.get("/epss/statistics")
def get_epss_statistics(
    version_id: Optional[str] = Query(None, description="Optional dataset version ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/epss/statistics
    Get EPSS dataset breakdown statistics including score distribution, trends, and top CVEs.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    if hasattr(repo, "get_epss_statistics_for_version"):
        stats = repo.get_epss_statistics_for_version(version_id)
        return {"status": "success", "statistics": stats}
    return {"status": "success", "statistics": {}}


@router.get("/epss/version")
def get_epss_active_version() -> Dict[str, Any]:
    """
    GET /intelligence/epss/version
    Get current active FIRST EPSS dataset version.
    """
    engine = get_intelligence_engine()
    repo = engine.repository
    active_ver = repo.get_active_dataset_version("first_epss_1.0")
    if active_ver:
        return {"status": "success", "active_version": active_ver.to_dict()}
    return {"status": "success", "active_version": None}


from netfusion_intelligence.identity.api import router as identity_router
router.include_router(identity_router)

# =====================================================================
# IL-8: Unified Threat Knowledge Graph (UTKG) Routes
# =====================================================================

from netfusion_intelligence.graph.api import router as utkg_router, set_utkg
from netfusion_intelligence.graph.repository import GraphRepository
from netfusion_intelligence.graph.service import UnifiedThreatKnowledgeGraph

_utkg_service_instance: Optional[UnifiedThreatKnowledgeGraph] = None


def _get_or_init_utkg() -> UnifiedThreatKnowledgeGraph:
    """Lazily initialise the UTKG, wiring it to the intelligence repository."""
    global _utkg_service_instance
    if _utkg_service_instance is None:
        try:
            import os
            db_url = os.getenv("UTKG_DB_URL", "sqlite:///./utkg.db")
            graph_repo = GraphRepository(db_url=db_url)
            intel_repo = get_intelligence_engine().repository
            _utkg_service_instance = UnifiedThreatKnowledgeGraph(
                graph_repository=graph_repo,
                intelligence_repository=intel_repo,
            )
            set_utkg(_utkg_service_instance)
        except Exception:
            pass
    return _utkg_service_instance


# Patch the UTKG API module to use the singleton
import netfusion_intelligence.graph.api as _utkg_api_module


def _patched_get_utkg() -> UnifiedThreatKnowledgeGraph:
    instance = _get_or_init_utkg()
    if instance is None:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=503, detail="UTKG is not yet initialised.")
    return instance


_utkg_api_module.get_utkg = _patched_get_utkg

router.include_router(utkg_router)

# -------------------------------------------------------------------------
# IL-5.1 EPSS Time-Aware Analytics Engine API Endpoints
# -------------------------------------------------------------------------

from netfusion_intelligence.analytics.epss.api import (
    router as epss_analytics_router,
    set_analytics_engine,
)
from netfusion_intelligence.analytics.epss.engine import EpssAnalyticsEngine

_epss_analytics_engine_instance: Optional[EpssAnalyticsEngine] = None


def _get_or_init_epss_analytics_engine() -> EpssAnalyticsEngine:
    """
    Lazily initialises and wires the EPSS analytics engine to the intelligence
    engine's repository.  Idempotent — only creates once.
    """
    global _epss_analytics_engine_instance
    if _epss_analytics_engine_instance is None:
        try:
            eng = get_intelligence_engine()
            _epss_analytics_engine_instance = EpssAnalyticsEngine(eng.repository)
            set_analytics_engine(_epss_analytics_engine_instance)
        except Exception:
            pass
    return _epss_analytics_engine_instance


# Override the analytics router's get_analytics_engine dependency to use the
# lazily initialised singleton so it picks up the real repository.
import netfusion_intelligence.analytics.epss.api as _epss_analytics_api_module


def _patched_get_analytics_engine() -> EpssAnalyticsEngine:
    engine = _get_or_init_epss_analytics_engine()
    if engine is None:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(
            status_code=503,
            detail="EPSS Analytics Engine is not yet initialised.",
        )
    return engine


_epss_analytics_api_module.get_analytics_engine = _patched_get_analytics_engine

# Include the analytics router — all routes are prefixed /intelligence/epss/analytics-*
# The router itself is already prefixed with /intelligence/epss so no extra prefix needed.
router.include_router(epss_analytics_router)






# =====================================================================
# IL-6: CWE Enterprise Intelligence Routes
# =====================================================================

@router.get("/cwe")
def list_cwe_weaknesses(
    abstraction: Optional[str] = Query(None, description="Filter by abstraction level (Base, Variant, Class, Compound)"),
    status: Optional[str] = Query(None, description="Filter by status (Stable, Draft, Incomplete, etc.)"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    version_id: Optional[str] = Query(None, description="Dataset version ID (defaults to active)"),
) -> Dict[str, Any]:
    """GET /intelligence/cwe — List CWE weaknesses with optional filters."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "list_cwe_weaknesses"):
        raise HTTPException(status_code=503, detail="CWE data not available")
    results = engine.repository.list_cwe_weaknesses(
        abstraction=abstraction, status=status, version_id=version_id, limit=limit, offset=offset
    )
    return {"status": "success", "count": len(results), "weaknesses": results}


@router.get("/cwe/search")
def search_cwe(
    q: Optional[str] = Query(None, description="Keyword search (name, description, ID)"),
    cwe_id: Optional[str] = Query(None, description="Specific CWE ID filter (e.g. CWE-79)"),
    abstraction: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/cwe/search — Search CWE weaknesses."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "search_cwe_weaknesses"):
        raise HTTPException(status_code=503, detail="CWE search not available")
    results = engine.repository.search_cwe_weaknesses(
        query=q or "", cwe_id=cwe_id, abstraction=abstraction, status=status,
        version_id=version_id, limit=limit
    )
    return {"status": "success", "count": len(results), "weaknesses": results}


@router.get("/cwe/statistics")
def get_cwe_statistics(version_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    """GET /intelligence/cwe/statistics — CWE dataset statistics."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_cwe_statistics_for_version"):
        return {"status": "success", "statistics": {}}
    stats = engine.repository.get_cwe_statistics_for_version(version_id)
    return {"status": "success", "statistics": stats}


@router.get("/cwe/version")
def get_cwe_active_version() -> Dict[str, Any]:
    """GET /intelligence/cwe/version — Active CWE dataset version."""
    engine = get_intelligence_engine()
    active = engine.repository.get_active_dataset_version("mitre_cwe_xml")
    if not active:
        return {"status": "success", "version": None}
    return {"status": "success", "version": active.to_dict()}


@router.get("/cwe/{cwe_id}")
def get_cwe_weakness(
    cwe_id: str = Path(..., description="CWE ID (e.g. CWE-79 or 79)"),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/cwe/{id} — Retrieve a single CWE weakness by ID."""
    engine = get_intelligence_engine()
    # Normalize format
    if not cwe_id.upper().startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    if not hasattr(engine.repository, "get_cwe_weakness"):
        raise HTTPException(status_code=503, detail="CWE data not available")
    result = engine.repository.get_cwe_weakness(cwe_id, version_id=version_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"CWE '{cwe_id}' not found")
    return {"status": "success", "weakness": result}


# =====================================================================
# IL-6: CAPEC Enterprise Intelligence Routes
# =====================================================================

@router.get("/capec")
def list_capec_patterns(
    abstraction: Optional[str] = Query(None, description="Filter by abstraction (Meta, Standard, Detailed, etc.)"),
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by typical severity (High, Medium, Low)"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/capec — List CAPEC attack patterns with optional filters."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "list_capec_attack_patterns"):
        raise HTTPException(status_code=503, detail="CAPEC data not available")
    results = engine.repository.list_capec_attack_patterns(
        abstraction=abstraction, status=status, severity=severity,
        version_id=version_id, limit=limit, offset=offset
    )
    return {"status": "success", "count": len(results), "attack_patterns": results}


@router.get("/capec/search")
def search_capec(
    q: Optional[str] = Query(None, description="Keyword search (name, description, ID)"),
    capec_id: Optional[str] = Query(None, description="Specific CAPEC ID (e.g. CAPEC-79)"),
    abstraction: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    cwe_id: Optional[str] = Query(None, description="Filter CAPEC patterns by related CWE ID"),
    attack_technique_id: Optional[str] = Query(None, description="Filter by ATT&CK technique ID"),
    limit: int = Query(100, ge=1, le=500),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/capec/search — Search CAPEC attack patterns."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "search_capec_attack_patterns"):
        raise HTTPException(status_code=503, detail="CAPEC search not available")
    results = engine.repository.search_capec_attack_patterns(
        query=q or "", capec_id=capec_id, abstraction=abstraction, severity=severity,
        cwe_id=cwe_id, attack_technique_id=attack_technique_id,
        version_id=version_id, limit=limit
    )
    return {"status": "success", "count": len(results), "attack_patterns": results}


@router.get("/capec/statistics")
def get_capec_statistics(version_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    """GET /intelligence/capec/statistics — CAPEC dataset statistics."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_capec_statistics_for_version"):
        return {"status": "success", "statistics": {}}
    stats = engine.repository.get_capec_statistics_for_version(version_id)
    return {"status": "success", "statistics": stats}


@router.get("/capec/version")
def get_capec_active_version() -> Dict[str, Any]:
    """GET /intelligence/capec/version — Active CAPEC dataset version."""
    engine = get_intelligence_engine()
    active = engine.repository.get_active_dataset_version("mitre_capec_xml")
    if not active:
        return {"status": "success", "version": None}
    return {"status": "success", "version": active.to_dict()}


@router.get("/capec/{capec_id}")
def get_capec_pattern(
    capec_id: str = Path(..., description="CAPEC ID (e.g. CAPEC-66 or 66)"),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/capec/{id} — Retrieve a single CAPEC attack pattern by ID."""
    engine = get_intelligence_engine()
    if not capec_id.upper().startswith("CAPEC-"):
        capec_id = f"CAPEC-{capec_id}"
    if not hasattr(engine.repository, "get_capec_attack_pattern"):
        raise HTTPException(status_code=503, detail="CAPEC data not available")
    result = engine.repository.get_capec_attack_pattern(capec_id, version_id=version_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"CAPEC '{capec_id}' not found")
    return {"status": "success", "attack_pattern": result}


# =====================================================================
# IL-6: Unified Knowledge Graph Route
# =====================================================================

@router.get("/cve/{cve_id}/knowledge")
def get_cve_knowledge(
    cve_id: str = Path(..., description="CVE ID (e.g. CVE-2021-44228)"),
) -> Dict[str, Any]:
    """
    GET /intelligence/cve/{cve_id}/knowledge
    Returns the full knowledge card for a CVE traversing the knowledge graph:
      CVE → CWE → CAPEC → ATT&CK Techniques → Mitigations → Detection Guidance
    """
    engine = get_intelligence_engine()
    from netfusion_intelligence.services.knowledge_graph import KnowledgeGraphService
    kg = KnowledgeGraphService(engine.repository)
    try:
        result = kg.get_cve_knowledge(cve_id.upper())
        return {"status": "success", "knowledge": result}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Knowledge graph error: {exc}")


# =====================================================================
# IL-7: IOC Enterprise Intelligence Routes
# =====================================================================

@router.get("/ioc")
def list_ioc_indicators(
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type (ipv4, domain, sha256, url, …)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    status: Optional[str] = Query(None, description="Filter by status (active, expired, revoked, …)"),
    provider: Optional[str] = Query(None, description="Filter by provider name"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    min_reputation: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum reputation score"),
    version_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """GET /intelligence/ioc — List IOC indicators with optional filters."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "list_ioc_indicators"):
        raise HTTPException(status_code=503, detail="IOC data not available")
    results = engine.repository.list_ioc_indicators(
        ioc_type=ioc_type, status=status, severity=severity,
        min_confidence=min_confidence, min_reputation=min_reputation,
        provider=provider, version_id=version_id, limit=limit, offset=offset,
    )
    return {"status": "success", "count": len(results), "indicators": results}


@router.get("/ioc/search")
def search_ioc_indicators(
    q: Optional[str] = Query(None, description="Keyword search across value, description, tags"),
    ioc_type: Optional[str] = Query(None),
    value: Optional[str] = Query(None, description="Exact or partial indicator value"),
    hash_value: Optional[str] = Query(None, description="Hash value (MD5/SHA1/SHA256/SHA512)"),
    ip: Optional[str] = Query(None, description="IP address search"),
    domain: Optional[str] = Query(None, description="Domain/hostname search"),
    threat_actor: Optional[str] = Query(None),
    campaign: Optional[str] = Query(None),
    malware: Optional[str] = Query(None, description="Malware family name"),
    attack_technique: Optional[str] = Query(None, description="ATT&CK technique ID (e.g. T1059)"),
    capec_id: Optional[str] = Query(None, description="CAPEC ID (e.g. CAPEC-66)"),
    cwe_id: Optional[str] = Query(None, description="CWE ID (e.g. CWE-79)"),
    cve_id: Optional[str] = Query(None, description="CVE ID (e.g. CVE-2021-44228)"),
    provider: Optional[str] = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    min_reputation: Optional[float] = Query(None, ge=0.0, le=10.0),
    first_seen_start: Optional[str] = Query(None),
    first_seen_end: Optional[str] = Query(None),
    last_seen_start: Optional[str] = Query(None),
    last_seen_end: Optional[str] = Query(None),
    version_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """GET /intelligence/ioc/search — Multi-parameter IOC search."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "search_ioc_indicators"):
        raise HTTPException(status_code=503, detail="IOC search not available")
    results = engine.repository.search_ioc_indicators(
        query=q or "", ioc_type=ioc_type, value=value, hash_value=hash_value,
        ip=ip, domain=domain, threat_actor=threat_actor, campaign=campaign,
        malware=malware, attack_technique=attack_technique, capec_id=capec_id,
        cwe_id=cwe_id, cve_id=cve_id, provider=provider,
        min_confidence=min_confidence, min_reputation=min_reputation,
        first_seen_start=first_seen_start, first_seen_end=first_seen_end,
        last_seen_start=last_seen_start, last_seen_end=last_seen_end,
        version_id=version_id, limit=limit,
    )
    return {"status": "success", "count": len(results), "results": results}


@router.get("/ioc/statistics")
def get_ioc_statistics(version_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    """GET /intelligence/ioc/statistics — IOC dataset breakdown statistics."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_ioc_statistics_for_version"):
        return {"status": "success", "statistics": {}}
    stats = engine.repository.get_ioc_statistics_for_version(version_id)
    return {"status": "success", "statistics": stats}


@router.get("/ioc/version")
def get_ioc_active_version() -> Dict[str, Any]:
    """GET /intelligence/ioc/version — Active IOC dataset version."""
    engine = get_intelligence_engine()
    active = engine.repository.get_active_dataset_version("netfusion_ioc_v1")
    return {"status": "success", "version": active.to_dict() if active else None}


@router.get("/ioc/{ioc_id}/reputation")
def get_ioc_reputation(
    ioc_id: str = Path(..., description="IOC entity ID"),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/ioc/{id}/reputation — Reputation record for an IOC."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_ioc_reputation"):
        raise HTTPException(status_code=503, detail="IOC reputation not available")
    rep = engine.repository.get_ioc_reputation(ioc_id, version_id=version_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Reputation for IOC '{ioc_id}' not found")
    return {"status": "success", "reputation": rep}


@router.get("/ioc/{ioc_id}/sightings")
def get_ioc_sightings(
    ioc_id: str = Path(..., description="IOC entity ID"),
    version_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """GET /intelligence/ioc/{id}/sightings — Sighting observations for an IOC."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_ioc_sightings"):
        raise HTTPException(status_code=503, detail="IOC sightings not available")
    sightings = engine.repository.get_ioc_sightings(ioc_id, version_id=version_id, limit=limit)
    return {"status": "success", "count": len(sightings), "sightings": sightings}


@router.get("/ioc/{ioc_id}/correlation")
def get_ioc_correlation(
    ioc_id: str = Path(..., description="IOC entity ID"),
    version_id: Optional[str] = Query(None),
    direction: str = Query("both", description="Relationship direction: both | source | target"),
    limit: int = Query(200, ge=1, le=1000),
) -> Dict[str, Any]:
    """GET /intelligence/ioc/{id}/correlation — All relationships for an IOC."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_ioc_relationships"):
        raise HTTPException(status_code=503, detail="IOC correlation not available")
    relationships = engine.repository.get_ioc_relationships(
        ioc_id, version_id=version_id, direction=direction, limit=limit,
    )
    return {"status": "success", "count": len(relationships), "relationships": relationships}


@router.get("/ioc/{ioc_id}")
def get_ioc_indicator(
    ioc_id: str = Path(..., description="IOC entity ID"),
    version_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """GET /intelligence/ioc/{id} — Retrieve a single IOC indicator by ID."""
    engine = get_intelligence_engine()
    if not hasattr(engine.repository, "get_ioc_indicator"):
        raise HTTPException(status_code=503, detail="IOC data not available")
    result = engine.repository.get_ioc_indicator(ioc_id, version_id=version_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found")
    return {"status": "success", "indicator": result}


@router.get("/ioc/{ioc_id}/knowledge")
def get_ioc_knowledge(
    ioc_id: str = Path(..., description="IOC entity ID"),
) -> Dict[str, Any]:
    """
    GET /intelligence/ioc/{id}/knowledge
    Full knowledge card traversing the graph:
    IOC → Malware → Campaign → ATT&CK → CAPEC → CWE → CVE
    """
    engine = get_intelligence_engine()
    from netfusion_intelligence.services.knowledge_graph import KnowledgeGraphService
    kg = KnowledgeGraphService(engine.repository)
    try:
        result = kg.get_ioc_knowledge(ioc_id)
        return {"status": "success", "knowledge": result}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Knowledge graph error: {exc}")
