"""
Smoke Test — Provider Registry API (Phase A4.8.8)
==================================================
Target: 1600+ assertions, 0 failures.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.provider_registry_router import (
    provider_registry_router,
    _reset_store,
    _bootstrap_store,
    _PROVIDER_STORE,
    list_providers,
    get_provider_statistics,
    get_provider,
    create_provider,
    update_provider,
    delete_provider,
    list_provider_models,
    create_provider_model,
    update_provider_model_route,
    delete_provider_model_route,
    get_provider_capabilities,
    get_provider_health,
    get_provider_summary_route,
    bulk_create_providers,
    bulk_update_providers,
    bulk_delete_providers,
    search_providers_endpoint,
    # Helpers
    find_provider,
    sort_providers,
    filter_providers,
    paginate_providers,
    search_providers,
    find_provider_model,
    append_provider_model,
    update_provider_model,
    delete_provider_model,
    search_provider_models,
    build_provider_summary,
    calculate_provider_statistics,
)
from api.ai.provider_registry_models import (
    CreateProviderRequest,
    UpdateProviderRequest,
    ProviderModelRequest,
    ProviderCapabilityRequest,
    ProviderHealthResponse,
    ProviderModelResponse,
    ProviderResponse,
    ProviderListResponse,
    ProviderStatisticsResponse,
    ProviderSearchResponse,
    BulkCreateProvidersRequest,
    BulkUpdateProvidersRequest,
    BulkDeleteProvidersRequest,
    BulkOperationResult,
)
from services.provider_registry_service import (
    build_provider_definition,
    build_provider_model,
    build_provider_capability,
)

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0

def _eq(a, b, label: str) -> None:
    global _PASS, _FAIL
    if a == b:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: {a!r} != {b!r}")

def _ne(a, b, label: str) -> None:
    global _PASS, _FAIL
    if a != b:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected not-equal but got {a!r}")

def _is(obj, typ, label: str) -> None:
    global _PASS, _FAIL
    if isinstance(obj, typ):
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {typ.__name__}, got {type(obj).__name__}")

def _true(v, label: str) -> None:
    global _PASS, _FAIL
    if v:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected True")

def _false(v, label: str) -> None:
    global _PASS, _FAIL
    if not v:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected False")

# ---------------------------------------------------------------------------
# Run Tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    global _PASS, _FAIL
    print("Starting AI Provider Registry API Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in provider_registry_router.routes}
    expected_paths = {
        "/providers", "/providers/statistics", "/providers/search",
        "/providers/bulk/create", "/providers/bulk/update", "/providers/bulk/delete",
        "/providers/{providerId}", "/providers/{providerId}/models",
        "/providers/{providerId}/models/{modelId}", "/providers/{providerId}/capabilities",
        "/providers/{providerId}/health", "/providers/{providerId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (140 items -> 1680+ assertions)
    # =======================================================================
    sessions = []
    for i in range(140):
        prov = build_provider_definition(
            provider_name    = f"provider-{i:03d}",
            display_name     = f"Display {i:03d}",
            api_version      = "2026-07-01",
            endpoint         = f"https://api.provider-{i:03d}.com/v1",
            supported_models = [f"model-{i}-1", f"model-{i}-2"],
            default_model    = f"model-{i}-1",
            created_at       = f"2026-07-03T12:{i % 60:02d}:00Z",
            enabled          = (i % 2 == 0),
        )
        
        models_dict = {}
        for m_idx in range(i % 3 + 1):
            cap = build_provider_capability(
                streaming=True, tool_calling=True, json_mode=True,
                vision=False, embeddings=False,
                max_context_tokens=1000 * (m_idx + 1), max_output_tokens=500,
            )
            mdl = build_provider_model(
                provider     = prov.providerName,
                model_name   = f"model-{i}-{m_idx}",
                capabilities = cap,
                created_at   = prov.createdAt,
                alias        = f"alias-{i}-{m_idx}",
                enabled      = True,
                priority     = 10 * m_idx,
            )
            models_dict[mdl.modelId] = mdl

        session_dict = {
            "package"      : prov,
            "models"       : models_dict,
            "status"       : "ACTIVE" if prov.enabled else "DISABLED",
            "priority"     : 5 * (i % 15),
            "healthScore"  : 50.0 + (i % 50),
            "providerType" : "local" if i % 4 == 0 else "cloud",
        }
        sessions.append(session_dict)

    sort_fields = ["providerName", "createdAt", "updatedAt", "priority", "healthScore", "modelCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_providers(sessions, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 140, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(139):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["package"]
                c2 = s2["package"]
                
                if field == "modelCount":
                    v1 = len(s1["models"])
                    v2 = len(s2["models"])
                elif field == "priority":
                    v1 = s1.get("priority", 50)
                    v2 = s2.get("priority", 50)
                elif field == "healthScore":
                    v1 = s1.get("healthScore", 100.0)
                    v2 = s2.get("healthScore", 100.0)
                elif field == "providerName":
                    v1 = c1.providerName.lower()
                    v2 = c2.providerName.lower()
                elif field in ("createdAt", "updatedAt"):
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                
                if reverse:
                    _true(v1 >= v2, f"Sort verification: {field} desc index {k}")
                else:
                    _true(v1 <= v2, f"Sort verification: {field} asc index {k}")

    # =======================================================================
    # 3. Filtering Helper Verification
    # =======================================================================
    filters = [
        ({"status": "ACTIVE"}, 70),
        ({"status": "DISABLED"}, 70),
        ({"providerType": "local"}, 35),
        ({"providerType": "cloud"}, 105),
        ({"minimumPriority": 50}, 45),
        ({"maximumPriority": 20}, 50),
        ({"minimumHealthScore": 80}, 50),
        ({"maximumHealthScore": 60}, 33),
        ({"supportsStreaming": True}, 140),
        ({"supportsVision": True}, 0),
        ({"status": "ACTIVE", "providerType": "local"}, 35),
    ]
    for filt, expected_count in filters:
        filtered = filter_providers(
            sessions,
            status=filt.get("status"),
            providerType=filt.get("providerType"),
            minimumPriority=filt.get("minimumPriority"),
            maximumPriority=filt.get("maximumPriority"),
            minimumHealthScore=filt.get("minimumHealthScore"),
            maximumHealthScore=filt.get("maximumHealthScore"),
            supportsStreaming=filt.get("supportsStreaming"),
            supportsVision=filt.get("supportsVision"),
        )
        _eq(len(filtered), expected_count, f"Filter count: {filt}")

    # =======================================================================
    # 4. Pagination Helper Verification
    # =======================================================================
    for page in [1, 2, 3]:
        for page_size in [5, 10]:
            slice_res, pag = paginate_providers(sessions, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 140, "TotalItems meta")
            _eq(pag.totalPages, math.ceil(140 / page_size), "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & model actions
    # =======================================================================
    _bootstrap_store()  # seeds with 6 standard providers

    stats_resp = get_provider_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalProviders"], 6, "Total providers seeded")

    # Create Provider Request
    body1 = CreateProviderRequest(
        providerName="custom-prov",
        displayName="Custom Provider",
        apiVersion="v1",
        endpoint="https://api.custom.com",
        supportedModels=["custom-model-1", "custom-model-2"],
        defaultModel="custom-model-1",
        createdAt="2026-07-03T12:00:00Z",
        enabled=True,
        priority=60,
        healthScore=95.0,
        providerType="cloud",
    )
    resp1 = create_provider(body1)
    _eq(resp1.success, True, "Create provider")
    pid1 = resp1.data["providerId"]
    _true(pid1 is not None, "Valid providerId returned")

    # Duplicate detection
    dup_resp = create_provider(body1)
    _eq(dup_resp.success, False, "Duplicate create fails")
    _eq(dup_resp.data.errorCode, "CONFLICT", "Conflict error code")

    # Get provider
    get1 = get_provider(pid1)
    _eq(get1.data["displayName"], "Custom Provider", "displayName matches")
    _eq(get1.data["priority"], 60, "priority matches")

    # Create model in custom provider
    cap_req = ProviderCapabilityRequest(
        streaming=True, toolCalling=True, jsonMode=True, vision=True, embeddings=False,
        maxContextTokens=32000, maxOutputTokens=8000
    )
    model_req = ProviderModelRequest(
        modelName="custom-model-1",
        alias="custom-1",
        capabilities=cap_req,
        enabled=True,
        priority=80,
        createdAt="2026-07-03T12:00:00Z"
    )
    m_resp = create_provider_model(pid1, model_req)
    _eq(m_resp.success, True, "Model appended to provider")
    mid1 = m_resp.data["modelId"]

    # List provider models
    m_list = list_provider_models(pid1)
    _eq(len(m_list.data), 1, "Provider has 1 model")

    # Update model in custom provider
    model_req_upd = ProviderModelRequest(
        modelName="custom-model-1",
        alias="custom-1-updated",
        capabilities=cap_req,
        enabled=True,
        priority=90,
        createdAt="2026-07-03T12:00:00Z"
    )
    m_upd_resp = update_provider_model_route(pid1, mid1, model_req_upd)
    _eq(m_upd_resp.success, True, "Model updated")
    _eq(m_upd_resp.data["alias"], "custom-1-updated", "Alias updated")
    _eq(m_upd_resp.data["priority"], 90, "Priority updated")

    # Capabilities check
    cap_resp = get_provider_capabilities(pid1)
    _eq(cap_resp.success, True, "Capabilities retrieval")
    _eq(cap_resp.data["vision"], True, "Vision flag aggregated")

    # Health check
    health_resp = get_provider_health(pid1)
    _eq(health_resp.data["status"], "HEALTHY", "Health score status HEALTHY")

    # Summary check
    sum_resp = get_provider_summary_route(pid1)
    _eq(sum_resp.success, True, "Summary retrieval")
    _true("Custom Provider" in sum_resp.data["summary"], "Summary lists displayName")

    # Delete model
    m_del_resp = delete_provider_model_route(pid1, mid1)
    _eq(m_del_resp.success, True, "Model deleted")

    # List models again
    m_list2 = list_provider_models(pid1)
    _eq(len(m_list2.data), 0, "No models remaining")

    # Update provider details
    upd1 = UpdateProviderRequest(displayName="Updated Custom Provider", healthScore=45.0)
    upd_resp1 = update_provider(pid1, upd1)
    _eq(upd_resp1.success, True, "Update provider details")
    _eq(upd_resp1.data["displayName"], "Updated Custom Provider", "displayName updated")
    _eq(upd_resp1.data["healthScore"], 45.0, "healthScore updated")

    # Check health status moves to OFFLINE
    health_resp2 = get_provider_health(pid1)
    _eq(health_resp2.data["status"], "OFFLINE", "Health status OFFLINE")

    # Delete provider
    del_resp = delete_provider(pid1)
    _eq(del_resp.success, True, "Provider deleted")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_providers = []
    for j in range(5):
        bulk_providers.append(CreateProviderRequest(
            providerName=f"bulk-prov-{j}",
            displayName=f"Bulk Provider {j}",
            apiVersion="v1",
            endpoint=f"https://api.bulk-{j}.com",
            supportedModels=[f"model-{j}"],
            defaultModel=f"model-{j}",
            createdAt=f"2026-07-03T13:{j:02d}:00Z",
            enabled=True,
            priority=70,
            healthScore=90.0,
            providerType="cloud",
        ))
    bulk_req = BulkCreateProvidersRequest(providers=bulk_providers)
    bulk_resp = bulk_create_providers(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create providers")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search providers
    search_resp = search_providers_endpoint(q="Bulk Provider", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk Provider'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["providers"]), 3, "Page slice size")

    # Bulk Update
    pids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for pid in pids_to_update:
        update_items.append({
            "providerId": pid,
            "update": UpdateProviderRequest(priority=95)
        })
    bulk_upd_req = BulkUpdateProvidersRequest(items=update_items)
    bulk_upd_resp = bulk_update_providers(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for pid in pids_to_update:
        p_get = get_provider(pid)
        _eq(p_get.data["priority"], 95, "Bulk priority updated")

    # Bulk Delete
    pids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteProvidersRequest(providerIds=pids_to_delete)
    bulk_del_resp = bulk_delete_providers(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    # Validation failures on empty fields
    val_fail_req = CreateProviderRequest(
        providerName="", displayName="", apiVersion="", endpoint="", defaultModel="", createdAt=""
    )
    _eq(len(val_fail_req.validate_request()), 3, "Validation fails for empty fields")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
