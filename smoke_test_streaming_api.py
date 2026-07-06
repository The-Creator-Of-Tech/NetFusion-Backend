"""
Smoke Test — AI Streaming API (Phase A4.8.9)
==============================================
Tests all endpoints, utilities, models, and edge cases.
Target: 1800+ assertions.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.streaming_router import (
    streaming_router,
    _reset_store,
    _STREAM_STORE,
    list_streams,
    get_statistics,
    search_streams_endpoint,
    get_stream,
    create_stream,
    update_stream,
    delete_stream,
    get_stream_status_endpoint,
    get_stream_summary_endpoint,
    get_stream_chunks,
    append_chunk_endpoint,
    update_chunk_endpoint,
    delete_chunk_endpoint,
    start_stream,
    pause_stream,
    resume_stream,
    cancel_stream,
    bulk_create_streams,
    bulk_update_streams,
    bulk_delete_streams,
    # Helpers
    find_stream,
    search_streams,
    sort_streams,
    filter_streams,
    paginate_streams,
    append_stream_chunk,
    update_stream_chunk,
    delete_stream_chunk,
    find_stream_chunk,
    search_stream_chunks,
    build_stream_summary,
    calculate_stream_statistics,
    get_stream_status,
)
from api.ai.streaming_models import (
    CreateStreamRequest,
    UpdateStreamRequest,
    StreamChunkRequest,
    StreamChunkResponse,
    StreamResponse,
    StreamListResponse,
    StreamStatisticsResponse,
    StreamStatusResponse,
    StreamSummaryResponse,
    BulkCreateStreamsRequest,
    BulkUpdateStreamsRequest,
    BulkDeleteStreamsRequest,
    BulkOperationResult,
)
from services.groq_streaming_service import build_stream_chunk
from api.models import APIResponse

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

def _raises(exc_type, fn, label: str) -> None:
    global _PASS, _FAIL
    try:
        fn()
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {exc_type.__name__}, got no exception")
    except exc_type:
        _PASS += 1
    except Exception as e:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {exc_type.__name__}, got {type(e).__name__}: {e}")

# ---------------------------------------------------------------------------
# Run Tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    global _PASS, _FAIL
    print("Starting AI Streaming API Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in streaming_router.routes}
    expected_paths = {
        "/streaming",
        "/streaming/statistics",
        "/streaming/search",
        "/streaming/{streamId}",
        "/streaming/{streamId}/status",
        "/streaming/{streamId}/summary",
        "/streaming/{streamId}/chunks",
        "/streaming/{streamId}/chunks/{chunkId}",
        "/streaming/{streamId}/start",
        "/streaming/{streamId}/pause",
        "/streaming/{streamId}/resume",
        "/streaming/{streamId}/cancel",
        "/streaming/bulk/create",
        "/streaming/bulk/update",
        "/streaming/bulk/delete",
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered in router")

    # =======================================================================
    # 2. Programmatic Sort Testing (80 items -> 7 fields * 2 orders * 79 pairs = 1106 assertions)
    # =======================================================================
    streams: List[Dict[str, Any]] = []
    for i in range(80):
        # Build deterministic chunks list
        chunks_list = []
        for seq in range(i % 5):
            chunks_list.append(
                build_stream_chunk(
                    stream_id=f"stream-{i:03d}",
                    sequence_number=seq,
                    content=f"token {seq} for {i}",
                )
            )
            
        acc_content = "".join(c.content for c in chunks_list)
        
        streams.append({
            "streamId": f"stream-{i:03d}",
            "requestId": f"req-{i:03d}",
            "streamName": f"Stream Name {i:03d}",
            "provider": f"provider-{(i % 3)}",
            "model": f"model-{(i % 4)}",
            "status": "completed" if i % 3 == 0 else ("paused" if i % 3 == 1 else "active"),
            "createdAt": f"2026-07-06T10:{i:02d}:00Z",
            "updatedAt": f"2026-07-06T11:{i:02d}:00Z",
            "userId": f"user-{(i % 5)}",
            "projectId": f"proj-{(i % 2)}",
            "investigationId": f"inv-{(i % 6)}",
            "chunks": chunks_list,
            "accumulatedContent": acc_content,
            "finishReason": "stop" if i % 3 == 0 else None,
            "startedAt": 1000 + i * 10,
            "completedAt": 2000 + i * 20 if i % 3 == 0 else 0,
            "totalTokens": max(0, -(-len(acc_content) // 4)),
            "latencyMs": (1000 + i * 10) if i % 3 == 0 else 0,
            "warnings": [],
        })

    sort_fields = ["streamName", "createdAt", "updatedAt", "status", "chunkCount", "totalTokens", "latencyMs"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_streams(streams, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 80, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(79):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                if field == "streamName":
                    v1, v2 = s1["streamName"], s2["streamName"]
                elif field == "createdAt":
                    v1, v2 = s1["createdAt"], s2["createdAt"]
                elif field == "updatedAt":
                    v1, v2 = s1["updatedAt"], s2["updatedAt"]
                elif field == "status":
                    v1, v2 = s1["status"], s2["status"]
                elif field == "chunkCount":
                    v1, v2 = len(s1["chunks"]), len(s2["chunks"])
                elif field == "totalTokens":
                    v1, v2 = s1["totalTokens"], s2["totalTokens"]
                elif field == "latencyMs":
                    v1, v2 = s1["latencyMs"], s2["latencyMs"]
                
                if reverse:
                    _true(v1 >= v2, f"Sort verify: {field} desc index {k}: {v1!r} >= {v2!r}")
                else:
                    _true(v1 <= v2, f"Sort verify: {field} asc index {k}: {v1!r} <= {v2!r}")

    # =======================================================================
    # 3. Filtering Helper Verification (20 combinations * average matched checks = 900+ assertions)
    # =======================================================================
    filter_tests = [
        ({"status": "active"}, lambda s: s["status"] == "active"),
        ({"status": "completed"}, lambda s: s["status"] == "completed"),
        ({"status": "paused"}, lambda s: s["status"] == "paused"),
        ({"provider": "provider-0"}, lambda s: s["provider"] == "provider-0"),
        ({"provider": "provider-1"}, lambda s: s["provider"] == "provider-1"),
        ({"provider": "provider-2"}, lambda s: s["provider"] == "provider-2"),
        ({"model": "model-0"}, lambda s: s["model"] == "model-0"),
        ({"model": "model-3"}, lambda s: s["model"] == "model-3"),
        ({"userId": "user-1"}, lambda s: s["userId"] == "user-1"),
        ({"projectId": "proj-0"}, lambda s: s["projectId"] == "proj-0"),
        ({"projectId": "proj-1"}, lambda s: s["projectId"] == "proj-1"),
        ({"investigationId": "inv-3"}, lambda s: s["investigationId"] == "inv-3"),
        ({"minimumChunks": 3}, lambda s: len(s["chunks"]) >= 3),
        ({"maximumChunks": 1}, lambda s: len(s["chunks"]) <= 1),
        ({"minimumTokens": 10}, lambda s: s["totalTokens"] >= 10),
        ({"maximumTokens": 5}, lambda s: s["totalTokens"] <= 5),
        ({"minimumLatency": 1200}, lambda s: s["latencyMs"] >= 1200),
        ({"maximumLatency": 1100}, lambda s: s["latencyMs"] <= 1100),
        ({"createdAfter": "2026-07-06T10:15:00Z"}, lambda s: s["createdAt"] > "2026-07-06T10:15:00Z"),
        ({"createdBefore": "2026-07-06T10:30:00Z"}, lambda s: s["createdAt"] < "2026-07-06T10:30:00Z"),
    ]

    for f_params, cond in filter_tests:
        filtered = filter_streams(streams, **f_params)
        expected_len = len([s for s in streams if cond(s)])
        _eq(len(filtered), expected_len, f"Filter {f_params} count")
        for item in filtered:
            _true(cond(item), f"Item {item['streamId']} satisfies filter {f_params}")

    # =======================================================================
    # 4. Pagination Helper Verification (20 sizes * 3 pages * 5 checks = 300 assertions)
    # =======================================================================
    for size in range(1, 21):
        for page in range(1, 4):
            slice_list, pagination = paginate_streams(streams, page=page, page_size=size)
            _eq(pagination.page, page, f"Pag page size={size} page={page}")
            _eq(pagination.pageSize, size, f"Pag size size={size} page={page}")
            _eq(pagination.totalItems, 80, f"Pag total size={size} page={page}")
            _eq(pagination.totalPages, math.ceil(80 / size), f"Pag pages size={size} page={page}")
            
            expected_len = min(size, max(0, 80 - (page - 1) * size))
            _eq(len(slice_list), expected_len, f"Pag slice length size={size} page={page}")

    # =======================================================================
    # 5. Endpoint CRUD Verification (Start from reset store)
    # =======================================================================
    _reset_store()
    _eq(len(_STREAM_STORE), 0, "Store empty after reset")

    # POST / create 5 streams
    for i in range(5):
        body = CreateStreamRequest(
            requestId=f"req-endpoint-{i}",
            provider="groq",
            model="llama3-70b",
            createdAt=f"2026-07-06T10:00:0{i}Z",
            streamName=f"My Stream {i}",
            userId="analyst-x",
            projectId="proj-y",
            investigationId="inv-z",
            status="active",
        )
        resp = create_stream(body)
        _true(resp.success, f"Create stream {i} response success")
        _eq(resp.message, "Stream created successfully.", f"Create stream {i} message")
        _true(resp.data["streamId"] is not None, f"Create stream {i} streamId present")
        _eq(resp.data["requestId"], f"req-endpoint-{i}", f"Create stream {i} requestId")
        _eq(resp.data["streamName"], f"My Stream {i}", f"Create stream {i} streamName")

    _eq(len(_STREAM_STORE), 5, "Store has 5 streams after creation")

    # POST duplicate requestId -> CONFLICT (409)
    body_dup = CreateStreamRequest(
        requestId="req-endpoint-0",
        provider="groq",
        model="llama3-70b",
        createdAt="2026-07-06T10:00:00Z",
    )
    resp_dup = create_stream(body_dup)
    _false(resp_dup.success, "Duplicate create response success is False")
    _eq(resp_dup.data.errorCode, "CONFLICT", "Duplicate create error code")

    # POST validation failure -> VALIDATION_ERROR (422)
    body_bad = CreateStreamRequest(
        requestId="",
        provider="groq",
        model="",
        createdAt="2026-07-06T10:00:00Z",
    )
    resp_bad = create_stream(body_bad)
    _false(resp_bad.success, "Bad create response success is False")
    _eq(resp_bad.data.errorCode, "VALIDATION_ERROR", "Bad create error code")

    # GET /{streamId} retrieval
    stream_ids = sorted(list(_STREAM_STORE.keys()))
    for sid in stream_ids:
        resp_get = get_stream(sid)
        _true(resp_get.success, f"Get stream {sid} success")
        _eq(resp_get.data["streamId"], sid, f"Get stream {sid} streamId")
        _eq(resp_get.data["provider"], "groq", f"Get stream {sid} provider")
        _eq(resp_get.data["userId"], "analyst-x", f"Get stream {sid} userId")

    # GET missing streamId -> NOT_FOUND (404)
    resp_missing = get_stream("stream-missing-id")
    _false(resp_missing.success, "Get missing stream response success is False")
    _eq(resp_missing.data.errorCode, "NOT_FOUND", "Get missing stream error code")

    # PUT /{streamId} updates
    update_body = UpdateStreamRequest(
        streamName="Updated Stream Name",
        status="paused",
        userId="analyst-updated",
        projectId="proj-updated",
        investigationId="inv-updated",
        updatedAt="2026-07-06T10:10:00Z",
    )
    resp_upd = update_stream(stream_ids[0], update_body)
    _true(resp_upd.success, "Update stream success")
    _eq(resp_upd.data["streamName"], "Updated Stream Name", "Update stream name check")
    _eq(resp_upd.data["status"], "paused", "Update stream status check")
    _eq(resp_upd.data["userId"], "analyst-updated", "Update stream userId check")
    _eq(resp_upd.data["projectId"], "proj-updated", "Update stream projectId check")
    _eq(resp_upd.data["investigationId"], "inv-updated", "Update stream investigationId check")
    _eq(resp_upd.data["updatedAt"], "2026-07-06T10:10:00Z", "Update stream updatedAt check")

    # PUT update with no fields -> VALIDATION_ERROR (422)
    resp_upd_empty = update_stream(stream_ids[0], UpdateStreamRequest())
    _false(resp_upd_empty.success, "Empty update response success is False")
    _eq(resp_upd_empty.data.errorCode, "VALIDATION_ERROR", "Empty update error code")

    # PUT missing stream -> NOT_FOUND (404)
    resp_upd_missing = update_stream("stream-missing-id", update_body)
    _false(resp_upd_missing.success, "Update missing stream response success is False")
    _eq(resp_upd_missing.data.errorCode, "NOT_FOUND", "Update missing stream error code")

    # DELETE /{streamId} delete a stream
    target_delete = stream_ids[4]
    resp_del = delete_stream(target_delete)
    _true(resp_del.success, "Delete stream success")
    _eq(len(_STREAM_STORE), 4, "Store has 4 streams after deletion")
    resp_del_get = get_stream(target_delete)
    _false(resp_del_get.success, "Deleted stream cannot be retrieved")
    _eq(resp_del_get.data.errorCode, "NOT_FOUND", "Deleted stream get error code")

    # DELETE missing stream -> NOT_FOUND (404)
    resp_del_missing = delete_stream("stream-missing-id")
    _false(resp_del_missing.success, "Delete missing stream response success is False")
    _eq(resp_del_missing.data.errorCode, "NOT_FOUND", "Delete missing stream error code")

    # =======================================================================
    # 6. Chunks CRUD Verification
    # =======================================================================
    active_stream_id = stream_ids[1]

    # Append 5 chunks to active_stream_id
    chunk_ids = []
    for seq in range(5):
        chunk_req = StreamChunkRequest(
            sequenceNumber=seq,
            content=f"Hello token {seq}!",
            finishReason="stop" if seq == 4 else None,
        )
        resp_chunk = append_chunk_endpoint(active_stream_id, chunk_req)
        _true(resp_chunk.success, f"Append chunk {seq} success")
        _eq(resp_chunk.message, "Chunk appended successfully.", f"Append chunk {seq} message")
        _eq(resp_chunk.data["sequenceNumber"], seq, f"Append chunk {seq} sequenceNumber")
        _eq(resp_chunk.data["content"], f"Hello token {seq}!", f"Append chunk {seq} content")
        _eq(resp_chunk.data["finishReason"], "stop" if seq == 4 else None, f"Append chunk {seq} finishReason")
        chunk_ids.append(resp_chunk.data["chunkId"])

    # Verify stream status transitions to completed because sequence 4 has finishReason='stop'
    resp_status = get_stream_status_endpoint(active_stream_id)
    _true(resp_status.success, "Get stream status success")
    _eq(resp_status.data["status"], "completed", "Status transitioned to completed")
    _true(resp_status.data["completed"], "Completed flag is True")
    _eq(resp_status.data["chunkCount"], 5, "Chunk count is 5")

    # Verify duplicate chunk sequenceNumber -> CONFLICT (409)
    chunk_req_dup = StreamChunkRequest(
        sequenceNumber=0,
        content="duplicate",
    )
    resp_chunk_dup = append_chunk_endpoint(active_stream_id, chunk_req_dup)
    _false(resp_chunk_dup.success, "Duplicate chunk response success is False")
    _eq(resp_chunk_dup.data.errorCode, "CONFLICT", "Duplicate chunk error code")

    # Verify invalid chunk sequenceNumber -> VALIDATION_ERROR (422)
    chunk_req_bad = StreamChunkRequest(
        sequenceNumber=-1,
        content="bad seq",
    )
    resp_chunk_bad = append_chunk_endpoint(active_stream_id, chunk_req_bad)
    _false(resp_chunk_bad.success, "Bad chunk response success is False")
    _eq(resp_chunk_bad.data.errorCode, "VALIDATION_ERROR", "Bad chunk error code")

    # GET /{streamId}/chunks listing
    resp_chunks_list = get_stream_chunks(active_stream_id)
    print("DEBUG RESP CHUNKS LIST:", resp_chunks_list)
    _true(resp_chunks_list.success, "Get chunks list success")
    _eq(len(resp_chunks_list.data), 5, "Returned chunks list has 5 elements")
    for seq in range(5):
        _eq(resp_chunks_list.data[seq]["sequenceNumber"], seq, f"Chunk listing index {seq}")

    # GET /{streamId}/chunks listing with search query q
    resp_chunks_search = get_stream_chunks(active_stream_id, q="token 2")
    _true(resp_chunks_search.success, "Get chunks search success")
    _eq(len(resp_chunks_search.data), 1, "Search returns exactly 1 chunk")
    _eq(resp_chunks_search.data[0]["sequenceNumber"], 2, "Search matches chunk 2")

    # PUT /{streamId}/chunks/{chunkId} update
    chunk_update = StreamChunkRequest(
        sequenceNumber=2,
        content="Updated token 2 content!",
        finishReason=None,
    )
    resp_chunk_upd = update_chunk_endpoint(active_stream_id, chunk_ids[2], chunk_update)
    _true(resp_chunk_upd.success, "Update chunk success")
    _eq(resp_chunk_upd.data["content"], "Updated token 2 content!", "Updated chunk content check")
    _eq(resp_chunk_upd.data["sequenceNumber"], 2, "Updated chunk sequence number check")
    chunk_ids[2] = resp_chunk_upd.data["chunkId"]

    # PUT duplicate sequence number on update -> CONFLICT (409)
    chunk_upd_dup = StreamChunkRequest(
        sequenceNumber=0, # conflict with sequence number 0
        content="conflicting seq",
    )
    resp_chunk_upd_dup = update_chunk_endpoint(active_stream_id, chunk_ids[2], chunk_upd_dup)
    _false(resp_chunk_upd_dup.success, "Duplicate chunk update response success is False")
    _eq(resp_chunk_upd_dup.data.errorCode, "CONFLICT", "Duplicate chunk update error code")

    # PUT missing chunk -> NOT_FOUND (404)
    resp_chunk_upd_missing = update_chunk_endpoint(active_stream_id, "chunk-missing-id", chunk_update)
    _false(resp_chunk_upd_missing.success, "Update missing chunk response success is False")
    _eq(resp_chunk_upd_missing.data.errorCode, "NOT_FOUND", "Update missing chunk error code")

    # DELETE /{streamId}/chunks/{chunkId} deletion
    resp_chunk_del = delete_chunk_endpoint(active_stream_id, chunk_ids[1])
    _true(resp_chunk_del.success, "Delete chunk success")
    resp_chunks_post_del = get_stream_chunks(active_stream_id)
    _eq(len(resp_chunks_post_del.data), 4, "Chunks list has 4 elements after deletion")
    # Verify sequence number 1 is not in the list
    chunk_seqs = {c["sequenceNumber"] for c in resp_chunks_post_del.data}
    _false(1 in chunk_seqs, "Sequence number 1 is deleted")

    # DELETE missing chunk -> NOT_FOUND (404)
    resp_chunk_del_missing = delete_chunk_endpoint(active_stream_id, "chunk-missing-id")
    _false(resp_chunk_del_missing.success, "Delete missing chunk response success is False")
    _eq(resp_chunk_del_missing.data.errorCode, "NOT_FOUND", "Delete missing chunk error code")

    # =======================================================================
    # 7. Lifecycle Endpoints (start, pause, resume, cancel)
    # =======================================================================
    lifecycle_sid = stream_ids[2]

    # POST /{streamId}/start
    resp_start = start_stream(lifecycle_sid)
    _true(resp_start.success, "Start stream success")
    _eq(resp_start.data["status"], "active", "Started status is active")

    # POST /{streamId}/pause
    resp_pause = pause_stream(lifecycle_sid)
    _true(resp_pause.success, "Pause stream success")
    _eq(resp_pause.data["status"], "paused", "Paused status is paused")

    # POST /{streamId}/resume
    resp_resume = resume_stream(lifecycle_sid)
    _true(resp_resume.success, "Resume stream success")
    _eq(resp_resume.data["status"], "active", "Resumed status is active")

    # POST /{streamId}/cancel
    resp_cancel = cancel_stream(lifecycle_sid)
    _true(resp_cancel.success, "Cancel stream success")
    _eq(resp_cancel.data["status"], "cancelled", "Cancelled status is cancelled")
    _true(resp_cancel.data["latencyMs"] >= 0, "Cancelled stream latencyMs calculated")

    # =======================================================================
    # 8. GET /{streamId}/summary
    # =======================================================================
    resp_summary = get_stream_summary_endpoint(active_stream_id)
    _true(resp_summary.success, "Get summary success")
    _eq(resp_summary.data["streamId"], active_stream_id, "Summary streamId check")
    _eq(resp_summary.data["chunkCount"], 4, "Summary chunkCount check")
    _true("Stream summary:" in resp_summary.data["summaryText"], "Summary text contains prefix")

    # =======================================================================
    # 9. GET /search & GET / (Endpoints)
    # =======================================================================
    # GET / (List streams endpoint)
    resp_list_endpoints = list_streams(page=1, pageSize=10, sortBy="streamName", sortOrder="asc")
    _true(resp_list_endpoints.success, "List streams endpoint success")
    _eq(len(resp_list_endpoints.data), 4, "List streams has 4 streams in data")
    _true("pagination" in resp_list_endpoints.metadata, "Pagination metadata present")

    # GET /search
    resp_search_endpoint = search_streams_endpoint(q="llama3", page=1, pageSize=10)
    _true(resp_search_endpoint.success, "Search streams endpoint success")
    _eq(len(resp_search_endpoint.data), 4, "Search streams returns 4 streams matching llama3")

    # =======================================================================
    # 10. Bulk Operations (create, update, delete)
    # =======================================================================
    # Bulk Create
    dup_req_id = _STREAM_STORE[active_stream_id]["requestId"]
    bulk_create_body = BulkCreateStreamsRequest(
        streams=[
            CreateStreamRequest(
                requestId="req-bulk-create-1",
                provider="groq",
                model="llama3-8b",
                createdAt="2026-07-06T10:30:00Z",
                streamName="Bulk Stream 1",
            ),
            CreateStreamRequest(
                requestId="req-bulk-create-2",
                provider="groq",
                model="llama3-8b",
                createdAt="2026-07-06T10:30:00Z",
                streamName="Bulk Stream 2",
            ),
            # Duplicate one to test failed list
            CreateStreamRequest(
                requestId=dup_req_id, # duplicate -> business validation failure
                provider="groq",
                model="llama3-8b",
                createdAt="2026-07-06T10:30:00Z",
            ),
        ]
    )
    resp_bulk_c = bulk_create_streams(bulk_create_body)
    _true(resp_bulk_c.success, "Bulk create response success")
    bulk_res = BulkOperationResult(**resp_bulk_c.data)
    _eq(bulk_res.total, 3, "Bulk create total items is 3")
    _eq(bulk_res.successCount, 2, "Bulk create successCount is 2")
    _eq(bulk_res.failCount, 1, "Bulk create failCount is 1")
    _eq(len(bulk_res.succeeded), 2, "Bulk create succeeded length is 2")
    _eq(len(bulk_res.failed), 1, "Bulk create failed length is 1")
    
    # Store the bulk created ids
    bulk_sids = bulk_res.succeeded

    # Bulk Update
    bulk_update_body = BulkUpdateStreamsRequest(
        items=[
            BulkUpdateStreamsRequest.BulkUpdateItem(
                streamId=bulk_sids[0],
                update=UpdateStreamRequest(
                    streamName="Bulk Stream 1 Updated",
                    status="paused",
                )
            ),
            BulkUpdateStreamsRequest.BulkUpdateItem(
                streamId=bulk_sids[1],
                update=UpdateStreamRequest(
                    streamName="Bulk Stream 2 Updated",
                    status="completed",
                )
            ),
            # Missing one to test failure
            BulkUpdateStreamsRequest.BulkUpdateItem(
                streamId="stream-missing-id",
                update=UpdateStreamRequest(
                    streamName="Doesn't matter",
                )
            )
        ]
    )
    resp_bulk_u = bulk_update_streams(bulk_update_body)
    _true(resp_bulk_u.success, "Bulk update response success")
    bulk_u_res = BulkOperationResult(**resp_bulk_u.data)
    _eq(bulk_u_res.total, 3, "Bulk update total items is 3")
    _eq(bulk_u_res.successCount, 2, "Bulk update successCount is 2")
    _eq(bulk_u_res.failCount, 1, "Bulk update failCount is 1")

    # Bulk Delete
    bulk_delete_body = BulkDeleteStreamsRequest(
        streamIds=[
            bulk_sids[0],
            bulk_sids[1],
            "stream-missing-id",
        ]
    )
    resp_bulk_d = bulk_delete_streams(bulk_delete_body)
    _true(resp_bulk_d.success, "Bulk delete response success")
    bulk_d_res = BulkOperationResult(**resp_bulk_d.data)
    _eq(bulk_d_res.total, 3, "Bulk delete total items is 3")
    _eq(bulk_d_res.successCount, 2, "Bulk delete successCount is 2")
    _eq(bulk_d_res.failCount, 1, "Bulk delete failCount is 1")

    # =======================================================================
    # 11. Statistics Verification
    # =======================================================================
    resp_stats = get_statistics()
    _true(resp_stats.success, "Get statistics endpoint success")
    stats_data = resp_stats.data
    _eq(stats_data["totalStreams"], 4, "Stats totalStreams check")
    _eq(stats_data["completedStreams"], 1, "Stats completedStreams check (active_stream_id is completed)")
    _eq(stats_data["cancelledStreams"], 1, "Stats cancelledStreams check (lifecycle_sid is cancelled)")
    _is(stats_data["averageChunks"], float, "Stats averageChunks is float")
    _is(stats_data["averageTokens"], float, "Stats averageTokens is float")
    _is(stats_data["averageLatency"], float, "Stats averageLatency is float")
    _true("active" in stats_data["statusCounts"], "active in statusCounts")
    _true("groq" in stats_data["providerCounts"], "groq in providerCounts")

    # =======================================================================
    # 12. Serialization & Model Assertions
    # =======================================================================
    # CreateStreamRequest
    req_c = CreateStreamRequest(requestId="r-1", provider="p-1", model="m-1", createdAt="2026-07-06T10:00:00Z")
    req_c_json = req_c.model_dump_json()
    req_c_parsed = CreateStreamRequest.model_validate_json(req_c_json)
    _eq(req_c_parsed.requestId, "r-1", "Serialize CreateStreamRequest requestId")
    _eq(req_c_parsed.provider, "p-1", "Serialize CreateStreamRequest provider")
    
    # UpdateStreamRequest
    req_u = UpdateStreamRequest(streamName="n-1", status="active")
    _true(req_u.has_any_field(), "UpdateStreamRequest has_any_field")
    _false(UpdateStreamRequest().has_any_field(), "Empty UpdateStreamRequest does not has_any_field")
    
    # StreamChunkRequest
    req_ch = StreamChunkRequest(sequenceNumber=1, content="t-1", finishReason="stop")
    _eq(req_ch.sequenceNumber, 1, "Serialize StreamChunkRequest sequenceNumber")
    
    # StreamChunkResponse
    resp_ch = StreamChunkResponse(chunkId="c-1", sequenceNumber=1, content="t-1", finishReason="stop", receivedAt=123)
    _eq(resp_ch.chunkId, "c-1", "Serialize StreamChunkResponse chunkId")
    _eq(resp_ch.receivedAt, 123, "Serialize StreamChunkResponse receivedAt")

    # StreamResponse
    resp_s = StreamResponse(
        streamId="s-1",
        requestId="r-1",
        streamName="n-1",
        provider="p-1",
        model="m-1",
        status="active",
        createdAt="2026-07-06T10:00:00Z",
        updatedAt="2026-07-06T10:00:00Z",
        userId="u-1",
        projectId="pr-1",
        investigationId="i-1",
        chunkCount=1,
        totalTokens=5,
        latencyMs=100,
        accumulatedContent="acc",
        finishReason="stop",
        chunks=[resp_ch],
    )
    _eq(resp_s.streamId, "s-1", "Serialize StreamResponse streamId")
    _eq(len(resp_s.chunks), 1, "Serialize StreamResponse chunks length")

    # StreamListResponse
    resp_sl = StreamListResponse(streams=[resp_s], total=1)
    _eq(resp_sl.total, 1, "Serialize StreamListResponse total")

    # StreamStatisticsResponse
    resp_stat = StreamStatisticsResponse(
        totalStreams=1,
        activeStreams=1,
        pausedStreams=0,
        completedStreams=0,
        cancelledStreams=0,
        failedStreams=0,
        averageChunks=1.0,
        averageTokens=5.0,
        averageLatency=100.0,
        statusCounts={"active": 1},
        providerCounts={"p-1": 1},
    )
    _eq(resp_stat.totalStreams, 1, "Serialize StreamStatisticsResponse totalStreams")

    # StreamStatusResponse
    resp_ss = StreamStatusResponse(streamId="s-1", status="active", chunkCount=1, totalTokens=5, latencyMs=100, completed=False)
    _eq(resp_ss.completed, False, "Serialize StreamStatusResponse completed")

    # StreamSummaryResponse
    resp_sum = StreamSummaryResponse(
        streamId="s-1",
        requestId="r-1",
        streamName="n-1",
        status="active",
        chunkCount=1,
        totalTokens=5,
        latencyMs=100,
        summaryText="summary",
        createdAt="2026-07-06T10:00:00Z",
        updatedAt="2026-07-06T10:00:00Z",
    )
    _eq(resp_sum.summaryText, "summary", "Serialize StreamSummaryResponse summaryText")

    # BulkCreateStreamsRequest
    bulk_c_req = BulkCreateStreamsRequest(streams=[req_c])
    _eq(len(bulk_c_req.streams), 1, "Serialize BulkCreateStreamsRequest streams length")

    # BulkUpdateStreamsRequest
    bulk_u_req = BulkUpdateStreamsRequest(items=[BulkUpdateStreamsRequest.BulkUpdateItem(streamId="s-1", update=req_u)])
    _eq(bulk_u_req.items[0].streamId, "s-1", "Serialize BulkUpdateStreamsRequest items streamId")

    # BulkDeleteStreamsRequest
    bulk_d_req = BulkDeleteStreamsRequest(streamIds=["s-1"])
    _eq(bulk_d_req.streamIds[0], "s-1", "Serialize BulkDeleteStreamsRequest streamIds")

    # BulkOperationResult
    bulk_op_res = BulkOperationResult(succeeded=["s-1"], failed=[], total=1, successCount=1, failCount=0)
    _eq(bulk_op_res.successCount, 1, "Serialize BulkOperationResult successCount")

    # Summary of assertion counts
    print(f"\nSmoke Test Completed.")
    print(f"Total Passed Assertions: {_PASS}")
    print(f"Total Failed Assertions: {_FAIL}")
    
    if _FAIL == 0:
        print("ALL ASSERTIONS PASSED")
    else:
        print("SOME ASSERTIONS FAILED")
        raise AssertionError("Smoke test failed because some assertions did not pass.")

if __name__ == "__main__":
    run_tests()
