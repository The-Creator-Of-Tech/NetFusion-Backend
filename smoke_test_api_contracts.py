"""
Smoke Test — API Contracts
===========================
Phase A4.7.1 — Comprehensive test suite for the NetFusion V2 API layer.

Covers
------
- API_LAYER_VERSION constant
- Models: APIResponse, APIError, Pagination, HealthResponse, VersionResponse
- Model immutability (frozen=True)
- Model serialisation (model_dump round-trip)
- Exception hierarchy: APILayerError, APIErrorValidation, APIErrorNotFound,
  APIErrorConflict, APIErrorInternal
- Response builders: build_success_response, build_error_response,
  build_error_response_from_exception, build_paginated_response
- Utility helpers: exception_to_api_response, validate_pagination,
  build_health_response, build_version_response, get_engine_version_registry
- Router registration: root_router, all 6 sub-routers, prefixes, tags
- System endpoints registered on system_router
- Deterministic engine version registry (sorted, stable, complete)
- Pagination edge cases
- Error detail propagation
- Metadata merging
- Edge cases and zero-randomness properties

Target: 300+ assertions
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Assertion counter
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_ERRORS: list = []


def _assert(condition: bool, msg: str) -> None:
    global _PASS, _FAIL
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
        _ERRORS.append(f"FAIL: {msg}")
        print(f"  FAIL: {msg}")


def _assert_raises(exc_type, fn, *args, msg: str = "", **kwargs) -> None:
    global _PASS, _FAIL
    try:
        fn(*args, **kwargs)
        _FAIL += 1
        _ERRORS.append(f"FAIL (no exception): {msg or fn.__name__}")
        print(f"  FAIL (no exception): {msg or fn.__name__}")
    except exc_type:
        _PASS += 1
    except Exception as e:
        _FAIL += 1
        _ERRORS.append(f"FAIL (wrong exception {type(e).__name__}): {msg}")
        print(f"  FAIL (wrong exception {type(e).__name__}): {msg}")


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from core.constants import API_LAYER_VERSION

from api.models import (
    APIError,
    APIResponse,
    HealthResponse,
    Pagination,
    VersionResponse,
)
from api.errors import (
    APILayerError,
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.responses import (
    build_error_response,
    build_error_response_from_exception,
    build_paginated_response,
    build_success_response,
)
from api.utils import (
    build_health_response,
    build_version_response,
    exception_to_api_response,
    get_engine_version_registry,
    validate_pagination,
)
from api.router import (
    root_router,
    investigation_router,
    ai_router,
    knowledge_router,
    workflow_router,
    reports_router,
    system_router,
)

TS = "2026-07-03T00:00:00Z"

print("=" * 60)
print("API Contracts Smoke Test")
print("=" * 60)


# ===========================================================================
# 1. API_LAYER_VERSION constant
# ===========================================================================
print("\n[1] API_LAYER_VERSION")

_assert(API_LAYER_VERSION == "api-layer-v1",          "API_LAYER_VERSION value")
_assert(isinstance(API_LAYER_VERSION, str),            "API_LAYER_VERSION is str")
_assert(len(API_LAYER_VERSION) > 0,                    "API_LAYER_VERSION non-empty")
_assert("v1" in API_LAYER_VERSION,                     "API_LAYER_VERSION contains v1")


# ===========================================================================
# 2. Enumerations / Model fields
# ===========================================================================
print("\n[2] Model field contracts")

# APIResponse required fields exist
r = APIResponse(success=True, message="OK")
_assert(hasattr(r, "success"),    "APIResponse has success")
_assert(hasattr(r, "message"),    "APIResponse has message")
_assert(hasattr(r, "data"),       "APIResponse has data")
_assert(hasattr(r, "metadata"),   "APIResponse has metadata")
_assert(hasattr(r, "timestamp"),  "APIResponse has timestamp")
_assert(r.success  == True,       "APIResponse success default True")
_assert(r.message  == "OK",       "APIResponse message set")
_assert(r.data     is None,       "APIResponse data defaults None")
_assert(r.metadata is None,       "APIResponse metadata defaults None")
_assert(r.timestamp is None,      "APIResponse timestamp defaults None")

# APIError required fields
e = APIError(errorCode="TEST", error="test error")
_assert(hasattr(e, "errorCode"), "APIError has errorCode")
_assert(hasattr(e, "error"),     "APIError has error")
_assert(hasattr(e, "details"),   "APIError has details")
_assert(e.errorCode == "TEST",   "APIError errorCode set")
_assert(e.error     == "test error", "APIError error set")
_assert(e.details   is None,     "APIError details defaults None")

# APIError with details
e2 = APIError(errorCode="VAL", error="invalid", details=["f1 required", "f2 bad"])
_assert(len(e2.details) == 2,    "APIError details length 2")
_assert(e2.details[0]   == "f1 required", "APIError details[0]")

# Pagination required fields
p = Pagination(page=2, pageSize=20, totalItems=100, totalPages=5)
_assert(hasattr(p, "page"),       "Pagination has page")
_assert(hasattr(p, "pageSize"),   "Pagination has pageSize")
_assert(hasattr(p, "totalItems"), "Pagination has totalItems")
_assert(hasattr(p, "totalPages"), "Pagination has totalPages")
_assert(p.page       == 2,   "Pagination page")
_assert(p.pageSize   == 20,  "Pagination pageSize")
_assert(p.totalItems == 100, "Pagination totalItems")
_assert(p.totalPages == 5,   "Pagination totalPages")

# HealthResponse fields
h = HealthResponse(status="healthy")
_assert(hasattr(h, "status"),  "HealthResponse has status")
_assert(hasattr(h, "version"), "HealthResponse has version")
_assert(hasattr(h, "uptime"),  "HealthResponse has uptime")
_assert(h.status  == "healthy",       "HealthResponse status set")
_assert(h.version == API_LAYER_VERSION, "HealthResponse version = API_LAYER_VERSION")
_assert(h.uptime  is None,            "HealthResponse uptime defaults None")

# HealthResponse with uptime
h2 = HealthResponse(status="degraded", uptime="2d 03h")
_assert(h2.status == "degraded", "HealthResponse degraded status")
_assert(h2.uptime == "2d 03h",   "HealthResponse uptime set")

# VersionResponse fields
vr = VersionResponse(apiVersion="api-layer-v1", engineVersions={"report": "report-engine-v1"})
_assert(hasattr(vr, "apiVersion"),     "VersionResponse has apiVersion")
_assert(hasattr(vr, "engineVersions"), "VersionResponse has engineVersions")
_assert(vr.apiVersion == "api-layer-v1",     "VersionResponse apiVersion")
_assert(vr.engineVersions["report"] == "report-engine-v1", "VersionResponse engineVersions")


# ===========================================================================
# 3. Model Immutability (frozen=True)
# ===========================================================================
print("\n[3] Model Immutability")

_assert_raises(Exception, setattr, r,  "success",   False, msg="APIResponse frozen")
_assert_raises(Exception, setattr, r,  "message",   "x",   msg="APIResponse message frozen")
_assert_raises(Exception, setattr, r,  "data",      {},    msg="APIResponse data frozen")
_assert_raises(Exception, setattr, r,  "timestamp", "x",   msg="APIResponse timestamp frozen")
_assert_raises(Exception, setattr, e,  "errorCode", "X",   msg="APIError errorCode frozen")
_assert_raises(Exception, setattr, e,  "error",     "X",   msg="APIError error frozen")
_assert_raises(Exception, setattr, p,  "page",       99,   msg="Pagination page frozen")
_assert_raises(Exception, setattr, p,  "pageSize",   99,   msg="Pagination pageSize frozen")
_assert_raises(Exception, setattr, p,  "totalItems", 99,   msg="Pagination totalItems frozen")
_assert_raises(Exception, setattr, p,  "totalPages", 99,   msg="Pagination totalPages frozen")
_assert_raises(Exception, setattr, h,  "status",    "x",   msg="HealthResponse status frozen")
_assert_raises(Exception, setattr, h,  "version",   "x",   msg="HealthResponse version frozen")
_assert_raises(Exception, setattr, vr, "apiVersion","x",   msg="VersionResponse apiVersion frozen")


# ===========================================================================
# 4. Model Serialisation
# ===========================================================================
print("\n[4] Model Serialisation")

# APIResponse round-trip
r_full = APIResponse(
    success=True, message="Created",
    data={"id": "abc"}, metadata={"k": "v"}, timestamp=TS
)
d = r_full.model_dump()
_assert(d["success"]   == True,       "dump success")
_assert(d["message"]   == "Created",  "dump message")
_assert(d["data"]      == {"id": "abc"}, "dump data")
_assert(d["metadata"]  == {"k": "v"}, "dump metadata")
_assert(d["timestamp"] == TS,         "dump timestamp")

r_back = APIResponse(**d)
_assert(r_back.success   == r_full.success,   "round-trip success")
_assert(r_back.message   == r_full.message,   "round-trip message")
_assert(r_back.data      == r_full.data,      "round-trip data")
_assert(r_back.timestamp == r_full.timestamp, "round-trip timestamp")

# APIError round-trip
ae = APIError(errorCode="NOT_FOUND", error="missing", details=["x not found"])
ae_d = ae.model_dump()
_assert(ae_d["errorCode"] == "NOT_FOUND",      "APIError dump errorCode")
_assert(ae_d["error"]     == "missing",        "APIError dump error")
_assert(ae_d["details"]   == ["x not found"],  "APIError dump details")

# Pagination round-trip
p_d = p.model_dump()
_assert(p_d["page"]       == 2,   "Pagination dump page")
_assert(p_d["pageSize"]   == 20,  "Pagination dump pageSize")
_assert(p_d["totalItems"] == 100, "Pagination dump totalItems")
_assert(p_d["totalPages"] == 5,   "Pagination dump totalPages")
p_back = Pagination(**p_d)
_assert(p_back.page == p.page,             "Pagination round-trip page")
_assert(p_back.totalPages == p.totalPages, "Pagination round-trip totalPages")

# HealthResponse round-trip
h_d = HealthResponse(status="healthy", uptime="1h").model_dump()
_assert(h_d["status"]  == "healthy",        "HealthResponse dump status")
_assert(h_d["version"] == API_LAYER_VERSION,"HealthResponse dump version")
_assert(h_d["uptime"]  == "1h",             "HealthResponse dump uptime")

# VersionResponse round-trip
vr_d = vr.model_dump()
_assert("apiVersion"     in vr_d, "VersionResponse dump apiVersion key")
_assert("engineVersions" in vr_d, "VersionResponse dump engineVersions key")


# ===========================================================================
# 5. Exception Hierarchy
# ===========================================================================
print("\n[5] Exception Hierarchy")

# Base class
_assert(issubclass(APILayerError, Exception),            "APILayerError inherits Exception")
_assert(issubclass(APIErrorValidation, APILayerError),   "APIErrorValidation inherits base")
_assert(issubclass(APIErrorNotFound,   APILayerError),   "APIErrorNotFound inherits base")
_assert(issubclass(APIErrorConflict,   APILayerError),   "APIErrorConflict inherits base")
_assert(issubclass(APIErrorInternal,   APILayerError),   "APIErrorInternal inherits base")
_assert(not issubclass(APIErrorValidation, APIErrorNotFound), "no cross-inheritance V/NF")
_assert(not issubclass(APIErrorNotFound, APIErrorConflict),   "no cross-inheritance NF/C")

# Default error codes
_assert(APIErrorValidation().error_code == "VALIDATION_ERROR", "validation error_code")
_assert(APIErrorNotFound().error_code   == "NOT_FOUND",        "not_found error_code")
_assert(APIErrorConflict().error_code   == "CONFLICT",         "conflict error_code")
_assert(APIErrorInternal().error_code   == "INTERNAL_ERROR",   "internal error_code")

# Default HTTP status codes
_assert(APIErrorValidation().http_status == 422, "validation http_status 422")
_assert(APIErrorNotFound().http_status   == 404, "not_found http_status 404")
_assert(APIErrorConflict().http_status   == 409, "conflict http_status 409")
_assert(APIErrorInternal().http_status   == 500, "internal http_status 500")

# Default messages
_assert("validation" in APIErrorValidation().message.lower(), "validation default message")
_assert("not found"  in APIErrorNotFound().message.lower()  or "resource" in APIErrorNotFound().message.lower(), "not_found default message")
_assert("conflict"   in APIErrorConflict().message.lower()  or "request"  in APIErrorConflict().message.lower(), "conflict default message")
_assert("unexpected" in APIErrorInternal().message.lower()  or "internal"  in APIErrorInternal().message.lower(), "internal default message")

# Custom message and details
exc_v = APIErrorValidation("Bad page param", details=["page must be >= 1"])
_assert(exc_v.message      == "Bad page param",    "custom message propagated")
_assert(exc_v.details      == ["page must be >= 1"], "custom details propagated")
_assert(exc_v.error_code   == "VALIDATION_ERROR",  "custom: error_code unchanged")
_assert(exc_v.http_status  == 422,                 "custom: http_status unchanged")

# isinstance checks
_assert(isinstance(exc_v, APILayerError),        "validation is-a APILayerError")
_assert(isinstance(exc_v, APIErrorValidation),   "validation is-a APIErrorValidation")
_assert(isinstance(exc_v, Exception),            "validation is-a Exception")

# str() representation
s = str(exc_v)
_assert("VALIDATION_ERROR" in s, "str contains error_code")
_assert("Bad page param"   in s, "str contains message")
_assert("page must be >= 1" in s, "str contains details")

# repr()
rp = repr(exc_v)
_assert("APIErrorValidation" in rp, "repr contains class name")
_assert("VALIDATION_ERROR"   in rp, "repr contains error_code")

# Empty details defaults to []
exc_nf = APIErrorNotFound("Not found")
_assert(exc_nf.details == [], "empty details defaults to []")

# Multiple details
exc_multi = APIErrorValidation("Multiple errors", details=["e1", "e2", "e3"])
_assert(len(exc_multi.details) == 3, "multiple details stored")

# Base class default error_code
exc_base = APILayerError("base error")
_assert(exc_base.error_code  == "API_ERROR", "base default error_code")
_assert(exc_base.http_status == 500,         "base default http_status")

# Per-instance error_code override
exc_custom = APILayerError("custom", error_code="CUSTOM_CODE")
_assert(exc_custom.error_code == "CUSTOM_CODE", "per-instance error_code override")


# ===========================================================================
# 6. build_success_response()
# ===========================================================================
print("\n[6] build_success_response")

# Default call
sr = build_success_response()
_assert(sr.success   == True,              "success default True")
_assert(sr.message   == "OK",              "success default message OK")
_assert(sr.data      is None,              "success default data None")
_assert(sr.timestamp is None,              "success default timestamp None")
_assert(sr.metadata["apiLayerVersion"] == API_LAYER_VERSION, "success metadata apiLayerVersion")

# With all params
sr2 = build_success_response(
    data={"id": "xyz"}, message="Created", timestamp=TS, metadata={"requestId": "r1"}
)
_assert(sr2.success          == True,        "full success: success")
_assert(sr2.message          == "Created",   "full success: message")
_assert(sr2.data             == {"id":"xyz"},"full success: data")
_assert(sr2.timestamp        == TS,          "full success: timestamp")
_assert(sr2.metadata["requestId"]    == "r1",        "full success: extra metadata")
_assert(sr2.metadata["apiLayerVersion"] == API_LAYER_VERSION, "full success: apiLayerVersion preserved")

# apiLayerVersion always present
sr3 = build_success_response(metadata={"a": "b"})
_assert("apiLayerVersion" in sr3.metadata, "apiLayerVersion always in metadata")
_assert(sr3.metadata["a"] == "b",          "extra metadata merged")

# Extra metadata doesn't clobber apiLayerVersion if key absent
sr4 = build_success_response()
_assert(sr4.metadata["apiLayerVersion"] == API_LAYER_VERSION, "no-extra: apiLayerVersion present")

# Caller can pass apiLayerVersion override (extra takes precedence)
sr5 = build_success_response(metadata={"apiLayerVersion": "override"})
_assert(sr5.metadata["apiLayerVersion"] == "override", "extra apiLayerVersion takes precedence")

# None data doesn't break things
sr6 = build_success_response(data=None)
_assert(sr6.data is None, "explicit None data OK")

# List data
sr7 = build_success_response(data=[1, 2, 3])
_assert(sr7.data == [1, 2, 3], "list data preserved")

# Immutability
_assert_raises(Exception, setattr, sr, "success", False, msg="success_response frozen")


# ===========================================================================
# 7. build_error_response()
# ===========================================================================
print("\n[7] build_error_response")

er = build_error_response("NOT_FOUND", "Thing not found", timestamp=TS)
_assert(er.success          == False,           "error success=False")
_assert(er.message          == "Thing not found","error message")
_assert(er.timestamp        == TS,              "error timestamp")
_assert(isinstance(er.data, APIError),          "error data is APIError")
_assert(er.data.errorCode   == "NOT_FOUND",     "error data.errorCode")
_assert(er.data.error       == "Thing not found","error data.error")
_assert(er.data.details     is None,            "error data.details None when not given")
_assert(er.metadata["apiLayerVersion"] == API_LAYER_VERSION, "error metadata apiLayerVersion")

# With details
er2 = build_error_response("VALIDATION_ERROR", "Bad input", details=["f1 required", "f2 invalid"])
_assert(er2.data.details == ["f1 required", "f2 invalid"], "error details propagated")
_assert(len(er2.data.details) == 2,                         "error details length 2")

# Details list is a copy (mutation of original doesn't affect response)
original_details = ["d1", "d2"]
er3 = build_error_response("X", "x", details=original_details)
original_details.append("d3")
_assert(len(er3.data.details) == 2, "error details copy — mutation doesn't affect response")

# With extra metadata
er4 = build_error_response("CONFLICT", "Duplicate", metadata={"traceId": "t1"})
_assert(er4.metadata["traceId"] == "t1",                    "error extra metadata")
_assert("apiLayerVersion" in er4.metadata,                  "error apiLayerVersion still present")

# Immutability
_assert_raises(Exception, setattr, er, "success", True, msg="error_response frozen")

# success=False for all error responses
for code in ["NOT_FOUND", "CONFLICT", "VALIDATION_ERROR", "INTERNAL_ERROR"]:
    r_tmp = build_error_response(code, "msg")
    _assert(r_tmp.success == False, f"error_response always success=False for {code}")


# ===========================================================================
# 8. build_error_response_from_exception()
# ===========================================================================
print("\n[8] build_error_response_from_exception")

for ExcClass, expected_code, expected_status in [
    (APIErrorValidation, "VALIDATION_ERROR", 422),
    (APIErrorNotFound,   "NOT_FOUND",        404),
    (APIErrorConflict,   "CONFLICT",         409),
    (APIErrorInternal,   "INTERNAL_ERROR",   500),
]:
    exc = ExcClass("test message", details=["detail 1"])
    resp = build_error_response_from_exception(exc, timestamp=TS)
    _assert(resp.success == False,               f"{expected_code}: success=False")
    _assert(resp.data.errorCode == expected_code,f"{expected_code}: errorCode")
    _assert(resp.data.error == "test message",   f"{expected_code}: error message")
    _assert(resp.data.details == ["detail 1"],   f"{expected_code}: details")
    _assert(resp.timestamp == TS,                f"{expected_code}: timestamp")

# Empty details
exc_no_det = APIErrorNotFound("Nothing here")
resp_no_det = build_error_response_from_exception(exc_no_det)
_assert(resp_no_det.data.details is None, "empty details → None in response")

# Extra metadata
resp_meta = build_error_response_from_exception(
    APIErrorConflict("dup"),
    metadata={"component": "reports"}
)
_assert(resp_meta.metadata["component"] == "reports", "from_exception: extra metadata")
_assert("apiLayerVersion" in resp_meta.metadata,       "from_exception: apiLayerVersion present")


# ===========================================================================
# 9. build_paginated_response()
# ===========================================================================
print("\n[9] build_paginated_response")

items = list(range(10))
pr = build_paginated_response(items=items, page=2, page_size=10, total_items=55, timestamp=TS)
_assert(pr.success          == True,            "paginated success=True")
_assert(pr.data             == items,           "paginated data=items")
_assert(pr.timestamp        == TS,              "paginated timestamp")
_assert("pagination"        in pr.metadata,     "pagination in metadata")
pag = pr.metadata["pagination"]
_assert(pag["page"]       == 2,   "paginated page")
_assert(pag["pageSize"]   == 10,  "paginated pageSize")
_assert(pag["totalItems"] == 55,  "paginated totalItems")
_assert(pag["totalPages"] == 6,   "paginated totalPages ceil(55/10)=6")
_assert("apiLayerVersion" in pr.metadata, "paginated apiLayerVersion present")

# First page
pr2 = build_paginated_response(items=[1,2,3], page=1, page_size=3, total_items=9)
_assert(pr2.metadata["pagination"]["totalPages"] == 3, "page 1: totalPages=3")

# Exact fit — no remainder
pr3 = build_paginated_response(items=[], page=1, page_size=10, total_items=20)
_assert(pr3.metadata["pagination"]["totalPages"] == 2, "exact fit: totalPages=2")

# Empty result
pr4 = build_paginated_response(items=[], page=1, page_size=20, total_items=0)
_assert(pr4.data == [],                                  "empty: data=[]")
_assert(pr4.metadata["pagination"]["totalPages"]  == 0,  "empty: totalPages=0")
_assert(pr4.metadata["pagination"]["totalItems"]  == 0,  "empty: totalItems=0")

# page_size=0 guard
pr5 = build_paginated_response(items=[], page=1, page_size=0, total_items=0)
_assert(pr5.metadata["pagination"]["pageSize"]   == 1,  "pageSize=0 guarded to 1")
_assert(pr5.metadata["pagination"]["totalPages"] == 0,  "pageSize=0: totalPages=0")

# page=0 guard
pr6 = build_paginated_response(items=[], page=0, page_size=10, total_items=0)
_assert(pr6.metadata["pagination"]["page"] == 1, "page=0 guarded to 1")

# Large page
pr7 = build_paginated_response(items=[], page=1, page_size=500, total_items=1000)
_assert(pr7.metadata["pagination"]["totalPages"] == 2, "large pageSize: totalPages=2")

# Single item
pr8 = build_paginated_response(items=["only"], page=1, page_size=50, total_items=1)
_assert(pr8.data == ["only"],                            "single item: data")
_assert(pr8.metadata["pagination"]["totalPages"] == 1,  "single item: totalPages=1")

# Extra metadata merged alongside pagination
pr9 = build_paginated_response(items=[1], page=1, page_size=1, total_items=1,
                                metadata={"sort": "title"})
_assert(pr9.metadata["sort"]        == "title", "extra metadata merged")
_assert("pagination" in pr9.metadata,           "pagination still present with extra metadata")
_assert("apiLayerVersion" in pr9.metadata,      "apiLayerVersion still present")

# custom message
pr10 = build_paginated_response(items=[], page=1, page_size=10, total_items=0, message="No results")
_assert(pr10.message == "No results", "custom message")

# Immutability
_assert_raises(Exception, setattr, pr, "data", [], msg="paginated_response frozen")


# ===========================================================================
# 10. exception_to_api_response()
# ===========================================================================
print("\n[10] exception_to_api_response")

for ExcClass, code in [
    (APIErrorValidation, "VALIDATION_ERROR"),
    (APIErrorNotFound,   "NOT_FOUND"),
    (APIErrorConflict,   "CONFLICT"),
    (APIErrorInternal,   "INTERNAL_ERROR"),
]:
    exc = ExcClass("msg for " + code, details=["d1"])
    resp = exception_to_api_response(exc, timestamp=TS)
    _assert(resp.success == False,          f"exception_to_api_response success=False [{code}]")
    _assert(resp.data.errorCode == code,    f"exception_to_api_response errorCode [{code}]")
    _assert(resp.data.details == ["d1"],    f"exception_to_api_response details [{code}]")
    _assert(resp.timestamp == TS,           f"exception_to_api_response timestamp [{code}]")

# No details
r_no_det = exception_to_api_response(APIErrorNotFound("x"))
_assert(r_no_det.data.details is None, "exception_to_api_response: no details → None")

# With extra metadata
r_meta = exception_to_api_response(
    APIErrorInternal("boom"),
    metadata={"component": "core"}
)
_assert(r_meta.metadata["component"] == "core",   "exception_to_api_response: extra metadata")
_assert("apiLayerVersion" in r_meta.metadata,      "exception_to_api_response: apiLayerVersion present")


# ===========================================================================
# 11. validate_pagination()
# ===========================================================================
print("\n[11] validate_pagination")

# Happy path
try:
    validate_pagination(1, 20)
    _assert(True, "validate_pagination: page=1, pageSize=20 accepted")
except Exception:
    _assert(False, "validate_pagination: page=1, pageSize=20 should not raise")

try:
    validate_pagination(1, 1)
    _assert(True, "validate_pagination: minimum valid values accepted")
except Exception:
    _assert(False, "validate_pagination: page=1, pageSize=1 should not raise")

try:
    validate_pagination(100, 500)
    _assert(True, "validate_pagination: page=100, pageSize=500 accepted")
except Exception:
    _assert(False, "validate_pagination: page=100, pageSize=500 should not raise")

# page < 1 rejected
_assert_raises(APIErrorValidation, validate_pagination, 0,  20, msg="page=0 rejected")
_assert_raises(APIErrorValidation, validate_pagination, -1, 20, msg="page=-1 rejected")
_assert_raises(APIErrorValidation, validate_pagination, -100, 20, msg="large negative page rejected")

# pageSize < 1 rejected
_assert_raises(APIErrorValidation, validate_pagination, 1, 0,  msg="pageSize=0 rejected")
_assert_raises(APIErrorValidation, validate_pagination, 1, -1, msg="pageSize=-1 rejected")

# pageSize > max_page_size rejected
_assert_raises(APIErrorValidation, validate_pagination, 1, 501, msg="pageSize=501 rejected (default max=500)")
_assert_raises(APIErrorValidation, validate_pagination, 1, 1000, msg="pageSize=1000 rejected")

# Custom max_page_size
try:
    validate_pagination(1, 100, max_page_size=100)
    _assert(True, "custom max_page_size=100 accepts pageSize=100")
except Exception:
    _assert(False, "custom max_page_size=100 should accept pageSize=100")

_assert_raises(APIErrorValidation, validate_pagination, 1, 101, 100, msg="custom max_page_size=100 rejects pageSize=101")

# Both invalid — details list contains both errors
try:
    validate_pagination(0, 0)
    _assert(False, "both invalid should raise")
except APIErrorValidation as exc:
    _assert(len(exc.details) >= 2, "both invalid: 2+ details")
    _assert(exc.error_code == "VALIDATION_ERROR", "both invalid: correct error_code")

# Bool values rejected (bool is subclass of int — guard must catch it)
_assert_raises(APIErrorValidation, validate_pagination, True, 20, msg="bool page rejected")
_assert_raises(APIErrorValidation, validate_pagination, 1, True, msg="bool pageSize rejected")

# Float values rejected
_assert_raises(APIErrorValidation, validate_pagination, 1.5, 20, msg="float page rejected")
_assert_raises(APIErrorValidation, validate_pagination, 1, 20.5, msg="float pageSize rejected")

# Raised exception is APIErrorValidation (subclass of APILayerError)
try:
    validate_pagination(0, 20)
except APIErrorValidation as exc:
    _assert(isinstance(exc, APILayerError), "raised exception is-a APILayerError")
    _assert(exc.http_status == 422,         "raised exception http_status=422")
except Exception:
    _assert(False, "should raise APIErrorValidation")


# ===========================================================================
# 12. build_health_response()
# ===========================================================================
print("\n[12] build_health_response")

# Defaults
hr = build_health_response()
_assert(hr.status  == "healthy",        "default status healthy")
_assert(hr.version == API_LAYER_VERSION,"default version API_LAYER_VERSION")
_assert(hr.uptime  is None,             "default uptime None")
_assert(isinstance(hr, HealthResponse), "returns HealthResponse instance")

# With uptime
hr2 = build_health_response("healthy", "5d 03h")
_assert(hr2.uptime == "5d 03h", "uptime set")

# Degraded
hr3 = build_health_response("degraded")
_assert(hr3.status == "degraded", "degraded status")

# Unhealthy
hr4 = build_health_response("unhealthy")
_assert(hr4.status == "unhealthy", "unhealthy status")

# Version always from constant (not caller-supplied)
_assert(hr.version  == API_LAYER_VERSION, "health version matches constant")
_assert(hr2.version == API_LAYER_VERSION, "health version always constant")
_assert(hr3.version == API_LAYER_VERSION, "degraded version always constant")

# Immutability
_assert_raises(Exception, setattr, hr, "status", "x", msg="HealthResponse frozen")

# Deterministic — same inputs, same output
hr_a = build_health_response("healthy", "1h")
hr_b = build_health_response("healthy", "1h")
_assert(hr_a.status  == hr_b.status,  "health deterministic status")
_assert(hr_a.version == hr_b.version, "health deterministic version")
_assert(hr_a.uptime  == hr_b.uptime,  "health deterministic uptime")


# ===========================================================================
# 13. build_version_response()
# ===========================================================================
print("\n[13] build_version_response")

vr_default = build_version_response()
_assert(isinstance(vr_default, VersionResponse), "returns VersionResponse")
_assert(vr_default.apiVersion == API_LAYER_VERSION, "apiVersion matches constant")
_assert(isinstance(vr_default.engineVersions, dict), "engineVersions is dict")
_assert(len(vr_default.engineVersions) >= 40,         "at least 40 engine versions")

# Sorted keys
keys = list(vr_default.engineVersions.keys())
_assert(keys == sorted(keys), "engineVersions keys sorted alphabetically")

# Known engines present
for engine in ["report", "alert", "finding", "investigation", "reasoning",
               "playbook", "case-flow", "mitre", "mitre-attack",
               "cve-intelligence", "ioc-intelligence", "threat-intelligence",
               "api-layer", "groq-provider", "groq-streaming", "groq-http-client",
               "chat-runtime", "session-memory", "context-window", "token-budget",
               "retry-failover", "automation", "rules", "evidence",
               "identity-confidence", "identity-resolution",
               "attack-graph", "attack-graph-query", "attack-graph-intelligence",
               "timeline-intelligence", "copilot-orchestrator", "ai-context",
               "ai-execution", "conversation-manager", "prompt-assembly",
               "investigation-narrative", "relationship", "relationship-history",
               "provider-registry", "tool-calling"]:
    _assert(engine in vr_default.engineVersions, f"engine '{engine}' in registry")

# All values are non-empty strings
for k, v in vr_default.engineVersions.items():
    _assert(isinstance(v, str) and len(v) > 0, f"engine '{k}' has non-empty version string")

# api-layer version matches constant
_assert(vr_default.engineVersions["api-layer"] == API_LAYER_VERSION,
        "api-layer engine version matches constant")

# report engine version
from core.constants import REPORT_ENGINE_VERSION
_assert(vr_default.engineVersions["report"] == REPORT_ENGINE_VERSION,
        "report engine version matches constant")

# Deterministic — same output every call
vr2 = build_version_response()
_assert(vr_default.apiVersion     == vr2.apiVersion,     "version deterministic apiVersion")
_assert(vr_default.engineVersions == vr2.engineVersions, "version deterministic engineVersions")

# Extra versions merged
vr_extra = build_version_response(extra_versions={"custom-engine": "custom-v1"})
_assert("custom-engine" in vr_extra.engineVersions,        "extra engine present")
_assert(vr_extra.engineVersions["custom-engine"] == "custom-v1", "extra engine version correct")
# Standard engines still present
_assert("report"    in vr_extra.engineVersions, "report still present with extras")
_assert("api-layer" in vr_extra.engineVersions, "api-layer still present with extras")
# Sorted after merge
keys_extra = list(vr_extra.engineVersions.keys())
_assert(keys_extra == sorted(keys_extra), "keys sorted after extra merge")

# Extra versions override existing
vr_override = build_version_response(extra_versions={"report": "report-override-v99"})
_assert(vr_override.engineVersions["report"] == "report-override-v99",
        "extra versions override existing")

# Immutability
_assert_raises(Exception, setattr, vr_default, "apiVersion", "x", msg="VersionResponse frozen")


# ===========================================================================
# 14. get_engine_version_registry()
# ===========================================================================
print("\n[14] get_engine_version_registry")

reg = get_engine_version_registry()
_assert(isinstance(reg, dict),                         "registry returns dict")
_assert(len(reg) >= 40,                               "registry has >= 40 entries")
_assert(list(reg.keys()) == sorted(reg.keys()),        "registry keys sorted")
_assert("api-layer" in reg,                            "api-layer in registry")
_assert("report"    in reg,                            "report in registry")

# Returns a copy — mutation doesn't affect the internal registry
reg2 = get_engine_version_registry()
reg["injected"] = "injected-v1"
reg3 = get_engine_version_registry()
_assert("injected" not in reg3, "mutation of returned dict doesn't affect registry")

# Consistent across calls
reg_a = get_engine_version_registry()
reg_b = get_engine_version_registry()
_assert(reg_a == reg_b, "registry consistent across calls")


# ===========================================================================
# 15. Router Registration
# ===========================================================================
print("\n[15] Router Registration")

# Root router prefix
_assert(root_router.prefix == "/api/v2", "root_router prefix /api/v2")

# Sub-router prefixes
_assert(investigation_router.prefix == "/investigation", "investigation prefix")
_assert(ai_router.prefix            == "/ai",            "ai prefix")
_assert(knowledge_router.prefix     == "/knowledge",     "knowledge prefix")
_assert(workflow_router.prefix      == "/workflow",      "workflow prefix")
_assert(reports_router.prefix       == "/reports",       "reports prefix")
_assert(system_router.prefix        == "/system",        "system prefix")

# Sub-router tags
_assert("Investigation" in investigation_router.tags, "investigation tag")
_assert("AI"            in ai_router.tags,            "ai tag")
_assert("Knowledge"     in knowledge_router.tags,     "knowledge tag")
_assert("Workflow"      in workflow_router.tags,      "workflow tag")
_assert("Reports"       in reports_router.tags,       "reports tag")
_assert("System"        in system_router.tags,        "system tag")

# Sub-routers are APIRouter instances
from fastapi import APIRouter as _APIRouter
for router, name in [
    (root_router,          "root"),
    (investigation_router, "investigation"),
    (ai_router,            "ai"),
    (knowledge_router,     "knowledge"),
    (workflow_router,      "workflow"),
    (reports_router,       "reports"),
    (system_router,        "system"),
]:
    _assert(isinstance(router, _APIRouter), f"{name}_router is APIRouter instance")

# Placeholder routers have no extra endpoints (investigation, ai, knowledge, workflow, reports)
for router, name in [
    (investigation_router, "investigation"),
    (ai_router,            "ai"),
    (knowledge_router,     "knowledge"),
    (workflow_router,      "workflow"),
    (reports_router,       "reports"),
]:
    _assert(len(router.routes) == 0, f"{name}_router has no endpoints yet")

# System router has exactly 2 routes
_assert(len(system_router.routes) == 2, "system_router has exactly 2 routes")

# System routes have correct paths and methods
system_paths  = {r.path for r in system_router.routes}
system_methods = {m for r in system_router.routes for m in (r.methods or [])}
_assert("/system/health"  in system_paths,  "system_router has /system/health")
_assert("/system/version" in system_paths,  "system_router has /system/version")
_assert("GET"             in system_methods,"system_router uses GET method")

# Root router aggregates the system endpoints (full paths)
root_paths = {r.path for r in root_router.routes}
_assert("/api/v2/system/health"  in root_paths, "root_router has /api/v2/system/health")
_assert("/api/v2/system/version" in root_paths, "root_router has /api/v2/system/version")

# Deterministic ordering — system comes last (after all domain routers)
# Verify all expected full paths exist in root
for path in ["/api/v2/system/health", "/api/v2/system/version"]:
    _assert(any(r.path == path for r in root_router.routes), f"root contains {path}")


# ===========================================================================
# 16. System Endpoint Responses
# ===========================================================================
print("\n[16] System Endpoint Responses")

# Locate endpoint functions via route objects
health_route  = next(r for r in system_router.routes if r.path == "/system/health")
version_route = next(r for r in system_router.routes if r.path == "/system/version")

# Call health endpoint function directly
health_fn  = health_route.endpoint
version_fn = version_route.endpoint

# Health — no uptime
h_resp = health_fn()
_assert(isinstance(h_resp, APIResponse),               "health returns APIResponse")
_assert(h_resp.success == True,                        "health success=True")
_assert(h_resp.message == "Service is healthy.",       "health message")
_assert(isinstance(h_resp.data, dict),                 "health data is dict")
_assert(h_resp.data["status"]  == "healthy",           "health data.status=healthy")
_assert(h_resp.data["version"] == API_LAYER_VERSION,   "health data.version=API_LAYER_VERSION")
_assert(h_resp.data["uptime"]  is None,                "health data.uptime=None when not supplied")
_assert(h_resp.metadata["apiLayerVersion"] == API_LAYER_VERSION, "health metadata apiLayerVersion")

# Health — with uptime
h_resp2 = health_fn(uptime="2d 04h")
_assert(h_resp2.data["uptime"] == "2d 04h", "health with uptime")

# Version — default
v_resp = version_fn()
_assert(isinstance(v_resp, APIResponse),               "version returns APIResponse")
_assert(v_resp.success == True,                        "version success=True")
_assert(v_resp.message == "Version information retrieved.", "version message")
_assert(isinstance(v_resp.data, dict),                 "version data is dict")
_assert(v_resp.data["apiVersion"] == API_LAYER_VERSION,"version data.apiVersion")
_assert(isinstance(v_resp.data["engineVersions"], dict),"version data.engineVersions is dict")
_assert(len(v_resp.data["engineVersions"]) >= 40,      "version data has >= 40 engines")
_assert(v_resp.metadata["apiLayerVersion"] == API_LAYER_VERSION, "version metadata apiLayerVersion")

# Version — engine versions sorted
ev_keys = list(v_resp.data["engineVersions"].keys())
_assert(ev_keys == sorted(ev_keys), "version endpoint: engineVersions sorted")

# Version — deterministic
v_resp2 = version_fn()
_assert(v_resp.data["engineVersions"] == v_resp2.data["engineVersions"],
        "version endpoint deterministic")

# Version — known engines present
_assert("report"    in v_resp.data["engineVersions"], "version: report engine present")
_assert("api-layer" in v_resp.data["engineVersions"], "version: api-layer engine present")
_assert("alert"     in v_resp.data["engineVersions"], "version: alert engine present")
_assert("finding"   in v_resp.data["engineVersions"], "version: finding engine present")


# ===========================================================================
# 17. Edge Cases
# ===========================================================================
print("\n[17] Edge Cases")

# Empty string message in success response
r_empty_msg = build_success_response(message="")
_assert(r_empty_msg.message == "", "empty message string allowed")

# Large data payload
large_data = {"items": list(range(1000))}
r_large = build_success_response(data=large_data)
_assert(r_large.data == large_data, "large data preserved")

# Nested dict data
nested = {"a": {"b": {"c": "deep"}}}
r_nested = build_success_response(data=nested)
_assert(r_nested.data["a"]["b"]["c"] == "deep", "nested dict data preserved")

# None details list in APIError
ae_none = APIError(errorCode="X", error="x", details=None)
_assert(ae_none.details is None, "APIError details=None allowed")

# Empty details list in APIError
ae_empty = APIError(errorCode="X", error="x", details=[])
_assert(ae_empty.details == [], "APIError details=[] allowed")

# Pagination with total_items=1 page_size=1
pr_exact = build_paginated_response(items=["x"], page=1, page_size=1, total_items=1)
_assert(pr_exact.metadata["pagination"]["totalPages"] == 1, "1 item, size 1 → 1 page")

# Pagination with very large numbers
pr_big = build_paginated_response(items=[], page=999, page_size=100, total_items=100000)
_assert(pr_big.metadata["pagination"]["totalPages"] == 1000, "large: 100000/100=1000 pages")
_assert(pr_big.metadata["pagination"]["page"] == 999,         "large: page=999 preserved")

# build_version_response with empty extra_versions
vr_empty_extra = build_version_response(extra_versions={})
_assert(vr_empty_extra.engineVersions == vr_default.engineVersions,
        "empty extra_versions doesn't change result")

# validate_pagination exact boundary: page=1, pageSize=500 (default max)
try:
    validate_pagination(1, 500)
    _assert(True, "pageSize=500 at default max boundary accepted")
except Exception:
    _assert(False, "pageSize=500 should be accepted at boundary")

# validate_pagination pageSize=501 rejects
_assert_raises(APIErrorValidation, validate_pagination, 1, 501,
               msg="pageSize=501 just above default max rejected")

# Exception string without details
exc_no_det = APIErrorNotFound("simple message")
s_no_det = str(exc_no_det)
_assert("NOT_FOUND"      in s_no_det, "str no details: contains error_code")
_assert("simple message" in s_no_det, "str no details: contains message")
_assert("—"              not in s_no_det or "details" not in s_no_det.split("—")[-1].lower(),
        "str no details: no dash separator when no details")

# Metadata never mutates caller's dict
caller_meta = {"original": "value"}
r_caller_meta = build_success_response(metadata=caller_meta)
caller_meta["injected"] = "after"
_assert("injected" not in r_caller_meta.metadata, "caller metadata dict not aliased in response")

# APIResponse success field is boolean
_assert(type(build_success_response().success) is bool, "success is bool True")
_assert(type(build_error_response("X","x").success) is bool, "error success is bool False")

# APILayerError is catchable as Exception
try:
    raise APIErrorInternal("boom")
except Exception as exc:
    _assert(isinstance(exc, APILayerError), "APILayerError catchable as Exception")
    _assert(exc.http_status == 500,         "caught http_status 500")

# validate_pagination with string values
_assert_raises(APIErrorValidation, validate_pagination, "1", 20, msg="string page rejected")
_assert_raises(APIErrorValidation, validate_pagination, 1, "20", msg="string pageSize rejected")

# version and health responses are always immutable
v3 = build_version_response()
_assert_raises(Exception, setattr, v3, "apiVersion", "x", msg="build_version_response result frozen")

h5 = build_health_response()
_assert_raises(Exception, setattr, h5, "status", "x", msg="build_health_response result frozen")


# ===========================================================================
# 18. __init__.py / Package-level imports
# ===========================================================================
print("\n[18] Package-level imports")

import api as api_pkg

# Models accessible from top-level package
_assert(hasattr(api_pkg, "APIResponse"),        "api.APIResponse exported")
_assert(hasattr(api_pkg, "APIError"),           "api.APIError exported")
_assert(hasattr(api_pkg, "Pagination"),         "api.Pagination exported")
_assert(hasattr(api_pkg, "HealthResponse"),     "api.HealthResponse exported")
_assert(hasattr(api_pkg, "VersionResponse"),    "api.VersionResponse exported")

# Errors accessible
_assert(hasattr(api_pkg, "APILayerError"),      "api.APILayerError exported")
_assert(hasattr(api_pkg, "APIErrorValidation"), "api.APIErrorValidation exported")
_assert(hasattr(api_pkg, "APIErrorNotFound"),   "api.APIErrorNotFound exported")
_assert(hasattr(api_pkg, "APIErrorConflict"),   "api.APIErrorConflict exported")
_assert(hasattr(api_pkg, "APIErrorInternal"),   "api.APIErrorInternal exported")

# Response builders accessible
_assert(hasattr(api_pkg, "build_success_response"),         "api.build_success_response exported")
_assert(hasattr(api_pkg, "build_error_response"),           "api.build_error_response exported")
_assert(hasattr(api_pkg, "build_error_response_from_exception"), "api.build_error_response_from_exception exported")
_assert(hasattr(api_pkg, "build_paginated_response"),       "api.build_paginated_response exported")

# Utility helpers accessible
_assert(hasattr(api_pkg, "build_health_response"),    "api.build_health_response exported")
_assert(hasattr(api_pkg, "build_version_response"),   "api.build_version_response exported")
_assert(hasattr(api_pkg, "exception_to_api_response"),"api.exception_to_api_response exported")
_assert(hasattr(api_pkg, "validate_pagination"),      "api.validate_pagination exported")
_assert(hasattr(api_pkg, "get_engine_version_registry"), "api.get_engine_version_registry exported")

# Routers accessible
_assert(hasattr(api_pkg, "root_router"),          "api.root_router exported")
_assert(hasattr(api_pkg, "investigation_router"), "api.investigation_router exported")
_assert(hasattr(api_pkg, "ai_router"),            "api.ai_router exported")
_assert(hasattr(api_pkg, "knowledge_router"),     "api.knowledge_router exported")
_assert(hasattr(api_pkg, "workflow_router"),      "api.workflow_router exported")
_assert(hasattr(api_pkg, "reports_router"),       "api.reports_router exported")
_assert(hasattr(api_pkg, "system_router"),        "api.system_router exported")


# ===========================================================================
# Final summary
# ===========================================================================
print()
print("=" * 60)
print(f"PASSED : {_PASS}")
print(f"FAILED : {_FAIL}")
print("=" * 60)

if _ERRORS:
    print("\nFailed assertions:")
    for err in _ERRORS:
        print(f"  {err}")

if _FAIL > 0:
    sys.exit(1)
else:
    print("\nALL ASSERTIONS PASSED ✓")
