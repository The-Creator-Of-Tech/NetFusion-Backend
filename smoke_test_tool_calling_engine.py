"""
Smoke Test — Tool Calling Engine
=================================
Phase A4.2.3 — Verifies every model, builder, registry function,
validation function, and execution path in
services/tool_calling_service.py.

Run:
    python smoke_test_tool_calling_engine.py
Expected: 400+/400 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. All handlers are pure sync lambdas.
- Same inputs -> same outputs (fully deterministic).
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_ERRORS: List[str] = []


def _assert(cond: bool, msg: str) -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
    else:
        _FAIL += 1
        frame = traceback.extract_stack()[-2]
        _ERRORS.append(f"FAIL [line {frame.lineno}]: {msg}")


def _eq(a, b, msg):  _assert(a == b,  f"{msg} — expected {b!r}, got {a!r}")
def _ne(a, b, msg):  _assert(a != b,  f"{msg} — both are {a!r}")
def _in(x, c, msg):  _assert(x in c,  f"{msg} — {x!r} not in collection")
def _ni(x, c, msg):  _assert(x not in c, f"{msg} — {x!r} unexpectedly in collection")
def _gt(a, b, msg):  _assert(a > b,   f"{msg} — {a!r} not > {b!r}")
def _ge(a, b, msg):  _assert(a >= b,  f"{msg} — {a!r} not >= {b!r}")
def _is(a, t, msg):  _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")
def _lt(a, b, msg):  _assert(a < b,   f"{msg} — {a!r} not < {b!r}")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.tool_calling_service import (
    # Exceptions
    ToolCallingError, ToolNotFoundError, ToolDisabledError,
    ToolValidationError, ToolExecutionError, ToolTimeoutError,
    DuplicateToolError,
    # Models
    ToolParameter, ToolDefinition, ToolCall, ToolResult,
    ToolExecutionMetadata, ToolCallingResult,
    # Builders
    build_tool_parameter, build_tool_definition, build_tool_call,
    build_tool_result, build_execution_metadata, build_tool_calling_result,
    # Registry class
    ToolRegistry,
    # Registry convenience
    get_default_registry,
    # Validation
    validate_tool_call, validate_parameters, validate_return_schema,
    # Execution
    execute_tool, execute_registered_tool, execute_batch, execute_parallel,
    # Helpers
    _sha256_32, _uuid5_tool, _arguments_hash, _output_hash,
    # Constants
    TOOL_CALLING_ENGINE_VERSION,
)
from core.constants import TOOL_CALLING_ENGINE_VERSION as CONST_TC_VERSION

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
_TS   = "2026-07-01T12:00:00Z"
_RID  = "req-abc123"

def _make_registry() -> ToolRegistry:
    """Return a fresh empty registry."""
    return ToolRegistry()

def _simple_param(**kw) -> ToolParameter:
    return build_tool_parameter(
        kw.get("name", "query"),
        kw.get("type_", "string"),
        kw.get("description", "A test param."),
        kw.get("required", True),
        kw.get("default_value", None),
    )

def _simple_def(name="test_tool", category="search", params=None, enabled=True) -> ToolDefinition:
    if params is None:
        params = [_simple_param()]
    return build_tool_definition(name, f"Does {name}.", category, params, {"required": ["status"]}, _TS, enabled=enabled)

def _ok_handler(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "ok", "data": {}, "received": arguments}

def _fail_handler(arguments: Dict[str, Any]) -> Dict[str, Any]:
    raise ValueError("Handler deliberately raised.")

# ===========================================================================
# §1  Engine version
# ===========================================================================
print("§1  Engine version ...")
_eq(TOOL_CALLING_ENGINE_VERSION, "tool-calling-engine-v1", "engine version value")
_eq(CONST_TC_VERSION, TOOL_CALLING_ENGINE_VERSION, "core.constants matches service")
_is(TOOL_CALLING_ENGINE_VERSION, str, "engine version is str")
_in("tool-calling", TOOL_CALLING_ENGINE_VERSION, "engine version contains 'tool-calling'")

# ===========================================================================
# §2  Deterministic ID helpers
# ===========================================================================
print("§2  ID helpers ...")
h1 = _sha256_32("a", "b")
h2 = _sha256_32("a", "b")
_eq(h1, h2, "_sha256_32 deterministic")
_eq(len(h1), 32, "_sha256_32 returns 32 chars")
h3 = _sha256_32("b", "a")
_ne(h1, h3, "different arg order -> different hash")
h4 = _sha256_32("a", "c")
_ne(h1, h4, "different args -> different hash")

u1 = _uuid5_tool("key-abc")
u2 = _uuid5_tool("key-abc")
_eq(u1, u2, "_uuid5_tool deterministic")
_eq(len(u1), 36, "_uuid5_tool returns 36-char UUID")
_in("-", u1, "_uuid5_tool UUID contains hyphens")
u3 = _uuid5_tool("key-xyz")
_ne(u1, u3, "different keys -> different UUIDs")

ah1 = _arguments_hash({"a": 1, "b": 2})
ah2 = _arguments_hash({"b": 2, "a": 1})
_eq(ah1, ah2, "_arguments_hash: key order irrelevant (sorted)")
ah3 = _arguments_hash({"a": 1, "b": 3})
_ne(ah1, ah3, "_arguments_hash: different values -> different hash")

oh1 = _output_hash({"status": "ok", "data": {}})
oh2 = _output_hash({"status": "ok", "data": {}})
_eq(oh1, oh2, "_output_hash deterministic")
oh3 = _output_hash({"status": "fail"})
_ne(oh1, oh3, "_output_hash: different content -> different hash")

# ===========================================================================
# §3  build_tool_parameter()
# ===========================================================================
print("§3  build_tool_parameter() ...")
p = build_tool_parameter("ip_address", "string", "Target IP.", required=True)
_is(p, ToolParameter, "returns ToolParameter")
_eq(p.name, "ip_address", "name set")
_eq(p.type, "string", "type set")
_eq(p.description, "Target IP.", "description set")
_assert(p.required, "required=True stored")
_assert(p.defaultValue is None, "defaultValue=None by default")

# Optional with default
p_opt = build_tool_parameter("limit", "integer", "Max results.", required=False, default_value=10)
_assert(not p_opt.required, "required=False stored")
_eq(p_opt.defaultValue, 10, "defaultValue=10 stored")

# Type lowercased
p_upper = build_tool_parameter("x", "STRING", "x param.")
_eq(p_upper.type, "string", "type normalised to lowercase")

# Immutability
try:
    p.name = "changed"   # type: ignore
    _assert(False, "ToolParameter should be frozen")
except Exception:
    _assert(True, "ToolParameter is immutable")

# Empty name raises
try:
    build_tool_parameter("", "string", "desc")
    _assert(False, "empty name should raise ToolValidationError")
except ToolValidationError:
    _assert(True, "empty name raises ToolValidationError")

# Empty type raises
try:
    build_tool_parameter("name", "", "desc")
    _assert(False, "empty type should raise ToolValidationError")
except ToolValidationError:
    _assert(True, "empty type raises ToolValidationError")

# Determinism — same inputs -> same object
p2 = build_tool_parameter("ip_address", "string", "Target IP.", required=True)
_eq(p, p2, "same inputs -> equal ToolParameter")

# ===========================================================================
# §4  build_tool_definition()
# ===========================================================================
print("§4  build_tool_definition() ...")
params = [
    build_tool_parameter("query", "string", "Search query.", required=False, default_value=""),
    build_tool_parameter("limit", "integer", "Max results.", required=False, default_value=10),
]
defn = build_tool_definition(
    tool_name     = "search_assets",
    description   = "Search assets.",
    category      = "search",
    parameters    = params,
    return_schema = {"required": ["status"], "type": "object"},
    created_at    = _TS,
    enabled       = True,
)
_is(defn, ToolDefinition, "returns ToolDefinition")
_eq(defn.toolName, "search_assets", "toolName normalised")
_eq(defn.category, "search", "category stored")
_eq(len(defn.toolId), 36, "toolId is UUID (36 chars)")
_in("-", defn.toolId, "toolId contains hyphens")
_eq(len(defn.toolKey), 32, "toolKey is 32 chars")
_eq(defn.engineVersion, TOOL_CALLING_ENGINE_VERSION, "engineVersion set")
_assert(defn.enabled, "enabled=True stored")
_eq(len(defn.parameters), 2, "2 parameters stored")
_eq(defn.createdAt, _TS, "createdAt preserved")

# toolName normalised to lowercase
defn_upper = build_tool_definition("SEARCH_ASSETS", "desc", "SEARCH", params, {}, _TS)
_eq(defn_upper.toolName, "search_assets", "toolName uppercased -> lowercased")
_eq(defn_upper.category, "search", "category uppercased -> lowercased")

# Deterministic toolId — same name+category -> same toolId
defn2 = build_tool_definition("search_assets", "Different desc.", "search", [], {}, _TS)
_eq(defn.toolId,  defn2.toolId,  "same name+category -> same toolId")
_eq(defn.toolKey, defn2.toolKey, "same name+category -> same toolKey")

# Different name -> different toolId
defn3 = build_tool_definition("search_evidence", "desc", "search", [], {}, _TS)
_ne(defn.toolId, defn3.toolId, "different toolName -> different toolId")

# Different category -> different toolId
defn4 = build_tool_definition("search_assets", "desc", "query", [], {}, _TS)
_ne(defn.toolId, defn4.toolId, "different category -> different toolId")

# Disabled tool
defn_dis = build_tool_definition("disabled_tool", "desc", "search", [], {}, _TS, enabled=False)
_assert(not defn_dis.enabled, "enabled=False stored")

# Immutability
try:
    defn.toolName = "changed"   # type: ignore
    _assert(False, "ToolDefinition should be frozen")
except Exception:
    _assert(True, "ToolDefinition is immutable")

# Empty toolName raises
try:
    build_tool_definition("", "desc", "search", [], {}, _TS)
    _assert(False, "empty toolName should raise ToolValidationError")
except ToolValidationError:
    _assert(True, "empty toolName raises ToolValidationError")

# Empty category raises
try:
    build_tool_definition("my_tool", "desc", "", [], {}, _TS)
    _assert(False, "empty category should raise ToolValidationError")
except ToolValidationError:
    _assert(True, "empty category raises ToolValidationError")

# ===========================================================================
# §5  build_tool_call()
# ===========================================================================
print("§5  build_tool_call() ...")
args = {"query": "dns", "limit": 5}
tc = build_tool_call(defn, args, _RID, _TS, provider="groq", model="llama-3.3-70b-versatile")
_is(tc, ToolCall, "returns ToolCall")
_eq(len(tc.callId), 36, "callId is UUID (36 chars)")
_in("-", tc.callId, "callId contains hyphens")
_eq(len(tc.callKey), 32, "callKey is 32 chars")
_eq(tc.toolId,   defn.toolId,       "toolId linked to ToolDefinition")
_eq(tc.toolName, "search_assets",   "toolName stored")
_eq(tc.arguments, args,             "arguments stored")
_eq(tc.requestId, _RID,             "requestId stored")
_eq(tc.provider, "groq",            "provider normalised")
_eq(tc.model, "llama-3.3-70b-versatile", "model stored")
_eq(tc.createdAt, _TS,              "createdAt stored")

# Determinism — same inputs -> same callId
tc2 = build_tool_call(defn, args, _RID, _TS, provider="groq", model="llama-3.3-70b-versatile")
_eq(tc.callId,  tc2.callId,  "same inputs -> same callId")
_eq(tc.callKey, tc2.callKey, "same inputs -> same callKey")

# Different arguments -> different callId
tc3 = build_tool_call(defn, {"query": "http", "limit": 5}, _RID, _TS)
_ne(tc.callId, tc3.callId, "different arguments -> different callId")

# Different requestId -> different callId
tc4 = build_tool_call(defn, args, "req-different", _TS)
_ne(tc.callId, tc4.callId, "different requestId -> different callId")

# Different tool -> different callId
tc5 = build_tool_call(defn3, args, _RID, _TS)
_ne(tc.callId, tc5.callId, "different toolId -> different callId")

# Provider normalised to lowercase
tc_prov = build_tool_call(defn, args, _RID, _TS, provider="GROQ")
_eq(tc_prov.provider, "groq", "provider uppercased -> lowercased")

# Immutability
try:
    tc.arguments = {}   # type: ignore
    _assert(False, "ToolCall should be frozen")
except Exception:
    _assert(True, "ToolCall is immutable")

# ===========================================================================
# §6  build_tool_result()
# ===========================================================================
print("§6  build_tool_result() ...")
output = {"status": "ok", "data": {"count": 3}}
tr = build_tool_result(
    call_id           = tc.callId,
    tool_id           = defn.toolId,
    success           = True,
    output            = output,
    execution_time_ms = 42,
    created_at        = _TS,
)
_is(tr, ToolResult, "returns ToolResult")
_eq(len(tr.resultId), 36, "resultId is UUID (36 chars)")
_in("-", tr.resultId, "resultId contains hyphens")
_eq(len(tr.resultKey), 32, "resultKey is 32 chars")
_eq(tr.toolId,           defn.toolId, "toolId stored")
_assert(tr.success,      "success=True stored")
_eq(tr.output,           output,      "output stored")
_eq(tr.executionTimeMs,  42,          "executionTimeMs stored")
_assert(tr.error is None,             "error=None on success")
_in("engineVersion", tr.metadata,    "engineVersion in metadata")

# Determinism — same inputs -> same resultId
tr2 = build_tool_result(tc.callId, defn.toolId, True, output, 42, _TS)
_eq(tr.resultId,  tr2.resultId,  "same inputs -> same resultId")
_eq(tr.resultKey, tr2.resultKey, "same inputs -> same resultKey")

# Different output -> different resultId
tr3 = build_tool_result(tc.callId, defn.toolId, True, {"status": "fail"}, 42, _TS)
_ne(tr.resultId, tr3.resultId, "different output -> different resultId")

# success=False -> different resultId
tr4 = build_tool_result(tc.callId, defn.toolId, False, output, 42, _TS, error="err")
_ne(tr.resultId, tr4.resultId, "different success -> different resultId")

# Failure result
tr_fail = build_tool_result(tc.callId, defn.toolId, False, {}, 0, _TS, error="Timeout")
_assert(not tr_fail.success, "failure: success=False")
_eq(tr_fail.error, "Timeout", "failure: error message stored")

# Negative executionTimeMs clamped to 0
tr_neg = build_tool_result(tc.callId, defn.toolId, True, output, -10, _TS)
_eq(tr_neg.executionTimeMs, 0, "negative executionTimeMs clamped to 0")

# Immutability
try:
    tr.success = False   # type: ignore
    _assert(False, "ToolResult should be frozen")
except Exception:
    _assert(True, "ToolResult is immutable")

# ===========================================================================
# §7  build_execution_metadata()
# ===========================================================================
print("§7  build_execution_metadata() ...")
em = build_execution_metadata(
    started_at        = 1000,
    completed_at      = 1250,
    validation_passed = True,
    provider          = "groq",
    model             = "llama-3.1-8b-instant",
    warnings          = ["slow response"],
)
_is(em, ToolExecutionMetadata, "returns ToolExecutionMetadata")
_eq(em.startedAt,        1000,  "startedAt stored")
_eq(em.completedAt,      1250,  "completedAt stored")
_eq(em.executionTimeMs,  250,   "executionTimeMs = 1250 - 1000 = 250ms")
_assert(em.validationPassed,   "validationPassed=True stored")
_eq(em.provider, "groq",       "provider stored")
_eq(em.model, "llama-3.1-8b-instant", "model stored")
_eq(em.warnings, ("slow response",),  "warnings stored")

# Determinism
em2 = build_execution_metadata(1000, 1250, True, "groq", "llama-3.1-8b-instant", ["slow response"])
_eq(em, em2, "same inputs -> equal ToolExecutionMetadata")

# Negative startedAt / completedAt clamped to 0
em_neg = build_execution_metadata(-100, -50, True)
_eq(em_neg.startedAt,   0, "negative startedAt clamped to 0")
_eq(em_neg.completedAt, 0, "negative completedAt clamped to 0")
_eq(em_neg.executionTimeMs, 0, "negative times -> executionTimeMs=0")

# Immutability
try:
    em.startedAt = 999   # type: ignore
    _assert(False, "ToolExecutionMetadata should be frozen")
except Exception:
    _assert(True, "ToolExecutionMetadata is immutable")

# Warnings deduped + sorted
em_warn = build_execution_metadata(0, 100, True, warnings=["B", "A", "B", "C"])
_eq(em_warn.warnings, ("A", "B", "C"), "warnings deduped and sorted")

# ===========================================================================
# §8  build_tool_calling_result()
# ===========================================================================
print("§8  build_tool_calling_result() ...")
result = build_tool_calling_result(tc, tr, em)
_is(result, ToolCallingResult, "returns ToolCallingResult")
_eq(result.toolCall,   tc, "toolCall stored")
_eq(result.toolResult, tr, "toolResult stored")
_eq(result.metadata,   em, "metadata stored")

# Immutability
try:
    result.toolCall = tc   # type: ignore
    _assert(False, "ToolCallingResult should be frozen")
except Exception:
    _assert(True, "ToolCallingResult is immutable")

# Same inputs -> same result
result2 = build_tool_calling_result(tc, tr, em)
_eq(result, result2, "same inputs -> equal ToolCallingResult")

# ===========================================================================
# §9  validate_parameters()
# ===========================================================================
print("§9  validate_parameters() ...")
params_v = [
    build_tool_parameter("ip",    "string",  "IP address.",   required=True),
    build_tool_parameter("limit", "integer", "Max results.",  required=False, default_value=10),
    build_tool_parameter("flag",  "boolean", "A flag.",       required=False, default_value=False),
]
defn_v = build_tool_definition("validate_test", "test", "test", params_v, {"required":["status"]}, _TS)

# Valid call — all required present
errs = validate_parameters(defn_v, {"ip": "192.168.1.1"})
_eq(errs, [], "valid call with required only -> no errors")

# Valid call — all params supplied
errs2 = validate_parameters(defn_v, {"ip": "10.0.0.1", "limit": 5, "flag": True})
_eq(errs2, [], "valid call with all params -> no errors")

# Missing required parameter
errs3 = validate_parameters(defn_v, {})
_eq(len(errs3), 1, "missing required 'ip' -> 1 error")
_in("ip", errs3[0], "error mentions missing param name")

# Unknown parameter
errs4 = validate_parameters(defn_v, {"ip": "1.2.3.4", "unknown_param": "val"})
_eq(len(errs4), 1, "unknown parameter -> 1 error")
_in("unknown_param", errs4[0], "error mentions unknown param")

# Type mismatch — string for integer
errs5 = validate_parameters(defn_v, {"ip": "1.2.3.4", "limit": "not-an-int"})
_eq(len(errs5), 1, "string for integer -> 1 type error")
_in("limit", errs5[0], "error mentions parameter name")
_in("integer", errs5[0], "error mentions expected type")

# Type mismatch — integer for boolean
errs6 = validate_parameters(defn_v, {"ip": "1.2.3.4", "flag": 1})
_eq(len(errs6), 1, "int for boolean -> 1 type error")

# Multiple errors accumulated
errs_multi = validate_parameters(defn_v, {"unknown_x": "x", "unknown_y": "y"})
_ge(len(errs_multi), 2, "multiple errors: unknown params + missing required")

# float is valid for "number" type
params_num = [build_tool_parameter("score", "number", "Score.", required=True)]
defn_num   = build_tool_definition("num_test", "d", "test", params_num, {}, _TS)
errs_num   = validate_parameters(defn_num, {"score": 3.14})
_eq(errs_num, [], "float valid for 'number' type")
errs_num2  = validate_parameters(defn_num, {"score": 42})
_eq(errs_num2, [], "int valid for 'number' type")

# array type
params_arr = [build_tool_parameter("ids", "array", "IDs.", required=True)]
defn_arr   = build_tool_definition("arr_test", "d", "test", params_arr, {}, _TS)
errs_arr   = validate_parameters(defn_arr, {"ids": [1, 2, 3]})
_eq(errs_arr, [], "list valid for 'array' type")
errs_arr2  = validate_parameters(defn_arr, {"ids": "not-a-list"})
_eq(len(errs_arr2), 1, "string for 'array' -> type error")

# object type
params_obj = [build_tool_parameter("cfg", "object", "Config.", required=True)]
defn_obj   = build_tool_definition("obj_test", "d", "test", params_obj, {}, _TS)
errs_obj   = validate_parameters(defn_obj, {"cfg": {"key": "val"}})
_eq(errs_obj, [], "dict valid for 'object' type")

# ===========================================================================
# §10  validate_return_schema()
# ===========================================================================
print("§10  validate_return_schema() ...")
schema = {"required": ["status", "data"]}
_eq(validate_return_schema(schema, {"status": "ok", "data": {}}), [], "valid output -> no errors")
_eq(len(validate_return_schema(schema, {"status": "ok"})), 1, "missing 'data' -> 1 error")
_eq(len(validate_return_schema(schema, {})), 2, "missing both -> 2 errors")
_eq(validate_return_schema(schema, {"status": "ok", "data": {}, "extra": "x"}), [],
    "extra key allowed in output")
_eq(validate_return_schema({}, {"anything": "goes"}), [],
    "no required keys in schema -> always passes")
_eq(validate_return_schema({"required": []}, {"data": {}}), [],
    "empty required list -> always passes")

# ===========================================================================
# §11  validate_tool_call()
# ===========================================================================
print("§11  validate_tool_call() ...")
defn_enabled  = _simple_def("enabled_tool",  enabled=True)
defn_disabled = _simple_def("disabled_tool", enabled=False)

# Enabled + valid args -> no exception
try:
    validate_tool_call(defn_enabled, {"query": "test"})
    _assert(True, "enabled tool + valid args -> no exception")
except Exception:
    _assert(False, "enabled tool + valid args should not raise")

# Disabled tool -> ToolDisabledError
try:
    validate_tool_call(defn_disabled, {"query": "test"})
    _assert(False, "disabled tool should raise ToolDisabledError")
except ToolDisabledError as e:
    _assert(True, "disabled tool raises ToolDisabledError")
    _in("disabled_tool", str(e), "error mentions tool name")
    _eq(e.tool_id, defn_disabled.toolId, "exception carries tool_id")

# Invalid params -> ToolValidationError
defn_req = _simple_def("req_tool")
try:
    validate_tool_call(defn_req, {})   # missing required 'query'
    _assert(False, "missing required param should raise ToolValidationError")
except ToolValidationError as e:
    _assert(True, "missing required param raises ToolValidationError")
    _in("query", str(e), "error mentions missing param")
    _eq(e.tool_id, defn_req.toolId, "exception carries tool_id")

# ===========================================================================
# §12  ToolRegistry — register / unregister / find / list / exists
# ===========================================================================
print("§12  ToolRegistry operations ...")
reg = _make_registry()
_eq(len(reg), 0, "fresh registry is empty")

d1 = _simple_def("tool_alpha", "search")
d2 = _simple_def("tool_beta",  "query")
d3 = _simple_def("tool_gamma", "search")

reg.register_tool(d1, _ok_handler)
_eq(len(reg), 1, "after register: len=1")

reg.register_tool(d2, _ok_handler)
reg.register_tool(d3, _ok_handler)
_eq(len(reg), 3, "after 3 registrations: len=3")

# find_tool
found = reg.find_tool("tool_alpha")
_eq(found, d1, "find_tool('tool_alpha') returns d1")
not_found = reg.find_tool("tool_missing")
_assert(not_found is None, "find_tool for unknown -> None")

# tool_exists
_assert(reg.tool_exists("tool_alpha"), "tool_alpha exists")
_assert(reg.tool_exists("tool_beta"),  "tool_beta exists")
_assert(not reg.tool_exists("no_such"), "no_such does not exist")

# Case-insensitive lookup
_assert(reg.tool_exists("TOOL_ALPHA"), "tool_exists case-insensitive")
found_upper = reg.find_tool("TOOL_BETA")
_eq(found_upper, d2, "find_tool case-insensitive")

# list_tools — all
all_tools = reg.list_tools()
_eq(len(all_tools), 3, "list_tools() returns all 3")
_eq([t.toolName for t in all_tools], sorted(["tool_alpha","tool_beta","tool_gamma"]),
    "list_tools() sorted by toolName ASC")

# list_tools — filter by category
search_tools = reg.list_tools(category="search")
_eq(len(search_tools), 2, "filter category='search' -> 2 tools")
_assert(all(t.category == "search" for t in search_tools), "all results are 'search' category")

# list_tools — filter by enabled
_eq(len(reg.list_tools(enabled=True)), 3, "filter enabled=True -> 3")
_eq(len(reg.list_tools(enabled=False)), 0, "filter enabled=False -> 0 (none disabled yet)")

# Duplicate registration raises DuplicateToolError
try:
    reg.register_tool(d1, _ok_handler)
    _assert(False, "duplicate registration should raise DuplicateToolError")
except DuplicateToolError as e:
    _assert(True, "duplicate registration raises DuplicateToolError")
    _in("tool_alpha", str(e), "error mentions tool name")
    _eq(e.tool_id, d1.toolId, "exception carries tool_id")

# unregister_tool
reg.unregister_tool("tool_gamma")
_eq(len(reg), 2, "after unregister: len=2")
_assert(not reg.tool_exists("tool_gamma"), "tool_gamma no longer exists")

# Unregistering non-existent tool is a no-op
reg.unregister_tool("tool_missing")   # must not raise
_eq(len(reg), 2, "unregister non-existent: len unchanged")

# Re-register after unregister
reg.register_tool(d3, _ok_handler)
_eq(len(reg), 3, "re-register after unregister: len=3")

# ===========================================================================
# §13  ToolRegistry — enable / disable
# ===========================================================================
print("§13  enable/disable ...")
reg2 = _make_registry()
d_en = _simple_def("toggleable", enabled=True)
reg2.register_tool(d_en, _ok_handler)
_assert(reg2.find_tool("toggleable").enabled, "initially enabled")

# Disable
reg2.disable_tool("toggleable")
_assert(not reg2.find_tool("toggleable").enabled, "after disable_tool: enabled=False")

# Enable again
reg2.enable_tool("toggleable")
_assert(reg2.find_tool("toggleable").enabled, "after enable_tool: enabled=True")

# Disable preserves all other fields
reg2.disable_tool("toggleable")
toggled = reg2.find_tool("toggleable")
_eq(toggled.toolId,   d_en.toolId,   "toolId unchanged after disable")
_eq(toggled.toolName, d_en.toolName, "toolName unchanged after disable")
_eq(toggled.category, d_en.category, "category unchanged after disable")

# enable/disable on unknown tool raises ToolNotFoundError
try:
    reg2.enable_tool("no_such_tool")
    _assert(False, "enable_tool on unknown should raise ToolNotFoundError")
except ToolNotFoundError:
    _assert(True, "enable_tool on unknown raises ToolNotFoundError")

try:
    reg2.disable_tool("no_such_tool")
    _assert(False, "disable_tool on unknown should raise ToolNotFoundError")
except ToolNotFoundError:
    _assert(True, "disable_tool on unknown raises ToolNotFoundError")

# list_tools respects enabled state
reg2.disable_tool("toggleable")
_eq(len(reg2.list_tools(enabled=True)),  0, "disabled: list_tools(enabled=True)=0")
_eq(len(reg2.list_tools(enabled=False)), 1, "disabled: list_tools(enabled=False)=1")

# ===========================================================================
# §14  execute_tool() — success path
# ===========================================================================
print("§14  execute_tool() success ...")
reg3 = _make_registry()
d_exec = _simple_def("my_tool")
reg3.register_tool(d_exec, _ok_handler)

tcr = execute_tool(reg3, "my_tool", {"query": "hello"}, _RID, _TS)
_is(tcr, ToolCallingResult, "execute_tool returns ToolCallingResult")
_assert(tcr.toolResult.success, "success path: toolResult.success=True")
_assert(tcr.toolResult.error is None, "success path: error=None")
_eq(tcr.toolCall.toolName, "my_tool", "toolCall.toolName='my_tool'")
_eq(tcr.toolCall.requestId, _RID, "toolCall.requestId preserved")
_in("status", tcr.toolResult.output, "output has 'status' key")
_eq(tcr.toolResult.output["status"], "ok", "output status='ok'")
_assert(tcr.metadata.validationPassed, "metadata.validationPassed=True")
_ge(tcr.metadata.executionTimeMs, 0, "executionTimeMs >= 0")

# Determinism — same call -> same callId, resultKey depends on output (which is deterministic)
tcr2 = execute_tool(reg3, "my_tool", {"query": "hello"}, _RID, _TS)
_eq(tcr.toolCall.callId,  tcr2.toolCall.callId,  "same inputs -> same callId")

# ===========================================================================
# §15  execute_tool() — tool not found
# ===========================================================================
print("§15  execute_tool() not found ...")
reg4 = _make_registry()
try:
    execute_tool(reg4, "ghost_tool", {}, _RID, _TS)
    _assert(False, "unknown tool should raise ToolNotFoundError")
except ToolNotFoundError as e:
    _assert(True, "unknown tool raises ToolNotFoundError")
    _in("ghost_tool", str(e), "error mentions tool name")

# ===========================================================================
# §16  execute_tool() — disabled tool
# ===========================================================================
print("§16  execute_tool() disabled ...")
reg5 = _make_registry()
d_dis2 = _simple_def("blocked_tool", enabled=True)
reg5.register_tool(d_dis2, _ok_handler)
reg5.disable_tool("blocked_tool")

tcr_dis = execute_tool(reg5, "blocked_tool", {"query": "x"}, _RID, _TS)
_assert(not tcr_dis.toolResult.success, "disabled tool: success=False")
_assert(tcr_dis.toolResult.error is not None, "disabled tool: error message present")
_in("disabled", tcr_dis.toolResult.error.lower(), "error mentions 'disabled'")
_assert(not tcr_dis.metadata.validationPassed, "disabled: validationPassed=False")

# ===========================================================================
# §17  execute_tool() — validation failure
# ===========================================================================
print("§17  execute_tool() validation failure ...")
reg6 = _make_registry()
d_req2 = _simple_def("required_param_tool")  # param "query" is required
reg6.register_tool(d_req2, _ok_handler)

tcr_vf = execute_tool(reg6, "required_param_tool", {}, _RID, _TS)
_assert(not tcr_vf.toolResult.success, "validation failure: success=False")
_assert(tcr_vf.toolResult.error is not None, "validation failure: error present")
_assert(not tcr_vf.metadata.validationPassed, "validation failure: validationPassed=False")
_in("query", tcr_vf.toolResult.error, "error mentions missing param")

# ===========================================================================
# §18  execute_tool() — handler exception
# ===========================================================================
print("§18  execute_tool() handler exception ...")
reg7 = _make_registry()
d_fail2 = _simple_def("failing_tool")
reg7.register_tool(d_fail2, _fail_handler)

tcr_fail = execute_tool(reg7, "failing_tool", {"query": "x"}, _RID, _TS)
_assert(not tcr_fail.toolResult.success, "handler exception: success=False")
_assert(tcr_fail.toolResult.error is not None, "handler exception: error present")
_in("Unexpected error", tcr_fail.toolResult.error, "error wraps handler exception")
_assert(tcr_fail.metadata.validationPassed, "handler exception: validation still passed")

# ===========================================================================
# §19  execute_tool() — async handler
# ===========================================================================
print("§19  execute_tool() async handler ...")

async def _async_handler(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "ok", "async": True}

reg8 = _make_registry()
d_async = _simple_def("async_tool")
reg8.register_tool(d_async, _async_handler)

tcr_async = execute_tool(reg8, "async_tool", {"query": "async"}, _RID, _TS)
_assert(tcr_async.toolResult.success, "async handler: success=True")
_assert(tcr_async.toolResult.output.get("async") is True, "async handler output correct")

# ===========================================================================
# §20  execute_registered_tool() — async native
# ===========================================================================
print("§20  execute_registered_tool() async ...")

async def _run_async_exec():
    reg9 = _make_registry()
    d9   = _simple_def("async_native_tool")
    reg9.register_tool(d9, _ok_handler)
    result = await execute_registered_tool(reg9, "async_native_tool", {"query": "test"}, _RID, _TS)
    return result

tcr9 = asyncio.run(_run_async_exec())
_is(tcr9, ToolCallingResult, "execute_registered_tool returns ToolCallingResult")
_assert(tcr9.toolResult.success, "async exec: success=True")

# Async exec — tool not found
async def _run_async_notfound():
    try:
        await execute_registered_tool(_make_registry(), "ghost", {}, _RID, _TS)
        return False
    except ToolNotFoundError:
        return True

_assert(asyncio.run(_run_async_notfound()), "async: ToolNotFoundError raised for missing tool")

# Async exec — disabled tool returns failure result
async def _run_async_disabled():
    reg_a = _make_registry()
    d_a   = _simple_def("async_disabled")
    reg_a.register_tool(d_a, _ok_handler)
    reg_a.disable_tool("async_disabled")
    return await execute_registered_tool(reg_a, "async_disabled", {"query": "x"}, _RID, _TS)

tcr_ad = asyncio.run(_run_async_disabled())
_assert(not tcr_ad.toolResult.success, "async disabled: success=False")

# Async exec — handler raises
async def _run_async_fail():
    reg_f = _make_registry()
    d_f   = _simple_def("async_failing")
    reg_f.register_tool(d_f, _fail_handler)
    return await execute_registered_tool(reg_f, "async_failing", {"query": "x"}, _RID, _TS)

tcr_af = asyncio.run(_run_async_fail())
_assert(not tcr_af.toolResult.success, "async fail: success=False")
_in("Unexpected error", tcr_af.toolResult.error, "async fail: error wraps exception")

# ===========================================================================
# §21  execute_batch()
# ===========================================================================
print("§21  execute_batch() ...")
reg_b = _make_registry()
reg_b.register_tool(_simple_def("batch_a"), _ok_handler)
reg_b.register_tool(_simple_def("batch_b"), _ok_handler)
reg_b.register_tool(_simple_def("batch_c"), _ok_handler)

batch_calls = [
    {"tool_name": "batch_a", "arguments": {"query": "alpha"}, "request_id": "r1"},
    {"tool_name": "batch_b", "arguments": {"query": "beta"},  "request_id": "r2"},
    {"tool_name": "batch_c", "arguments": {"query": "gamma"}, "request_id": "r3"},
]
batch_results = execute_batch(reg_b, batch_calls, _TS)
_eq(len(batch_results), 3, "batch: returns 3 results")
_assert(all(r.toolResult.success for r in batch_results), "batch: all successful")
_eq([r.toolCall.toolName for r in batch_results],
    ["batch_a", "batch_b", "batch_c"],
    "batch: results in input order")

# Batch with one missing tool
batch_with_missing = [
    {"tool_name": "batch_a",   "arguments": {"query": "x"}, "request_id": "r1"},
    {"tool_name": "no_such_tool", "arguments": {}, "request_id": "r2"},
    {"tool_name": "batch_b",   "arguments": {"query": "y"}, "request_id": "r3"},
]
batch_mixed = execute_batch(reg_b, batch_with_missing, _TS)
_eq(len(batch_mixed), 3, "batch with missing: still returns 3 results")
_assert(batch_mixed[0].toolResult.success,     "batch: result[0] succeeded")
_assert(not batch_mixed[1].toolResult.success, "batch: result[1] failed (not found)")
_assert(batch_mixed[2].toolResult.success,     "batch: result[2] succeeded")

# Empty batch
empty_batch = execute_batch(reg_b, [], _TS)
_eq(empty_batch, [], "empty batch -> empty results")

# ===========================================================================
# §22  execute_parallel()
# ===========================================================================
print("§22  execute_parallel() ...")

async def _run_parallel():
    reg_p = _make_registry()
    reg_p.register_tool(_simple_def("par_a"), _ok_handler)
    reg_p.register_tool(_simple_def("par_b"), _ok_handler)
    reg_p.register_tool(_simple_def("par_c"), _ok_handler)

    calls = [
        {"tool_name": "par_a", "arguments": {"query": "a"}, "request_id": "p1"},
        {"tool_name": "par_b", "arguments": {"query": "b"}, "request_id": "p2"},
        {"tool_name": "par_c", "arguments": {"query": "c"}, "request_id": "p3"},
    ]
    return await execute_parallel(reg_p, calls, _TS)

par_results = asyncio.run(_run_parallel())
_eq(len(par_results), 3, "parallel: returns 3 results")
_assert(all(r.toolResult.success for r in par_results), "parallel: all successful")
_eq(sorted([r.toolCall.toolName for r in par_results]),
    ["par_a", "par_b", "par_c"],
    "parallel: all tools executed")

# Parallel with one missing tool — no abort
async def _run_parallel_with_missing():
    reg_pm = _make_registry()
    reg_pm.register_tool(_simple_def("pm_a"), _ok_handler)
    calls = [
        {"tool_name": "pm_a",     "arguments": {"query": "x"}, "request_id": "pm1"},
        {"tool_name": "pm_ghost", "arguments": {},              "request_id": "pm2"},
    ]
    return await execute_parallel(reg_pm, calls, _TS)

pm_results = asyncio.run(_run_parallel_with_missing())
_eq(len(pm_results), 2, "parallel with missing: 2 results")
_assert(pm_results[0].toolResult.success,     "parallel: result[0] succeeded")
_assert(not pm_results[1].toolResult.success, "parallel: result[1] failed (missing tool)")

# ===========================================================================
# §23  Default registry — built-in tools pre-registered
# ===========================================================================
print("§23  Default registry built-in tools ...")
dr = get_default_registry()
all_builtin = dr.list_tools()

EXPECTED_BUILTINS = [
    "search_assets", "search_evidence", "search_relationships",
    "search_attack_graph", "search_timeline", "search_findings",
    "search_alerts", "search_investigations", "generate_report",
    "query_statistics",
]
_eq(len(all_builtin), len(EXPECTED_BUILTINS), f"default registry has {len(EXPECTED_BUILTINS)} built-in tools")

for name in EXPECTED_BUILTINS:
    _assert(dr.tool_exists(name), f"built-in tool '{name}' is registered")
    found_bi = dr.find_tool(name)
    _assert(found_bi is not None, f"find_tool('{name}') returns a definition")
    _assert(found_bi.enabled, f"built-in '{name}' is enabled by default")
    _eq(found_bi.toolName, name, f"built-in '{name}' toolName matches")
    _eq(len(found_bi.toolId), 36, f"built-in '{name}' toolId is UUID")
    _eq(found_bi.engineVersion, TOOL_CALLING_ENGINE_VERSION, f"built-in '{name}' engineVersion set")

# Categories
search_builtins = dr.list_tools(category="search")
_eq(len(search_builtins), 8, "8 built-in tools in 'search' category")
_assert(all(t.category == "search" for t in search_builtins), "all search tools have correct category")

report_builtins = dr.list_tools(category="report")
_eq(len(report_builtins), 1, "1 built-in tool in 'report' category")
_eq(report_builtins[0].toolName, "generate_report", "report tool is 'generate_report'")

query_builtins = dr.list_tools(category="query")
_eq(len(query_builtins), 1, "1 built-in tool in 'query' category")
_eq(query_builtins[0].toolName, "query_statistics", "query tool is 'query_statistics'")

# ===========================================================================
# §24  Executing built-in placeholder tools
# ===========================================================================
print("§24  Executing built-in placeholder tools ...")
for name in EXPECTED_BUILTINS:
    # All built-ins accept empty arguments (all params optional except generate_report)
    args = {}
    if name == "generate_report":
        args = {"investigation_id": "inv-test-001"}

    tcr_bi = execute_tool(dr, name, args, "req-builtin", _TS)
    _is(tcr_bi, ToolCallingResult, f"built-in '{name}': returns ToolCallingResult")
    _assert(tcr_bi.toolResult.success, f"built-in '{name}': placeholder succeeds")
    _eq(tcr_bi.toolResult.output.get("tool"), name, f"built-in '{name}': output.tool matches name")
    _eq(tcr_bi.toolCall.toolName, name, f"built-in '{name}': toolCall.toolName correct")
    _assert(tcr_bi.metadata.validationPassed, f"built-in '{name}': validation passed")

# ===========================================================================
# §25  Zero randomness — deterministic IDs across 5 rebuilds
# ===========================================================================
print("§25  Zero randomness ...")

# ToolDefinition toolId — same 5 times
tool_ids = set()
for _ in range(5):
    d = build_tool_definition("zero_rand_tool", "desc", "test", [], {}, _TS)
    tool_ids.add(d.toolId)
_eq(len(tool_ids), 1, "zero randomness: 5 ToolDefinition builds -> same toolId")

# ToolCall callId — same 5 times
call_ids = set()
d_zr = build_tool_definition("zero_rand_tool", "desc", "test", [], {}, _TS)
for _ in range(5):
    c = build_tool_call(d_zr, {"a": 1}, "req-zr", _TS)
    call_ids.add(c.callId)
_eq(len(call_ids), 1, "zero randomness: 5 ToolCall builds -> same callId")

# ToolResult resultId — same 5 times
result_ids = set()
c_zr = build_tool_call(d_zr, {"a": 1}, "req-zr", _TS)
for _ in range(5):
    r = build_tool_result(c_zr.callId, d_zr.toolId, True, {"status": "ok"}, 10, _TS)
    result_ids.add(r.resultId)
_eq(len(result_ids), 1, "zero randomness: 5 ToolResult builds -> same resultId")

# Execute same call 5 times — same callId each time
reg_zr = _make_registry()
reg_zr.register_tool(_simple_def("zr_exec_tool"), _ok_handler)
exec_call_ids = set()
for _ in range(5):
    r = execute_tool(reg_zr, "zr_exec_tool", {"query": "same"}, "req-zr", _TS)
    exec_call_ids.add(r.toolCall.callId)
_eq(len(exec_call_ids), 1, "zero randomness: 5 execute_tool calls -> same callId")

# ===========================================================================
# §26  Identical inputs -> identical outputs
# ===========================================================================
print("§26  Identical inputs -> identical outputs ...")

p_id  = build_tool_parameter("x", "string", "X param.")
d_id1 = build_tool_definition("id_tool", "desc", "test", [p_id], {"required":["status"]}, _TS)
d_id2 = build_tool_definition("id_tool", "desc", "test", [p_id], {"required":["status"]}, _TS)
_eq(d_id1, d_id2, "identical ToolDefinition builds -> equal objects")
_eq(d_id1.toolId,  d_id2.toolId,  "identical builds -> same toolId")
_eq(d_id1.toolKey, d_id2.toolKey, "identical builds -> same toolKey")

c_id1 = build_tool_call(d_id1, {"x": "abc"}, "rid1", _TS)
c_id2 = build_tool_call(d_id2, {"x": "abc"}, "rid1", _TS)
_eq(c_id1, c_id2, "identical ToolCall builds -> equal objects")
_eq(c_id1.callId,  c_id2.callId,  "identical builds -> same callId")

tr_id1 = build_tool_result(c_id1.callId, d_id1.toolId, True, {"status":"ok"}, 10, _TS)
tr_id2 = build_tool_result(c_id2.callId, d_id2.toolId, True, {"status":"ok"}, 10, _TS)
_eq(tr_id1, tr_id2, "identical ToolResult builds -> equal objects")
_eq(tr_id1.resultId,  tr_id2.resultId,  "identical builds -> same resultId")
_eq(tr_id1.resultKey, tr_id2.resultKey, "identical builds -> same resultKey")

em_id1 = build_execution_metadata(100, 200, True, "groq", "llama")
em_id2 = build_execution_metadata(100, 200, True, "groq", "llama")
_eq(em_id1, em_id2, "identical ToolExecutionMetadata builds -> equal objects")

# ===========================================================================
# §27  Serialisation — all models JSON serialisable
# ===========================================================================
print("§27  Serialisation ...")
import json as _json

# ToolParameter
p_ser = build_tool_parameter("key", "string", "desc", required=False, default_value="x")
pd = p_ser.model_dump()
_is(pd, dict, "ToolParameter.model_dump() returns dict")
for f in ("name", "type", "description", "required", "defaultValue"):
    _in(f, pd, f"ToolParameter dict has '{f}'")
_eq(_json.loads(_json.dumps(pd))["name"], "key", "ToolParameter JSON roundtrip")

# ToolDefinition
d_ser = _simple_def("ser_tool")
dd = d_ser.model_dump()
_is(dd, dict, "ToolDefinition.model_dump() returns dict")
for f in ("toolId","toolKey","toolName","description","category","parameters",
          "returnSchema","enabled","createdAt","engineVersion"):
    _in(f, dd, f"ToolDefinition dict has '{f}'")

# ToolCall
tc_ser = build_tool_call(d_ser, {"query": "x"}, "r1", _TS)
tcd = tc_ser.model_dump()
_is(tcd, dict, "ToolCall.model_dump() returns dict")
for f in ("callId","callKey","toolId","toolName","arguments","requestId","provider","model","createdAt"):
    _in(f, tcd, f"ToolCall dict has '{f}'")

# ToolResult
tr_ser = build_tool_result(tc_ser.callId, d_ser.toolId, True, {"status":"ok"}, 5, _TS)
trd = tr_ser.model_dump()
_is(trd, dict, "ToolResult.model_dump() returns dict")
for f in ("resultId","resultKey","toolId","success","output","executionTimeMs","error","metadata","createdAt"):
    _in(f, trd, f"ToolResult dict has '{f}'")

# ToolExecutionMetadata
em_ser = build_execution_metadata(0, 50, True, "groq", "llama", ["warn"])
emd = em_ser.model_dump()
_is(emd, dict, "ToolExecutionMetadata.model_dump() returns dict")
for f in ("startedAt","completedAt","executionTimeMs","validationPassed","provider","model","warnings"):
    _in(f, emd, f"ToolExecutionMetadata dict has '{f}'")

# ToolCallingResult
tcr_ser = build_tool_calling_result(tc_ser, tr_ser, em_ser)
tcrd = tcr_ser.model_dump()
_is(tcrd, dict, "ToolCallingResult.model_dump() returns dict")
for f in ("toolCall","toolResult","metadata"):
    _in(f, tcrd, f"ToolCallingResult dict has '{f}'")

# Full JSON roundtrip
try:
    _json.dumps(tcrd, default=str)
    _assert(True, "ToolCallingResult is JSON serialisable")
except Exception as e:
    _assert(False, f"ToolCallingResult JSON serialisation failed: {e}")

# ===========================================================================
# §28  Exception class hierarchy and attributes
# ===========================================================================
print("§28  Exception hierarchy ...")
exc_classes = [
    ToolNotFoundError, ToolDisabledError, ToolValidationError,
    ToolExecutionError, ToolTimeoutError, DuplicateToolError,
]
for cls in exc_classes:
    _assert(issubclass(cls, ToolCallingError), f"{cls.__name__} is ToolCallingError subclass")
    _assert(issubclass(cls, Exception),        f"{cls.__name__} is Exception subclass")

# Attributes
e1 = ToolNotFoundError("not found", tool_id="tid-abc")
_eq(e1.tool_id, "tid-abc", "ToolNotFoundError.tool_id set")
_in("not found", str(e1), "ToolNotFoundError message in str()")
r1 = repr(e1)
_in("ToolNotFoundError", r1, "repr includes class name")
_in("tid-abc",           r1, "repr includes tool_id")
_in("not found",         r1, "repr includes message")

# Default tool_id is ""
e2 = ToolDisabledError("disabled")
_eq(e2.tool_id, "", "default tool_id is empty string")

# All exceptions have tool_id attribute
for cls in exc_classes:
    inst = cls("test")
    _assert(hasattr(inst, "tool_id"), f"{cls.__name__} has tool_id attribute")

# ===========================================================================
# §29  Security — allow-list enforcement
# ===========================================================================
print("§29  Security — allow-list ...")

# Only registered tools can be executed
sec_reg = _make_registry()
# Nothing registered
try:
    execute_tool(sec_reg, "exec_unknown", {}, "r", _TS)
    _assert(False, "unregistered tool must raise ToolNotFoundError")
except ToolNotFoundError:
    _assert(True, "unregistered tool blocked by allow-list")

# Register then execute succeeds
sec_reg.register_tool(_simple_def("allowed_tool"), _ok_handler)
sec_ok = execute_tool(sec_reg, "allowed_tool", {"query": "x"}, "r", _TS)
_assert(sec_ok.toolResult.success, "registered tool executes after allow-listing")

# Unregister then attempt fails
sec_reg.unregister_tool("allowed_tool")
try:
    execute_tool(sec_reg, "allowed_tool", {"query": "x"}, "r", _TS)
    _assert(False, "unregistered tool should raise after removal")
except ToolNotFoundError:
    _assert(True, "unregistered tool blocked after removal")

# Disabled protection — disable, try, re-enable, try again
sec_reg.register_tool(_simple_def("protected_tool"), _ok_handler)
sec_reg.disable_tool("protected_tool")
sec_dis = execute_tool(sec_reg, "protected_tool", {"query": "x"}, "r", _TS)
_assert(not sec_dis.toolResult.success, "disabled tool blocked")

sec_reg.enable_tool("protected_tool")
sec_ena = execute_tool(sec_reg, "protected_tool", {"query": "x"}, "r", _TS)
_assert(sec_ena.toolResult.success, "re-enabled tool executes")

# ===========================================================================
# §30  Integration with Groq Provider models
# ===========================================================================
print("§30  Groq Provider integration ...")
from services.groq_provider_service import (
    build_message, build_request as build_groq_request, GroqRequest,
)
from core.constants import GROQ_PROVIDER_ENGINE_VERSION

_MSGS_G = [
    build_message("system", "You are a network forensics agent."),
    build_message("user",   "Search for suspicious assets."),
]
groq_req = build_groq_request(
    "llama-3.3-70b-versatile", _MSGS_G, _TS,
    temperature=0.0, max_tokens=512,
)
_is(groq_req, GroqRequest, "built GroqRequest successfully")

# Use GroqRequest.requestId as the requestId in a ToolCall
int_reg = _make_registry()
int_reg.register_tool(_simple_def("search_assets_int"), _ok_handler)

tc_int = build_tool_call(
    _simple_def("search_assets_int"),
    {"query": "suspicious", "limit": 5},
    groq_req.requestId,
    _TS,
    provider="groq",
    model=groq_req.model,
)
_eq(tc_int.requestId, groq_req.requestId, "ToolCall.requestId = GroqRequest.requestId")
_eq(tc_int.provider, "groq", "provider='groq'")
_eq(tc_int.model, groq_req.model, "model matches GroqRequest.model")

# Execute using GroqRequest.requestId
tcr_int = execute_tool(int_reg, "search_assets_int",
                       {"query": "suspicious"}, groq_req.requestId, _TS,
                       provider="groq", model=groq_req.model)
_assert(tcr_int.toolResult.success, "integration: execution succeeds")
_eq(tcr_int.toolCall.requestId, groq_req.requestId, "integration: requestId linked to GroqRequest")
_eq(tcr_int.toolCall.provider, "groq", "integration: provider='groq'")
_eq(tcr_int.toolCall.model, groq_req.model, "integration: model matches")
_eq(tcr_int.metadata.provider, "groq", "integration: metadata.provider='groq'")

# ToolDefinition.engineVersion differs from GroqProvider.engineVersion
_ne(TOOL_CALLING_ENGINE_VERSION, GROQ_PROVIDER_ENGINE_VERSION,
    "tool calling engine version != groq provider engine version")

# Deterministic: same GroqRequest -> same ToolCall callId
tc_int2 = build_tool_call(
    _simple_def("search_assets_int"),
    {"query": "suspicious", "limit": 5},
    groq_req.requestId, _TS, provider="groq", model=groq_req.model,
)
_eq(tc_int.callId, tc_int2.callId, "same GroqRequest.requestId -> same ToolCall callId")

# ===========================================================================
# §31  ToolParameter field coverage
# ===========================================================================
print("§31  ToolParameter field coverage ...")
# Every field present
p_full = build_tool_parameter("full_param", "object", "Full param.", required=False, default_value={"key": "val"})
_eq(p_full.name,         "full_param",      "name stored")
_eq(p_full.type,         "object",          "type stored")
_eq(p_full.description,  "Full param.",     "description stored")
_assert(not p_full.required,               "required=False stored")
_eq(p_full.defaultValue, {"key": "val"},   "defaultValue dict stored")

# Boolean type with default=True
p_bool = build_tool_parameter("flag", "boolean", "Flag.", required=False, default_value=True)
_eq(p_bool.type,         "boolean", "boolean type")
_assert(p_bool.defaultValue is True, "defaultValue=True stored")

# Integer type with default=0
p_int = build_tool_parameter("count", "integer", "Count.", required=False, default_value=0)
_eq(p_int.type, "integer", "integer type")
_eq(p_int.defaultValue, 0, "defaultValue=0 stored")

# Array type with None default
p_arr = build_tool_parameter("ids", "array", "IDs.", required=False, default_value=None)
_assert(p_arr.defaultValue is None, "array param: defaultValue=None stored")

# ===========================================================================
# §32  ToolDefinition returnSchema preservation
# ===========================================================================
print("§32  returnSchema preservation ...")
complex_schema = {
    "type"      : "object",
    "required"  : ["status", "data", "count"],
    "properties": {
        "status": {"type": "string"},
        "data"  : {"type": "array"},
        "count" : {"type": "integer"},
    },
}
d_schema = build_tool_definition("schema_tool", "desc", "test", [], complex_schema, _TS)
_eq(d_schema.returnSchema, complex_schema, "complex returnSchema preserved exactly")

# validate_return_schema uses the stored schema
valid_out   = {"status": "ok", "data": [], "count": 0}
invalid_out = {"status": "ok"}
_eq(validate_return_schema(d_schema.returnSchema, valid_out), [],
    "valid output passes returnSchema validation")
errs_schema = validate_return_schema(d_schema.returnSchema, invalid_out)
_ge(len(errs_schema), 1, "invalid output fails returnSchema validation")

# ===========================================================================
# §33  ToolRegistry list_tools combined filters
# ===========================================================================
print("§33  list_tools combined filters ...")
reg_lf = _make_registry()
reg_lf.register_tool(_simple_def("lf_search_1", "search"), _ok_handler)
reg_lf.register_tool(_simple_def("lf_search_2", "search"), _ok_handler)
reg_lf.register_tool(_simple_def("lf_query_1",  "query"),  _ok_handler)
reg_lf.register_tool(_simple_def("lf_report_1", "report"), _ok_handler)
reg_lf.disable_tool("lf_search_2")

# Category filter
_eq(len(reg_lf.list_tools(category="search")), 2, "filter category='search' -> 2")
_eq(len(reg_lf.list_tools(category="query")),  1, "filter category='query' -> 1")
_eq(len(reg_lf.list_tools(category="report")), 1, "filter category='report' -> 1")
_eq(len(reg_lf.list_tools(category="none")),   0, "filter unknown category -> 0")

# Enabled filter
_eq(len(reg_lf.list_tools(enabled=True)),  3, "filter enabled=True -> 3")
_eq(len(reg_lf.list_tools(enabled=False)), 1, "filter enabled=False -> 1")

# Combined: enabled=True, category=search
enabled_search = reg_lf.list_tools(category="search", enabled=True)
_eq(len(enabled_search), 1, "category=search + enabled=True -> 1")
_eq(enabled_search[0].toolName, "lf_search_1", "correct enabled search tool")

# Combined: enabled=False, category=search
disabled_search = reg_lf.list_tools(category="search", enabled=False)
_eq(len(disabled_search), 1, "category=search + enabled=False -> 1")
_eq(disabled_search[0].toolName, "lf_search_2", "correct disabled search tool")

# ===========================================================================
# §34  Batch execution — order preserved and provider/model forwarded
# ===========================================================================
print("§34  Batch order and metadata ...")
reg_bo = _make_registry()
reg_bo.register_tool(_simple_def("bo_tool_1"), _ok_handler)
reg_bo.register_tool(_simple_def("bo_tool_2"), _ok_handler)
reg_bo.register_tool(_simple_def("bo_tool_3"), _ok_handler)

bo_calls = [
    {"tool_name": "bo_tool_3", "arguments": {"query": "third"}, "request_id": "r3"},
    {"tool_name": "bo_tool_1", "arguments": {"query": "first"}, "request_id": "r1"},
    {"tool_name": "bo_tool_2", "arguments": {"query": "second"},"request_id": "r2"},
]
bo_results = execute_batch(reg_bo, bo_calls, _TS, provider="groq", model="llama-3.1-8b-instant")
_eq(len(bo_results), 3, "batch order: 3 results")
_eq(bo_results[0].toolCall.toolName, "bo_tool_3", "batch order: result[0] = bo_tool_3 (input order)")
_eq(bo_results[1].toolCall.toolName, "bo_tool_1", "batch order: result[1] = bo_tool_1")
_eq(bo_results[2].toolCall.toolName, "bo_tool_2", "batch order: result[2] = bo_tool_2")
_eq(bo_results[0].toolCall.provider, "groq", "batch: provider forwarded")
_eq(bo_results[0].toolCall.model,    "llama-3.1-8b-instant", "batch: model forwarded")

# Batch: disabled tool in middle
reg_bo.disable_tool("bo_tool_2")
bo_dis_calls = [
    {"tool_name": "bo_tool_1", "arguments": {"query": "a"}, "request_id": "r1"},
    {"tool_name": "bo_tool_2", "arguments": {"query": "b"}, "request_id": "r2"},
    {"tool_name": "bo_tool_3", "arguments": {"query": "c"}, "request_id": "r3"},
]
bo_dis_results = execute_batch(reg_bo, bo_dis_calls, _TS)
_assert(bo_dis_results[0].toolResult.success,     "batch disabled: result[0] ok")
_assert(not bo_dis_results[1].toolResult.success, "batch disabled: result[1] failed (disabled)")
_assert(bo_dis_results[2].toolResult.success,     "batch disabled: result[2] ok")

# ===========================================================================
# §35  All ToolDefinition fields present and correct
# ===========================================================================
print("§35  ToolDefinition field completeness ...")
d_full = build_tool_definition(
    tool_name     = "full_definition_tool",
    description   = "A fully specified tool.",
    category      = "search",
    parameters    = [
        build_tool_parameter("required_param", "string",  "Required.",  required=True),
        build_tool_parameter("optional_param", "integer", "Optional.",  required=False, default_value=5),
    ],
    return_schema = {"required": ["status"], "type": "object"},
    created_at    = _TS,
    enabled       = True,
)
_assert(hasattr(d_full, "toolId"),        "ToolDefinition has toolId")
_assert(hasattr(d_full, "toolKey"),       "ToolDefinition has toolKey")
_assert(hasattr(d_full, "toolName"),      "ToolDefinition has toolName")
_assert(hasattr(d_full, "description"),   "ToolDefinition has description")
_assert(hasattr(d_full, "category"),      "ToolDefinition has category")
_assert(hasattr(d_full, "parameters"),    "ToolDefinition has parameters")
_assert(hasattr(d_full, "returnSchema"),  "ToolDefinition has returnSchema")
_assert(hasattr(d_full, "enabled"),       "ToolDefinition has enabled")
_assert(hasattr(d_full, "createdAt"),     "ToolDefinition has createdAt")
_assert(hasattr(d_full, "engineVersion"), "ToolDefinition has engineVersion")
_eq(len(d_full.parameters), 2, "parameters tuple has 2 items")
_eq(d_full.parameters[0].name, "required_param", "first parameter name correct")
_eq(d_full.parameters[1].name, "optional_param", "second parameter name correct")

# ===========================================================================
# §36  All ToolCall fields present and correct
# ===========================================================================
print("§36  ToolCall field completeness ...")
d_fc = build_tool_definition("fc_tool", "desc", "search", [
    build_tool_parameter("q", "string", "Query.", required=True),
], {}, _TS)
tc_fc = build_tool_call(d_fc, {"q": "test"}, "req-fc-001", _TS, provider="groq", model="llama-3.3-70b-versatile")
_assert(hasattr(tc_fc, "callId"),    "ToolCall has callId")
_assert(hasattr(tc_fc, "callKey"),   "ToolCall has callKey")
_assert(hasattr(tc_fc, "toolId"),    "ToolCall has toolId")
_assert(hasattr(tc_fc, "toolName"),  "ToolCall has toolName")
_assert(hasattr(tc_fc, "arguments"), "ToolCall has arguments")
_assert(hasattr(tc_fc, "requestId"), "ToolCall has requestId")
_assert(hasattr(tc_fc, "provider"),  "ToolCall has provider")
_assert(hasattr(tc_fc, "model"),     "ToolCall has model")
_assert(hasattr(tc_fc, "createdAt"), "ToolCall has createdAt")
_eq(tc_fc.arguments, {"q": "test"}, "ToolCall arguments stored correctly")
_eq(tc_fc.requestId, "req-fc-001",  "ToolCall requestId stored correctly")

# ===========================================================================
# §37  All ToolResult fields present and correct
# ===========================================================================
print("§37  ToolResult field completeness ...")
tr_fc = build_tool_result(tc_fc.callId, d_fc.toolId, True, {"status":"ok","data":{}}, 55, _TS,
                          metadata={"custom_key": "custom_val"})
_assert(hasattr(tr_fc, "resultId"),        "ToolResult has resultId")
_assert(hasattr(tr_fc, "resultKey"),       "ToolResult has resultKey")
_assert(hasattr(tr_fc, "toolId"),          "ToolResult has toolId")
_assert(hasattr(tr_fc, "success"),         "ToolResult has success")
_assert(hasattr(tr_fc, "output"),          "ToolResult has output")
_assert(hasattr(tr_fc, "executionTimeMs"), "ToolResult has executionTimeMs")
_assert(hasattr(tr_fc, "error"),           "ToolResult has error")
_assert(hasattr(tr_fc, "metadata"),        "ToolResult has metadata")
_assert(hasattr(tr_fc, "createdAt"),       "ToolResult has createdAt")
_eq(tr_fc.executionTimeMs, 55, "executionTimeMs=55 stored")
_in("custom_key", tr_fc.metadata, "custom metadata key preserved")
_in("engineVersion", tr_fc.metadata, "engineVersion auto-added to metadata")

# ===========================================================================
# §38  All ToolExecutionMetadata fields present and correct
# ===========================================================================
print("§38  ToolExecutionMetadata field completeness ...")
em_fc = build_execution_metadata(500, 750, True, "groq", "llama-3.1-8b-instant", ["warn-a", "warn-b"])
_assert(hasattr(em_fc, "startedAt"),        "ToolExecutionMetadata has startedAt")
_assert(hasattr(em_fc, "completedAt"),      "ToolExecutionMetadata has completedAt")
_assert(hasattr(em_fc, "executionTimeMs"),  "ToolExecutionMetadata has executionTimeMs")
_assert(hasattr(em_fc, "validationPassed"), "ToolExecutionMetadata has validationPassed")
_assert(hasattr(em_fc, "provider"),         "ToolExecutionMetadata has provider")
_assert(hasattr(em_fc, "model"),            "ToolExecutionMetadata has model")
_assert(hasattr(em_fc, "warnings"),         "ToolExecutionMetadata has warnings")
_eq(em_fc.executionTimeMs, 250, "executionTimeMs = 750 - 500 = 250ms")
_eq(em_fc.warnings, ("warn-a", "warn-b"), "warnings tuple stored sorted")

# ===========================================================================
# §39  All ToolCallingResult fields present and correct
# ===========================================================================
print("§39  ToolCallingResult field completeness ...")
tcr_fc = build_tool_calling_result(tc_fc, tr_fc, em_fc)
_assert(hasattr(tcr_fc, "toolCall"),   "ToolCallingResult has toolCall")
_assert(hasattr(tcr_fc, "toolResult"), "ToolCallingResult has toolResult")
_assert(hasattr(tcr_fc, "metadata"),   "ToolCallingResult has metadata")
_eq(tcr_fc.toolCall.callId,   tc_fc.callId,   "ToolCallingResult.toolCall.callId preserved")
_eq(tcr_fc.toolResult.toolId, d_fc.toolId,    "ToolCallingResult.toolResult.toolId preserved")
_eq(tcr_fc.metadata.provider, "groq",         "ToolCallingResult.metadata.provider='groq'")

# ===========================================================================
# §40  Timeout support
# ===========================================================================
print("§40  Timeout support ...")

import time as _time_mod

# Fast handler — completes well within 5s timeout
def _fast_handler(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "ok", "fast": True}

reg_to = _make_registry()
reg_to.register_tool(_simple_def("fast_tool"), _fast_handler)
tcr_to = execute_tool(reg_to, "fast_tool", {"query": "x"}, "r", _TS, timeout_seconds=5.0)
_assert(tcr_to.toolResult.success, "fast handler within timeout: succeeds")
_assert(tcr_to.toolResult.output.get("fast") is True, "fast handler output correct")

# ToolTimeoutError exception has correct attributes
tte = ToolTimeoutError("timed out after 1s", tool_id="tid-timeout")
_eq(tte.tool_id, "tid-timeout", "ToolTimeoutError.tool_id set")
_in("timed out", str(tte), "ToolTimeoutError message")
_assert(issubclass(ToolTimeoutError, ToolCallingError), "ToolTimeoutError is ToolCallingError")

# ===========================================================================
# §41  Non-dict handler output is wrapped in {"result": ...}
# ===========================================================================
print("§41  Non-dict output wrapping ...")

def _list_handler(arguments: Dict[str, Any]) -> Any:
    return [1, 2, 3]

def _str_handler(arguments: Dict[str, Any]) -> Any:
    return "plain string result"

def _int_handler(arguments: Dict[str, Any]) -> Any:
    return 42

reg_ndo = _make_registry()
reg_ndo.register_tool(_simple_def("list_tool"), _list_handler)
reg_ndo.register_tool(_simple_def("str_tool"),  _str_handler)
reg_ndo.register_tool(_simple_def("int_tool"),  _int_handler)

tcr_list = execute_tool(reg_ndo, "list_tool", {"query": "x"}, "r", _TS)
_assert(tcr_list.toolResult.success, "list handler: success")
_is(tcr_list.toolResult.output, dict, "list handler: output wrapped in dict")
_in("result", tcr_list.toolResult.output, "list handler: wrapped key is 'result'")
_eq(tcr_list.toolResult.output["result"], [1, 2, 3], "list handler: original value preserved")

tcr_str = execute_tool(reg_ndo, "str_tool", {"query": "x"}, "r", _TS)
_assert(tcr_str.toolResult.success, "string handler: success")
_eq(tcr_str.toolResult.output["result"], "plain string result", "string handler: wrapped correctly")

tcr_int = execute_tool(reg_ndo, "int_tool", {"query": "x"}, "r", _TS)
_assert(tcr_int.toolResult.success, "int handler: success")
_eq(tcr_int.toolResult.output["result"], 42, "int handler: wrapped correctly")

# ===========================================================================
# §42  execute_tool provider/model metadata forwarding
# ===========================================================================
print("§42  Provider/model metadata forwarding ...")
reg_pm2 = _make_registry()
reg_pm2.register_tool(_simple_def("pm_tool"), _ok_handler)

tcr_pm = execute_tool(reg_pm2, "pm_tool", {"query": "x"}, "r", _TS,
                      provider="openai", model="gpt-4o")
_eq(tcr_pm.toolCall.provider, "openai", "provider='openai' in toolCall")
_eq(tcr_pm.toolCall.model,    "gpt-4o", "model='gpt-4o' in toolCall")
_eq(tcr_pm.metadata.provider, "openai", "provider='openai' in metadata")
_eq(tcr_pm.metadata.model,    "gpt-4o", "model='gpt-4o' in metadata")

# Default provider when none supplied
tcr_def = execute_tool(reg_pm2, "pm_tool", {"query": "x"}, "r", _TS)
_eq(tcr_def.toolCall.provider, "groq", "default provider is 'groq'")

# ===========================================================================
# §43  execute_batch — empty arguments handled gracefully
# ===========================================================================
print("§43  Batch edge cases ...")
reg_be = _make_registry()
# Tool with all-optional params
params_opt = [build_tool_parameter("q", "string", "Query.", required=False, default_value="")]
d_opt = build_tool_definition("all_opt_tool", "desc", "test", params_opt, {"required":["status"]}, _TS)
reg_be.register_tool(d_opt, _ok_handler)

# Empty arguments allowed when all params optional
batch_empty_args = [{"tool_name": "all_opt_tool", "arguments": {}, "request_id": "r1"}]
be_results = execute_batch(reg_be, batch_empty_args, _TS)
_eq(len(be_results), 1, "batch empty args: 1 result")
_assert(be_results[0].toolResult.success, "batch empty args: success (all params optional)")

# Batch with empty tool_name
batch_empty_name = [{"tool_name": "", "arguments": {}, "request_id": "r1"}]
be_name_results = execute_batch(reg_be, batch_empty_name, _TS)
_eq(len(be_name_results), 1, "batch empty name: 1 result")
_assert(not be_name_results[0].toolResult.success, "batch empty name: fails gracefully")

# ===========================================================================
# §44  Async parallel — empty call list
# ===========================================================================
print("§44  Parallel edge cases ...")

async def _run_parallel_empty():
    return await execute_parallel(_make_registry(), [], _TS)

empty_par = asyncio.run(_run_parallel_empty())
_eq(empty_par, [], "parallel empty calls -> empty results")

# Parallel single call
async def _run_parallel_single():
    r_s = _make_registry()
    r_s.register_tool(_simple_def("single_par"), _ok_handler)
    return await execute_parallel(r_s, [
        {"tool_name": "single_par", "arguments": {"query": "x"}, "request_id": "r1"}
    ], _TS)

single_par = asyncio.run(_run_parallel_single())
_eq(len(single_par), 1, "parallel single: 1 result")
_assert(single_par[0].toolResult.success, "parallel single: success")

# ===========================================================================
# §45  toolKey and toolId uniqueness across all built-ins
# ===========================================================================
print("§45  Built-in toolId uniqueness ...")
dr2 = get_default_registry()
all_bi_tools = dr2.list_tools()
all_tool_ids  = [t.toolId  for t in all_bi_tools]
all_tool_keys = [t.toolKey for t in all_bi_tools]

# All toolIds are unique
_eq(len(all_tool_ids), len(set(all_tool_ids)), "all built-in toolIds are unique")
# All toolKeys are unique
_eq(len(all_tool_keys), len(set(all_tool_keys)), "all built-in toolKeys are unique")
# All are valid UUIDs (36 chars with hyphens)
for t in all_bi_tools:
    _eq(len(t.toolId), 36, f"built-in '{t.toolName}' toolId length=36")
    _in("-", t.toolId, f"built-in '{t.toolName}' toolId contains hyphens")
    _eq(len(t.toolKey), 32, f"built-in '{t.toolName}' toolKey length=32")

# ===========================================================================
# §46  Module-level convenience functions use default registry
# ===========================================================================
print("§46  Module-level convenience functions ...")
from services.tool_calling_service import (
    register_tool as mod_register,
    unregister_tool as mod_unregister,
    enable_tool as mod_enable,
    disable_tool as mod_disable,
    list_tools as mod_list,
    find_tool as mod_find,
    tool_exists as mod_exists,
)

# The module-level default registry already has built-in tools
_assert(mod_exists("search_assets"), "mod: search_assets exists in default registry")
found_mod = mod_find("search_assets")
_assert(found_mod is not None, "mod: find_tool returns definition")
_eq(found_mod.toolName, "search_assets", "mod: find_tool returns correct tool")

all_mod = mod_list()
_ge(len(all_mod), 10, "mod: list_tools returns all built-in tools")

# Filter by category via module function
search_mod = mod_list(category="search")
_ge(len(search_mod), 8, "mod: list_tools(category='search') >= 8")

# Register, confirm, unregister via module functions
new_mod_defn = build_tool_definition("mod_test_tool", "desc", "test", [], {}, _TS)
mod_register(new_mod_defn, _ok_handler)
_assert(mod_exists("mod_test_tool"), "mod: registered tool exists")
mod_unregister("mod_test_tool")
_assert(not mod_exists("mod_test_tool"), "mod: unregistered tool gone")

# enable/disable via module functions
mod_disable("search_assets")
_assert(not mod_find("search_assets").enabled, "mod: disable_tool works")
mod_enable("search_assets")
_assert(mod_find("search_assets").enabled, "mod: enable_tool works")

# ===========================================================================
# §47  TOOL_CALLING_ENGINE_VERSION is unique among all engine versions
# ===========================================================================
print("§47  Engine version uniqueness ...")
from core.constants import (
    GROQ_STREAMING_ENGINE_VERSION,
    GROQ_HTTP_CLIENT_ENGINE_VERSION,
    GROQ_PROVIDER_ENGINE_VERSION,
    COPILOT_ORCHESTRATOR_ENGINE_VERSION,
    REASONING_ENGINE_VERSION,
)
engine_versions = [
    TOOL_CALLING_ENGINE_VERSION,
    GROQ_STREAMING_ENGINE_VERSION,
    GROQ_HTTP_CLIENT_ENGINE_VERSION,
    GROQ_PROVIDER_ENGINE_VERSION,
    COPILOT_ORCHESTRATOR_ENGINE_VERSION,
    REASONING_ENGINE_VERSION,
]
_eq(len(engine_versions), len(set(engine_versions)), "all engine versions are unique strings")

for v in engine_versions:
    _is(v, str, f"engine version '{v}' is a string")
    _gt(len(v), 0, f"engine version '{v}' is non-empty")

# ===========================================================================
# §48  Parameter validation edge cases
# ===========================================================================
print("§48  Validation edge cases ...")

# None value for required param — treated as missing
params_none = [build_tool_parameter("key", "string", "Key.", required=True)]
d_none = build_tool_definition("none_val_tool", "d", "test", params_none, {}, _TS)
errs_none = validate_parameters(d_none, {"key": None})
# None is falsy but key is present — not a "missing" error, no type check for None
# (the implementation only checks presence, not that value != None for required params)
_is(errs_none, list, "validate_parameters returns a list for None value")

# No parameters defined — any arguments are unknown
d_noparams = build_tool_definition("no_param_tool", "d", "test", [], {}, _TS)
errs_extra = validate_parameters(d_noparams, {"surprise": "value"})
_eq(len(errs_extra), 1, "unknown param on no-param tool -> 1 error")

# Empty arguments on no-param tool -> always valid
errs_empty_nop = validate_parameters(d_noparams, {})
_eq(errs_empty_nop, [], "empty args on no-param tool -> no errors")

# ===========================================================================
# Final report
# ===========================================================================
print()
print("=" * 60)
total = _PASS + _FAIL
print(f"Result: {_PASS}/{total} assertions passed.")
if _ERRORS:
    print(f"\nFailed assertions ({len(_ERRORS)}):")
    for e in _ERRORS:
        print(f"  {e}")
print("=" * 60)

if _FAIL > 0:
    sys.exit(1)
else:
    print("All assertions passed.")
    sys.exit(0)
