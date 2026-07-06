"""
Smoke Test — Provider Registry Engine
======================================
Phase A4.3.0 — Verifies every model, builder, registry function,
validation function, selection engine, and integration helper in
services/provider_registry_service.py.

Run:
    python smoke_test_provider_registry_engine.py
Expected: 500+/500 assertions passed.

Design rules:
- Zero randomness. No uuid4(). No random module.
- No real network calls. Pure metadata/registry operations only.
- Same inputs -> same outputs (fully deterministic).
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, List

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


def _eq(a, b, msg): _assert(a == b,  f"{msg} — expected {b!r}, got {a!r}")
def _ne(a, b, msg): _assert(a != b,  f"{msg} — both are {a!r}")
def _in(x, c, msg): _assert(x in c,  f"{msg} — {x!r} not in collection")
def _ni(x, c, msg): _assert(x not in c, f"{msg} — {x!r} unexpectedly in collection")
def _gt(a, b, msg): _assert(a > b,   f"{msg} — {a!r} not > {b!r}")
def _ge(a, b, msg): _assert(a >= b,  f"{msg} — {a!r} not >= {b!r}")
def _lt(a, b, msg): _assert(a < b,   f"{msg} — {a!r} not < {b!r}")
def _is(a, t, msg): _assert(isinstance(a, t), f"{msg} — got {type(a)!r}")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from services.provider_registry_service import (
    # Exceptions
    ProviderRegistryError, ProviderNotFoundError, ModelNotFoundError,
    ProviderValidationError, DuplicateProviderError, DuplicateModelError,
    SelectionError,
    # Models
    ProviderCapability, ProviderModel, ProviderDefinition,
    ProviderSelection, ProviderRegistryMetadata, ProviderRegistryResult,
    # Builders
    build_provider_capability, build_provider_model, build_provider_definition,
    build_provider_selection, build_registry_metadata, build_registry_result,
    # Validation
    validate_capabilities, validate_model, validate_provider,
    # Registry
    ProviderRegistry,
    # Selection
    select_provider, select_model,
    # Default registry helpers
    get_default_registry, build_default_registry, reset_default_registry,
    # Integration helpers
    get_groq_provider, get_groq_model, get_registry_summary,
    # ID helpers
    _sha256_32, _uuid5, _norm_name,
    # Constants
    PROVIDER_REGISTRY_ENGINE_VERSION,
    _VALID_STRATEGIES,
)
from core.constants import PROVIDER_REGISTRY_ENGINE_VERSION as CONST_PRV_VERSION

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
_TS = "2026-07-01T12:00:00Z"


def _cap(**kw) -> ProviderCapability:
    return build_provider_capability(
        streaming         = kw.get("streaming",         True),
        tool_calling      = kw.get("tool_calling",      True),
        json_mode         = kw.get("json_mode",         True),
        vision            = kw.get("vision",            False),
        embeddings        = kw.get("embeddings",        False),
        max_context_tokens= kw.get("max_context_tokens",128000),
        max_output_tokens = kw.get("max_output_tokens", 8192),
    )


def _model(provider="groq", name="llama-3.3-70b-versatile",
           priority=50, enabled=True, alias=None, **cap_kw) -> ProviderModel:
    return build_provider_model(
        provider, name, _cap(**cap_kw), _TS,
        alias=alias, enabled=enabled, priority=priority,
    )


def _provider(name="groq", models=None, default="llama-3.3-70b-versatile",
              enabled=True) -> ProviderDefinition:
    if models is None:
        models = ["llama-3.3-70b-versatile"]
    return build_provider_definition(
        provider_name=name, display_name=name.title(),
        api_version="1.0", endpoint=f"https://api.{name}.com/v1",
        supported_models=models, default_model=default,
        created_at=_TS, enabled=enabled,
    )


def _fresh_reg_with_one() -> ProviderRegistry:
    reg = ProviderRegistry()
    reg.register_provider(_provider())
    reg.register_model(_model())
    return reg


# ===========================================================================
# §1  Engine version constant
# ===========================================================================
print("§1  Engine version ...")
_eq(PROVIDER_REGISTRY_ENGINE_VERSION, "provider-registry-v1", "engine version value")
_eq(CONST_PRV_VERSION, PROVIDER_REGISTRY_ENGINE_VERSION, "core.constants matches service")
_is(PROVIDER_REGISTRY_ENGINE_VERSION, str, "engine version is str")
_in("provider-registry", PROVIDER_REGISTRY_ENGINE_VERSION, "version contains 'provider-registry'")

# ===========================================================================
# §2  Deterministic ID helpers
# ===========================================================================
print("§2  ID helpers ...")
h1 = _sha256_32("a", "b")
h2 = _sha256_32("a", "b")
_eq(h1, h2, "_sha256_32 deterministic")
_eq(len(h1), 32, "_sha256_32 length=32")
h3 = _sha256_32("b", "a")
_ne(h1, h3, "different order -> different hash")
h4 = _sha256_32("a", "c")
_ne(h1, h4, "different value -> different hash")

u1 = _uuid5("key-abc")
u2 = _uuid5("key-abc")
_eq(u1, u2, "_uuid5 deterministic")
_eq(len(u1), 36, "_uuid5 returns 36-char UUID")
_in("-", u1, "_uuid5 contains hyphens")
u3 = _uuid5("key-xyz")
_ne(u1, u3, "different key -> different UUID")

# norm_name
_eq(_norm_name("  GROQ  "), "groq", "_norm_name strips+lowercases")
_eq(_norm_name(""), "", "_norm_name empty -> empty")
_eq(_norm_name("OpenAI"), "openai", "_norm_name OpenAI -> openai")

# ===========================================================================
# §3  build_provider_capability()
# ===========================================================================
print("§3  build_provider_capability() ...")
cap = build_provider_capability(
    streaming=True, tool_calling=True, json_mode=True,
    vision=False, embeddings=False,
    max_context_tokens=128000, max_output_tokens=8192,
)
_is(cap, ProviderCapability, "returns ProviderCapability")
_assert(cap.streaming,    "streaming=True stored")
_assert(cap.toolCalling,  "toolCalling=True stored")
_assert(cap.jsonMode,     "jsonMode=True stored")
_assert(not cap.vision,   "vision=False stored")
_assert(not cap.embeddings,"embeddings=False stored")
_eq(cap.maxContextTokens, 128000, "maxContextTokens stored")
_eq(cap.maxOutputTokens,   8192,  "maxOutputTokens stored")

# Immutability
try:
    cap.streaming = False   # type: ignore
    _assert(False, "ProviderCapability should be frozen")
except Exception:
    _assert(True, "ProviderCapability is immutable")

# Defaults
cap_def = build_provider_capability()
_assert(not cap_def.streaming, "default streaming=False")
_ge(cap_def.maxContextTokens, 1, "default maxContextTokens >= 1")
_ge(cap_def.maxOutputTokens,  1, "default maxOutputTokens >= 1")

# Clamping — negative token counts clamped to 1
cap_clamp = build_provider_capability(max_context_tokens=-100, max_output_tokens=-5)
_eq(cap_clamp.maxContextTokens, 1, "negative maxContextTokens clamped to 1")
_eq(cap_clamp.maxOutputTokens,  1, "negative maxOutputTokens clamped to 1")

# Determinism — same inputs -> same object
cap2 = build_provider_capability(
    streaming=True, tool_calling=True, json_mode=True,
    vision=False, embeddings=False,
    max_context_tokens=128000, max_output_tokens=8192,
)
_eq(cap, cap2, "same inputs -> equal ProviderCapability")

# ===========================================================================
# §4  build_provider_model()
# ===========================================================================
print("§4  build_provider_model() ...")
mdl = build_provider_model("groq", "llama-3.3-70b-versatile", cap, _TS, alias="llama-70b", priority=90)
_is(mdl, ProviderModel, "returns ProviderModel")
_eq(mdl.provider,   "groq",                    "provider normalised to lowercase")
_eq(mdl.modelName,  "llama-3.3-70b-versatile", "modelName stored")
_eq(mdl.alias,      "llama-70b",               "alias stored")
_eq(len(mdl.modelId),  36, "modelId is 36-char UUID")
_eq(len(mdl.modelKey), 32, "modelKey is 32 hex chars")
_in("-", mdl.modelId, "modelId contains hyphens")
_assert(mdl.enabled, "enabled=True by default")
_eq(mdl.priority, 90, "priority=90 stored")
_eq(mdl.createdAt, _TS, "createdAt preserved")
_eq(mdl.engineVersion, PROVIDER_REGISTRY_ENGINE_VERSION, "engineVersion set")

# Determinism — same inputs -> same IDs
mdl2 = build_provider_model("groq", "llama-3.3-70b-versatile", cap, _TS, alias="llama-70b", priority=90)
_eq(mdl.modelId,  mdl2.modelId,  "same inputs -> same modelId")
_eq(mdl.modelKey, mdl2.modelKey, "same inputs -> same modelKey")

# Different provider -> different ID
mdl_other = build_provider_model("openai", "llama-3.3-70b-versatile", cap, _TS)
_ne(mdl.modelId, mdl_other.modelId, "different provider -> different modelId")

# Different model name -> different ID
mdl_8b = build_provider_model("groq", "llama-3.1-8b-instant", cap, _TS)
_ne(mdl.modelId, mdl_8b.modelId, "different modelName -> different modelId")

# Provider name normalised to lowercase
mdl_upper = build_provider_model("GROQ", "llama-3.3-70b-versatile", cap, _TS)
_eq(mdl_upper.provider, "groq", "GROQ -> groq")
_eq(mdl_upper.modelId,  mdl.modelId, "case-normalised -> same modelId")

# Alias normalised to lowercase
mdl_alias = build_provider_model("groq", "llama-3.3-70b-versatile", cap, _TS, alias="LLAMA-70B")
_eq(mdl_alias.alias, "llama-70b", "alias lowercased")

# Disabled model
mdl_dis = build_provider_model("groq", "llama-3.3-70b-versatile", cap, _TS, enabled=False)
_assert(not mdl_dis.enabled, "enabled=False stored")

# Priority clamped at 0 for negative
mdl_neg = build_provider_model("groq", "m", cap, _TS, priority=-10)
_eq(mdl_neg.priority, 0, "negative priority clamped to 0")

# Immutability
try:
    mdl.provider = "openai"  # type: ignore
    _assert(False, "ProviderModel should be frozen")
except Exception:
    _assert(True, "ProviderModel is immutable")

# Empty provider raises
try:
    build_provider_model("", "model-x", cap, _TS)
    _assert(False, "empty provider should raise ProviderValidationError")
except ProviderValidationError:
    _assert(True, "empty provider raises ProviderValidationError")

# Empty model name raises
try:
    build_provider_model("groq", "", cap, _TS)
    _assert(False, "empty modelName should raise ProviderValidationError")
except ProviderValidationError:
    _assert(True, "empty modelName raises ProviderValidationError")

# ===========================================================================
# §5  build_provider_definition()
# ===========================================================================
print("§5  build_provider_definition() ...")
pdef = build_provider_definition(
    provider_name    = "groq",
    display_name     = "Groq",
    api_version      = "2024-01-01",
    endpoint         = "https://api.groq.com/openai/v1/chat/completions",
    supported_models = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
    default_model    = "llama-3.3-70b-versatile",
    created_at       = _TS,
)
_is(pdef, ProviderDefinition, "returns ProviderDefinition")
_eq(pdef.providerName, "groq",  "providerName normalised to lowercase")
_eq(pdef.displayName,  "Groq",  "displayName stored")
_eq(pdef.apiVersion,   "2024-01-01", "apiVersion stored")
_eq(len(pdef.providerId),  36, "providerId is 36-char UUID")
_eq(len(pdef.providerKey), 32, "providerKey is 32 hex chars")
_in("-", pdef.providerId, "providerId contains hyphens")
_assert(pdef.enabled, "enabled=True by default")
_eq(pdef.defaultModel, "llama-3.3-70b-versatile", "defaultModel stored")
_in("llama-3.3-70b-versatile", pdef.supportedModels, "model in supportedModels")
_in("llama-3.1-8b-instant",    pdef.supportedModels, "second model in supportedModels")
_eq(pdef.engineVersion, PROVIDER_REGISTRY_ENGINE_VERSION, "engineVersion set")

# supportedModels is sorted
pdef_order = build_provider_definition("p", "P", "1.0", "https://x.com", ["z-model","a-model"], "a-model", _TS)
_eq(pdef_order.supportedModels, ("a-model", "z-model"), "supportedModels sorted")

# Determinism — same inputs -> same IDs
pdef2 = build_provider_definition(
    "groq", "Groq", "2024-01-01",
    "https://api.groq.com/openai/v1/chat/completions",
    ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
    "llama-3.3-70b-versatile", _TS,
)
_eq(pdef.providerId,  pdef2.providerId,  "same inputs -> same providerId")
_eq(pdef.providerKey, pdef2.providerKey, "same inputs -> same providerKey")

# Different provider name -> different IDs
pdef_openai = build_provider_definition("openai","OpenAI","1.0","https://api.openai.com",["gpt-4o"],"gpt-4o",_TS)
_ne(pdef.providerId, pdef_openai.providerId, "different providerName -> different providerId")

# Provider name normalised to uppercase input
pdef_up = build_provider_definition("GROQ","Groq","1.0","https://api.groq.com",["m"],"m",_TS)
_eq(pdef_up.providerName, "groq", "GROQ -> groq")
_eq(pdef_up.providerId, pdef.providerId, "uppercase input -> same ID after normalisation")

# Disabled provider
pdef_dis = build_provider_definition("disabled-p","D","1.0","https://x.com",[],  "", _TS, enabled=False)
_assert(not pdef_dis.enabled, "enabled=False stored")

# Immutability
try:
    pdef.providerName = "changed"  # type: ignore
    _assert(False, "ProviderDefinition should be frozen")
except Exception:
    _assert(True, "ProviderDefinition is immutable")

# Empty name raises
try:
    build_provider_definition("", "D", "1.0", "https://x.com", [], "", _TS)
    _assert(False, "empty providerName should raise ProviderValidationError")
except ProviderValidationError:
    _assert(True, "empty providerName raises ProviderValidationError")

# ===========================================================================
# §6  build_provider_selection()
# ===========================================================================
print("§6  build_provider_selection() ...")
sel = build_provider_selection(
    provider_id="pid-001", model_id="mid-001",
    strategy="priority", reason="Highest priority", created_at=_TS,
)
_is(sel, ProviderSelection, "returns ProviderSelection")
_eq(len(sel.selectionId), 36, "selectionId is 36-char UUID")
_in("-", sel.selectionId, "selectionId contains hyphens")
_eq(sel.providerId, "pid-001",       "providerId stored")
_eq(sel.modelId,    "mid-001",       "modelId stored")
_eq(sel.strategy,   "priority",      "strategy stored lowercase")
_eq(sel.reason,     "Highest priority", "reason stored")
_eq(sel.createdAt,  _TS,             "createdAt stored")

# Strategy normalised to lowercase
sel_upper = build_provider_selection("p", "m", "PRIORITY", "r", _TS)
_eq(sel_upper.strategy, "priority", "strategy uppercased -> lowercased")

# Determinism
sel2 = build_provider_selection("pid-001", "mid-001", "priority", "Highest priority", _TS)
_eq(sel.selectionId, sel2.selectionId, "same inputs -> same selectionId")

# Different inputs -> different ID
sel3 = build_provider_selection("pid-001", "mid-002", "priority", "r", _TS)
_ne(sel.selectionId, sel3.selectionId, "different modelId -> different selectionId")

# Immutability
try:
    sel.providerId = "changed"  # type: ignore
    _assert(False, "ProviderSelection should be frozen")
except Exception:
    _assert(True, "ProviderSelection is immutable")

# ===========================================================================
# §7  build_registry_metadata()
# ===========================================================================
print("§7  build_registry_metadata() ...")
provs = [_provider("groq"), _provider("openai")]
mdls  = [_model("groq"), _model("openai", "gpt-4o")]
meta = build_registry_metadata(provs, mdls, "pid-1", "mid-1", ["warn1"])
_is(meta, ProviderRegistryMetadata, "returns ProviderRegistryMetadata")
_eq(meta.totalProviders,   2,     "totalProviders=2")
_eq(meta.enabledProviders, 2,     "enabledProviders=2 (both enabled)")
_eq(meta.totalModels,      2,     "totalModels=2")
_eq(meta.selectedProvider, "pid-1","selectedProvider stored")
_eq(meta.selectedModel,    "mid-1","selectedModel stored")
_eq(meta.warnings,         ("warn1",), "warnings stored and sorted")
_eq(meta.engineVersion, PROVIDER_REGISTRY_ENGINE_VERSION, "engineVersion set")

# Immutability
try:
    meta.totalProviders = 99  # type: ignore
    _assert(False, "ProviderRegistryMetadata should be frozen")
except Exception:
    _assert(True, "ProviderRegistryMetadata is immutable")

# Disabled provider not counted in enabledProviders
provs_mix = [_provider("groq"), _provider("openai", enabled=False)]
meta2 = build_registry_metadata(provs_mix, [])
_eq(meta2.enabledProviders, 1, "disabled provider not counted in enabledProviders")

# Warnings deduped and sorted
meta3 = build_registry_metadata([], [], warnings=["B", "A", "B", "C"])
_eq(meta3.warnings, ("A", "B", "C"), "warnings deduped and sorted")

# ===========================================================================
# §8  build_registry_result()
# ===========================================================================
print("§8  build_registry_result() ...")
result = build_registry_result(provs, mdls, sel, meta)
_is(result, ProviderRegistryResult, "returns ProviderRegistryResult")
_eq(len(result.providers), 2,  "providers tuple length=2")
_eq(len(result.models),    2,  "models tuple length=2")
_eq(result.selection,      sel, "selection stored")
_eq(result.metadata,       meta,"metadata stored")

# Providers sorted by providerName
pdef_z = _provider("z-prov", models=["m"], default="m")
pdef_a = _provider("a-prov", models=["m"], default="m")
result_sorted = build_registry_result([pdef_z, pdef_a], [], None, meta)
_eq(result_sorted.providers[0].providerName, "a-prov", "providers sorted asc")
_eq(result_sorted.providers[1].providerName, "z-prov", "providers sorted asc 2nd")

# Models sorted by (provider, modelName)
mdl_zg = _model("z-prov", "m")
mdl_ag = _model("a-prov", "m")
result_msorted = build_registry_result([], [mdl_zg, mdl_ag], None, meta)
_eq(result_msorted.models[0].provider, "a-prov", "models sorted by provider first")

# Immutability
try:
    result.selection = None  # type: ignore
    _assert(False, "ProviderRegistryResult should be frozen")
except Exception:
    _assert(True, "ProviderRegistryResult is immutable")

# ===========================================================================
# §9  validate_capabilities()
# ===========================================================================
print("§9  validate_capabilities() ...")
# Valid capability
try:
    validate_capabilities(cap)
    _assert(True, "valid capability -> no exception")
except ProviderValidationError:
    _assert(False, "valid capability should not raise")

# maxContextTokens < 1 raises — bypass builder clamping via direct model construction
bad_cap = ProviderCapability(
    streaming=False, toolCalling=False, jsonMode=False, vision=False,
    embeddings=False, maxContextTokens=0, maxOutputTokens=1,
)
try:
    validate_capabilities(bad_cap)
    _assert(False, "maxContextTokens<1 should raise ProviderValidationError")
except ProviderValidationError as e:
    _assert(True, "maxContextTokens<1 raises ProviderValidationError")
    _in("maxContextTokens", str(e), "error mentions maxContextTokens")

# maxOutputTokens < 1 raises (set to 1 for context first)
bad_cap2 = ProviderCapability(
    streaming=False, toolCalling=False, jsonMode=False, vision=False,
    embeddings=False, maxContextTokens=8192, maxOutputTokens=0,
)
try:
    validate_capabilities(bad_cap2)
    _assert(False, "maxOutputTokens=0 should raise ProviderValidationError")
except ProviderValidationError as e:
    _assert(True, "maxOutputTokens=0 raises ProviderValidationError")
    _in("maxOutputTokens", str(e), "error mentions maxOutputTokens")

# maxOutputTokens > maxContextTokens raises
bad_cap3 = build_provider_capability(max_context_tokens=1000, max_output_tokens=2000)
try:
    validate_capabilities(bad_cap3)
    _assert(False, "maxOutputTokens > maxContextTokens should raise")
except ProviderValidationError as e:
    _assert(True, "maxOutputTokens > maxContextTokens raises ProviderValidationError")
    _in("maxOutputTokens", str(e), "error mentions maxOutputTokens")

# ===========================================================================
# §10  validate_model()
# ===========================================================================
print("§10  validate_model() ...")
# Valid model
try:
    validate_model(mdl)
    _assert(True, "valid model -> no exception")
except ProviderValidationError:
    _assert(False, "valid model should not raise")

# Priority out of range (> 100)
mdl_prio = build_provider_model("groq", "m", cap, _TS, priority=50)
bad_prio_mdl = ProviderModel(
    modelId=mdl_prio.modelId, modelKey=mdl_prio.modelKey,
    provider=mdl_prio.provider, modelName=mdl_prio.modelName,
    alias=None, capabilities=cap, enabled=True, priority=150,
    createdAt=_TS, engineVersion=PROVIDER_REGISTRY_ENGINE_VERSION,
)
try:
    validate_model(bad_prio_mdl)
    _assert(False, "priority=150 should raise ProviderValidationError")
except ProviderValidationError as e:
    _assert(True, "priority=150 raises ProviderValidationError")
    _in("priority", str(e), "error mentions priority")

# ===========================================================================
# §11  validate_provider()
# ===========================================================================
print("§11  validate_provider() ...")
# Valid provider
try:
    validate_provider(pdef)
    _assert(True, "valid provider -> no exception")
except ProviderValidationError:
    _assert(False, "valid provider should not raise")

# defaultModel not in supportedModels raises
bad_pdef = build_provider_definition("bad-p","B","1.0","https://x.com",["model-a"],"model-z",_TS)
try:
    validate_provider(bad_pdef)
    _assert(False, "defaultModel not in supportedModels should raise")
except ProviderValidationError as e:
    _assert(True, "defaultModel not in supportedModels raises ProviderValidationError")
    _in("defaultModel", str(e), "error mentions defaultModel")

# ===========================================================================
# §12  ProviderRegistry — provider registration
# ===========================================================================
print("§12  ProviderRegistry — provider ops ...")
reg = ProviderRegistry()
_eq(len(reg), 0, "fresh registry has 0 providers")

p1 = _provider("alpha", models=["m"], default="m")
p2 = _provider("beta",  models=["m"], default="m")

reg.register_provider(p1)
_eq(len(reg), 1, "after first register: len=1")
_assert(reg.provider_exists("alpha"), "alpha exists")

reg.register_provider(p2)
_eq(len(reg), 2, "after second register: len=2")
_assert(reg.provider_exists("beta"), "beta exists")
_assert(not reg.provider_exists("gamma"), "gamma does not exist")

# find_provider
found = reg.find_provider("alpha")
_eq(found, p1, "find_provider('alpha') returns p1")
_assert(reg.find_provider("missing") is None, "find_provider missing -> None")

# Case-insensitive
_assert(reg.provider_exists("ALPHA"), "provider_exists case-insensitive")
found_upper = reg.find_provider("BETA")
_eq(found_upper, p2, "find_provider case-insensitive")

# list_providers
all_provs = reg.list_providers()
_eq(len(all_provs), 2, "list_providers() returns 2")
_eq([p.providerName for p in all_provs], ["alpha", "beta"], "list_providers sorted asc")

# Duplicate raises DuplicateProviderError
try:
    reg.register_provider(p1)
    _assert(False, "duplicate register should raise DuplicateProviderError")
except DuplicateProviderError as e:
    _assert(True, "duplicate register raises DuplicateProviderError")
    _in("alpha", str(e), "error mentions provider name")

# Unregister
reg.unregister_provider("alpha")
_eq(len(reg), 1, "after unregister: len=1")
_assert(not reg.provider_exists("alpha"), "alpha gone after unregister")

# Unregister non-existent is no-op
reg.unregister_provider("no-such-provider")
_eq(len(reg), 1, "unregister non-existent: len unchanged")

# Re-register after unregister
reg.register_provider(p1)
_eq(len(reg), 2, "re-register after unregister: len=2")

# enable/disable provider
reg.disable_provider("alpha")
_assert(not reg.find_provider("alpha").enabled, "after disable: enabled=False")
reg.enable_provider("alpha")
_assert(reg.find_provider("alpha").enabled, "after enable: enabled=True")

# enable/disable preserves other fields
reg.disable_provider("alpha")
toggled = reg.find_provider("alpha")
_eq(toggled.providerId, p1.providerId, "providerId unchanged after disable")
_eq(toggled.providerName, "alpha",     "providerName unchanged after disable")

# enable/disable on unknown raises ProviderNotFoundError
try:
    reg.enable_provider("no-such")
    _assert(False, "enable unknown should raise ProviderNotFoundError")
except ProviderNotFoundError:
    _assert(True, "enable unknown raises ProviderNotFoundError")

try:
    reg.disable_provider("no-such")
    _assert(False, "disable unknown should raise ProviderNotFoundError")
except ProviderNotFoundError:
    _assert(True, "disable unknown raises ProviderNotFoundError")

# list_providers filtered by enabled
_eq(len(reg.list_providers(enabled_only=True)),  1, "enabled_only=True -> 1 (beta)")
_eq(len(reg.list_providers(enabled_only=False)), 1, "enabled_only=False -> 1 (alpha)")

# ===========================================================================
# §13  ProviderRegistry — model registration
# ===========================================================================
print("§13  ProviderRegistry — model ops ...")
reg2 = ProviderRegistry()
prov_g = _provider("groq",   models=["llama-3.3-70b-versatile","llama-3.1-8b-instant"], default="llama-3.3-70b-versatile")
reg2.register_provider(prov_g)

m70b = _model("groq", "llama-3.3-70b-versatile", priority=90)
m8b  = _model("groq", "llama-3.1-8b-instant",    priority=70)

reg2.register_model(m70b)
_assert(reg2.model_exists("groq", "llama-3.3-70b-versatile"), "70b model exists")

reg2.register_model(m8b)
_eq(len(reg2.list_models()), 2, "2 models registered")

# find_model
found_m = reg2.find_model("groq", "llama-3.3-70b-versatile")
_eq(found_m, m70b, "find_model returns correct model")
_assert(reg2.find_model("groq", "missing") is None, "find_model missing -> None")

# Case-insensitive model lookup
_assert(reg2.model_exists("GROQ", "LLAMA-3.3-70B-VERSATILE"), "model_exists case-insensitive")
found_uc = reg2.find_model("GROQ", "LLAMA-3.1-8B-INSTANT")
_eq(found_uc, m8b, "find_model case-insensitive")

# list_models
all_mdls = reg2.list_models()
_eq(len(all_mdls), 2, "list_models() returns 2")
_eq([m.modelName for m in all_mdls],
    sorted(["llama-3.3-70b-versatile","llama-3.1-8b-instant"]),
    "list_models sorted by modelName")

# list_models filtered by provider
_eq(len(reg2.list_models(provider_name="groq")), 2, "filter by provider -> 2")
_eq(len(reg2.list_models(provider_name="openai")), 0, "filter by missing provider -> 0")

# list_models filtered by enabled
reg2.disable_model("groq", "llama-3.1-8b-instant")
_eq(len(reg2.list_models(enabled_only=True)),  1, "enabled_only=True -> 1")
_eq(len(reg2.list_models(enabled_only=False)), 1, "enabled_only=False -> 1")

reg2.enable_model("groq", "llama-3.1-8b-instant")
_eq(len(reg2.list_models(enabled_only=True)), 2, "re-enabled: enabled_only=True -> 2")

# Duplicate model raises DuplicateModelError
try:
    reg2.register_model(m70b)
    _assert(False, "duplicate model should raise DuplicateModelError")
except DuplicateModelError as e:
    _assert(True, "duplicate model raises DuplicateModelError")
    _in("llama-3.3-70b-versatile", str(e), "error mentions model name")

# Unregister model
reg2.unregister_model("groq", "llama-3.1-8b-instant")
_assert(not reg2.model_exists("groq", "llama-3.1-8b-instant"), "model gone after unregister")
_eq(len(reg2.list_models()), 1, "1 model left after unregister")

# Re-register after unregister
reg2.register_model(m8b)
_eq(len(reg2.list_models()), 2, "re-register model: 2 models")

# enable/disable model — field preservation
reg2.disable_model("groq", "llama-3.3-70b-versatile")
dm = reg2.find_model("groq", "llama-3.3-70b-versatile")
_assert(not dm.enabled,        "after disable: enabled=False")
_eq(dm.modelId,   m70b.modelId, "modelId unchanged after disable")
_eq(dm.priority,  90,           "priority unchanged after disable")

# enable/disable on missing model raises ModelNotFoundError
try:
    reg2.enable_model("groq", "no-such-model")
    _assert(False, "enable missing model should raise ModelNotFoundError")
except ModelNotFoundError:
    _assert(True, "enable missing model raises ModelNotFoundError")

try:
    reg2.disable_model("groq", "no-such-model")
    _assert(False, "disable missing model should raise ModelNotFoundError")
except ModelNotFoundError:
    _assert(True, "disable missing model raises ModelNotFoundError")

# Unregistering provider also removes its models
reg3 = ProviderRegistry()
p_tmp = _provider("tmp-prov", models=["tmp-m"], default="tmp-m")
m_tmp = _model("tmp-prov", "tmp-m")
reg3.register_provider(p_tmp)
reg3.register_model(m_tmp)
_eq(len(reg3.list_models()), 1, "model registered")
reg3.unregister_provider("tmp-prov")
_eq(len(reg3.list_models()), 0, "unregister provider removes its models")

# ===========================================================================
# §14  Selection Engine — strategy: priority
# ===========================================================================
print("§14  Selection — priority strategy ...")

def _sel_reg() -> ProviderRegistry:
    """Fresh registry with groq+openai providers and a few models."""
    r = ProviderRegistry()
    pg = _provider("groq",   models=["llama-3.3-70b-versatile","llama-3.1-8b-instant"], default="llama-3.3-70b-versatile")
    po = _provider("openai", models=["gpt-4o","gpt-4o-mini"], default="gpt-4o")
    r.register_provider(pg)
    r.register_provider(po)
    r.register_model(_model("groq",   "llama-3.3-70b-versatile", priority=90))
    r.register_model(_model("groq",   "llama-3.1-8b-instant",    priority=70))
    r.register_model(_model("openai", "gpt-4o",                  priority=80))
    r.register_model(_model("openai", "gpt-4o-mini",             priority=60))
    return r

sr = _sel_reg()
sel_p = select_provider(sr, strategy="priority", created_at=_TS)
_is(sel_p, ProviderSelection, "priority select returns ProviderSelection")
_eq(sel_p.strategy, "priority", "strategy='priority' stored")

# Should pick 70b (priority=90) deterministically
winning_model_p = sr.find_model("groq","llama-3.3-70b-versatile")
_eq(sel_p.modelId, winning_model_p.modelId, "priority=90 model selected")

# Determinism — same inputs same selectionId
sel_p2 = select_provider(sr, strategy="priority", created_at=_TS)
_eq(sel_p.selectionId, sel_p2.selectionId, "priority selection is deterministic")

# After disabling 70b, should fall to gpt-4o (priority=80)
sr.disable_model("groq","llama-3.3-70b-versatile")
sel_p3 = select_provider(sr, strategy="priority", created_at=_TS)
gpt4o_m = sr.find_model("openai","gpt-4o")
_eq(sel_p3.modelId, gpt4o_m.modelId, "priority select skips disabled model")
sr.enable_model("groq","llama-3.3-70b-versatile")

# ===========================================================================
# §15  Selection — provider_name strategy
# ===========================================================================
print("§15  Selection — provider_name strategy ...")
sel_pn = select_provider(sr, strategy="provider_name", provider_name="groq", created_at=_TS)
# Should pick groq's highest priority model (70b)
_eq(sel_pn.strategy, "provider_name", "strategy stored")
g_prov = sr.find_provider("groq")
_eq(sel_pn.providerId, g_prov.providerId, "providerId matches groq")
sel_pn2 = select_provider(sr, strategy="provider_name", provider_name="openai", created_at=_TS)
o_prov = sr.find_provider("openai")
_eq(sel_pn2.providerId, o_prov.providerId, "providerId matches openai")

# Missing provider_name raises SelectionError
try:
    select_provider(sr, strategy="provider_name", created_at=_TS)
    _assert(False, "provider_name strategy without name should raise SelectionError")
except SelectionError as e:
    _assert(True, "raises SelectionError when provider_name missing")
    _in("provider_name", str(e), "error mentions strategy")

# ===========================================================================
# §16  Selection — model_name strategy
# ===========================================================================
print("§16  Selection — model_name strategy ...")
sel_mn = select_provider(sr, strategy="model_name", model_name="llama-3.1-8b-instant", created_at=_TS)
m8b_obj = sr.find_model("groq","llama-3.1-8b-instant")
_eq(sel_mn.modelId, m8b_obj.modelId, "model_name selection picks correct model")
_eq(sel_mn.strategy, "model_name", "strategy stored")

# model_name strategy without name raises SelectionError
try:
    select_provider(sr, strategy="model_name", created_at=_TS)
    _assert(False, "model_name strategy without name should raise SelectionError")
except SelectionError as e:
    _assert(True, "raises SelectionError when model_name missing")

# Unknown model name -> SelectionError (no match)
try:
    select_provider(sr, strategy="model_name", model_name="gpt-999", created_at=_TS)
    _assert(False, "unknown model_name should raise SelectionError")
except SelectionError:
    _assert(True, "unknown model_name raises SelectionError")

# ===========================================================================
# §17  Selection — cheapest strategy
# ===========================================================================
print("§17  Selection — cheapest strategy ...")
# 8b is cheapest Groq model
sel_cheap = select_provider(sr, strategy="cheapest", created_at=_TS)
_eq(sel_cheap.strategy, "cheapest", "strategy='cheapest' stored")
# gpt-4o-mini and llama-8b compete; llama-8b is cheapest overall
m8b_cheap = sr.find_model("groq","llama-3.1-8b-instant")
_eq(sel_cheap.modelId, m8b_cheap.modelId, "cheapest strategy picks llama-8b")

# Determinism
sel_cheap2 = select_provider(sr, strategy="cheapest", created_at=_TS)
_eq(sel_cheap.selectionId, sel_cheap2.selectionId, "cheapest selection is deterministic")

# ===========================================================================
# §18  Selection — highest_context strategy
# ===========================================================================
print("§18  Selection — highest_context strategy ...")

def _hc_reg() -> ProviderRegistry:
    r = ProviderRegistry()
    ph = _provider("high-ctx", models=["big-model"], default="big-model")
    pl = _provider("low-ctx",  models=["small-model"], default="small-model")
    r.register_provider(ph)
    r.register_provider(pl)
    r.register_model(build_provider_model("high-ctx","big-model",
        build_provider_capability(max_context_tokens=1000000, max_output_tokens=4096),
        _TS, priority=50))
    r.register_model(build_provider_model("low-ctx","small-model",
        build_provider_capability(max_context_tokens=8192, max_output_tokens=4096),
        _TS, priority=50))
    return r

hcr = _hc_reg()
sel_hc = select_provider(hcr, strategy="highest_context", created_at=_TS)
_eq(sel_hc.strategy, "highest_context", "strategy='highest_context' stored")
hc_model = hcr.find_model("high-ctx","big-model")
_eq(sel_hc.modelId, hc_model.modelId, "highest_context picks model with 1M context")

# ===========================================================================
# §19  Selection — streaming_required strategy
# ===========================================================================
print("§19  Selection — streaming_required strategy ...")

def _stream_reg() -> ProviderRegistry:
    r = ProviderRegistry()
    ps = _provider("stream-p", models=["stream-m"], default="stream-m")
    pn = _provider("nostream-p", models=["nostream-m"], default="nostream-m")
    r.register_provider(ps)
    r.register_provider(pn)
    r.register_model(_model("stream-p",   "stream-m",   streaming=True,  priority=50))
    r.register_model(_model("nostream-p", "nostream-m", streaming=False, priority=80))
    return r

str_reg = _stream_reg()
sel_stream = select_provider(str_reg, strategy="streaming_required", created_at=_TS)
_eq(sel_stream.strategy, "streaming_required", "strategy stored")
stream_model = str_reg.find_model("stream-p","stream-m")
_eq(sel_stream.modelId, stream_model.modelId, "streaming_required picks streaming model")

# All streaming disabled -> SelectionError
str_reg.disable_model("stream-p","stream-m")
try:
    select_provider(str_reg, strategy="streaming_required", created_at=_TS)
    _assert(False, "no streaming model should raise SelectionError")
except SelectionError:
    _assert(True, "no streaming model raises SelectionError")

# ===========================================================================
# §20  Selection — tool_calling_required strategy
# ===========================================================================
print("§20  Selection — tool_calling_required strategy ...")

def _tc_reg() -> ProviderRegistry:
    r = ProviderRegistry()
    pt = _provider("tc-p",   models=["tc-m"],   default="tc-m")
    pnt= _provider("notc-p", models=["notc-m"], default="notc-m")
    r.register_provider(pt)
    r.register_provider(pnt)
    r.register_model(_model("tc-p",   "tc-m",   tool_calling=True,  priority=50))
    r.register_model(_model("notc-p", "notc-m", tool_calling=False, priority=80))
    return r

tcr = _tc_reg()
sel_tc = select_provider(tcr, strategy="tool_calling_required", created_at=_TS)
tc_model = tcr.find_model("tc-p","tc-m")
_eq(sel_tc.modelId, tc_model.modelId, "tool_calling_required picks tool-calling model")

# ===========================================================================
# §21  Selection — capability strategy
# ===========================================================================
print("§21  Selection — capability filter ...")
sr_cap = _sel_reg()
# All models in sel_reg have streaming=True; filter should return them all
sel_cap_stream = select_provider(sr_cap, strategy="capability", require_capability="streaming", created_at=_TS)
_is(sel_cap_stream, ProviderSelection, "capability filter returns ProviderSelection")

# require_capability = vision — no models have vision in sel_reg
try:
    select_provider(sr_cap, strategy="capability", require_capability="vision", created_at=_TS)
    _assert(False, "no vision model should raise SelectionError")
except SelectionError:
    _assert(True, "no vision model raises SelectionError")

# ===========================================================================
# §22  Selection — unknown strategy raises SelectionError
# ===========================================================================
print("§22  Selection — unknown strategy ...")
try:
    select_provider(sr, strategy="totally_unknown", created_at=_TS)
    _assert(False, "unknown strategy should raise SelectionError")
except SelectionError as e:
    _assert(True, "unknown strategy raises SelectionError")
    _in("totally_unknown", str(e), "error mentions strategy name")

# ===========================================================================
# §23  Selection — empty registry raises SelectionError
# ===========================================================================
print("§23  Selection — empty registry ...")
try:
    select_provider(ProviderRegistry(), strategy="priority", created_at=_TS)
    _assert(False, "empty registry should raise SelectionError")
except SelectionError:
    _assert(True, "empty registry raises SelectionError")

# ===========================================================================
# §24  select_model() wrapper
# ===========================================================================
print("§24  select_model() wrapper ...")
sr_sm = _sel_reg()
sel_sm = select_model(sr_sm, provider_name="groq", strategy="priority", created_at=_TS)
_is(sel_sm, ProviderSelection, "select_model returns ProviderSelection")
g_prov2 = sr_sm.find_provider("groq")
_eq(sel_sm.providerId, g_prov2.providerId, "select_model: providerId is groq")

# Determinism
sel_sm2 = select_model(sr_sm, provider_name="groq", strategy="priority", created_at=_TS)
_eq(sel_sm.selectionId, sel_sm2.selectionId, "select_model is deterministic")

# ===========================================================================
# §25  Selection — pre-filters (require_streaming + min_context_tokens)
# ===========================================================================
print("§25  Selection — pre-filters ...")
sr_pf = ProviderRegistry()
pf_prov = _provider("pf-p", models=["pf-big","pf-small"], default="pf-big")
sr_pf.register_provider(pf_prov)
sr_pf.register_model(build_provider_model(
    "pf-p", "pf-big",
    build_provider_capability(streaming=True, tool_calling=True,
                              max_context_tokens=100000, max_output_tokens=4096),
    _TS, priority=90,
))
sr_pf.register_model(build_provider_model(
    "pf-p", "pf-small",
    build_provider_capability(streaming=True, tool_calling=False,
                              max_context_tokens=4096, max_output_tokens=2048),
    _TS, priority=70,
))

# min_context_tokens=50000 -> only pf-big qualifies
sel_min = select_provider(sr_pf, strategy="priority",
                          min_context_tokens=50000, created_at=_TS)
big_m = sr_pf.find_model("pf-p","pf-big")
_eq(sel_min.modelId, big_m.modelId, "min_context_tokens filter works")

# require_tool_calling=True -> only pf-big qualifies
sel_rtc = select_provider(sr_pf, strategy="priority",
                          require_tool_calling=True, created_at=_TS)
_eq(sel_rtc.modelId, big_m.modelId, "require_tool_calling filter works")

# Combined: require_streaming + min_context_tokens=50000 -> pf-big
sel_comb = select_provider(sr_pf, strategy="priority",
                           require_streaming=True, min_context_tokens=50000,
                           created_at=_TS)
_eq(sel_comb.modelId, big_m.modelId, "combined filters work")

# Impossible filter -> SelectionError
try:
    select_provider(sr_pf, strategy="priority", min_context_tokens=999999999, created_at=_TS)
    _assert(False, "impossible filter should raise SelectionError")
except SelectionError:
    _assert(True, "impossible filter raises SelectionError")

# ===========================================================================
# §26  Built-in provider registry — structure
# ===========================================================================
print("§26  Built-in registry — structure ...")
breg = build_default_registry()

# All 6 built-in providers registered
builtin_names = {"groq","openai","anthropic","google","ollama","azure"}
registered_names = {p.providerName for p in breg.list_providers()}
for name in builtin_names:
    _assert(name in registered_names, f"built-in provider '{name}' registered")

_eq(len(breg.list_providers()), 6, "exactly 6 built-in providers")

# Total model count: groq(3) + openai(3) + anthropic(2) + google(2) + ollama(3) + azure(2) = 15
_eq(len(breg.list_models()), 15, "exactly 15 built-in models total")

# All providers enabled by default
_eq(len(breg.list_providers(enabled_only=True)), 6, "all built-in providers enabled")

# All models enabled by default
_eq(len(breg.list_models(enabled_only=True)), 15, "all built-in models enabled")

# ===========================================================================
# §27  Built-in provider registry — Groq models
# ===========================================================================
print("§27  Built-in registry — Groq ...")
groq_models = breg.list_models(provider_name="groq")
_eq(len(groq_models), 3, "groq has 3 built-in models")
groq_names = {m.modelName for m in groq_models}
_in("llama-3.3-70b-versatile", groq_names, "groq has llama-3.3-70b-versatile")
_in("llama-3.1-8b-instant",    groq_names, "groq has llama-3.1-8b-instant")
_in("openai/gpt-oss-120b",     groq_names, "groq has openai/gpt-oss-120b")

# Groq models have streaming + tool calling
for gm in groq_models:
    _assert(gm.capabilities.streaming,   f"groq/{gm.modelName}: streaming=True")
    _assert(gm.capabilities.toolCalling, f"groq/{gm.modelName}: toolCalling=True")
    _assert(gm.capabilities.jsonMode,    f"groq/{gm.modelName}: jsonMode=True")

# Groq provider metadata
g_prov = breg.find_provider("groq")
_assert(g_prov is not None, "groq provider found")
_eq(g_prov.defaultModel, "llama-3.3-70b-versatile", "groq defaultModel")
_in("groq.com", g_prov.endpoint, "groq endpoint contains groq.com")

# ===========================================================================
# §28  Built-in registry — OpenAI models
# ===========================================================================
print("§28  Built-in registry — OpenAI ...")
oai_models = breg.list_models(provider_name="openai")
_eq(len(oai_models), 3, "openai has 3 models")
oai_names = {m.modelName for m in oai_models}
_in("gpt-4.1",     oai_names, "openai has gpt-4.1")
_in("gpt-4o",      oai_names, "openai has gpt-4o")
_in("gpt-4o-mini", oai_names, "openai has gpt-4o-mini")

# vision capability on gpt-4o
gpt4o = breg.find_model("openai","gpt-4o")
_assert(gpt4o is not None, "gpt-4o found")
_assert(gpt4o.capabilities.vision, "gpt-4o has vision")
_gt(gpt4o.capabilities.maxContextTokens, 8192, "gpt-4o has large context")

# ===========================================================================
# §29  Built-in registry — Anthropic models
# ===========================================================================
print("§29  Built-in registry — Anthropic ...")
ant_models = breg.list_models(provider_name="anthropic")
_eq(len(ant_models), 2, "anthropic has 2 models")
ant_names = {m.modelName for m in ant_models}
_in("claude-sonnet-4", ant_names, "anthropic has claude-sonnet-4")
_in("claude-opus-4",   ant_names, "anthropic has claude-opus-4")

# Large context for Anthropic
for am in ant_models:
    _ge(am.capabilities.maxContextTokens, 100000, f"anthropic/{am.modelName}: big context")

# ===========================================================================
# §30  Built-in registry — Google models
# ===========================================================================
print("§30  Built-in registry — Google ...")
g_models = breg.list_models(provider_name="google")
_eq(len(g_models), 2, "google has 2 models")
g_names = {m.modelName for m in g_models}
_in("gemini-2.5-pro",   g_names, "google has gemini-2.5-pro")
_in("gemini-2.5-flash", g_names, "google has gemini-2.5-flash")

gemini_pro = breg.find_model("google","gemini-2.5-pro")
_assert(gemini_pro.capabilities.embeddings, "gemini-2.5-pro supports embeddings")
_ge(gemini_pro.capabilities.maxContextTokens, 1000000, "gemini-2.5-pro has 1M context")

# ===========================================================================
# §31  Built-in registry — Ollama models
# ===========================================================================
print("§31  Built-in registry — Ollama ...")
oll_models = breg.list_models(provider_name="ollama")
_eq(len(oll_models), 3, "ollama has 3 models")
oll_names = {m.modelName for m in oll_models}
_in("llama3.1", oll_names, "ollama has llama3.1")
_in("mistral",  oll_names, "ollama has mistral")
_in("qwen2.5",  oll_names, "ollama has qwen2.5")

# Ollama models are local (no tool calling in our definition)
for om in oll_models:
    _assert(not om.capabilities.toolCalling, f"ollama/{om.modelName}: toolCalling=False")

# ===========================================================================
# §32  Built-in registry — Azure models
# ===========================================================================
print("§32  Built-in registry — Azure ...")
az_models = breg.list_models(provider_name="azure")
_eq(len(az_models), 2, "azure has 2 models")
az_names = {m.modelName for m in az_models}
_in("azure/gpt-4o",  az_names, "azure has azure/gpt-4o")
_in("azure/gpt-4.1", az_names, "azure has azure/gpt-4.1")

# ===========================================================================
# §33  Built-in registry — deterministic IDs (zero randomness)
# ===========================================================================
print("§33  Built-in registry — deterministic IDs ...")
breg_copy1 = build_default_registry()
breg_copy2 = build_default_registry()

# Every provider ID must be identical across both builds
for p1, p2 in zip(
    sorted(breg_copy1.list_providers(), key=lambda x: x.providerName),
    sorted(breg_copy2.list_providers(), key=lambda x: x.providerName),
):
    _eq(p1.providerId, p2.providerId, f"'{p1.providerName}' providerId deterministic")
    _eq(p1.providerKey,p2.providerKey,f"'{p1.providerName}' providerKey deterministic")

# Every model ID must be identical across both builds
for m1, m2 in zip(
    sorted(breg_copy1.list_models(), key=lambda x: (x.provider, x.modelName)),
    sorted(breg_copy2.list_models(), key=lambda x: (x.provider, x.modelName)),
):
    _eq(m1.modelId,  m2.modelId,  f"'{m1.provider}/{m1.modelName}' modelId deterministic")
    _eq(m1.modelKey, m2.modelKey, f"'{m1.provider}/{m1.modelName}' modelKey deterministic")

# No uuid4 — IDs must be UUID version 5 (digit at position 14 == '5')
for pdef in breg_copy1.list_providers():
    _eq(pdef.providerId[14], "5", f"'{pdef.providerName}' providerId is UUIDv5")
for mdl in breg_copy1.list_models():
    _eq(mdl.modelId[14], "5", f"'{mdl.provider}/{mdl.modelName}' modelId is UUIDv5")

# ===========================================================================
# §34  Default registry singleton
# ===========================================================================
print("§34  Default registry singleton ...")
reset_default_registry()
r1 = get_default_registry()
r2 = get_default_registry()
_assert(r1 is r2, "get_default_registry() returns same object on repeated calls")

# build_default_registry() always returns fresh instance
f1 = build_default_registry()
f2 = build_default_registry()
_assert(f1 is not f2, "build_default_registry() returns new instance each time")
_eq(len(f1.list_providers()), len(f2.list_providers()), "both have same provider count")

reset_default_registry()
r3 = get_default_registry()
_assert(r3 is not r1, "after reset, get_default_registry returns new instance")

# ===========================================================================
# §35  Integration helpers
# ===========================================================================
print("§35  Integration helpers ...")
reset_default_registry()
g_p = get_groq_provider()
_assert(g_p is not None, "get_groq_provider() returns a ProviderDefinition")
_eq(g_p.providerName, "groq", "get_groq_provider() returns groq")

g_m = get_groq_model("llama-3.3-70b-versatile")
_assert(g_m is not None, "get_groq_model() returns a ProviderModel")
_eq(g_m.modelName, "llama-3.3-70b-versatile", "get_groq_model() returns correct model")
_assert(g_m.capabilities.toolCalling, "groq model has tool calling via get_groq_model()")

g_m_missing = get_groq_model("gpt-9999")
_assert(g_m_missing is None, "get_groq_model() returns None for missing model")

# get_registry_summary
summary = get_registry_summary(created_at=_TS)
_is(summary, ProviderRegistryResult, "get_registry_summary returns ProviderRegistryResult")
_eq(len(summary.providers), 6,  "summary has 6 providers")
_eq(len(summary.models),    15, "summary has 15 models")
_assert(summary.selection is None, "summary.selection is None (no selection made)")
_eq(summary.metadata.totalProviders,   6,  "metadata.totalProviders=6")
_eq(summary.metadata.enabledProviders, 6,  "metadata.enabledProviders=6")
_eq(summary.metadata.totalModels,      15, "metadata.totalModels=15")
_eq(summary.metadata.engineVersion, PROVIDER_REGISTRY_ENGINE_VERSION, "metadata.engineVersion set")

# ===========================================================================
# §36  Built-in registry — selection works end-to-end
# ===========================================================================
print("§36  Built-in registry — end-to-end selection ...")
breg_sel = build_default_registry()

# Priority selection picks highest-priority model across all providers
sel_overall = select_provider(breg_sel, strategy="priority", created_at=_TS)
_is(sel_overall, ProviderSelection, "priority selection returns ProviderSelection")
_eq(len(sel_overall.selectionId), 36, "selectionId is UUID")

# Cheapest selection
sel_cheapest = select_provider(breg_sel, strategy="cheapest", created_at=_TS)
_is(sel_cheapest, ProviderSelection, "cheapest selection returns ProviderSelection")
# Ollama (free) or llama-8b should win
winning_mdl = None
for m in breg_sel.list_models():
    if m.modelId == sel_cheapest.modelId:
        winning_mdl = m
        break
_assert(winning_mdl is not None, "cheapest modelId maps to a real model")

# Streaming required — should succeed (many models support it)
sel_stream_full = select_provider(breg_sel, strategy="streaming_required", created_at=_TS)
stream_winner = breg_sel.find_model(
    next(p.providerName for p in breg_sel.list_providers()
         if p.providerId == sel_stream_full.providerId),
    next(m.modelName for m in breg_sel.list_models()
         if m.modelId == sel_stream_full.modelId),
)
_assert(stream_winner is not None, "streaming_required winner is a real model")
_assert(stream_winner.capabilities.streaming, "winner supports streaming")

# Tool calling required
sel_tc_full = select_provider(breg_sel, strategy="tool_calling_required", created_at=_TS)
_is(sel_tc_full, ProviderSelection, "tool_calling_required returns ProviderSelection")

# highest_context — Gemini Pro has 1M context
sel_hc_full = select_provider(breg_sel, strategy="highest_context", created_at=_TS)
hc_winner = next((m for m in breg_sel.list_models() if m.modelId == sel_hc_full.modelId), None)
_assert(hc_winner is not None, "highest_context winner is a real model")
_ge(hc_winner.capabilities.maxContextTokens, 1000000, "highest_context winner has >= 1M context")

# Select by provider_name=groq, strategy=cheapest
sel_groq_cheap = select_provider(breg_sel, strategy="cheapest",
                                 provider_name="groq", created_at=_TS)
groq_winner = next((m for m in breg_sel.list_models() if m.modelId == sel_groq_cheap.modelId), None)
_assert(groq_winner is not None, "groq cheapest winner is a real model")
# With provider_name=groq filter, the strategy applies provider_name first,
# so the selection only includes groq models; cheapest among groq is llama-8b
_eq(groq_winner.provider, "groq", "groq cheapest: provider=groq")

# ===========================================================================
# §37  Serialization — models are JSON-serialisable
# ===========================================================================
print("§37  Serialization ...")
import json

# ProviderCapability
cap_json = cap.model_dump()
_is(cap_json, dict, "ProviderCapability.model_dump() returns dict")
cap_restored = ProviderCapability(**cap_json)
_eq(cap_restored, cap, "ProviderCapability round-trips through dict")

# ProviderModel
mdl_json = mdl.model_dump()
_is(mdl_json, dict, "ProviderModel.model_dump() returns dict")

# ProviderDefinition
pdef_json = pdef.model_dump()
_is(pdef_json, dict, "ProviderDefinition.model_dump() returns dict")

# ProviderSelection
sel_json = sel.model_dump()
_is(sel_json, dict, "ProviderSelection.model_dump() returns dict")
_in("selectionId", sel_json, "selectionId in dict")
_in("strategy",    sel_json, "strategy in dict")

# JSON roundtrip for ProviderRegistryResult
summary2 = get_registry_summary(created_at=_TS)
result_json = summary2.model_dump()
_is(result_json, dict, "ProviderRegistryResult.model_dump() returns dict")
_in("providers", result_json, "providers key in result dict")
_in("models",    result_json, "models key in result dict")
_in("metadata",  result_json, "metadata key in result dict")
json_str = json.dumps(result_json, default=str)
_is(json_str, str, "ProviderRegistryResult serialises to JSON string")

# ===========================================================================
# §38  Valid strategies set
# ===========================================================================
print("§38  Valid strategies ...")
_in("priority",              _VALID_STRATEGIES, "priority in valid strategies")
_in("provider_name",         _VALID_STRATEGIES, "provider_name in valid strategies")
_in("model_name",            _VALID_STRATEGIES, "model_name in valid strategies")
_in("capability",            _VALID_STRATEGIES, "capability in valid strategies")
_in("cheapest",              _VALID_STRATEGIES, "cheapest in valid strategies")
_in("highest_context",       _VALID_STRATEGIES, "highest_context in valid strategies")
_in("streaming_required",    _VALID_STRATEGIES, "streaming_required in valid strategies")
_in("tool_calling_required", _VALID_STRATEGIES, "tool_calling_required in valid strategies")
_eq(len(_VALID_STRATEGIES), 8, "exactly 8 valid strategies")

# ===========================================================================
# §39  Zero randomness — identical inputs always yield identical outputs
# ===========================================================================
print("§39  Zero randomness ...")

# Build same capability 100 times — always identical
cap_a = build_provider_capability(streaming=True, tool_calling=True, json_mode=False,
                                  vision=True, embeddings=False,
                                  max_context_tokens=65536, max_output_tokens=4096)
for i in range(5):
    cap_x = build_provider_capability(streaming=True, tool_calling=True, json_mode=False,
                                      vision=True, embeddings=False,
                                      max_context_tokens=65536, max_output_tokens=4096)
    _eq(cap_a, cap_x, f"capability iteration {i}: identical inputs -> identical output")

# Build same model 5 times — always identical IDs
mdl_a = build_provider_model("groq","llama-3.3-70b-versatile",cap_a,_TS,priority=90)
for i in range(5):
    mdl_x = build_provider_model("groq","llama-3.3-70b-versatile",cap_a,_TS,priority=90)
    _eq(mdl_a.modelId,  mdl_x.modelId,  f"model iteration {i}: same modelId")
    _eq(mdl_a.modelKey, mdl_x.modelKey, f"model iteration {i}: same modelKey")

# Build same provider 5 times — always identical IDs
pdef_a = build_provider_definition("groq","Groq","2024-01-01","https://api.groq.com",
                                   ["llama-3.3-70b-versatile"],"llama-3.3-70b-versatile",_TS)
for i in range(5):
    pdef_x = build_provider_definition("groq","Groq","2024-01-01","https://api.groq.com",
                                       ["llama-3.3-70b-versatile"],"llama-3.3-70b-versatile",_TS)
    _eq(pdef_a.providerId,  pdef_x.providerId,  f"provider iteration {i}: same providerId")
    _eq(pdef_a.providerKey, pdef_x.providerKey, f"provider iteration {i}: same providerKey")

# ===========================================================================
# §40  Groq integration metadata
# ===========================================================================
print("§40  Groq integration metadata ...")
from core.constants import (
    GROQ_API_ENDPOINT, GROQ_API_VERSION, GROQ_SUPPORTED_MODELS,
)

reset_default_registry()
g_provider = get_groq_provider()
_assert(g_provider is not None, "get_groq_provider() not None")
_eq(g_provider.apiVersion, GROQ_API_VERSION, "groq apiVersion matches GROQ_API_VERSION const")
_in("groq.com", g_provider.endpoint, "groq endpoint contains groq.com")

# All GROQ_SUPPORTED_MODELS are present in the built-in registry
for mname in GROQ_SUPPORTED_MODELS:
    gm = get_groq_model(mname)
    _assert(gm is not None, f"GROQ_SUPPORTED_MODELS: '{mname}' in built-in registry")
    _assert(gm.enabled, f"'{mname}' is enabled by default")
    _eq(gm.engineVersion, PROVIDER_REGISTRY_ENGINE_VERSION, f"'{mname}' engineVersion set")

# groq 70b has higher priority than 8b
g70b = get_groq_model("llama-3.3-70b-versatile")
g8b  = get_groq_model("llama-3.1-8b-instant")
_gt(g70b.priority, g8b.priority, "groq 70b has higher priority than 8b")

# Priority selection on default registry picks a groq model (highest priority = 90 is groq 70b)
reset_default_registry()
sel_default = select_provider(get_default_registry(), strategy="priority", created_at=_TS)
_is(sel_default, ProviderSelection, "default registry priority selection works")

# ===========================================================================
# Final summary
# ===========================================================================
print()
print(f"{'='*60}")
total = _PASS + _FAIL
print(f"  {_PASS}/{total} assertions passed")
if _FAIL:
    print(f"\n  FAILURES ({_FAIL}):")
    for err in _ERRORS:
        print(f"    {err}")
    sys.exit(1)
else:
    print("  All assertions passed.")
    sys.exit(0)
