"""
Tool Calling Engine
===================
Phase A4.2.3 — Deterministic, immutable tool-calling orchestration layer.

Responsibilities
----------------
- Expose NetFusion's internal services as structured, discoverable tools.
- Build deterministic ToolDefinition, ToolCall, and ToolResult objects.
- Maintain a secure, immutable tool registry (allow-list pattern).
- Validate tool calls, parameters, and return schemas before execution.
- Execute registered tools via deterministic dispatch; wrap every execution
  in safe exception handling and structured logging.
- Support batch and parallel execution (sync + async).
- Provide deterministic IDs for every object (UUIDv5 / SHA-256 only).

This service is a PURE ORCHESTRATION / FRAMEWORK LAYER.
It contains NO AI reasoning, NO investigation logic, NO attack graph
algorithms, NO timeline generation, NO evidence processing.

The actual backend implementations of each tool are registered as
placeholder handlers — real engine integration is the next phase.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic).
- All builder functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Engine version from core/constants.py — never hardcoded.
- Never log secrets (API keys, auth tokens).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import TOOL_CALLING_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("tool_calling_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; changing it invalidates all stored IDs
# ---------------------------------------------------------------------------
_TOOL_NS = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ToolCallingError(Exception):
    """Base class for all Tool Calling Engine errors."""
    def __init__(self, message: str, tool_id: str = "") -> None:
        super().__init__(message)
        self.tool_id = tool_id

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"tool_id={self.tool_id!r}, "
            f"message={str(self)!r})"
        )


class ToolNotFoundError(ToolCallingError):
    """Raised when a requested tool is not in the registry."""


class ToolDisabledError(ToolCallingError):
    """Raised when attempting to execute a disabled tool."""


class ToolValidationError(ToolCallingError):
    """Raised when a tool call fails parameter or schema validation."""


class ToolExecutionError(ToolCallingError):
    """Raised when a tool handler raises an unexpected error."""


class ToolTimeoutError(ToolCallingError):
    """Raised when a tool execution exceeds its configured timeout."""


class DuplicateToolError(ToolCallingError):
    """Raised when registering a tool that already exists with the same key."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class ToolParameter(BaseModel):
    """
    One immutable parameter definition for a tool.

    Fields
    ------
    name         : parameter name (snake_case).
    type         : JSON schema type string (e.g. "string", "integer", "boolean").
    description  : human-readable description of the parameter.
    required     : True if the parameter must be present in every call.
    defaultValue : optional default value when parameter is not required.
    """
    name         : str
    type         : str
    description  : str
    required     : bool
    defaultValue : Optional[Any] = None

    class Config:
        frozen = True


class ToolDefinition(BaseModel):
    """
    One complete, immutable tool definition registered in the engine.

    Identity
    --------
    toolId       : UUIDv5(_TOOL_NS, toolKey) — deterministic.
    toolKey      : SHA256(toolName + category)[:32]
    toolName     : canonical snake_case name (e.g. "search_assets").

    Fields
    ------
    description  : what this tool does (shown to the LLM).
    category     : logical grouping (e.g. "search", "report", "query").
    parameters   : ordered tuple of ToolParameter definitions.
    returnSchema : dict describing the shape of the returned output.
    enabled      : whether this tool may be executed.
    createdAt    : ISO-8601 timestamp (caller-supplied).
    engineVersion: TOOL_CALLING_ENGINE_VERSION at registration time.
    """
    toolId        : str
    toolKey       : str
    toolName      : str
    description   : str
    category      : str
    parameters    : Tuple[ToolParameter, ...]
    returnSchema  : Dict[str, Any]
    enabled       : bool
    createdAt     : str
    engineVersion : str

    class Config:
        frozen = True


class ToolCall(BaseModel):
    """
    One immutable record of a tool invocation request.

    Identity
    --------
    callId   : UUIDv5(_TOOL_NS, callKey) — deterministic.
    callKey  : SHA256(toolId + requestId + sorted(arguments))[:32]

    Fields
    ------
    toolId    : ToolDefinition.toolId being invoked.
    toolName  : ToolDefinition.toolName (denormalised for readability).
    arguments : dict of parameter name → value pairs.
    requestId : caller-supplied request context ID (may be GroqRequest.requestId).
    provider  : originating provider (e.g. "groq", "openai").
    model     : originating model name.
    createdAt : ISO-8601 timestamp (caller-supplied).
    """
    callId    : str
    callKey   : str
    toolId    : str
    toolName  : str
    arguments : Dict[str, Any]
    requestId : str
    provider  : str
    model     : str
    createdAt : str

    class Config:
        frozen = True


class ToolResult(BaseModel):
    """
    One immutable result from a tool execution.

    Identity
    --------
    resultId  : UUIDv5(_TOOL_NS, resultKey) — deterministic.
    resultKey : SHA256(callId + str(success) + output_hash)[:32]

    Fields
    ------
    toolId          : ToolDefinition.toolId that was executed.
    success         : True if the tool completed without error.
    output          : dict containing the tool's return value.
    executionTimeMs : wall-clock ms the execution took.
    error           : error message string (None on success).
    metadata        : arbitrary provenance dict.
    createdAt       : ISO-8601 timestamp (caller-supplied).
    """
    resultId        : str
    resultKey       : str
    toolId          : str
    success         : bool
    output          : Dict[str, Any]
    executionTimeMs : int
    error           : Optional[str]
    metadata        : Dict[str, Any]
    createdAt       : str

    class Config:
        frozen = True


class ToolExecutionMetadata(BaseModel):
    """
    Immutable execution provenance for one tool call round-trip.

    Fields
    ------
    startedAt        : monotonic ms when execution started.
    completedAt      : monotonic ms when execution completed.
    executionTimeMs  : completedAt - startedAt (≥ 0).
    validationPassed : True if parameter validation succeeded.
    provider         : LLM provider that requested the call.
    model            : LLM model that requested the call.
    warnings         : sorted tuple of non-fatal advisory strings.
    """
    startedAt        : int
    completedAt      : int
    executionTimeMs  : int
    validationPassed : bool
    provider         : str
    model            : str
    warnings         : Tuple[str, ...]

    class Config:
        frozen = True


class ToolCallingResult(BaseModel):
    """
    Immutable combined result of one tool call + execution + metadata.

    Fields
    ------
    toolCall   : the ToolCall that was made.
    toolResult : the ToolResult that was produced.
    metadata   : ToolExecutionMetadata — provenance and timings.
    """
    toolCall   : ToolCall
    toolResult : ToolResult
    metadata   : ToolExecutionMetadata

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5_tool(key: str) -> str:
    """UUIDv5(_TOOL_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_TOOL_NS, key))


def _mono_ms() -> int:
    """Monotonic clock in milliseconds (latency measurement only)."""
    return int(time.monotonic() * 1000)


def _arguments_hash(arguments: Dict[str, Any]) -> str:
    """Deterministic 32-char hash of an arguments dict (sorted keys)."""
    import json
    serialised = json.dumps(arguments, sort_keys=True, ensure_ascii=True, default=str)
    return _sha256_32(serialised)


def _output_hash(output: Dict[str, Any]) -> str:
    """Deterministic 32-char hash of an output dict (sorted keys)."""
    import json
    serialised = json.dumps(output, sort_keys=True, ensure_ascii=True, default=str)
    return _sha256_32(serialised)


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


# ===========================================================================
# Builder: build_tool_parameter()
# ===========================================================================

def build_tool_parameter(
    name         : str,
    type_        : str,
    description  : str,
    required     : bool       = True,
    default_value: Any        = None,
) -> ToolParameter:
    """
    Build an immutable ToolParameter.

    Parameters
    ----------
    name          : parameter name (stripped).
    type_         : JSON schema type string (e.g. "string", "integer").
    description   : human-readable description.
    required      : True if this parameter must be supplied on every call.
    default_value : optional default (only meaningful when required=False).

    Returns
    -------
    ToolParameter (frozen / immutable)

    Raises
    ------
    ToolValidationError : if name or type_ is empty.
    """
    if not name or not name.strip():
        raise ToolValidationError("ToolParameter.name must not be empty.")
    if not type_ or not type_.strip():
        raise ToolValidationError("ToolParameter.type must not be empty.")
    return ToolParameter(
        name         = name.strip(),
        type         = type_.strip().lower(),
        description  = description,
        required     = bool(required),
        defaultValue = default_value,
    )


# ===========================================================================
# Builder: build_tool_definition()
# ===========================================================================

def build_tool_definition(
    tool_name    : str,
    description  : str,
    category     : str,
    parameters   : List[ToolParameter],
    return_schema: Dict[str, Any],
    created_at   : str,
    enabled      : bool = True,
) -> ToolDefinition:
    """
    Build an immutable ToolDefinition.

    toolKey = SHA256(toolName + category)[:32]
    toolId  = UUIDv5(_TOOL_NS, toolKey)

    Parameters
    ----------
    tool_name     : canonical snake_case tool name.
    description   : what this tool does (shown to the LLM).
    category      : logical grouping ("search", "report", "query").
    parameters    : list of ToolParameter definitions.
    return_schema : dict describing the shape of the tool's output.
    created_at    : ISO-8601 timestamp.
    enabled       : whether the tool may be executed (default True).

    Returns
    -------
    ToolDefinition (frozen / immutable)

    Raises
    ------
    ToolValidationError : if tool_name or category is empty.
    """
    if not tool_name or not tool_name.strip():
        raise ToolValidationError("ToolDefinition.toolName must not be empty.")
    if not category or not category.strip():
        raise ToolValidationError("ToolDefinition.category must not be empty.")

    norm_name = tool_name.strip().lower()
    norm_cat  = category.strip().lower()

    tool_key = _sha256_32(norm_name, norm_cat)
    tool_id  = _uuid5_tool(tool_key)

    return ToolDefinition(
        toolId        = tool_id,
        toolKey       = tool_key,
        toolName      = norm_name,
        description   = description,
        category      = norm_cat,
        parameters    = tuple(parameters),
        returnSchema  = dict(return_schema),
        enabled       = bool(enabled),
        createdAt     = created_at,
        engineVersion = TOOL_CALLING_ENGINE_VERSION,
    )


# ===========================================================================
# Builder: build_tool_call()
# ===========================================================================

def build_tool_call(
    tool_definition: ToolDefinition,
    arguments      : Dict[str, Any],
    request_id     : str,
    created_at     : str,
    provider       : str = "groq",
    model          : str = "",
) -> ToolCall:
    """
    Build an immutable ToolCall.

    callKey = SHA256(toolId + requestId + arguments_hash)[:32]
    callId  = UUIDv5(_TOOL_NS, callKey)

    Parameters
    ----------
    tool_definition : ToolDefinition to invoke.
    arguments       : parameter name → value dict.
    request_id      : caller context ID (e.g. GroqRequest.requestId).
    created_at      : ISO-8601 timestamp.
    provider        : LLM provider making the call.
    model           : LLM model making the call.

    Returns
    -------
    ToolCall (frozen / immutable)
    """
    arg_hash = _arguments_hash(arguments)
    call_key = _sha256_32(tool_definition.toolId, request_id, arg_hash)
    call_id  = _uuid5_tool(call_key)

    return ToolCall(
        callId    = call_id,
        callKey   = call_key,
        toolId    = tool_definition.toolId,
        toolName  = tool_definition.toolName,
        arguments = dict(arguments),
        requestId = request_id.strip(),
        provider  = provider.strip().lower() if provider else "groq",
        model     = model.strip().lower()    if model    else "",
        createdAt = created_at,
    )


# ===========================================================================
# Builder: build_tool_result()
# ===========================================================================

def build_tool_result(
    call_id        : str,
    tool_id        : str,
    success        : bool,
    output         : Dict[str, Any],
    execution_time_ms: int,
    created_at     : str,
    error          : Optional[str]       = None,
    metadata       : Optional[Dict[str, Any]] = None,
) -> ToolResult:
    """
    Build an immutable ToolResult.

    resultKey = SHA256(callId + str(success) + output_hash)[:32]
    resultId  = UUIDv5(_TOOL_NS, resultKey)

    Parameters
    ----------
    call_id           : ToolCall.callId this result answers.
    tool_id           : ToolDefinition.toolId that was executed.
    success           : True if execution completed without error.
    output            : tool return value dict.
    execution_time_ms : wall-clock ms (≥ 0).
    created_at        : ISO-8601 timestamp.
    error             : error message (None on success).
    metadata          : arbitrary provenance dict.

    Returns
    -------
    ToolResult (frozen / immutable)
    """
    out_hash   = _output_hash(output)
    result_key = _sha256_32(call_id, str(success), out_hash)
    result_id  = _uuid5_tool(result_key)

    meta = dict(metadata) if metadata else {}
    meta.setdefault("engineVersion", TOOL_CALLING_ENGINE_VERSION)

    return ToolResult(
        resultId        = result_id,
        resultKey       = result_key,
        toolId          = tool_id,
        success         = bool(success),
        output          = dict(output),
        executionTimeMs = max(0, int(execution_time_ms)),
        error           = error,
        metadata        = meta,
        createdAt       = created_at,
    )


# ===========================================================================
# Builder: build_execution_metadata()
# ===========================================================================

def build_execution_metadata(
    started_at       : int,
    completed_at     : int,
    validation_passed: bool,
    provider         : str                   = "groq",
    model            : str                   = "",
    warnings         : Optional[List[str]]   = None,
) -> ToolExecutionMetadata:
    """
    Build an immutable ToolExecutionMetadata.

    Parameters
    ----------
    started_at        : monotonic ms when execution started.
    completed_at      : monotonic ms when execution completed.
    validation_passed : True if parameter validation passed.
    provider          : LLM provider that requested the call.
    model             : LLM model that requested the call.
    warnings          : non-fatal advisory strings.

    Returns
    -------
    ToolExecutionMetadata (frozen / immutable)
    """
    clamped_start = max(0, int(started_at))
    clamped_end   = max(0, int(completed_at))
    exec_time     = max(0, clamped_end - clamped_start)
    return ToolExecutionMetadata(
        startedAt        = clamped_start,
        completedAt      = clamped_end,
        executionTimeMs  = exec_time,
        validationPassed = bool(validation_passed),
        provider         = provider.strip().lower() if provider else "groq",
        model            = model.strip().lower()    if model    else "",
        warnings         = _norm_strings(warnings),
    )


# ===========================================================================
# Builder: build_tool_calling_result()
# ===========================================================================

def build_tool_calling_result(
    tool_call  : ToolCall,
    tool_result: ToolResult,
    metadata   : ToolExecutionMetadata,
) -> ToolCallingResult:
    """
    Build an immutable ToolCallingResult combining call, result, and metadata.

    Parameters
    ----------
    tool_call   : the ToolCall that was made.
    tool_result : the ToolResult that was produced.
    metadata    : ToolExecutionMetadata.

    Returns
    -------
    ToolCallingResult (frozen / immutable)
    """
    return ToolCallingResult(
        toolCall   = tool_call,
        toolResult = tool_result,
        metadata   = metadata,
    )


# ===========================================================================
# Validation Functions
# ===========================================================================

def validate_parameters(
    tool_definition: ToolDefinition,
    arguments      : Dict[str, Any],
) -> List[str]:
    """
    Validate ``arguments`` against a ToolDefinition's parameter schema.

    Checks
    ------
    - All required parameters are present and not None.
    - No unknown parameter names (parameters not in the definition).
    - Parameter types are consistent with the declared JSON schema type.
      (Soft check: coercible values are accepted; strict type mismatch raises.)

    Parameters
    ----------
    tool_definition : registered ToolDefinition.
    arguments       : dict of parameter name → value to validate.

    Returns
    -------
    List[str] — list of validation error messages (empty = valid).
    """
    errors: List[str] = []
    defined = {p.name: p for p in tool_definition.parameters}

    # Unknown parameters
    for arg_name in arguments:
        if arg_name not in defined:
            errors.append(
                f"Unknown parameter '{arg_name}' for tool '{tool_definition.toolName}'. "
                f"Defined: {sorted(defined.keys())}"
            )

    # Required parameter presence
    for param in tool_definition.parameters:
        if param.required:
            val = arguments.get(param.name)
            if val is None and param.name not in arguments:
                errors.append(
                    f"Required parameter '{param.name}' is missing "
                    f"for tool '{tool_definition.toolName}'."
                )

    # Type compatibility (soft checks only)
    _TYPE_CHECKS: Dict[str, type] = {
        "string" : str,
        "integer": int,
        "number" : (int, float),
        "boolean": bool,
        "array"  : list,
        "object" : dict,
    }
    for param in tool_definition.parameters:
        val = arguments.get(param.name)
        if val is None:
            continue
        expected_type = _TYPE_CHECKS.get(param.type)
        if expected_type and not isinstance(val, expected_type):
            errors.append(
                f"Parameter '{param.name}' expected type '{param.type}', "
                f"got {type(val).__name__!r} for tool '{tool_definition.toolName}'."
            )

    return errors


def validate_return_schema(
    return_schema: Dict[str, Any],
    output       : Dict[str, Any],
) -> List[str]:
    """
    Validate a tool output dict against its declared returnSchema.

    Checks that every key declared as required in returnSchema is present
    in the output.  Unknown output keys are allowed (additive).

    Parameters
    ----------
    return_schema : ToolDefinition.returnSchema dict.
    output        : actual output dict from tool execution.

    Returns
    -------
    List[str] — validation error messages (empty = valid).
    """
    errors: List[str] = []
    required_keys = return_schema.get("required", [])
    if isinstance(required_keys, list):
        for key in required_keys:
            if key not in output:
                errors.append(
                    f"Output is missing required return key '{key}'."
                )
    return errors


def validate_tool_call(
    tool_definition: ToolDefinition,
    arguments      : Dict[str, Any],
) -> None:
    """
    Validate a tool call fully.  Raises on the first error set found.

    Checks both parameter presence/type and that the tool is enabled.

    Parameters
    ----------
    tool_definition : ToolDefinition to validate against.
    arguments       : call arguments.

    Raises
    ------
    ToolDisabledError   : if the tool is disabled.
    ToolValidationError : if any parameter validation error is found.
    """
    if not tool_definition.enabled:
        raise ToolDisabledError(
            f"Tool '{tool_definition.toolName}' is disabled and cannot be executed.",
            tool_id=tool_definition.toolId,
        )
    errors = validate_parameters(tool_definition, arguments)
    if errors:
        raise ToolValidationError(
            f"Tool call validation failed for '{tool_definition.toolName}':\n"
            + "\n".join(f"  - {e}" for e in errors),
            tool_id=tool_definition.toolId,
        )


# ===========================================================================
# Tool Registry
# ===========================================================================

class ToolRegistry:
    """
    Secure, mutable registry of ToolDefinition objects.

    Design
    ------
    - Tools are keyed by toolName (lowercase, stripped).
    - Handlers are keyed separately and never stored on ToolDefinition
      (keeps the model immutable and clean).
    - Only registered tools may be executed.
    - Disabled tools are blocked at validate_tool_call() time.
    """

    def __init__(self) -> None:
        # toolName → ToolDefinition
        self._definitions: Dict[str, ToolDefinition] = {}
        # toolName → callable handler
        self._handlers   : Dict[str, Callable]       = {}

    # ------------------------------------------------------------------
    # register_tool()
    # ------------------------------------------------------------------
    def register_tool(
        self,
        definition: ToolDefinition,
        handler   : Callable,
    ) -> None:
        """
        Register a tool definition and its execution handler.

        Parameters
        ----------
        definition : ToolDefinition (immutable).
        handler    : callable(arguments: Dict[str, Any]) → Dict[str, Any].
                     May be sync or async.

        Raises
        ------
        DuplicateToolError : if a tool with the same toolName is already registered.
        """
        name = definition.toolName
        if name in self._definitions:
            raise DuplicateToolError(
                f"Tool '{name}' is already registered. "
                "Unregister it first with unregister_tool().",
                tool_id=definition.toolId,
            )
        self._definitions[name] = definition
        self._handlers[name]    = handler
        _log.info(
            f"[tool_calling] tool_registered "
            f"tool_name={name} "
            f"tool_id={definition.toolId} "
            f"category={definition.category} "
            f"enabled={definition.enabled}"
        )

    # ------------------------------------------------------------------
    # unregister_tool()
    # ------------------------------------------------------------------
    def unregister_tool(self, tool_name: str) -> None:
        """
        Remove a tool from the registry by name.

        Silently succeeds if the tool is not registered.

        Parameters
        ----------
        tool_name : canonical tool name to remove.
        """
        name = tool_name.strip().lower()
        removed = self._definitions.pop(name, None)
        self._handlers.pop(name, None)
        if removed:
            _log.info(
                f"[tool_calling] tool_unregistered "
                f"tool_name={name} "
                f"tool_id={removed.toolId}"
            )

    # ------------------------------------------------------------------
    # enable_tool() / disable_tool()
    # ------------------------------------------------------------------
    def enable_tool(self, tool_name: str) -> None:
        """
        Enable a registered tool so it can be executed.

        Parameters
        ----------
        tool_name : canonical tool name.

        Raises
        ------
        ToolNotFoundError : if the tool is not registered.
        """
        name = tool_name.strip().lower()
        defn = self._definitions.get(name)
        if defn is None:
            raise ToolNotFoundError(
                f"Cannot enable: tool '{name}' is not registered."
            )
        # Rebuild definition with enabled=True (immutable model — must replace)
        updated = ToolDefinition(
            toolId        = defn.toolId,
            toolKey       = defn.toolKey,
            toolName      = defn.toolName,
            description   = defn.description,
            category      = defn.category,
            parameters    = defn.parameters,
            returnSchema  = defn.returnSchema,
            enabled       = True,
            createdAt     = defn.createdAt,
            engineVersion = defn.engineVersion,
        )
        self._definitions[name] = updated
        _log.info(f"[tool_calling] tool_enabled tool_name={name}")

    def disable_tool(self, tool_name: str) -> None:
        """
        Disable a registered tool so it cannot be executed.

        Parameters
        ----------
        tool_name : canonical tool name.

        Raises
        ------
        ToolNotFoundError : if the tool is not registered.
        """
        name = tool_name.strip().lower()
        defn = self._definitions.get(name)
        if defn is None:
            raise ToolNotFoundError(
                f"Cannot disable: tool '{name}' is not registered."
            )
        updated = ToolDefinition(
            toolId        = defn.toolId,
            toolKey       = defn.toolKey,
            toolName      = defn.toolName,
            description   = defn.description,
            category      = defn.category,
            parameters    = defn.parameters,
            returnSchema  = defn.returnSchema,
            enabled       = False,
            createdAt     = defn.createdAt,
            engineVersion = defn.engineVersion,
        )
        self._definitions[name] = updated
        _log.info(
            f"[tool_calling] tool_disabled tool_name={name}"
        )

    # ------------------------------------------------------------------
    # list_tools()
    # ------------------------------------------------------------------
    def list_tools(
        self,
        category : Optional[str] = None,
        enabled  : Optional[bool] = None,
    ) -> List[ToolDefinition]:
        """
        Return a sorted list of registered ToolDefinition objects.

        Parameters
        ----------
        category : filter by category (case-insensitive, exact match).
        enabled  : filter by enabled state (True / False / None = all).

        Returns
        -------
        List[ToolDefinition] — sorted by toolName ASC.
        """
        results = list(self._definitions.values())
        if category is not None:
            cat = category.strip().lower()
            results = [d for d in results if d.category == cat]
        if enabled is not None:
            results = [d for d in results if d.enabled == enabled]
        return sorted(results, key=lambda d: d.toolName)

    # ------------------------------------------------------------------
    # find_tool()
    # ------------------------------------------------------------------
    def find_tool(self, tool_name: str) -> Optional[ToolDefinition]:
        """
        Look up a ToolDefinition by name.

        Returns None if not found (never raises).

        Parameters
        ----------
        tool_name : canonical tool name (normalised internally).
        """
        return self._definitions.get(tool_name.strip().lower())

    # ------------------------------------------------------------------
    # tool_exists()
    # ------------------------------------------------------------------
    def tool_exists(self, tool_name: str) -> bool:
        """
        Return True if a tool with ``tool_name`` is registered.

        Parameters
        ----------
        tool_name : canonical tool name.
        """
        return tool_name.strip().lower() in self._definitions

    # ------------------------------------------------------------------
    # get_handler() — internal
    # ------------------------------------------------------------------
    def _get_handler(self, tool_name: str) -> Optional[Callable]:
        return self._handlers.get(tool_name.strip().lower())

    def __len__(self) -> int:
        return len(self._definitions)


# ===========================================================================
# Execution Functions
# ===========================================================================

def execute_tool(
    registry        : ToolRegistry,
    tool_name       : str,
    arguments       : Dict[str, Any],
    request_id      : str,
    created_at      : str,
    provider        : str = "groq",
    model           : str = "",
    timeout_seconds : Optional[float] = None,
) -> ToolCallingResult:
    """
    Execute a registered tool synchronously.

    Steps
    -----
    1. Look up the ToolDefinition in the registry (allow-list check).
    2. Validate the call (enabled check + parameter validation).
    3. Build a deterministic ToolCall object.
    4. Invoke the handler; wrap exceptions safely.
    5. Build ToolResult, ToolExecutionMetadata, ToolCallingResult.
    6. Emit structured log entries.

    Parameters
    ----------
    registry        : ToolRegistry to look up the tool.
    tool_name       : name of the tool to execute.
    arguments       : parameter name → value dict.
    request_id      : caller context ID.
    created_at      : ISO-8601 timestamp (caller-supplied).
    provider        : LLM provider making the call.
    model           : LLM model making the call.
    timeout_seconds : optional execution timeout (float seconds).

    Returns
    -------
    ToolCallingResult (frozen / immutable)

    Raises
    ------
    ToolNotFoundError  : tool not in registry.
    ToolDisabledError  : tool is disabled.
    ToolValidationError: parameter validation failed.
    ToolTimeoutError   : execution exceeded timeout.
    """
    name = tool_name.strip().lower()
    defn = registry.find_tool(name)
    if defn is None:
        _log.warning(
            f"[tool_calling] tool_not_found tool_name={name}"
        )
        raise ToolNotFoundError(
            f"Tool '{name}' is not registered. "
            f"Registered tools: {[d.toolName for d in registry.list_tools()]}",
        )

    # Build call object before validation (so we have a callId for logging)
    tool_call = build_tool_call(defn, arguments, request_id, created_at, provider, model)

    started_at = _mono_ms()
    validation_passed = False
    warnings: List[str] = []

    try:
        validate_tool_call(defn, arguments)
        validation_passed = True
    except (ToolDisabledError, ToolValidationError) as exc:
        completed_at = _mono_ms()
        _log.warning(
            f"[tool_calling] validation_failed "
            f"tool_name={name} "
            f"call_id={tool_call.callId} "
            f"error={exc}"
        )
        meta = build_execution_metadata(started_at, completed_at, False, provider, model, warnings)
        result = build_tool_result(
            call_id           = tool_call.callId,
            tool_id           = defn.toolId,
            success           = False,
            output            = {},
            execution_time_ms = completed_at - started_at,
            created_at        = created_at,
            error             = str(exc),
        )
        return build_tool_calling_result(tool_call, result, meta)

    # Execute handler
    handler = registry._get_handler(name)
    try:
        if timeout_seconds is not None:
            # Run with timeout via asyncio event-loop creation
            async def _timed():
                if asyncio.iscoroutinefunction(handler):
                    return await asyncio.wait_for(handler(arguments), timeout=timeout_seconds)
                else:
                    return handler(arguments)
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is None:
                output = asyncio.run(_timed())
            else:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, _timed())
                    output = future.result()
        else:
            if asyncio.iscoroutinefunction(handler):
                output = asyncio.run(handler(arguments))
            else:
                output = handler(arguments)

        completed_at = _mono_ms()
        if not isinstance(output, dict):
            output = {"result": output}

        # Validate return schema
        schema_errors = validate_return_schema(defn.returnSchema, output)
        if schema_errors:
            warnings.extend(schema_errors)

        _log.info(
            f"[tool_calling] tool_executed "
            f"tool_name={name} "
            f"call_id={tool_call.callId} "
            f"execution_ms={completed_at - started_at}"
        )
        meta   = build_execution_metadata(started_at, completed_at, validation_passed, provider, model, warnings)
        result = build_tool_result(
            call_id           = tool_call.callId,
            tool_id           = defn.toolId,
            success           = True,
            output            = output,
            execution_time_ms = completed_at - started_at,
            created_at        = created_at,
            error             = None,
        )
        return build_tool_calling_result(tool_call, result, meta)

    except asyncio.TimeoutError:
        completed_at = _mono_ms()
        _log.error(
            f"[tool_calling] tool_timeout "
            f"tool_name={name} "
            f"call_id={tool_call.callId} "
            f"timeout_s={timeout_seconds}"
        )
        raise ToolTimeoutError(
            f"Tool '{name}' timed out after {timeout_seconds}s.",
            tool_id=defn.toolId,
        )

    except (ToolDisabledError, ToolNotFoundError, ToolValidationError, ToolTimeoutError):
        raise

    except Exception as exc:
        completed_at = _mono_ms()
        _log.error(
            f"[tool_calling] tool_failed "
            f"tool_name={name} "
            f"call_id={tool_call.callId} "
            f"error={exc}"
        )
        meta   = build_execution_metadata(started_at, completed_at, validation_passed, provider, model, warnings)
        result = build_tool_result(
            call_id           = tool_call.callId,
            tool_id           = defn.toolId,
            success           = False,
            output            = {},
            execution_time_ms = completed_at - started_at,
            created_at        = created_at,
            error             = f"Unexpected error: {exc}",
        )
        return build_tool_calling_result(tool_call, result, meta)


async def execute_registered_tool(
    registry       : ToolRegistry,
    tool_name      : str,
    arguments      : Dict[str, Any],
    request_id     : str,
    created_at     : str,
    provider       : str = "groq",
    model          : str = "",
    timeout_seconds: Optional[float] = None,
) -> ToolCallingResult:
    """
    Execute a registered tool asynchronously.

    Identical semantics to execute_tool() but native async — suitable for
    use within an async event loop without thread-pool wrapping.

    Parameters
    ----------
    Same as execute_tool().

    Returns
    -------
    ToolCallingResult (frozen / immutable)
    """
    name = tool_name.strip().lower()
    defn = registry.find_tool(name)
    if defn is None:
        _log.warning(f"[tool_calling] tool_not_found tool_name={name}")
        raise ToolNotFoundError(
            f"Tool '{name}' is not registered.",
        )

    tool_call  = build_tool_call(defn, arguments, request_id, created_at, provider, model)
    started_at = _mono_ms()
    validation_passed = False
    warnings: List[str] = []

    try:
        validate_tool_call(defn, arguments)
        validation_passed = True
    except (ToolDisabledError, ToolValidationError) as exc:
        completed_at = _mono_ms()
        _log.warning(f"[tool_calling] validation_failed tool_name={name} error={exc}")
        meta   = build_execution_metadata(started_at, completed_at, False, provider, model, warnings)
        result = build_tool_result(tool_call.callId, defn.toolId, False, {},
                                   completed_at - started_at, created_at, error=str(exc))
        return build_tool_calling_result(tool_call, result, meta)

    handler = registry._get_handler(name)
    try:
        if timeout_seconds is not None:
            if asyncio.iscoroutinefunction(handler):
                output = await asyncio.wait_for(handler(arguments), timeout=timeout_seconds)
            else:
                output = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(None, lambda: handler(arguments)),
                    timeout=timeout_seconds,
                )
        else:
            if asyncio.iscoroutinefunction(handler):
                output = await handler(arguments)
            else:
                output = handler(arguments)

        completed_at = _mono_ms()
        if not isinstance(output, dict):
            output = {"result": output}

        schema_errors = validate_return_schema(defn.returnSchema, output)
        if schema_errors:
            warnings.extend(schema_errors)

        _log.info(f"[tool_calling] tool_executed tool_name={name} call_id={tool_call.callId}")
        meta   = build_execution_metadata(started_at, completed_at, validation_passed, provider, model, warnings)
        result = build_tool_result(tool_call.callId, defn.toolId, True, output,
                                   completed_at - started_at, created_at)
        return build_tool_calling_result(tool_call, result, meta)

    except asyncio.TimeoutError:
        _log.error(f"[tool_calling] tool_timeout tool_name={name}")
        raise ToolTimeoutError(f"Tool '{name}' timed out.", tool_id=defn.toolId)

    except (ToolDisabledError, ToolNotFoundError, ToolValidationError, ToolTimeoutError):
        raise

    except Exception as exc:
        completed_at = _mono_ms()
        _log.error(f"[tool_calling] tool_failed tool_name={name} error={exc}")
        meta   = build_execution_metadata(started_at, completed_at, validation_passed, provider, model, warnings)
        result = build_tool_result(tool_call.callId, defn.toolId, False, {},
                                   completed_at - started_at, created_at,
                                   error=f"Unexpected error: {exc}")
        return build_tool_calling_result(tool_call, result, meta)


def execute_batch(
    registry   : ToolRegistry,
    calls      : List[Dict[str, Any]],
    created_at : str,
    provider   : str = "groq",
    model      : str = "",
) -> List[ToolCallingResult]:
    """
    Execute a list of tool calls sequentially (batch mode).

    Each call dict must contain:
      - tool_name  : str
      - arguments  : Dict[str, Any]
      - request_id : str

    Individual failures do NOT abort the batch — each result captures
    its own success/failure state.

    Parameters
    ----------
    registry   : ToolRegistry.
    calls      : list of call descriptor dicts.
    created_at : ISO-8601 timestamp (shared across the batch).
    provider   : LLM provider.
    model      : LLM model.

    Returns
    -------
    List[ToolCallingResult] — one per input call, in input order.
    """
    results: List[ToolCallingResult] = []
    for call_desc in calls:
        tool_name  = call_desc.get("tool_name", "")
        arguments  = call_desc.get("arguments", {})
        request_id = call_desc.get("request_id", "batch")
        try:
            r = execute_tool(registry, tool_name, arguments, request_id, created_at, provider, model)
        except (ToolNotFoundError, ToolTimeoutError) as exc:
            # Build a failure result for registry/timeout errors
            defn = registry.find_tool(tool_name)
            tool_id = defn.toolId if defn else _uuid5_tool(_sha256_32(tool_name, "unknown"))
            dummy_call = ToolCall(
                callId    = _uuid5_tool(_sha256_32(tool_name, request_id, "batch-error")),
                callKey   = _sha256_32(tool_name, request_id, "batch-error"),
                toolId    = tool_id,
                toolName  = tool_name.strip().lower() or "unknown",
                arguments = dict(arguments),
                requestId = request_id,
                provider  = provider,
                model     = model,
                createdAt = created_at,
            )
            ts = _mono_ms()
            meta   = build_execution_metadata(ts, ts, False, provider, model)
            result = build_tool_result(dummy_call.callId, tool_id, False, {},
                                       0, created_at, error=str(exc))
            results.append(build_tool_calling_result(dummy_call, result, meta))
        else:
            results.append(r)
    return results


async def execute_parallel(
    registry   : ToolRegistry,
    calls      : List[Dict[str, Any]],
    created_at : str,
    provider   : str = "groq",
    model      : str = "",
) -> List[ToolCallingResult]:
    """
    Execute a list of tool calls in parallel using asyncio.gather().

    Each call dict must contain:
      - tool_name  : str
      - arguments  : Dict[str, Any]
      - request_id : str

    Individual failures do NOT abort the parallel run.  Order of results
    matches order of input calls.

    Parameters
    ----------
    registry   : ToolRegistry.
    calls      : list of call descriptor dicts.
    created_at : ISO-8601 timestamp (shared).
    provider   : LLM provider.
    model      : LLM model.

    Returns
    -------
    List[ToolCallingResult] — one per input call, in input order.
    """
    async def _safe_execute(call_desc: Dict[str, Any]) -> ToolCallingResult:
        tool_name  = call_desc.get("tool_name", "")
        arguments  = call_desc.get("arguments", {})
        request_id = call_desc.get("request_id", "parallel")
        try:
            return await execute_registered_tool(
                registry, tool_name, arguments, request_id,
                created_at, provider, model,
            )
        except (ToolNotFoundError, ToolTimeoutError) as exc:
            defn    = registry.find_tool(tool_name)
            tool_id = defn.toolId if defn else _uuid5_tool(_sha256_32(tool_name, "unknown"))
            dummy   = ToolCall(
                callId    = _uuid5_tool(_sha256_32(tool_name, request_id, "par-error")),
                callKey   = _sha256_32(tool_name, request_id, "par-error"),
                toolId    = tool_id,
                toolName  = tool_name.strip().lower() or "unknown",
                arguments = dict(arguments),
                requestId = request_id,
                provider  = provider,
                model     = model,
                createdAt = created_at,
            )
            ts   = _mono_ms()
            meta = build_execution_metadata(ts, ts, False, provider, model)
            res  = build_tool_result(dummy.callId, tool_id, False, {}, 0, created_at, error=str(exc))
            return build_tool_calling_result(dummy, res, meta)

    results = await asyncio.gather(*[_safe_execute(c) for c in calls])
    return list(results)


# ===========================================================================
# Built-in Tool Definitions (Placeholder handlers)
# ===========================================================================

_CREATED_AT_DEFAULT = "2026-07-01T00:00:00Z"

# --- Parameter templates ---

def _p(name: str, type_: str, desc: str, required: bool = True, default: Any = None) -> ToolParameter:
    return build_tool_parameter(name, type_, desc, required, default)


# Shared parameters used across multiple tools
_PARAM_QUERY         = _p("query",          "string",  "Search query string.",                    required=False, default="")
_PARAM_LIMIT         = _p("limit",          "integer", "Maximum number of results to return.",    required=False, default=10)
_PARAM_OFFSET        = _p("offset",         "integer", "Pagination offset.",                      required=False, default=0)
_PARAM_SESSION_ID    = _p("session_id",     "string",  "Session/investigation context ID.",       required=False, default="")
_PARAM_INVESTIGATION = _p("investigation_id","string", "Investigation ID to scope results.",      required=False, default="")
_PARAM_INCLUDE_CLOSED= _p("include_closed", "boolean", "Include closed/resolved items.",          required=False, default=False)
_PARAM_SEVERITY      = _p("severity",       "string",  "Minimum severity filter.",                required=False, default="")
_PARAM_FORMAT        = _p("format",         "string",  "Output format: json | summary | full.",   required=False, default="json")

# Shared return schema base
_BASE_RETURN = {"type": "object", "required": ["status", "data"], "properties": {
    "status": {"type": "string"},
    "data"  : {"type": "object"},
    "count" : {"type": "integer"},
}}


def _placeholder_handler(tool_name: str) -> Callable:
    """
    Return a deterministic placeholder handler for a given tool name.

    The handler returns a consistent, deterministic output keyed by tool_name.
    This is NOT real business logic — it is a framework stub that will be
    replaced in the next phase when actual engine integration is completed.
    """
    def _handler(arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status"    : "ok",
            "data"      : {},
            "count"     : 0,
            "tool"      : tool_name,
            "arguments" : arguments,
            "note"      : f"Placeholder handler for '{tool_name}'. Real integration pending.",
        }
    return _handler


# --- Built-in tool specifications ---

_BUILTIN_TOOLS: List[Dict[str, Any]] = [
    {
        "name"       : "search_assets",
        "description": "Search and retrieve network asset records. Returns matching assets with identity, confidence, and relationship metadata.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET, _PARAM_SESSION_ID,
                        _p("ip_address", "string", "Filter by IP address.", required=False, default=""),
                        _p("mac_address","string", "Filter by MAC address.", required=False, default=""),
                        _p("hostname",   "string", "Filter by hostname.",   required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_evidence",
        "description": "Search captured network evidence records. Returns evidence items with source, confidence, and correlation metadata.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET, _PARAM_SESSION_ID,
                        _p("source_type", "string", "Filter by evidence source type.", required=False, default=""),
                        _p("min_confidence","integer","Minimum confidence score 0-100.", required=False, default=0),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_relationships",
        "description": "Search asset-to-asset communication relationships. Returns pairs with protocols, packet counts, and confidence scores.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET, _PARAM_SESSION_ID,
                        _p("asset_id",  "string", "Filter by one endpoint asset ID.", required=False, default=""),
                        _p("protocol",  "string", "Filter by network protocol.",      required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_attack_graph",
        "description": "Query the attack graph for nodes, edges, and attack paths. Returns graph elements with MITRE ATT&CK mappings.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_SESSION_ID, _PARAM_INVESTIGATION,
                        _p("node_type", "string", "Filter by graph node type.", required=False, default=""),
                        _p("technique", "string", "Filter by MITRE technique ID.", required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_timeline",
        "description": "Query the investigation timeline for ordered events. Returns timestamped events with severity and source attribution.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET, _PARAM_SESSION_ID, _PARAM_INVESTIGATION,
                        _p("event_type",    "string", "Filter by event type.",           required=False, default=""),
                        _p("start_time_iso","string", "ISO-8601 start boundary.",        required=False, default=""),
                        _p("end_time_iso",  "string", "ISO-8601 end boundary.",          required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_findings",
        "description": "Search security findings generated by the analysis engine. Returns findings with risk scores and evidence links.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET, _PARAM_SESSION_ID,
                        _PARAM_SEVERITY, _PARAM_INCLUDE_CLOSED,
                        _p("finding_type","string","Filter by finding type.",required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_alerts",
        "description": "Search active and historical security alerts. Returns alerts with severity, status, and correlated findings.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET, _PARAM_SESSION_ID,
                        _PARAM_SEVERITY, _PARAM_INCLUDE_CLOSED,
                        _p("alert_type","string","Filter by alert type.", required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "search_investigations",
        "description": "Search investigation records and their current status. Returns investigations with scope, findings count, and timeline.",
        "category"   : "search",
        "parameters" : [_PARAM_QUERY, _PARAM_LIMIT, _PARAM_OFFSET,
                        _PARAM_INCLUDE_CLOSED,
                        _p("status","string","Filter by investigation status.", required=False, default=""),
                        ],
        "return_schema": _BASE_RETURN,
    },
    {
        "name"       : "generate_report",
        "description": "Generate a structured investigation report. Returns a formatted report with executive summary, findings, and recommendations.",
        "category"   : "report",
        "parameters" : [
            _p("investigation_id","string","Investigation ID to generate report for.", required=True),
            _PARAM_FORMAT,
            _p("include_evidence","boolean","Include raw evidence in report.", required=False, default=False),
            _p("include_timeline","boolean","Include timeline section.",        required=False, default=True),
            _p("include_graph",   "boolean","Include attack graph section.",    required=False, default=True),
        ],
        "return_schema": {"type": "object", "required": ["status", "report"], "properties": {
            "status": {"type": "string"}, "report": {"type": "object"},
        }},
    },
    {
        "name"       : "query_statistics",
        "description": "Query aggregate statistics for the current session or investigation. Returns counts, scores, and summary metrics.",
        "category"   : "query",
        "parameters" : [
            _PARAM_SESSION_ID, _PARAM_INVESTIGATION,
            _p("metric_types","array","List of metric categories to include.", required=False, default=None),
        ],
        "return_schema": {"type": "object", "required": ["status", "statistics"], "properties": {
            "status": {"type": "string"}, "statistics": {"type": "object"},
        }},
    },
]


def _build_and_register_builtins(registry: ToolRegistry) -> None:
    """Register all built-in placeholder tool definitions."""
    for spec in _BUILTIN_TOOLS:
        defn = build_tool_definition(
            tool_name     = spec["name"],
            description   = spec["description"],
            category      = spec["category"],
            parameters    = spec["parameters"],
            return_schema = spec["return_schema"],
            created_at    = _CREATED_AT_DEFAULT,
            enabled       = True,
        )
        registry.register_tool(defn, _placeholder_handler(spec["name"]))


# ===========================================================================
# Module-level default registry (pre-populated with built-in tools)
# ===========================================================================

_default_registry = ToolRegistry()
_build_and_register_builtins(_default_registry)


def get_default_registry() -> ToolRegistry:
    """Return the module-level default registry (pre-loaded with built-ins)."""
    return _default_registry


# ===========================================================================
# Public convenience wrappers (use default registry)
# ===========================================================================

def register_tool(definition: ToolDefinition, handler: Callable) -> None:
    """Register a tool in the default registry."""
    _default_registry.register_tool(definition, handler)


def unregister_tool(tool_name: str) -> None:
    """Unregister a tool from the default registry."""
    _default_registry.unregister_tool(tool_name)


def enable_tool(tool_name: str) -> None:
    """Enable a tool in the default registry."""
    _default_registry.enable_tool(tool_name)


def disable_tool(tool_name: str) -> None:
    """Disable a tool in the default registry."""
    _default_registry.disable_tool(tool_name)


def list_tools(category: Optional[str] = None, enabled: Optional[bool] = None) -> List[ToolDefinition]:
    """List tools in the default registry."""
    return _default_registry.list_tools(category=category, enabled=enabled)


def find_tool(tool_name: str) -> Optional[ToolDefinition]:
    """Find a tool in the default registry."""
    return _default_registry.find_tool(tool_name)


def tool_exists(tool_name: str) -> bool:
    """Check if a tool exists in the default registry."""
    return _default_registry.tool_exists(tool_name)


# ===========================================================================
# Public API surface
# ===========================================================================

__all__ = [
    # Exceptions
    "ToolCallingError", "ToolNotFoundError", "ToolDisabledError",
    "ToolValidationError", "ToolExecutionError", "ToolTimeoutError",
    "DuplicateToolError",
    # Models
    "ToolParameter", "ToolDefinition", "ToolCall", "ToolResult",
    "ToolExecutionMetadata", "ToolCallingResult",
    # Builders
    "build_tool_parameter", "build_tool_definition", "build_tool_call",
    "build_tool_result", "build_execution_metadata", "build_tool_calling_result",
    # Registry class
    "ToolRegistry",
    # Registry functions (default registry)
    "register_tool", "unregister_tool", "enable_tool", "disable_tool",
    "list_tools", "find_tool", "tool_exists", "get_default_registry",
    # Validation
    "validate_tool_call", "validate_parameters", "validate_return_schema",
    # Execution
    "execute_tool", "execute_registered_tool",
    "execute_batch", "execute_parallel",
    # Constants
    "TOOL_CALLING_ENGINE_VERSION",
]
