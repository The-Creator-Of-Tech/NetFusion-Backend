"""
Provider Registry Engine
========================
Phase A4.3.0 — Central provider abstraction layer for NetFusion AI Copilot.

Responsibilities
----------------
- Discover, validate, register, select, and route AI providers.
- Expose a deterministic single interface over multiple LLM providers.
- Register built-in provider definitions for Groq, OpenAI, Anthropic,
  Google, Ollama, and Azure OpenAI with their respective models.
- Support provider/model enable/disable, priority-based selection,
  and capability-based filtering.

This service does NOT contain:
- Reasoning logic, prompt generation, or investigation logic.
- HTTP networking or streaming implementation.
- Tool execution logic.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 and UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- Never log API keys or secrets.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import PROVIDER_REGISTRY_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("provider_registry_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_REGISTRY_NS = uuid.UUID("6ba7b820-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ProviderRegistryError(Exception):
    """Base class for all Provider Registry errors."""
    def __init__(self, message: str, provider_id: str = "", model_id: str = "") -> None:
        super().__init__(message)
        self.provider_id = provider_id
        self.model_id    = model_id

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"provider_id={self.provider_id!r}, "
            f"model_id={self.model_id!r}, "
            f"message={str(self)!r})"
        )


class ProviderNotFoundError(ProviderRegistryError):
    """Raised when a requested provider is not in the registry."""


class ModelNotFoundError(ProviderRegistryError):
    """Raised when a requested model is not in the registry."""


class ProviderValidationError(ProviderRegistryError):
    """Raised when a provider or model fails validation."""


class DuplicateProviderError(ProviderRegistryError):
    """Raised when registering a provider that already exists."""


class DuplicateModelError(ProviderRegistryError):
    """Raised when registering a model that already exists."""


class SelectionError(ProviderRegistryError):
    """Raised when no provider/model can be selected for the given criteria."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class ProviderCapability(BaseModel):
    """
    Immutable capability flags for an AI provider model.

    Fields
    ------
    streaming        : whether the model supports streaming responses.
    toolCalling      : whether the model supports tool/function calling.
    jsonMode         : whether the model supports JSON output mode.
    vision           : whether the model supports vision/image inputs.
    embeddings       : whether the model supports embeddings generation.
    maxContextTokens : maximum context window in tokens.
    maxOutputTokens  : maximum output tokens per request.
    """
    streaming        : bool
    toolCalling      : bool
    jsonMode         : bool
    vision           : bool
    embeddings       : bool
    maxContextTokens : int
    maxOutputTokens  : int

    class Config:
        frozen = True


class ProviderModel(BaseModel):
    """
    Immutable definition of one AI model within a provider.

    Identity
    --------
    modelId       : UUIDv5(_REGISTRY_NS, modelKey) — deterministic.
    modelKey      : SHA256(provider + modelId_raw + modelName)[:32]

    Fields
    ------
    modelId       : deterministic UUID for this model.
    modelKey      : deterministic 32-char hex key.
    provider      : provider key this model belongs to (e.g. "groq").
    modelName     : canonical model name (e.g. "llama-3.3-70b-versatile").
    alias         : optional short alias (e.g. "llama-70b").
    capabilities  : ProviderCapability flags.
    enabled       : whether this model may be selected.
    priority      : selection priority (higher = preferred); 0 = lowest.
    createdAt     : ISO-8601 timestamp (caller-supplied for determinism).
    engineVersion : PROVIDER_REGISTRY_ENGINE_VERSION at build time.
    """
    modelId       : str
    modelKey      : str
    provider      : str
    modelName     : str
    alias         : Optional[str]
    capabilities  : ProviderCapability
    enabled       : bool
    priority      : int
    createdAt     : str
    engineVersion : str

    class Config:
        frozen = True


class ProviderDefinition(BaseModel):
    """
    Immutable definition of one AI provider.

    Identity
    --------
    providerId      : UUIDv5(_REGISTRY_NS, providerKey) — deterministic.
    providerKey     : SHA256(providerKey_raw + providerName)[:32]

    Fields
    ------
    providerId      : deterministic UUID for this provider.
    providerKey     : deterministic 32-char hex key (slug).
    providerName    : canonical provider name (e.g. "groq").
    displayName     : human-readable name (e.g. "Groq").
    apiVersion      : provider API version string.
    endpoint        : provider API base URL.
    supportedModels : sorted tuple of model names this provider supports.
    defaultModel    : model name to use when none is specified.
    enabled         : whether this provider is active.
    createdAt       : ISO-8601 timestamp.
    engineVersion   : PROVIDER_REGISTRY_ENGINE_VERSION at build time.
    """
    providerId      : str
    providerKey     : str
    providerName    : str
    displayName     : str
    apiVersion      : str
    endpoint        : str
    supportedModels : Tuple[str, ...]
    defaultModel    : str
    enabled         : bool
    createdAt       : str
    engineVersion   : str

    class Config:
        frozen = True


class ProviderSelection(BaseModel):
    """
    Immutable record of one provider/model selection decision.

    Fields
    ------
    selectionId : UUIDv5(_REGISTRY_NS, selectionKey) — deterministic.
    providerId  : selected ProviderDefinition.providerId.
    modelId     : selected ProviderModel.modelId.
    strategy    : selection strategy used (e.g. "priority", "cheapest").
    reason      : human-readable reason for the selection.
    createdAt   : ISO-8601 timestamp.
    """
    selectionId : str
    providerId  : str
    modelId     : str
    strategy    : str
    reason      : str
    createdAt   : str

    class Config:
        frozen = True


class ProviderRegistryMetadata(BaseModel):
    """
    Immutable metadata snapshot of the registry state.

    Fields
    ------
    totalProviders   : total number of registered providers.
    enabledProviders : count of currently enabled providers.
    totalModels      : total number of registered models.
    selectedProvider : providerId of the last selection (or empty string).
    selectedModel    : modelId of the last selection (or empty string).
    warnings         : sorted tuple of non-fatal advisory strings.
    engineVersion    : PROVIDER_REGISTRY_ENGINE_VERSION.
    """
    totalProviders   : int
    enabledProviders : int
    totalModels      : int
    selectedProvider : str
    selectedModel    : str
    warnings         : Tuple[str, ...]
    engineVersion    : str

    class Config:
        frozen = True


class ProviderRegistryResult(BaseModel):
    """
    Immutable complete result of a registry query or selection operation.

    Fields
    ------
    providers : tuple of all ProviderDefinition objects at query time.
    models    : tuple of all ProviderModel objects at query time.
    selection : the ProviderSelection made (or None if no selection).
    metadata  : ProviderRegistryMetadata snapshot.
    """
    providers : Tuple[ProviderDefinition, ...]
    models    : Tuple[ProviderModel, ...]
    selection : Optional[ProviderSelection]
    metadata  : ProviderRegistryMetadata

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5(key: str) -> str:
    """UUIDv5(_REGISTRY_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_REGISTRY_NS, key))


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _norm_name(s: str) -> str:
    """Lowercase and strip a name string."""
    return s.strip().lower() if s else ""


# ===========================================================================
# Builder Functions
# ===========================================================================

def build_provider_capability(
    streaming        : bool = False,
    tool_calling     : bool = False,
    json_mode        : bool = False,
    vision           : bool = False,
    embeddings       : bool = False,
    max_context_tokens: int = 8192,
    max_output_tokens : int = 4096,
) -> ProviderCapability:
    """
    Build an immutable ProviderCapability.

    Parameters
    ----------
    streaming         : model supports streaming responses.
    tool_calling      : model supports tool/function calling.
    json_mode         : model supports JSON output mode.
    vision            : model supports vision/image inputs.
    embeddings        : model supports embeddings.
    max_context_tokens: maximum context window in tokens (≥ 1).
    max_output_tokens : maximum output tokens per request (≥ 1).

    Returns
    -------
    ProviderCapability (frozen / immutable)
    """
    return ProviderCapability(
        streaming        = bool(streaming),
        toolCalling      = bool(tool_calling),
        jsonMode         = bool(json_mode),
        vision           = bool(vision),
        embeddings       = bool(embeddings),
        maxContextTokens = max(1, int(max_context_tokens)),
        maxOutputTokens  = max(1, int(max_output_tokens)),
    )


def build_provider_model(
    provider          : str,
    model_name        : str,
    capabilities      : ProviderCapability,
    created_at        : str,
    alias             : Optional[str] = None,
    enabled           : bool = True,
    priority          : int  = 50,
) -> ProviderModel:
    """
    Build an immutable ProviderModel.

    modelKey = SHA256(provider + model_name)[:32]
    modelId  = UUIDv5(_REGISTRY_NS, modelKey)

    Parameters
    ----------
    provider     : provider key (normalised to lowercase).
    model_name   : canonical model name (normalised to lowercase).
    capabilities : ProviderCapability flags.
    created_at   : ISO-8601 timestamp.
    alias        : optional short alias.
    enabled      : whether this model may be selected (default True).
    priority     : selection priority 0–100 (higher = preferred).

    Returns
    -------
    ProviderModel (frozen / immutable)

    Raises
    ------
    ProviderValidationError : if provider or model_name is empty.
    """
    norm_provider = _norm_name(provider)
    norm_model    = _norm_name(model_name)
    if not norm_provider:
        raise ProviderValidationError("ProviderModel.provider must not be empty.")
    if not norm_model:
        raise ProviderValidationError("ProviderModel.modelName must not be empty.")

    model_key = _sha256_32(norm_provider, norm_model)
    model_id  = _uuid5(model_key)

    return ProviderModel(
        modelId       = model_id,
        modelKey      = model_key,
        provider      = norm_provider,
        modelName     = norm_model,
        alias         = alias.strip().lower() if alias else None,
        capabilities  = capabilities,
        enabled       = bool(enabled),
        priority      = max(0, int(priority)),
        createdAt     = created_at,
        engineVersion = PROVIDER_REGISTRY_ENGINE_VERSION,
    )


def build_provider_definition(
    provider_name   : str,
    display_name    : str,
    api_version     : str,
    endpoint        : str,
    supported_models: List[str],
    default_model   : str,
    created_at      : str,
    enabled         : bool = True,
) -> ProviderDefinition:
    """
    Build an immutable ProviderDefinition.

    providerKey = SHA256(provider_name)[:32]
    providerId  = UUIDv5(_REGISTRY_NS, providerKey)

    Parameters
    ----------
    provider_name    : canonical provider name (normalised to lowercase).
    display_name     : human-readable display name.
    api_version      : provider API version string.
    endpoint         : provider base URL.
    supported_models : list of model name strings this provider supports.
    default_model    : model name to use by default (normalised).
    created_at       : ISO-8601 timestamp.
    enabled          : whether this provider is active (default True).

    Returns
    -------
    ProviderDefinition (frozen / immutable)

    Raises
    ------
    ProviderValidationError : if provider_name is empty.
    """
    norm_name = _norm_name(provider_name)
    if not norm_name:
        raise ProviderValidationError("ProviderDefinition.providerName must not be empty.")

    provider_key    = _sha256_32(norm_name)
    provider_id     = _uuid5(provider_key)
    sorted_models   = tuple(sorted(_norm_name(m) for m in supported_models if m and m.strip()))
    norm_default    = _norm_name(default_model)

    return ProviderDefinition(
        providerId      = provider_id,
        providerKey     = provider_key,
        providerName    = norm_name,
        displayName     = display_name.strip() if display_name else norm_name,
        apiVersion      = api_version.strip(),
        endpoint        = endpoint.strip(),
        supportedModels = sorted_models,
        defaultModel    = norm_default,
        enabled         = bool(enabled),
        createdAt       = created_at,
        engineVersion   = PROVIDER_REGISTRY_ENGINE_VERSION,
    )


def build_provider_selection(
    provider_id : str,
    model_id    : str,
    strategy    : str,
    reason      : str,
    created_at  : str,
) -> ProviderSelection:
    """
    Build an immutable ProviderSelection record.

    selectionKey = SHA256(provider_id + model_id + strategy)[:32]
    selectionId  = UUIDv5(_REGISTRY_NS, selectionKey)

    Parameters
    ----------
    provider_id : selected ProviderDefinition.providerId.
    model_id    : selected ProviderModel.modelId.
    strategy    : selection strategy used.
    reason      : human-readable explanation.
    created_at  : ISO-8601 timestamp.

    Returns
    -------
    ProviderSelection (frozen / immutable)
    """
    sel_key = _sha256_32(provider_id.strip(), model_id.strip(), strategy.strip().lower())
    sel_id  = _uuid5(sel_key)
    return ProviderSelection(
        selectionId = sel_id,
        providerId  = provider_id.strip(),
        modelId     = model_id.strip(),
        strategy    = strategy.strip().lower(),
        reason      = reason,
        createdAt   = created_at,
    )


def build_registry_metadata(
    providers        : List[ProviderDefinition],
    models           : List[ProviderModel],
    selected_provider: str = "",
    selected_model   : str = "",
    warnings         : Optional[List[str]] = None,
) -> ProviderRegistryMetadata:
    """
    Build an immutable ProviderRegistryMetadata snapshot.

    Parameters
    ----------
    providers         : all registered providers at this moment.
    models            : all registered models at this moment.
    selected_provider : providerId of the last selection (may be empty).
    selected_model    : modelId of the last selection (may be empty).
    warnings          : non-fatal advisory strings (deduped + sorted).

    Returns
    -------
    ProviderRegistryMetadata (frozen / immutable)
    """
    total     = len(providers)
    enabled   = sum(1 for p in providers if p.enabled)
    return ProviderRegistryMetadata(
        totalProviders   = total,
        enabledProviders = enabled,
        totalModels      = len(models),
        selectedProvider = selected_provider.strip(),
        selectedModel    = selected_model.strip(),
        warnings         = _norm_strings(warnings),
        engineVersion    = PROVIDER_REGISTRY_ENGINE_VERSION,
    )


def build_registry_result(
    providers : List[ProviderDefinition],
    models    : List[ProviderModel],
    selection : Optional[ProviderSelection],
    metadata  : ProviderRegistryMetadata,
) -> ProviderRegistryResult:
    """
    Build an immutable ProviderRegistryResult.

    Parameters
    ----------
    providers : list of ProviderDefinition objects.
    models    : list of ProviderModel objects.
    selection : the ProviderSelection made (or None).
    metadata  : ProviderRegistryMetadata snapshot.

    Returns
    -------
    ProviderRegistryResult (frozen / immutable)
    """
    sorted_providers = tuple(sorted(providers, key=lambda p: p.providerName))
    sorted_models    = tuple(sorted(models,    key=lambda m: (m.provider, m.modelName)))
    return ProviderRegistryResult(
        providers = sorted_providers,
        models    = sorted_models,
        selection = selection,
        metadata  = metadata,
    )


# ===========================================================================
# Validation Functions
# ===========================================================================

def validate_capabilities(capabilities: ProviderCapability) -> None:
    """
    Validate a ProviderCapability object.

    Checks
    ------
    - maxContextTokens ≥ 1.
    - maxOutputTokens ≥ 1.
    - maxOutputTokens ≤ maxContextTokens.

    Raises
    ------
    ProviderValidationError : if any check fails.
    """
    errors: List[str] = []
    if capabilities.maxContextTokens < 1:
        errors.append(
            f"maxContextTokens={capabilities.maxContextTokens} must be ≥ 1."
        )
    if capabilities.maxOutputTokens < 1:
        errors.append(
            f"maxOutputTokens={capabilities.maxOutputTokens} must be ≥ 1."
        )
    if capabilities.maxOutputTokens > capabilities.maxContextTokens:
        errors.append(
            f"maxOutputTokens={capabilities.maxOutputTokens} must be "
            f"≤ maxContextTokens={capabilities.maxContextTokens}."
        )
    if errors:
        raise ProviderValidationError(
            "ProviderCapability validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def validate_model(model: ProviderModel) -> None:
    """
    Validate a ProviderModel object.

    Checks
    ------
    - modelId is a 36-char UUID string.
    - modelKey is a 32-char hex string.
    - provider is non-empty.
    - modelName is non-empty.
    - priority is in [0, 100].
    - capabilities pass validate_capabilities().

    Raises
    ------
    ProviderValidationError : if any check fails.
    """
    errors: List[str] = []
    if len(model.modelId) != 36:
        errors.append(f"modelId must be a 36-char UUID, got {len(model.modelId)} chars.")
    if len(model.modelKey) != 32:
        errors.append(f"modelKey must be 32 hex chars, got {len(model.modelKey)} chars.")
    if not model.provider:
        errors.append("provider must not be empty.")
    if not model.modelName:
        errors.append("modelName must not be empty.")
    if not (0 <= model.priority <= 100):
        errors.append(f"priority={model.priority} must be in [0, 100].")
    if errors:
        raise ProviderValidationError(
            f"ProviderModel '{model.modelName}' validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors),
            model_id=model.modelId,
        )
    validate_capabilities(model.capabilities)


def validate_provider(provider: ProviderDefinition) -> None:
    """
    Validate a ProviderDefinition object.

    Checks
    ------
    - providerId is a 36-char UUID string.
    - providerKey is a 32-char hex string.
    - providerName is non-empty.
    - endpoint is non-empty.
    - defaultModel is in supportedModels (if supportedModels is non-empty).

    Raises
    ------
    ProviderValidationError : if any check fails.
    """
    errors: List[str] = []
    if len(provider.providerId) != 36:
        errors.append(
            f"providerId must be a 36-char UUID, got {len(provider.providerId)} chars."
        )
    if len(provider.providerKey) != 32:
        errors.append(
            f"providerKey must be 32 hex chars, got {len(provider.providerKey)} chars."
        )
    if not provider.providerName:
        errors.append("providerName must not be empty.")
    if not provider.endpoint:
        errors.append("endpoint must not be empty.")
    if provider.supportedModels and provider.defaultModel:
        if provider.defaultModel not in provider.supportedModels:
            errors.append(
                f"defaultModel='{provider.defaultModel}' not in supportedModels."
            )
    if errors:
        raise ProviderValidationError(
            f"ProviderDefinition '{provider.providerName}' validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors),
            provider_id=provider.providerId,
        )


# ===========================================================================
# Provider Registry Class
# ===========================================================================

class ProviderRegistry:
    """
    Central registry for AI provider definitions and models.

    Design
    ------
    - Providers are keyed by providerName (lowercase).
    - Models are keyed by (providerName, modelName) (both lowercase).
    - All state mutations produce structured log events.
    - Selection is fully deterministic for identical inputs.
    """

    def __init__(self) -> None:
        # providerName → ProviderDefinition
        self._providers: Dict[str, ProviderDefinition] = {}
        # (providerName, modelName) → ProviderModel
        self._models: Dict[Tuple[str, str], ProviderModel] = {}

    # ------------------------------------------------------------------ #
    # Registry operations — providers                                      #
    # ------------------------------------------------------------------ #

    def register_provider(self, definition: ProviderDefinition) -> None:
        """
        Register a provider definition.

        Raises
        ------
        DuplicateProviderError   : if a provider with the same name exists.
        ProviderValidationError  : if the definition fails validation.
        """
        validate_provider(definition)
        name = definition.providerName
        if name in self._providers:
            raise DuplicateProviderError(
                f"Provider '{name}' is already registered. "
                "Unregister it first with unregister_provider().",
                provider_id=definition.providerId,
            )
        self._providers[name] = definition
        _log.info(
            f"[provider_registry] provider_registered "
            f"provider_name={name} "
            f"provider_id={definition.providerId} "
            f"enabled={definition.enabled} "
            f"engine={PROVIDER_REGISTRY_ENGINE_VERSION}"
        )

    def unregister_provider(self, provider_name: str) -> None:
        """
        Remove a provider from the registry. Silently succeeds if not found.

        Also removes all models belonging to this provider.
        """
        name = _norm_name(provider_name)
        removed = self._providers.pop(name, None)
        # Remove all models for this provider
        stale = [k for k in self._models if k[0] == name]
        for k in stale:
            del self._models[k]
        if removed:
            _log.info(
                f"[provider_registry] provider_unregistered "
                f"provider_name={name} "
                f"provider_id={removed.providerId}"
            )

    def enable_provider(self, provider_name: str) -> None:
        """
        Enable a registered provider.

        Raises
        ------
        ProviderNotFoundError : if not registered.
        """
        name = _norm_name(provider_name)
        defn = self._providers.get(name)
        if defn is None:
            raise ProviderNotFoundError(
                f"Cannot enable: provider '{name}' is not registered."
            )
        updated = ProviderDefinition(
            providerId      = defn.providerId,
            providerKey     = defn.providerKey,
            providerName    = defn.providerName,
            displayName     = defn.displayName,
            apiVersion      = defn.apiVersion,
            endpoint        = defn.endpoint,
            supportedModels = defn.supportedModels,
            defaultModel    = defn.defaultModel,
            enabled         = True,
            createdAt       = defn.createdAt,
            engineVersion   = defn.engineVersion,
        )
        self._providers[name] = updated
        _log.info(f"[provider_registry] provider_enabled provider_name={name}")

    def disable_provider(self, provider_name: str) -> None:
        """
        Disable a registered provider.

        Raises
        ------
        ProviderNotFoundError : if not registered.
        """
        name = _norm_name(provider_name)
        defn = self._providers.get(name)
        if defn is None:
            raise ProviderNotFoundError(
                f"Cannot disable: provider '{name}' is not registered."
            )
        updated = ProviderDefinition(
            providerId      = defn.providerId,
            providerKey     = defn.providerKey,
            providerName    = defn.providerName,
            displayName     = defn.displayName,
            apiVersion      = defn.apiVersion,
            endpoint        = defn.endpoint,
            supportedModels = defn.supportedModels,
            defaultModel    = defn.defaultModel,
            enabled         = False,
            createdAt       = defn.createdAt,
            engineVersion   = defn.engineVersion,
        )
        self._providers[name] = updated
        _log.info(f"[provider_registry] provider_disabled provider_name={name}")

    # ------------------------------------------------------------------ #
    # Registry operations — models                                         #
    # ------------------------------------------------------------------ #

    def register_model(self, model: ProviderModel) -> None:
        """
        Register a model definition.

        Raises
        ------
        DuplicateModelError     : if a model with the same (provider, name) exists.
        ProviderValidationError : if the model fails validation.
        """
        validate_model(model)
        key = (model.provider, model.modelName)
        if key in self._models:
            raise DuplicateModelError(
                f"Model '{model.modelName}' for provider '{model.provider}' "
                "is already registered.",
                model_id=model.modelId,
            )
        self._models[key] = model
        _log.info(
            f"[provider_registry] model_registered "
            f"provider={model.provider} "
            f"model_name={model.modelName} "
            f"model_id={model.modelId} "
            f"enabled={model.enabled} "
            f"priority={model.priority}"
        )

    def unregister_model(self, provider_name: str, model_name: str) -> None:
        """Remove a model. Silently succeeds if not found."""
        key = (_norm_name(provider_name), _norm_name(model_name))
        removed = self._models.pop(key, None)
        if removed:
            _log.info(
                f"[provider_registry] model_unregistered "
                f"provider={removed.provider} "
                f"model_name={removed.modelName}"
            )

    def enable_model(self, provider_name: str, model_name: str) -> None:
        """
        Enable a registered model.

        Raises
        ------
        ModelNotFoundError : if the model is not registered.
        """
        key  = (_norm_name(provider_name), _norm_name(model_name))
        mdl  = self._models.get(key)
        if mdl is None:
            raise ModelNotFoundError(
                f"Cannot enable: model '{model_name}' for provider "
                f"'{provider_name}' is not registered."
            )
        updated = ProviderModel(
            modelId       = mdl.modelId,
            modelKey      = mdl.modelKey,
            provider      = mdl.provider,
            modelName     = mdl.modelName,
            alias         = mdl.alias,
            capabilities  = mdl.capabilities,
            enabled       = True,
            priority      = mdl.priority,
            createdAt     = mdl.createdAt,
            engineVersion = mdl.engineVersion,
        )
        self._models[key] = updated
        _log.info(
            f"[provider_registry] model_enabled "
            f"provider={mdl.provider} model_name={mdl.modelName}"
        )

    def disable_model(self, provider_name: str, model_name: str) -> None:
        """
        Disable a registered model.

        Raises
        ------
        ModelNotFoundError : if the model is not registered.
        """
        key  = (_norm_name(provider_name), _norm_name(model_name))
        mdl  = self._models.get(key)
        if mdl is None:
            raise ModelNotFoundError(
                f"Cannot disable: model '{model_name}' for provider "
                f"'{provider_name}' is not registered."
            )
        updated = ProviderModel(
            modelId       = mdl.modelId,
            modelKey      = mdl.modelKey,
            provider      = mdl.provider,
            modelName     = mdl.modelName,
            alias         = mdl.alias,
            capabilities  = mdl.capabilities,
            enabled       = False,
            priority      = mdl.priority,
            createdAt     = mdl.createdAt,
            engineVersion = mdl.engineVersion,
        )
        self._models[key] = updated
        _log.info(
            f"[provider_registry] model_disabled "
            f"provider={mdl.provider} model_name={mdl.modelName}"
        )

    # ------------------------------------------------------------------ #
    # Lookup / query helpers                                               #
    # ------------------------------------------------------------------ #

    def provider_exists(self, provider_name: str) -> bool:
        """Return True if a provider with this name is registered."""
        return _norm_name(provider_name) in self._providers

    def model_exists(self, provider_name: str, model_name: str) -> bool:
        """Return True if (provider_name, model_name) is registered."""
        return (_norm_name(provider_name), _norm_name(model_name)) in self._models

    def find_provider(self, provider_name: str) -> Optional[ProviderDefinition]:
        """Return the ProviderDefinition or None if not found."""
        return self._providers.get(_norm_name(provider_name))

    def find_model(
        self,
        provider_name: str,
        model_name   : str,
    ) -> Optional[ProviderModel]:
        """Return the ProviderModel or None if not found."""
        return self._models.get((_norm_name(provider_name), _norm_name(model_name)))

    def list_providers(
        self,
        enabled_only: Optional[bool] = None,
    ) -> List[ProviderDefinition]:
        """
        Return sorted list of providers (by providerName ASC).

        Parameters
        ----------
        enabled_only : None = all; True = enabled only; False = disabled only.
        """
        result = list(self._providers.values())
        if enabled_only is True:
            result = [p for p in result if p.enabled]
        elif enabled_only is False:
            result = [p for p in result if not p.enabled]
        return sorted(result, key=lambda p: p.providerName)

    def list_models(
        self,
        provider_name: Optional[str]  = None,
        enabled_only : Optional[bool] = None,
    ) -> List[ProviderModel]:
        """
        Return sorted list of models (by provider ASC, modelName ASC).

        Parameters
        ----------
        provider_name : filter by provider (None = all providers).
        enabled_only  : None = all; True = enabled only; False = disabled only.
        """
        result = list(self._models.values())
        if provider_name is not None:
            norm = _norm_name(provider_name)
            result = [m for m in result if m.provider == norm]
        if enabled_only is True:
            result = [m for m in result if m.enabled]
        elif enabled_only is False:
            result = [m for m in result if not m.enabled]
        return sorted(result, key=lambda m: (m.provider, m.modelName))

    def __len__(self) -> int:
        """Return total number of registered providers."""
        return len(self._providers)


# ===========================================================================
# Selection Engine
# ===========================================================================

# Supported strategies
_VALID_STRATEGIES = frozenset({
    "priority",
    "provider_name",
    "model_name",
    "capability",
    "cheapest",
    "highest_context",
    "streaming_required",
    "tool_calling_required",
})

# Approximate pricing per 1M tokens (USD) — used for "cheapest" strategy.
# Updated to match Groq constants; other providers use conservative estimates.
_MODEL_PRICING: Dict[str, float] = {
    # Groq
    "llama-3.1-8b-instant"    : 0.065,   # avg (prompt + completion) / 2
    "llama-3.3-70b-versatile" : 0.690,
    "openai/gpt-oss-120b"     : 10.00,
    # OpenAI
    "gpt-4.1"                 : 7.50,
    "gpt-4o"                  : 5.00,
    "gpt-4o-mini"             : 0.30,
    # Anthropic
    "claude-sonnet-4"         : 6.00,
    "claude-opus-4"           : 30.00,
    # Google
    "gemini-2.5-pro"          : 7.00,
    "gemini-2.5-flash"        : 0.50,
    # Ollama (local — effectively free)
    "llama3.1"                : 0.0,
    "mistral"                 : 0.0,
    "qwen2.5"                 : 0.0,
    # Azure OpenAI
    "azure/gpt-4o"            : 5.00,
    "azure/gpt-4.1"           : 7.50,
}


def select_provider(
    registry         : ProviderRegistry,
    strategy         : str = "priority",
    provider_name    : Optional[str]  = None,
    model_name       : Optional[str]  = None,
    require_streaming: bool = False,
    require_tool_calling: bool = False,
    require_capability: Optional[str] = None,
    min_context_tokens: Optional[int] = None,
    created_at       : str = "1970-01-01T00:00:00Z",
) -> ProviderSelection:
    """
    Deterministically select a provider+model from the registry.

    Strategy descriptions
    ---------------------
    priority              : highest-priority enabled model first.
    provider_name         : select specific provider by name.
    model_name            : select specific model by name.
    capability            : filter by required_capability flag name.
    cheapest              : select by lowest approximate cost per token.
    highest_context       : select model with largest context window.
    streaming_required    : only models with streaming=True.
    tool_calling_required : only models with toolCalling=True.

    Tie-breaking is always deterministic: sort by
    (priority DESC, provider ASC, modelName ASC).

    Parameters
    ----------
    registry              : ProviderRegistry to query.
    strategy              : selection strategy key.
    provider_name         : required for "provider_name" strategy; optional filter.
    model_name            : required for "model_name" strategy; optional filter.
    require_streaming     : pre-filter to streaming=True models.
    require_tool_calling  : pre-filter to toolCalling=True models.
    require_capability    : one of "streaming", "toolCalling", "jsonMode",
                            "vision", "embeddings" — pre-filter.
    min_context_tokens    : pre-filter to models with maxContextTokens ≥ this.
    created_at            : ISO-8601 timestamp for the selection record.

    Returns
    -------
    ProviderSelection (frozen / immutable)

    Raises
    ------
    SelectionError : if strategy is unknown or no eligible model found.
    """
    strat = strategy.strip().lower()
    if strat not in _VALID_STRATEGIES:
        raise SelectionError(
            f"Unknown selection strategy '{strategy}'. "
            f"Valid strategies: {sorted(_VALID_STRATEGIES)}"
        )

    # Build initial candidate pool: enabled models from enabled providers
    candidates: List[ProviderModel] = []
    for mdl in registry.list_models(enabled_only=True):
        prov = registry.find_provider(mdl.provider)
        if prov is None or not prov.enabled:
            continue
        candidates.append(mdl)

    # Apply universal pre-filters
    if require_streaming:
        candidates = [c for c in candidates if c.capabilities.streaming]
    if require_tool_calling:
        candidates = [c for c in candidates if c.capabilities.toolCalling]
    if require_capability:
        cap = require_capability.strip()
        cap_map = {
            "streaming"   : lambda c: c.capabilities.streaming,
            "toolcalling" : lambda c: c.capabilities.toolCalling,
            "jsonmode"    : lambda c: c.capabilities.jsonMode,
            "vision"      : lambda c: c.capabilities.vision,
            "embeddings"  : lambda c: c.capabilities.embeddings,
        }
        cap_fn = cap_map.get(cap.lower())
        if cap_fn:
            candidates = [c for c in candidates if cap_fn(c)]
    if min_context_tokens is not None:
        candidates = [
            c for c in candidates
            if c.capabilities.maxContextTokens >= min_context_tokens
        ]
    # Optional provider_name pre-filter — applies to all strategies when supplied
    # (for "provider_name" strategy, this is also enforced below in strategy block)
    if provider_name and strat != "provider_name":
        norm_pname = _norm_name(provider_name)
        candidates = [c for c in candidates if c.provider == norm_pname]

    # Strategy-specific filtering
    reason = ""

    if strat == "provider_name":
        if not provider_name:
            raise SelectionError(
                "strategy='provider_name' requires provider_name to be specified."
            )
        norm = _norm_name(provider_name)
        candidates = [c for c in candidates if c.provider == norm]
        reason = f"Selected by provider_name='{norm}'"

    elif strat == "model_name":
        if not model_name:
            raise SelectionError(
                "strategy='model_name' requires model_name to be specified."
            )
        norm = _norm_name(model_name)
        # Match by modelName or alias
        candidates = [
            c for c in candidates
            if c.modelName == norm or (c.alias and c.alias == norm)
        ]
        reason = f"Selected by model_name='{norm}'"

    elif strat == "streaming_required":
        candidates = [c for c in candidates if c.capabilities.streaming]
        reason = "Selected streaming-capable model"

    elif strat == "tool_calling_required":
        candidates = [c for c in candidates if c.capabilities.toolCalling]
        reason = "Selected tool-calling-capable model"

    elif strat == "capability":
        if require_capability:
            reason = f"Selected model with capability='{require_capability}'"
        else:
            reason = "Selected by capability filter"

    elif strat == "cheapest":
        candidates = sorted(
            candidates,
            key=lambda c: (
                _MODEL_PRICING.get(c.modelName, 9999.0),
                c.provider,
                c.modelName,
            ),
        )
        reason = "Selected cheapest model by estimated cost"

    elif strat == "highest_context":
        candidates = sorted(
            candidates,
            key=lambda c: (
                -c.capabilities.maxContextTokens,
                c.provider,
                c.modelName,
            ),
        )
        reason = "Selected model with highest context window"

    # "priority" — default tie-breaking already applied below
    if not reason:
        reason = "Selected by priority"

    if not candidates:
        raise SelectionError(
            f"No eligible provider/model found for strategy='{strat}' "
            f"with the given filters."
        )

    # Deterministic tie-breaking for all strategies (except cheapest/highest_context
    # which already sorted by their primary key above)
    if strat not in ("cheapest", "highest_context"):
        candidates = sorted(
            candidates,
            key=lambda c: (-c.priority, c.provider, c.modelName),
        )

    winner = candidates[0]
    prov   = registry.find_provider(winner.provider)

    _log.info(
        f"[provider_registry] provider_selected "
        f"provider={winner.provider} "
        f"model={winner.modelName} "
        f"strategy={strat} "
        f"provider_id={prov.providerId if prov else ''} "
        f"model_id={winner.modelId}"
    )

    return build_provider_selection(
        provider_id = prov.providerId if prov else "",
        model_id    = winner.modelId,
        strategy    = strat,
        reason      = reason,
        created_at  = created_at,
    )


def select_model(
    registry      : ProviderRegistry,
    provider_name : str,
    strategy      : str = "priority",
    created_at    : str = "1970-01-01T00:00:00Z",
    **kwargs: Any,
) -> ProviderSelection:
    """
    Select a model within a specific provider.

    Thin wrapper over select_provider() that forces provider_name filtering.

    Parameters
    ----------
    registry      : ProviderRegistry.
    provider_name : the provider to select a model from.
    strategy      : selection strategy (defaults to "priority").
    created_at    : ISO-8601 timestamp.
    **kwargs      : forwarded to select_provider().

    Returns
    -------
    ProviderSelection (frozen / immutable)
    """
    return select_provider(
        registry      = registry,
        strategy      = strategy,
        provider_name = provider_name,
        created_at    = created_at,
        **kwargs,
    )


# ===========================================================================
# Built-in Provider Definitions
# ===========================================================================

_BUILTIN_CREATED_AT = "2026-07-01T00:00:00Z"


def _make_groq_provider_and_models() -> Tuple[ProviderDefinition, List[ProviderModel]]:
    """Build deterministic Groq provider + models."""
    from core.constants import GROQ_API_ENDPOINT, GROQ_API_VERSION

    provider = build_provider_definition(
        provider_name    = "groq",
        display_name     = "Groq",
        api_version      = GROQ_API_VERSION,
        endpoint         = GROQ_API_ENDPOINT,
        supported_models = [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "openai/gpt-oss-120b",
        ],
        default_model    = "llama-3.3-70b-versatile",
        created_at       = _BUILTIN_CREATED_AT,
    )

    cap_70b = build_provider_capability(
        streaming=True, tool_calling=True, json_mode=True,
        vision=False, embeddings=False,
        max_context_tokens=128000, max_output_tokens=8192,
    )
    cap_8b = build_provider_capability(
        streaming=True, tool_calling=True, json_mode=True,
        vision=False, embeddings=False,
        max_context_tokens=128000, max_output_tokens=8192,
    )
    cap_gpt_oss = build_provider_capability(
        streaming=True, tool_calling=True, json_mode=True,
        vision=False, embeddings=False,
        max_context_tokens=128000, max_output_tokens=8192,
    )

    models = [
        build_provider_model("groq", "llama-3.3-70b-versatile", cap_70b,  _BUILTIN_CREATED_AT, alias="llama-70b",  priority=90),
        build_provider_model("groq", "llama-3.1-8b-instant",    cap_8b,   _BUILTIN_CREATED_AT, alias="llama-8b",   priority=70),
        build_provider_model("groq", "openai/gpt-oss-120b",     cap_gpt_oss, _BUILTIN_CREATED_AT, alias="gpt-oss", priority=80),
    ]
    return provider, models


def _make_openai_provider_and_models() -> Tuple[ProviderDefinition, List[ProviderModel]]:
    """Build deterministic OpenAI provider + models."""
    provider = build_provider_definition(
        provider_name    = "openai",
        display_name     = "OpenAI",
        api_version      = "2024-01-01",
        endpoint         = "https://api.openai.com/v1/chat/completions",
        supported_models = ["gpt-4.1", "gpt-4o", "gpt-4o-mini"],
        default_model    = "gpt-4o",
        created_at       = _BUILTIN_CREATED_AT,
    )

    cap_41  = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True,  embeddings=False, max_context_tokens=1047576, max_output_tokens=32768)
    cap_4o  = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True,  embeddings=False, max_context_tokens=128000,  max_output_tokens=16384)
    cap_mini= build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True,  embeddings=False, max_context_tokens=128000,  max_output_tokens=16384)

    models = [
        build_provider_model("openai", "gpt-4.1",    cap_41,   _BUILTIN_CREATED_AT, alias="gpt41",     priority=85),
        build_provider_model("openai", "gpt-4o",     cap_4o,   _BUILTIN_CREATED_AT, alias="gpt4o",     priority=80),
        build_provider_model("openai", "gpt-4o-mini",cap_mini, _BUILTIN_CREATED_AT, alias="gpt4o-mini", priority=65),
    ]
    return provider, models


def _make_anthropic_provider_and_models() -> Tuple[ProviderDefinition, List[ProviderModel]]:
    """Build deterministic Anthropic provider + models."""
    provider = build_provider_definition(
        provider_name    = "anthropic",
        display_name     = "Anthropic",
        api_version      = "2023-06-01",
        endpoint         = "https://api.anthropic.com/v1/messages",
        supported_models = ["claude-sonnet-4", "claude-opus-4"],
        default_model    = "claude-sonnet-4",
        created_at       = _BUILTIN_CREATED_AT,
    )

    cap_sonnet = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True, embeddings=False, max_context_tokens=200000, max_output_tokens=64000)
    cap_opus   = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True, embeddings=False, max_context_tokens=200000, max_output_tokens=32000)

    models = [
        build_provider_model("anthropic", "claude-sonnet-4", cap_sonnet, _BUILTIN_CREATED_AT, alias="sonnet-4", priority=85),
        build_provider_model("anthropic", "claude-opus-4",   cap_opus,   _BUILTIN_CREATED_AT, alias="opus-4",   priority=75),
    ]
    return provider, models


def _make_google_provider_and_models() -> Tuple[ProviderDefinition, List[ProviderModel]]:
    """Build deterministic Google provider + models."""
    provider = build_provider_definition(
        provider_name    = "google",
        display_name     = "Google",
        api_version      = "v1",
        endpoint         = "https://generativelanguage.googleapis.com/v1beta/models",
        supported_models = ["gemini-2.5-pro", "gemini-2.5-flash"],
        default_model    = "gemini-2.5-pro",
        created_at       = _BUILTIN_CREATED_AT,
    )

    cap_pro   = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True, embeddings=True,  max_context_tokens=1048576, max_output_tokens=65536)
    cap_flash = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True, embeddings=False, max_context_tokens=1048576, max_output_tokens=65536)

    models = [
        build_provider_model("google", "gemini-2.5-pro",   cap_pro,   _BUILTIN_CREATED_AT, alias="gemini-pro",   priority=80),
        build_provider_model("google", "gemini-2.5-flash", cap_flash, _BUILTIN_CREATED_AT, alias="gemini-flash", priority=70),
    ]
    return provider, models


def _make_ollama_provider_and_models() -> Tuple[ProviderDefinition, List[ProviderModel]]:
    """Build deterministic Ollama provider + models."""
    provider = build_provider_definition(
        provider_name    = "ollama",
        display_name     = "Ollama",
        api_version      = "0.1.0",
        endpoint         = "http://localhost:11434/api/chat",
        supported_models = ["llama3.1", "mistral", "qwen2.5"],
        default_model    = "llama3.1",
        created_at       = _BUILTIN_CREATED_AT,
    )

    cap_local = build_provider_capability(streaming=True, tool_calling=False, json_mode=True, vision=False, embeddings=False, max_context_tokens=8192, max_output_tokens=4096)

    models = [
        build_provider_model("ollama", "llama3.1", cap_local, _BUILTIN_CREATED_AT, alias="llama3",   priority=40),
        build_provider_model("ollama", "mistral",  cap_local, _BUILTIN_CREATED_AT, alias="mistral7b", priority=35),
        build_provider_model("ollama", "qwen2.5",  cap_local, _BUILTIN_CREATED_AT, alias="qwen",      priority=30),
    ]
    return provider, models


def _make_azure_provider_and_models() -> Tuple[ProviderDefinition, List[ProviderModel]]:
    """Build deterministic Azure OpenAI provider + models."""
    provider = build_provider_definition(
        provider_name    = "azure",
        display_name     = "Azure OpenAI",
        api_version      = "2024-10-01",
        endpoint         = "https://{resource}.openai.azure.com/openai/deployments",
        supported_models = ["azure/gpt-4o", "azure/gpt-4.1"],
        default_model    = "azure/gpt-4o",
        created_at       = _BUILTIN_CREATED_AT,
    )

    cap_az4o  = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True, embeddings=False, max_context_tokens=128000, max_output_tokens=16384)
    cap_az41  = build_provider_capability(streaming=True, tool_calling=True, json_mode=True, vision=True, embeddings=False, max_context_tokens=1047576, max_output_tokens=32768)

    models = [
        build_provider_model("azure", "azure/gpt-4o",  cap_az4o, _BUILTIN_CREATED_AT, alias="az-gpt4o",  priority=75),
        build_provider_model("azure", "azure/gpt-4.1", cap_az41, _BUILTIN_CREATED_AT, alias="az-gpt41",  priority=80),
    ]
    return provider, models


# ===========================================================================
# Default registry singleton + bootstrap
# ===========================================================================

def _build_default_registry() -> ProviderRegistry:
    """
    Build and return a fully populated default ProviderRegistry with all
    built-in providers and models registered deterministically.

    This is the canonical factory — always returns a fresh registry with the
    same deterministic contents (same IDs, same ordering).
    """
    reg = ProviderRegistry()

    builders = [
        _make_groq_provider_and_models,
        _make_openai_provider_and_models,
        _make_anthropic_provider_and_models,
        _make_google_provider_and_models,
        _make_ollama_provider_and_models,
        _make_azure_provider_and_models,
    ]

    for builder in builders:
        provider, models = builder()
        reg.register_provider(provider)
        for mdl in models:
            reg.register_model(mdl)

    return reg


# Module-level default registry
_default_registry: Optional[ProviderRegistry] = None


def get_default_registry() -> ProviderRegistry:
    """
    Return the module-level default registry, initialising it on first call.

    The default registry is populated with all built-in providers/models.
    Callers may obtain a fresh copy with build_default_registry() if they
    need an isolated instance.

    Returns
    -------
    ProviderRegistry — shared default instance.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = _build_default_registry()
    return _default_registry


def build_default_registry() -> ProviderRegistry:
    """
    Build and return a fresh, isolated ProviderRegistry with all built-in
    providers and models.

    Unlike get_default_registry(), this always creates a new instance —
    useful for tests and isolated contexts.

    Returns
    -------
    ProviderRegistry — new isolated instance.
    """
    return _build_default_registry()


def reset_default_registry() -> None:
    """
    Reset the module-level default registry to None so it will be
    re-initialised on the next get_default_registry() call.

    Useful for test isolation.
    """
    global _default_registry
    _default_registry = None


# ===========================================================================
# Integration helpers — connect with existing phase services
# ===========================================================================

def get_groq_provider(registry: Optional[ProviderRegistry] = None) -> Optional[ProviderDefinition]:
    """
    Return the Groq ProviderDefinition from the registry, or None.

    Integrates with groq_provider_service.py, groq_http_client.py, and
    groq_streaming_service.py by providing the canonical provider metadata.

    Parameters
    ----------
    registry : ProviderRegistry (defaults to global default registry).

    Returns
    -------
    ProviderDefinition or None.
    """
    reg = registry or get_default_registry()
    return reg.find_provider("groq")


def get_groq_model(
    model_name: str,
    registry  : Optional[ProviderRegistry] = None,
) -> Optional[ProviderModel]:
    """
    Return a Groq ProviderModel by name, or None.

    Parameters
    ----------
    model_name : canonical model name (e.g. "llama-3.3-70b-versatile").
    registry   : ProviderRegistry (defaults to global default registry).

    Returns
    -------
    ProviderModel or None.
    """
    reg = registry or get_default_registry()
    return reg.find_model("groq", model_name)


def get_registry_summary(
    registry  : Optional[ProviderRegistry] = None,
    created_at: str = "1970-01-01T00:00:00Z",
) -> ProviderRegistryResult:
    """
    Build a complete ProviderRegistryResult snapshot from the registry.

    Integrates with copilot_orchestrator_service.py and
    tool_calling_service.py by providing full registry state.

    Parameters
    ----------
    registry   : ProviderRegistry (defaults to global default registry).
    created_at : ISO-8601 timestamp for the metadata record.

    Returns
    -------
    ProviderRegistryResult (frozen / immutable).
    """
    reg       = registry or get_default_registry()
    providers = reg.list_providers()
    models    = reg.list_models()
    metadata  = build_registry_metadata(providers, models)
    return build_registry_result(providers, models, None, metadata)
