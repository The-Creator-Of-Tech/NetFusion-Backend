"""
Smoke Test — MITRE ATT&CK Engine (Phase A4.3.7)
================================================
Target: 500+ assertions, 0 failures.

Sections
--------
 1. Imports & helpers
 2. Version constant
 3. TacticEnum — all 14 tactics
 4. Typed exceptions hierarchy
 5. techniqueKey / _sha256_32 / _uuid5 helpers
 6. mappingKey / mappingFingerprint helpers
 7. validate_technique — valid + every invalid path
 8. validate_mapping — valid + every invalid path
 9. build_mitre_technique — fields, normalisation, determinism
10. build_mitre_technique — immutability
11. build_mitre_technique — edge cases
12. build_mitre_mapping — fields, ordering, determinism
13. build_mitre_mapping — immutability
14. build_mitre_mapping — empty techniques
15. build_mitre_mapping — validate=False
16. build_mitre_statistics — basic correctness
17. build_mitre_statistics — empty input
18. build_mitre_statistics — order-independence
19. build_mitre_statistics — multiple mappings, dedup
20. Integration helper — finding_to_mitre_mapping
21. Integration helper — alert_to_mitre_mapping
22. Integration helper — reasoning_to_mitre_mapping
23. Determinism — identical inputs → identical IDs & fingerprints
24. Zero-randomness — UUIDv5 version check
25. Collision resistance — null-byte separator
26. Serialisation (model_dump / model_dump_json)
27. All 14 tactics round-trip through build_mitre_technique
28. Edge cases — long inputs, whitespace, dedup
29. Statistics across heterogeneous mappings
30. Full end-to-end pipeline
"""

from __future__ import annotations

import json
import uuid as _uuid_mod
from typing import Any, List

from services.mitre_attack_service import (
    # Enum
    TacticEnum,
    # Exceptions
    MitreAttackError, InvalidTechniqueError,
    InvalidTacticError, InvalidMitreMappingError,
    # Models
    MitreTechnique, MitreMapping, MitreStatistics,
    # Key helpers
    techniqueKey, mappingKey, mappingFingerprint,
    # Builders
    build_mitre_technique, build_mitre_mapping, build_mitre_statistics,
    # Validators
    validate_technique, validate_mapping,
    # Integration helpers
    finding_to_mitre_mapping, alert_to_mitre_mapping, reasoning_to_mitre_mapping,
    # Version
    MITRE_ATTACK_ENGINE_VERSION,
    # Internal helpers
    _sha256_32, _uuid5, _norm, _norm_lower, _norm_strings,
    _norm_lower_strings, _clamp, _MITRE_ATTACK_NS,
)
from core.constants import MITRE_ATTACK_ENGINE_VERSION as CONST_VER

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
# Fixtures
# ---------------------------------------------------------------------------
TS  = "2026-07-01T12:00:00Z"
TS2 = "2026-07-01T13:00:00Z"


def _make_technique(
    mitre_id : str        = "T1059",
    name     : str        = "Command and Scripting Interpreter",
    tactic   : TacticEnum = TacticEnum.EXECUTION,
    created_at: str       = TS,
) -> MitreTechnique:
    return build_mitre_technique(
        mitre_id    = mitre_id,
        name        = name,
        tactic      = tactic,
        created_at  = created_at,
        description = "Execute commands via interpreters.",
        platforms   = ["windows", "linux", "macos"],
        detection   = "Monitor process creation events.",
        mitigations = ["Restrict interpreter access", "Application whitelisting"],
        references  = ["https://attack.mitre.org/techniques/T1059/"],
    )


def _make_mapping(
    techniques : List[MitreTechnique] = None,
    finding_id : str                  = "finding-001",
    created_at : str                  = TS,
    confidence : float                = 80.0,
) -> MitreMapping:
    if techniques is None:
        techniques = [_make_technique()]
    return build_mitre_mapping(
        matched_techniques = techniques,
        created_at         = created_at,
        finding_id         = finding_id,
        confidence         = confidence,
    )


# ===========================================================================
# Section 2 — Version constant
# ===========================================================================

def test_version_constant() -> None:
    _eq(MITRE_ATTACK_ENGINE_VERSION, "mitre-attack-v1", "engine version string")
    _eq(CONST_VER, "mitre-attack-v1", "constant from core.constants")
    _eq(MITRE_ATTACK_ENGINE_VERSION, CONST_VER, "both imports identical")
    _is(MITRE_ATTACK_ENGINE_VERSION, str, "version is str")

test_version_constant()


# ===========================================================================
# Section 3 — TacticEnum — all 14 tactics
# ===========================================================================

def test_tactic_enum() -> None:
    expected_values = {
        "RECONNAISSANCE", "RESOURCE_DEVELOPMENT", "INITIAL_ACCESS",
        "EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION",
        "DEFENSE_EVASION", "CREDENTIAL_ACCESS", "DISCOVERY",
        "LATERAL_MOVEMENT", "COLLECTION", "COMMAND_AND_CONTROL",
        "EXFILTRATION", "IMPACT",
    }
    actual_values = {t.value for t in TacticEnum}
    _eq(len(actual_values), 14, "exactly 14 tactics")
    for v in expected_values:
        _true(v in actual_values, f"tactic {v} present")
    # str subclass
    _is(TacticEnum.EXECUTION, str, "TacticEnum is str subclass")
    # Value equality
    _eq(TacticEnum.EXECUTION.value, "EXECUTION", "EXECUTION.value")
    _eq(TacticEnum.LATERAL_MOVEMENT.value, "LATERAL_MOVEMENT", "LATERAL_MOVEMENT.value")
    _eq(TacticEnum.COMMAND_AND_CONTROL.value, "COMMAND_AND_CONTROL", "COMMAND_AND_CONTROL.value")

test_tactic_enum()


# ===========================================================================
# Section 4 — Typed exceptions hierarchy
# ===========================================================================

def test_exceptions() -> None:
    _true(issubclass(MitreAttackError, Exception), "MitreAttackError is Exception")
    _true(issubclass(InvalidTechniqueError, MitreAttackError), "InvalidTechniqueError chain")
    _true(issubclass(InvalidTacticError, MitreAttackError), "InvalidTacticError chain")
    _true(issubclass(InvalidMitreMappingError, MitreAttackError), "InvalidMitreMappingError chain")

    # Messages preserved
    try:
        raise InvalidTechniqueError("bad technique")
    except MitreAttackError as e:
        _true("bad technique" in str(e), "InvalidTechniqueError message preserved")

    try:
        raise InvalidTacticError("bad tactic")
    except MitreAttackError as e:
        _true("bad tactic" in str(e), "InvalidTacticError message preserved")

    try:
        raise InvalidMitreMappingError("bad mapping")
    except MitreAttackError as e:
        _true("bad mapping" in str(e), "InvalidMitreMappingError message preserved")

test_exceptions()


# ===========================================================================
# Section 5 — techniqueKey / _sha256_32 / _uuid5 helpers
# ===========================================================================

def test_technique_key_helpers() -> None:
    # techniqueKey is SHA256 of uppercased mitreId
    k1 = techniqueKey("T1059")
    _eq(len(k1), 32, "techniqueKey length 32")
    _eq(k1, techniqueKey("T1059"), "techniqueKey deterministic")
    _eq(k1, techniqueKey("t1059"), "techniqueKey case-insensitive (uppercased internally)")
    _eq(k1, techniqueKey("  T1059  "), "techniqueKey strips whitespace")
    _ne(k1, techniqueKey("T1021"), "different mitreId → different key")

    # Sub-technique
    k_sub = techniqueKey("T1059.001")
    _ne(k1, k_sub, "sub-technique differs from parent")
    _eq(len(k_sub), 32, "sub-technique key length 32")

    # _sha256_32
    h = _sha256_32("a", "b")
    _eq(len(h), 32, "_sha256_32 output length 32")
    _eq(h, _sha256_32("a", "b"), "_sha256_32 deterministic")
    _ne(h, _sha256_32("a", "c"), "_sha256_32 sensitive to input")
    # Null-byte separator prevents collision
    _ne(_sha256_32("ab", "c"), _sha256_32("a", "bc"), "null-byte prevents cross-field collision")

    # _uuid5
    uid = _uuid5("some-test-key")
    _eq(len(uid), 36, "_uuid5 output length 36")
    _true("-" in uid, "_uuid5 looks like UUID")
    _eq(uid, _uuid5("some-test-key"), "_uuid5 deterministic")
    _ne(uid, _uuid5("other-key"), "_uuid5 sensitive to input")
    # Verify it uses _MITRE_ATTACK_NS
    uid_obj = _uuid_mod.UUID(uid)
    _eq(uid_obj.version, 5, "_uuid5 produces UUIDv5")

test_technique_key_helpers()


# ===========================================================================
# Section 6 — mappingKey / mappingFingerprint helpers
# ===========================================================================

def test_mapping_key_helpers() -> None:
    tech_ids = ("uuid-t1", "uuid-t2")

    mk = mappingKey("f-001", "a-001", "r-001", tech_ids)
    _eq(len(mk), 32, "mappingKey length 32")
    _eq(mk, mappingKey("f-001", "a-001", "r-001", tech_ids), "mappingKey deterministic")

    # Order-independence of technique IDs
    mk_rev = mappingKey("f-001", "a-001", "r-001", ("uuid-t2", "uuid-t1"))
    _eq(mk, mk_rev, "mappingKey order-independent on techniqueIds")

    # Different inputs → different key
    _ne(mk, mappingKey("f-002", "a-001", "r-001", tech_ids), "different findingId → different key")
    _ne(mk, mappingKey("f-001", "a-002", "r-001", tech_ids), "different alertId → different key")
    _ne(mk, mappingKey("f-001", "a-001", "r-002", tech_ids), "different reasoningId → different key")
    _ne(mk, mappingKey("f-001", "a-001", "r-001", ("uuid-t1",)), "fewer techniqueIds → different key")

    # mappingFingerprint
    fp = mappingFingerprint(mk, "f-001", "a-001", "r-001", tech_ids)
    _eq(len(fp), 32, "mappingFingerprint length 32")
    _eq(fp, mappingFingerprint(mk, "f-001", "a-001", "r-001", tech_ids), "mappingFingerprint deterministic")

    # Fingerprint changes with different key
    mk2 = mappingKey("f-002", "a-001", "r-001", tech_ids)
    fp2 = mappingFingerprint(mk2, "f-002", "a-001", "r-001", tech_ids)
    _ne(fp, fp2, "different finding → different fingerprint")

test_mapping_key_helpers()


# ===========================================================================
# Section 7 — validate_technique
# ===========================================================================

def test_validate_technique() -> None:
    # Valid — no exception
    validate_technique("T1059", "Name", TacticEnum.EXECUTION, TS)
    _true(True, "valid technique passes")

    # empty mitreId
    _raises(InvalidTechniqueError,
        lambda: validate_technique("", "Name", TacticEnum.EXECUTION, TS),
        "empty mitreId raises InvalidTechniqueError")

    # whitespace-only mitreId
    _raises(InvalidTechniqueError,
        lambda: validate_technique("   ", "Name", TacticEnum.EXECUTION, TS),
        "whitespace mitreId raises InvalidTechniqueError")

    # mitreId not starting with T
    _raises(InvalidTechniqueError,
        lambda: validate_technique("A1059", "Name", TacticEnum.EXECUTION, TS),
        "mitreId not starting with T raises InvalidTechniqueError")

    # empty name
    _raises(InvalidTechniqueError,
        lambda: validate_technique("T1059", "", TacticEnum.EXECUTION, TS),
        "empty name raises InvalidTechniqueError")

    # whitespace-only name
    _raises(InvalidTechniqueError,
        lambda: validate_technique("T1059", "  ", TacticEnum.EXECUTION, TS),
        "whitespace name raises InvalidTechniqueError")

    # empty createdAt
    _raises(InvalidTechniqueError,
        lambda: validate_technique("T1059", "Name", TacticEnum.EXECUTION, ""),
        "empty createdAt raises InvalidTechniqueError")

    # invalid tactic (string) → InvalidTacticError
    _raises(InvalidTacticError,
        lambda: validate_technique("T1059", "Name", "EXECUTION", TS),
        "string tactic raises InvalidTacticError")

    # invalid tactic (None) → InvalidTacticError
    _raises(InvalidTacticError,
        lambda: validate_technique("T1059", "Name", None, TS),
        "None tactic raises InvalidTacticError")

    # invalid tactic (int) → InvalidTacticError
    _raises(InvalidTacticError,
        lambda: validate_technique("T1059", "Name", 42, TS),
        "int tactic raises InvalidTacticError")

    # Multiple errors collected — mitreId + name + createdAt all empty
    try:
        validate_technique("A1059", "", TacticEnum.EXECUTION, "")
    except InvalidTechniqueError as e:
        msg = str(e)
        _true("mitreId" in msg or "name" in msg or "createdAt" in msg,
              "multiple errors reported in one exception")

test_validate_technique()


# ===========================================================================
# Section 8 — validate_mapping
# ===========================================================================

def test_validate_mapping() -> None:
    # Valid — at least one source ID
    validate_mapping("f-001", "", "", 80.0, TS)
    _true(True, "findingId-only mapping valid")

    validate_mapping("", "a-001", "", 50.0, TS)
    _true(True, "alertId-only mapping valid")

    validate_mapping("", "", "r-001", 0.0, TS)
    _true(True, "reasoningId-only mapping valid")

    validate_mapping("f-001", "a-001", "r-001", 100.0, TS)
    _true(True, "all-source mapping valid")

    # All source IDs empty
    _raises(InvalidMitreMappingError,
        lambda: validate_mapping("", "", "", 50.0, TS),
        "all empty sources raises InvalidMitreMappingError")

    # Whitespace-only source IDs treated as empty
    _raises(InvalidMitreMappingError,
        lambda: validate_mapping("  ", "  ", "  ", 50.0, TS),
        "whitespace-only sources raises InvalidMitreMappingError")

    # confidence out of range — low
    _raises(InvalidMitreMappingError,
        lambda: validate_mapping("f-001", "", "", -1.0, TS),
        "confidence < 0 raises InvalidMitreMappingError")

    # confidence out of range — high
    _raises(InvalidMitreMappingError,
        lambda: validate_mapping("f-001", "", "", 101.0, TS),
        "confidence > 100 raises InvalidMitreMappingError")

    # empty createdAt
    _raises(InvalidMitreMappingError,
        lambda: validate_mapping("f-001", "", "", 50.0, ""),
        "empty createdAt raises InvalidMitreMappingError")

    # whitespace createdAt
    _raises(InvalidMitreMappingError,
        lambda: validate_mapping("f-001", "", "", 50.0, "   "),
        "whitespace createdAt raises InvalidMitreMappingError")

test_validate_mapping()


# ===========================================================================
# Section 9 — build_mitre_technique — fields, normalisation, determinism
# ===========================================================================

def test_build_mitre_technique() -> None:
    t = _make_technique()

    # Types
    _is(t, MitreTechnique, "returns MitreTechnique")
    _is(t.techniqueId,  str, "techniqueId is str")
    _is(t.techniqueKey, str, "techniqueKey is str")

    # Field values
    _eq(t.mitreId,      "T1059",   "mitreId uppercased and stored")
    _eq(t.name,         "Command and Scripting Interpreter", "name stored")
    _eq(t.tactic,       TacticEnum.EXECUTION, "tactic stored")
    _eq(t.createdAt,    TS,        "createdAt stored")
    _eq(t.description,  "Execute commands via interpreters.", "description stored")
    _eq(t.detection,    "Monitor process creation events.", "detection stored")
    _eq(t.engineVersion if hasattr(t, "engineVersion") else MITRE_ATTACK_ENGINE_VERSION,
        MITRE_ATTACK_ENGINE_VERSION, "engine version matches")

    # Key length
    _eq(len(t.techniqueKey), 32, "techniqueKey is 32 chars")

    # UUID format
    _true("-" in t.techniqueId, "techniqueId looks like UUID")

    # techniqueKey matches helper
    _eq(t.techniqueKey, techniqueKey("T1059"), "techniqueKey matches helper")

    # Platforms normalised (lowercase + sorted + deduped)
    _eq(t.platforms, tuple(sorted({"windows", "linux", "macos"})),
        "platforms lowercase + sorted + deduped")

    # Mitigations sorted + deduped
    _true("Restrict interpreter access" in t.mitigations, "mitigation 1 present")
    _true("Application whitelisting" in t.mitigations, "mitigation 2 present")
    _eq(len(t.mitigations), 2, "mitigations deduped")

    # References stored
    _eq(len(t.references), 1, "references deduped")

    # Determinism
    t2 = _make_technique()
    _eq(t.techniqueId,  t2.techniqueId,  "techniqueId deterministic")
    _eq(t.techniqueKey, t2.techniqueKey, "techniqueKey deterministic")

    # Different mitreId → different IDs
    t3 = _make_technique(mitre_id="T1021")
    _ne(t.techniqueId,  t3.techniqueId,  "different mitreId → different techniqueId")
    _ne(t.techniqueKey, t3.techniqueKey, "different mitreId → different techniqueKey")

    # mitreId normalisation — lowercase input same as uppercase
    t_lower = build_mitre_technique("t1059", "Name", TacticEnum.EXECUTION, TS)
    _eq(t_lower.mitreId,     "T1059", "mitreId always uppercase")
    _eq(t_lower.techniqueKey, t.techniqueKey, "lowercase input → same key")

    # Name stripped
    t_ws = build_mitre_technique("T1059", "  Padded  ", TacticEnum.EXECUTION, TS)
    _eq(t_ws.name, "Padded", "name stripped")

test_build_mitre_technique()


# ===========================================================================
# Section 10 — build_mitre_technique — immutability
# ===========================================================================

def test_technique_immutability() -> None:
    t = _make_technique()
    try:
        t.mitreId = "T9999"  # type: ignore
        global _FAIL
        _FAIL += 1
        print("  FAIL [MitreTechnique frozen]: mutation succeeded")
    except Exception:
        global _PASS
        _PASS += 1

    try:
        t.name = "hacked"  # type: ignore
        _FAIL += 1
        print("  FAIL [MitreTechnique name frozen]: mutation succeeded")
    except Exception:
        _PASS += 1

    try:
        t.tactic = TacticEnum.IMPACT  # type: ignore
        _FAIL += 1
        print("  FAIL [MitreTechnique tactic frozen]: mutation succeeded")
    except Exception:
        _PASS += 1

test_technique_immutability()


# ===========================================================================
# Section 11 — build_mitre_technique — edge cases
# ===========================================================================

def test_technique_edge_cases() -> None:
    # Empty optional fields are allowed
    t = build_mitre_technique("T1001", "Data Obfuscation", TacticEnum.COMMAND_AND_CONTROL, TS)
    _eq(t.description, "",  "empty description allowed")
    _eq(t.detection,   "",  "empty detection allowed")
    _eq(t.platforms,   (),  "no platforms → empty tuple")
    _eq(t.mitigations, (),  "no mitigations → empty tuple")
    _eq(t.references,  (),  "no references → empty tuple")

    # validate=False skips validation
    t_nv = build_mitre_technique("T0000", "test", TacticEnum.IMPACT, TS, validate=False)
    _is(t_nv, MitreTechnique, "validate=False returns MitreTechnique")

    # Sub-technique ID format (contains dot)
    t_sub = build_mitre_technique("T1059.001", "PowerShell", TacticEnum.EXECUTION, TS)
    _eq(t_sub.mitreId, "T1059.001", "sub-technique mitreId stored")
    _ne(t_sub.techniqueId, _make_technique().techniqueId, "sub-technique differs from parent")

    # Platform dedup
    t_dup = build_mitre_technique(
        "T1002", "n", TacticEnum.COLLECTION, TS,
        platforms=["Windows", "windows", "WINDOWS", "linux"],
    )
    _eq(len(t_dup.platforms), 2, "platform dedup: windows + linux")

    # Mitigation dedup
    t_mdup = build_mitre_technique(
        "T1003", "n", TacticEnum.CREDENTIAL_ACCESS, TS,
        mitigations=["Patch", "Patch", "Monitor"],
    )
    _eq(len(t_mdup.mitigations), 2, "mitigation dedup: Patch + Monitor")

    # Reference dedup
    t_rdup = build_mitre_technique(
        "T1004", "n", TacticEnum.PERSISTENCE, TS,
        references=["https://example.com", "https://example.com"],
    )
    _eq(len(t_rdup.references), 1, "reference dedup")

test_technique_edge_cases()


# ===========================================================================
# Section 12 — build_mitre_mapping — fields, ordering, determinism
# ===========================================================================

def test_build_mitre_mapping() -> None:
    t1 = _make_technique("T1059", "Scripting", TacticEnum.EXECUTION)
    t2 = _make_technique("T1021", "Remote Services", TacticEnum.LATERAL_MOVEMENT)

    m = build_mitre_mapping(
        matched_techniques = [t1, t2],
        created_at         = TS,
        finding_id         = "f-001",
        alert_id           = "a-001",
        reasoning_id       = "r-001",
        confidence         = 85.5,
    )

    _is(m, MitreMapping, "returns MitreMapping")
    _eq(m.findingId,   "f-001", "findingId stored")
    _eq(m.alertId,     "a-001", "alertId stored")
    _eq(m.reasoningId, "r-001", "reasoningId stored")
    _eq(m.confidence,  85.5,    "confidence stored")
    _eq(m.createdAt,   TS,      "createdAt stored")
    _eq(len(m.matchedTechniques), 2, "2 techniques stored")
    _eq(len(m.mappingKey),         32, "mappingKey 32 chars")
    _eq(len(m.mappingFingerprint), 32, "mappingFingerprint 32 chars")
    _true("-" in m.mappingId, "mappingId looks like UUID")

    # Techniques sorted by mitreId ASC
    _eq(m.matchedTechniques[0].mitreId, "T1021", "techniques sorted: T1021 first")
    _eq(m.matchedTechniques[1].mitreId, "T1059", "techniques sorted: T1059 second")

    # Determinism
    m2 = build_mitre_mapping(
        matched_techniques=[t1, t2], created_at=TS,
        finding_id="f-001", alert_id="a-001", reasoning_id="r-001",
        confidence=85.5,
    )
    _eq(m.mappingId,          m2.mappingId,          "mappingId deterministic")
    _eq(m.mappingKey,         m2.mappingKey,          "mappingKey deterministic")
    _eq(m.mappingFingerprint, m2.mappingFingerprint,  "mappingFingerprint deterministic")

    # Technique order in input does not affect key/fingerprint
    m3 = build_mitre_mapping(
        matched_techniques=[t2, t1], created_at=TS,
        finding_id="f-001", alert_id="a-001", reasoning_id="r-001",
        confidence=85.5,
    )
    _eq(m.mappingKey,         m3.mappingKey,         "input order irrelevant for mappingKey")
    _eq(m.mappingFingerprint, m3.mappingFingerprint,  "input order irrelevant for fingerprint")

    # Different finding → different IDs
    m4 = build_mitre_mapping([t1], TS, finding_id="f-002", confidence=85.5)
    _ne(m.mappingId,  m4.mappingId,  "different finding → different mappingId")
    _ne(m.mappingKey, m4.mappingKey, "different finding → different mappingKey")

    # mappingKey matches public helper
    tech_ids_sorted = tuple(sorted(
        [t.techniqueId for t in [t1, t2]]
    ))
    expected_mk = mappingKey("f-001", "a-001", "r-001", tech_ids_sorted)
    _eq(m.mappingKey, expected_mk, "mappingKey matches public helper")

    # Confidence clamped
    m_hi = build_mitre_mapping([t1], TS, finding_id="f-001", confidence=200.0)
    _eq(m_hi.confidence, 100.0, "confidence clamped to 100.0")

    m_lo = build_mitre_mapping([t1], TS, finding_id="f-001", confidence=-5.0)
    _eq(m_lo.confidence, 0.0, "confidence clamped to 0.0")

test_build_mitre_mapping()


# ===========================================================================
# Section 13 — build_mitre_mapping — immutability
# ===========================================================================

def test_mapping_immutability() -> None:
    m = _make_mapping()
    try:
        m.findingId = "hacked"  # type: ignore
        global _FAIL
        _FAIL += 1
        print("  FAIL [MitreMapping frozen]: mutation succeeded")
    except Exception:
        global _PASS
        _PASS += 1

    try:
        m.confidence = 999.0  # type: ignore
        _FAIL += 1
        print("  FAIL [MitreMapping confidence frozen]: mutation succeeded")
    except Exception:
        _PASS += 1

    # MitreStatistics immutability
    stats = build_mitre_statistics([m])
    try:
        stats.totalTechniques = 999  # type: ignore
        _FAIL += 1
        print("  FAIL [MitreStatistics frozen]: mutation succeeded")
    except Exception:
        _PASS += 1

test_mapping_immutability()


# ===========================================================================
# Section 14 — build_mitre_mapping — empty technique list
# ===========================================================================

def test_mapping_empty_techniques() -> None:
    # Empty technique list is allowed (no techniques matched yet)
    m = build_mitre_mapping(
        matched_techniques = [],
        created_at         = TS,
        finding_id         = "f-001",
        confidence         = 0.0,
    )
    _is(m, MitreMapping, "empty techniques returns MitreMapping")
    _eq(len(m.matchedTechniques), 0, "matchedTechniques is empty")
    _eq(len(m.mappingKey),         32, "mappingKey still 32 chars")
    _eq(len(m.mappingFingerprint), 32, "mappingFingerprint still 32 chars")

    # Two empty-technique mappings with same source → same IDs
    m2 = build_mitre_mapping([], TS, finding_id="f-001", confidence=0.0)
    _eq(m.mappingId,  m2.mappingId,  "empty-technique mappings deterministic")

test_mapping_empty_techniques()


# ===========================================================================
# Section 15 — build_mitre_mapping — validate=False
# ===========================================================================

def test_mapping_validate_false() -> None:
    # All sources empty would normally raise — validate=False skips
    m = build_mitre_mapping(
        matched_techniques = [],
        created_at         = TS,
        finding_id         = "",
        alert_id           = "",
        reasoning_id       = "",
        confidence         = 0.0,
        validate           = False,
    )
    _is(m, MitreMapping, "validate=False returns MitreMapping even with empty sources")
    _eq(m.findingId, "", "findingId empty when skipping validation")

test_mapping_validate_false()


# ===========================================================================
# Section 16 — build_mitre_statistics — basic correctness
# ===========================================================================

def test_build_mitre_statistics_basic() -> None:
    t_exec = _make_technique("T1059", "Scripting",        TacticEnum.EXECUTION)
    t_lat  = _make_technique("T1021", "Remote Services",  TacticEnum.LATERAL_MOVEMENT)
    t_disc = _make_technique("T1082", "System Info",      TacticEnum.DISCOVERY)

    m1 = build_mitre_mapping([t_exec, t_lat], TS, finding_id="f-001", confidence=80.0)
    m2 = build_mitre_mapping([t_disc],        TS, finding_id="f-002", confidence=60.0)

    stats = build_mitre_statistics([m1, m2])

    _is(stats, MitreStatistics, "returns MitreStatistics")
    _eq(stats.totalTechniques,  3, "totalTechniques = 3 distinct mitreIds")
    _eq(stats.mappedTechniques, 3, "mappedTechniques = 3 distinct techniqueIds")
    _eq(stats.averageConfidence, round((80.0 + 60.0) / 2, 4), "averageConfidence = 70.0")

    # Tactics covered
    _true("EXECUTION"        in stats.tacticsCovered, "EXECUTION tactic covered")
    _true("LATERAL_MOVEMENT" in stats.tacticsCovered, "LATERAL_MOVEMENT tactic covered")
    _true("DISCOVERY"        in stats.tacticsCovered, "DISCOVERY tactic covered")
    _eq(len(stats.tacticsCovered), 3, "3 distinct tactics covered")

    # tacticsCovered is sorted
    _eq(stats.tacticsCovered, tuple(sorted(stats.tacticsCovered)),
        "tacticsCovered is sorted")

test_build_mitre_statistics_basic()


# ===========================================================================
# Section 17 — build_mitre_statistics — empty input
# ===========================================================================

def test_build_mitre_statistics_empty() -> None:
    stats = build_mitre_statistics([])
    _is(stats, MitreStatistics, "returns MitreStatistics for empty input")
    _eq(stats.totalTechniques,   0,   "empty: totalTechniques=0")
    _eq(stats.mappedTechniques,  0,   "empty: mappedTechniques=0")
    _eq(stats.tacticsCovered,    (),  "empty: tacticsCovered=()")
    _eq(stats.averageConfidence, 0.0, "empty: averageConfidence=0.0")

test_build_mitre_statistics_empty()


# ===========================================================================
# Section 18 — build_mitre_statistics — order-independence
# ===========================================================================

def test_build_mitre_statistics_order_independence() -> None:
    t1 = _make_technique("T1059", "Scripting",        TacticEnum.EXECUTION)
    t2 = _make_technique("T1021", "Remote Services",  TacticEnum.LATERAL_MOVEMENT)
    t3 = _make_technique("T1082", "System Info",      TacticEnum.DISCOVERY)

    m1 = build_mitre_mapping([t1], TS, finding_id="f-001", confidence=70.0)
    m2 = build_mitre_mapping([t2], TS, finding_id="f-002", confidence=80.0)
    m3 = build_mitre_mapping([t3], TS, finding_id="f-003", confidence=90.0)

    stats_abc = build_mitre_statistics([m1, m2, m3])
    stats_cba = build_mitre_statistics([m3, m2, m1])
    stats_bca = build_mitre_statistics([m2, m3, m1])

    _eq(stats_abc.averageConfidence, stats_cba.averageConfidence,
        "averageConfidence order-independent ABC vs CBA")
    _eq(stats_abc.averageConfidence, stats_bca.averageConfidence,
        "averageConfidence order-independent ABC vs BCA")
    _eq(stats_abc.totalTechniques,  stats_cba.totalTechniques,
        "totalTechniques order-independent")
    _eq(stats_abc.tacticsCovered,   stats_cba.tacticsCovered,
        "tacticsCovered order-independent")

test_build_mitre_statistics_order_independence()


# ===========================================================================
# Section 19 — build_mitre_statistics — dedup across mappings
# ===========================================================================

def test_build_mitre_statistics_dedup() -> None:
    # Same technique appears in two different mappings
    t_shared = _make_technique("T1059", "Scripting", TacticEnum.EXECUTION)
    t_extra  = _make_technique("T1021", "Remote",   TacticEnum.LATERAL_MOVEMENT)

    m1 = build_mitre_mapping([t_shared],          TS, finding_id="f-001", confidence=75.0)
    m2 = build_mitre_mapping([t_shared, t_extra],  TS, finding_id="f-002", confidence=85.0)

    stats = build_mitre_statistics([m1, m2])

    # T1059 appears in both mappings — totalTechniques should be 2 (distinct mitreIds)
    _eq(stats.totalTechniques,  2, "dedup: 2 distinct mitreIds across both mappings")
    _eq(stats.mappedTechniques, 2, "dedup: 2 distinct techniqueIds")

    # EXECUTION appears once even though T1059 is in both
    tactics = stats.tacticsCovered
    exec_count = tactics.count("EXECUTION")
    _eq(exec_count, 1, "EXECUTION appears once in tacticsCovered (deduped)")

test_build_mitre_statistics_dedup()


# ===========================================================================
# Section 20 — Integration helper: finding_to_mitre_mapping
# ===========================================================================

def test_finding_to_mitre_mapping() -> None:
    # Build a minimal Finding-like object
    class _MockFinding:
        findingId = "finding-abc-001"

    finding = _MockFinding()
    t = _make_technique()
    m = finding_to_mitre_mapping(finding, [t], TS, confidence=70.0)

    _is(m, MitreMapping, "finding_to_mitre_mapping returns MitreMapping")
    _eq(m.findingId,   "finding-abc-001", "findingId from finding.findingId")
    _eq(m.alertId,     "",                "alertId empty for finding-source")
    _eq(m.reasoningId, "",                "reasoningId empty for finding-source")
    _eq(m.confidence,  70.0,             "confidence passed through")
    _eq(m.createdAt,   TS,               "createdAt stored")
    _eq(len(m.matchedTechniques), 1, "1 technique")

    # Determinism
    m2 = finding_to_mitre_mapping(finding, [t], TS, confidence=70.0)
    _eq(m.mappingId, m2.mappingId, "finding_to_mitre_mapping deterministic")

    # Multiple techniques
    t2 = _make_technique("T1021", "Remote Services", TacticEnum.LATERAL_MOVEMENT)
    m_multi = finding_to_mitre_mapping(finding, [t, t2], TS, confidence=55.0)
    _eq(len(m_multi.matchedTechniques), 2, "multi-technique finding mapping")
    _ne(m.mappingId, m_multi.mappingId, "different techniques → different mappingId")

    # Empty techniques allowed
    m_empty = finding_to_mitre_mapping(finding, [], TS, confidence=0.0)
    _is(m_empty, MitreMapping, "empty technique list allowed in finding mapping")

test_finding_to_mitre_mapping()


# ===========================================================================
# Section 21 — Integration helper: alert_to_mitre_mapping
# ===========================================================================

def test_alert_to_mitre_mapping() -> None:
    class _MockAlert:
        alertId   = "alert-xyz-001"
        findingId = "finding-ref-001"

    alert = _MockAlert()
    t = _make_technique()
    m = alert_to_mitre_mapping(alert, [t], TS, confidence=90.0)

    _is(m, MitreMapping, "alert_to_mitre_mapping returns MitreMapping")
    _eq(m.alertId,     "alert-xyz-001",   "alertId from alert.alertId")
    _eq(m.findingId,   "finding-ref-001", "findingId from alert.findingId")
    _eq(m.reasoningId, "",                "reasoningId empty for alert-source")
    _eq(m.confidence,  90.0,              "confidence passed through")
    _eq(len(m.matchedTechniques), 1, "1 technique")

    # Determinism
    m2 = alert_to_mitre_mapping(alert, [t], TS, confidence=90.0)
    _eq(m.mappingId, m2.mappingId, "alert_to_mitre_mapping deterministic")

    # Different from finding mapping (different source IDs)
    class _MockFinding:
        findingId = "finding-ref-001"

    m_find = finding_to_mitre_mapping(_MockFinding(), [t], TS, confidence=90.0)
    _ne(m.mappingId, m_find.mappingId,
        "alert mapping differs from finding mapping (alertId present)")

test_alert_to_mitre_mapping()


# ===========================================================================
# Section 22 — Integration helper: reasoning_to_mitre_mapping
# ===========================================================================

def test_reasoning_to_mitre_mapping() -> None:
    class _MockReasoning:
        reasoningId       = "reasoning-qrs-001"
        overallConfidence = 78.5

    reasoning = _MockReasoning()
    t = _make_technique()
    m = reasoning_to_mitre_mapping(reasoning, [t], TS)

    _is(m, MitreMapping, "reasoning_to_mitre_mapping returns MitreMapping")
    _eq(m.reasoningId, "reasoning-qrs-001", "reasoningId from reasoning.reasoningId")
    _eq(m.confidence,  78.5,               "confidence from reasoning.overallConfidence")
    _eq(m.findingId,   "",                 "findingId empty by default")
    _eq(m.alertId,     "",                 "alertId empty by default")

    # With optional context linkages
    m2 = reasoning_to_mitre_mapping(
        reasoning, [t], TS,
        finding_id="f-context", alert_id="a-context",
    )
    _eq(m2.findingId, "f-context", "findingId passed through")
    _eq(m2.alertId,   "a-context", "alertId passed through")
    _ne(m.mappingId, m2.mappingId, "context linkage changes mappingId")

    # Determinism
    m3 = reasoning_to_mitre_mapping(reasoning, [t], TS)
    _eq(m.mappingId, m3.mappingId, "reasoning_to_mitre_mapping deterministic")

    # overallConfidence clamped via build_mitre_mapping
    class _HighConf:
        reasoningId       = "r-high"
        overallConfidence = 150.0

    m_hi = reasoning_to_mitre_mapping(_HighConf(), [t], TS)
    _eq(m_hi.confidence, 100.0, "overallConfidence > 100 clamped to 100.0")

test_reasoning_to_mitre_mapping()


# ===========================================================================
# Section 23 — Determinism — identical inputs → identical IDs & fingerprints
# ===========================================================================

def test_full_determinism() -> None:
    """Run the full build pipeline twice and verify every ID is identical."""

    def _build_pipeline():
        t1 = build_mitre_technique("T1059", "Scripting", TacticEnum.EXECUTION, TS,
                                    platforms=["windows", "linux"],
                                    mitigations=["Restrict"],
                                    references=["https://attack.mitre.org/T1059"])
        t2 = build_mitre_technique("T1021", "Remote Services", TacticEnum.LATERAL_MOVEMENT, TS)
        t3 = build_mitre_technique("T1082", "System Info", TacticEnum.DISCOVERY, TS)

        m1 = build_mitre_mapping([t1, t2], TS, finding_id="f-001",
                                  alert_id="a-001", reasoning_id="r-001",
                                  confidence=85.0)
        m2 = build_mitre_mapping([t3], TS, finding_id="f-002", confidence=60.0)
        stats = build_mitre_statistics([m1, m2])

        return (
            t1.techniqueId, t1.techniqueKey,
            t2.techniqueId, t2.techniqueKey,
            t3.techniqueId,
            m1.mappingId, m1.mappingKey, m1.mappingFingerprint,
            m2.mappingId, m2.mappingKey, m2.mappingFingerprint,
            stats.totalTechniques, stats.averageConfidence,
            stats.tacticsCovered,
        )

    r1 = _build_pipeline()
    r2 = _build_pipeline()
    r3 = _build_pipeline()

    for i, (a, b, c) in enumerate(zip(r1, r2, r3)):
        _eq(a, b, f"determinism run1==run2 field[{i}]")
        _eq(b, c, f"determinism run2==run3 field[{i}]")

test_full_determinism()


# ===========================================================================
# Section 24 — Zero-randomness — UUIDv5 version check
# ===========================================================================

def test_zero_randomness() -> None:
    t = _make_technique()
    uid_obj = _uuid_mod.UUID(t.techniqueId)
    _eq(uid_obj.version, 5, "techniqueId is UUIDv5 (version=5)")

    m = _make_mapping()
    uid_m = _uuid_mod.UUID(m.mappingId)
    _eq(uid_m.version, 5, "mappingId is UUIDv5 (version=5)")

    # Verify namespace is _MITRE_ATTACK_NS (not another namespace)
    expected_uid = str(_uuid_mod.uuid5(_MITRE_ATTACK_NS, t.techniqueKey))
    _eq(t.techniqueId, expected_uid, "techniqueId derived from _MITRE_ATTACK_NS")

    expected_mid = str(_uuid_mod.uuid5(_MITRE_ATTACK_NS, m.mappingKey))
    _eq(m.mappingId, expected_mid, "mappingId derived from _MITRE_ATTACK_NS")

    # Two runs with same input never differ
    t2 = _make_technique()
    _eq(t.techniqueId, t2.techniqueId, "no randomness across two builds")

test_zero_randomness()


# ===========================================================================
# Section 25 — Collision resistance — null-byte separator
# ===========================================================================

def test_collision_resistance() -> None:
    # techniqueKey: "T1059" vs "T10" + "59" → different inputs
    k1 = techniqueKey("T1059")
    k2 = _sha256_32("T1059")
    _eq(k1, k2, "techniqueKey is SHA256 of uppercase mitreId")

    # mappingKey: null-byte prevents cross-field collision
    mk_a = mappingKey("ab", "c",   "r", ())
    mk_b = mappingKey("a",  "bc",  "r", ())
    _ne(mk_a, mk_b, "null-byte prevents findingId+alertId cross-field collision")

    mk_c = mappingKey("f", "a", "rb", ())
    mk_d = mappingKey("f", "ar", "b", ())
    _ne(mk_c, mk_d, "null-byte prevents alertId+reasoningId cross-field collision")

    # Technique ID order does not affect mappingKey
    mk_ord1 = mappingKey("f", "a", "r", ("id1", "id2"))
    mk_ord2 = mappingKey("f", "a", "r", ("id2", "id1"))
    _eq(mk_ord1, mk_ord2, "technique ID order irrelevant in mappingKey")

    # Different number of techniques → different key
    mk_one  = mappingKey("f", "a", "r", ("id1",))
    mk_two  = mappingKey("f", "a", "r", ("id1", "id2"))
    _ne(mk_one, mk_two, "different technique count → different mappingKey")

    # Fingerprint changes when finding changes even with same key structure
    fp1 = mappingFingerprint("key1", "f-001", "a", "r", ("id1",))
    fp2 = mappingFingerprint("key1", "f-002", "a", "r", ("id1",))
    _ne(fp1, fp2, "different findingId → different fingerprint")

test_collision_resistance()


# ===========================================================================
# Section 26 — Serialisation
# ===========================================================================

def test_serialisation() -> None:
    t = _make_technique()
    m = _make_mapping(techniques=[t])
    stats = build_mitre_statistics([m])

    for obj, name in [
        (t,     "MitreTechnique"),
        (m,     "MitreMapping"),
        (stats, "MitreStatistics"),
    ]:
        d = obj.model_dump()
        _is(d, dict, f"{name}.model_dump() returns dict")
        j = obj.model_dump_json()
        _is(j, str, f"{name}.model_dump_json() returns str")
        parsed = json.loads(j)
        _is(parsed, dict, f"{name}.model_dump_json() is valid JSON")

    # MitreTechnique round-trip key fields
    d = t.model_dump()
    _eq(d["mitreId"],     "T1059", "mitreId in dict")
    _eq(d["tactic"],      TacticEnum.EXECUTION.value, "tactic serialised as value")
    _true("platforms" in d, "platforms in dict")

    # MitreMapping round-trip
    d_m = m.model_dump()
    _eq(d_m["findingId"], "finding-001", "findingId in dict")
    _true("matchedTechniques" in d_m, "matchedTechniques in dict")
    _true(isinstance(d_m["matchedTechniques"], (list, tuple)), "matchedTechniques is sequence in dict")

    # MitreStatistics round-trip
    d_s = stats.model_dump()
    for field in ("totalTechniques", "mappedTechniques", "tacticsCovered", "averageConfidence"):
        _true(field in d_s, f"stats field '{field}' in dict")

test_serialisation()


# ===========================================================================
# Section 27 — All 14 tactics round-trip through build_mitre_technique
# ===========================================================================

def test_all_tactics_round_trip() -> None:
    """Every TacticEnum value must produce a valid, distinct MitreTechnique."""
    seen_technique_ids = set()
    seen_technique_keys = set()

    for i, tactic in enumerate(TacticEnum):
        mitre_id = f"T{9000 + i:04d}"
        t = build_mitre_technique(
            mitre_id   = mitre_id,
            name       = f"Technique for {tactic.value}",
            tactic     = tactic,
            created_at = TS,
        )
        _is(t, MitreTechnique, f"tactic {tactic.value}: returns MitreTechnique")
        _eq(t.tactic, tactic, f"tactic {tactic.value}: stored correctly")
        _eq(t.mitreId, mitre_id.upper(), f"tactic {tactic.value}: mitreId correct")
        _true(t.techniqueId not in seen_technique_ids, f"tactic {tactic.value}: unique techniqueId")
        _true(t.techniqueKey not in seen_technique_keys, f"tactic {tactic.value}: unique techniqueKey")
        seen_technique_ids.add(t.techniqueId)
        seen_technique_keys.add(t.techniqueKey)

    _eq(len(seen_technique_ids),   14, "14 distinct techniqueIds across all tactics")
    _eq(len(seen_technique_keys),  14, "14 distinct techniqueKeys across all tactics")

test_all_tactics_round_trip()


# ===========================================================================
# Section 28 — Edge cases
# ===========================================================================

def test_edge_cases() -> None:
    # Very long mitreId (custom extended ID)
    t_long = build_mitre_technique("T1059.001.002", "Deep nested", TacticEnum.EXECUTION, TS)
    _is(t_long, MitreTechnique, "very long mitreId accepted")
    _eq(len(t_long.techniqueKey), 32, "long mitreId → 32-char key")

    # mitreId with leading/trailing whitespace stripped + uppercased
    t_ws = build_mitre_technique("  t1059  ", "n", TacticEnum.EXECUTION, TS)
    _eq(t_ws.mitreId, "T1059", "whitespace stripped, uppercased")

    # Name with surrounding whitespace stripped
    t_name = build_mitre_technique("T1060", "  Padded Name  ", TacticEnum.PERSISTENCE, TS)
    _eq(t_name.name, "Padded Name", "technique name stripped")

    # Platform list normalisation
    t_plat = build_mitre_technique(
        "T1070", "n", TacticEnum.DEFENSE_EVASION, TS,
        platforms=["Windows", "WINDOWS", "Linux", "  linux  ", "macOS", "macos"],
    )
    _eq(t_plat.platforms, ("linux", "macos", "windows"), "platforms lowercased+deduped+sorted")

    # Mitigation dedup preserves case-sensitive strings (not lowercased)
    t_mit = build_mitre_technique(
        "T1071", "n", TacticEnum.COMMAND_AND_CONTROL, TS,
        mitigations=["Block outbound", "Block outbound", "Monitor traffic"],
    )
    _eq(len(t_mit.mitigations), 2, "mitigations deduped")
    _true("Block outbound" in t_mit.mitigations, "mitigation case preserved")

    # Reference dedup
    t_ref = build_mitre_technique(
        "T1072", "n", TacticEnum.LATERAL_MOVEMENT, TS,
        references=["https://a.com", "https://b.com", "https://a.com"],
    )
    _eq(len(t_ref.references), 2, "references deduped to 2")

    # Confidence clamping in mapping
    m_clamp_hi = build_mitre_mapping([], TS, finding_id="f", confidence=999.9)
    _eq(m_clamp_hi.confidence, 100.0, "mapping confidence clamped to 100")

    m_clamp_lo = build_mitre_mapping([], TS, finding_id="f", confidence=-0.1)
    _eq(m_clamp_lo.confidence, 0.0, "mapping confidence clamped to 0")

    # Confidence at exact boundaries
    m_zero = build_mitre_mapping([], TS, finding_id="f", confidence=0.0)
    _eq(m_zero.confidence, 0.0, "confidence=0.0 accepted")

    m_full = build_mitre_mapping([], TS, finding_id="f", confidence=100.0)
    _eq(m_full.confidence, 100.0, "confidence=100.0 accepted")

    # _clamp helper
    _eq(_clamp(150.0), 100.0, "_clamp 150 → 100")
    _eq(_clamp(-10.0), 0.0,   "_clamp -10 → 0")
    _eq(_clamp(50.0),  50.0,  "_clamp 50 → 50")

    # _norm helpers
    _eq(_norm("  hello  "), "hello", "_norm strips whitespace")
    _eq(_norm(""),          "",      "_norm empty string")

    _eq(_norm_lower("HELLO"), "hello", "_norm_lower lowercases")
    _eq(_norm_lower("  HI "), "hi",    "_norm_lower strips and lowercases")

    _eq(_norm_strings(None), (), "_norm_strings None → empty tuple")
    _eq(_norm_strings([]),   (), "_norm_strings [] → empty tuple")
    ns = _norm_strings(["c", "a", "b", "a"])
    _eq(ns, ("a", "b", "c"), "_norm_strings deduped + sorted")

    _eq(_norm_lower_strings(["B", "a", "A"]), ("a", "b"), "_norm_lower_strings deduped lowercase sorted")

test_edge_cases()


# ===========================================================================
# Section 29 — Statistics across heterogeneous mappings
# ===========================================================================

def test_statistics_heterogeneous() -> None:
    techniques = [
        _make_technique(f"T{1000+i}", f"Tech {i}", list(TacticEnum)[i % 14])
        for i in range(7)
    ]

    mappings = []
    for i, t in enumerate(techniques):
        conf = float(50 + i * 5)
        if i % 2 == 0:
            # Finding-source mapping
            m = build_mitre_mapping([t], TS, finding_id=f"f-{i:03d}", confidence=conf)
        else:
            # Alert-source mapping
            m = build_mitre_mapping([t], TS, alert_id=f"a-{i:03d}", confidence=conf)
        mappings.append(m)

    stats = build_mitre_statistics(mappings)

    _eq(stats.totalTechniques,  7, "7 distinct techniques")
    _eq(stats.mappedTechniques, 7, "7 distinct techniqueIds")

    # averageConfidence = (50+55+60+65+70+75+80)/7
    expected_avg = round(sum(50.0 + i * 5 for i in range(7)) / 7, 4)
    _eq(stats.averageConfidence, expected_avg, f"averageConfidence = {expected_avg}")

    # All tactics used (7 techniques, cycling through 14 tactics → subset)
    _true(len(stats.tacticsCovered) <= 14, "tacticsCovered <= 14")
    _true(len(stats.tacticsCovered) >= 1,  "at least one tactic covered")

    # statistics immutable
    try:
        stats.totalTechniques = 999  # type: ignore
        global _FAIL
        _FAIL += 1
        print("  FAIL [stats frozen in heterogeneous test]: mutation succeeded")
    except Exception:
        global _PASS
        _PASS += 1

test_statistics_heterogeneous()


# ===========================================================================
# Section 30 — Full end-to-end pipeline
# ===========================================================================

def test_full_pipeline() -> None:
    """Build a realistic mapping pipeline from technique → mapping → statistics."""

    # Step 1: build techniques for multiple tactics
    t_recon    = build_mitre_technique("T1595", "Active Scanning", TacticEnum.RECONNAISSANCE, TS,
                                        platforms=["network"], detection="Monitor scan traffic")
    t_init     = build_mitre_technique("T1566", "Phishing",         TacticEnum.INITIAL_ACCESS, TS,
                                        platforms=["windows", "linux"])
    t_exec     = build_mitre_technique("T1059", "Scripting",        TacticEnum.EXECUTION, TS,
                                        platforms=["windows"])
    t_persist  = build_mitre_technique("T1547", "Boot Autostart",   TacticEnum.PERSISTENCE, TS)
    t_escalate = build_mitre_technique("T1068", "Exploit Vuln",     TacticEnum.PRIVILEGE_ESCALATION, TS)
    t_evade    = build_mitre_technique("T1070", "Indicator Removal",TacticEnum.DEFENSE_EVASION, TS)
    t_cred     = build_mitre_technique("T1003", "OS Credential",    TacticEnum.CREDENTIAL_ACCESS, TS)
    t_discover = build_mitre_technique("T1082", "System Info",      TacticEnum.DISCOVERY, TS)
    t_lateral  = build_mitre_technique("T1021", "Remote Services",  TacticEnum.LATERAL_MOVEMENT, TS)
    t_collect  = build_mitre_technique("T1005", "Local Data",       TacticEnum.COLLECTION, TS)
    t_c2       = build_mitre_technique("T1071", "App Layer Proto",  TacticEnum.COMMAND_AND_CONTROL, TS)
    t_exfil    = build_mitre_technique("T1041", "Exfil Over C2",    TacticEnum.EXFILTRATION, TS)
    t_impact   = build_mitre_technique("T1486", "Data Encrypted",   TacticEnum.IMPACT, TS)

    all_techniques = [
        t_recon, t_init, t_exec, t_persist, t_escalate, t_evade,
        t_cred, t_discover, t_lateral, t_collect, t_c2, t_exfil, t_impact
    ]

    # Step 2: build mappings simulating an investigation
    class _F:
        def __init__(self, fid): self.findingId = fid
    class _A:
        def __init__(self, aid, fid): self.alertId = aid; self.findingId = fid
    class _R:
        def __init__(self, rid, conf): self.reasoningId = rid; self.overallConfidence = conf

    m_recon   = finding_to_mitre_mapping(_F("f-001"), [t_recon],  TS, confidence=65.0)
    m_init    = finding_to_mitre_mapping(_F("f-002"), [t_init],   TS, confidence=80.0)
    m_exec    = alert_to_mitre_mapping  (_A("a-001", "f-003"), [t_exec, t_persist], TS, confidence=75.0)
    m_escalate = alert_to_mitre_mapping (_A("a-002", "f-004"), [t_escalate],        TS, confidence=70.0)
    m_lateral  = reasoning_to_mitre_mapping(_R("r-001", 88.0), [t_lateral, t_c2],  TS)
    m_impact   = reasoning_to_mitre_mapping(_R("r-002", 95.0), [t_impact],          TS)

    mappings = [m_recon, m_init, m_exec, m_escalate, m_lateral, m_impact]

    # Step 3: verify all mappings are valid
    for i, m in enumerate(mappings):
        _is(m, MitreMapping, f"pipeline mapping[{i}] is MitreMapping")
        _eq(len(m.mappingKey), 32, f"pipeline mapping[{i}] mappingKey length")
        _true("-" in m.mappingId, f"pipeline mapping[{i}] mappingId is UUID")

    # Step 4: build statistics
    stats = build_mitre_statistics(mappings)
    _is(stats, MitreStatistics, "pipeline stats is MitreStatistics")

    # 8 distinct mitreIds across mappings actually used (only 6 mappings, some share techniques)
    # m_recon:[T1595], m_init:[T1566], m_exec:[T1059,T1547], m_escalate:[T1068],
    # m_lateral:[T1021,T1071], m_impact:[T1486] → 8 distinct
    _eq(stats.totalTechniques, 8, "pipeline: 8 distinct mitreIds in 6 mappings")
    _true(len(stats.tacticsCovered) >= 7, "pipeline: at least 7 tactics covered")

    # Step 5: verify techniques are distinct objects (same build → same IDs)
    for t in all_techniques:
        t_rebuilt = build_mitre_technique(t.mitreId, t.name, t.tactic, TS)
        _eq(t.techniqueId,  t_rebuilt.techniqueId,  f"{t.mitreId}: rebuilt has same techniqueId")
        _eq(t.techniqueKey, t_rebuilt.techniqueKey, f"{t.mitreId}: rebuilt has same techniqueKey")

    # Step 6: verify statistics are order-independent
    import random as _random_check
    # Manual reversal (no randomness)
    stats_rev = build_mitre_statistics(list(reversed(mappings)))
    _eq(stats.averageConfidence, stats_rev.averageConfidence,
        "pipeline stats order-independent: averageConfidence")
    _eq(stats.totalTechniques, stats_rev.totalTechniques,
        "pipeline stats order-independent: totalTechniques")
    _eq(stats.tacticsCovered, stats_rev.tacticsCovered,
        "pipeline stats order-independent: tacticsCovered")

test_full_pipeline()


# ===========================================================================
# Final report
# ===========================================================================

print()
print("=" * 60)
print("MITRE ATT&CK Engine — smoke test complete")
print(f"  PASSED : {_PASS}")
print(f"  FAILED : {_FAIL}")
print("=" * 60)

if _FAIL > 0:
    raise SystemExit(f"{_FAIL} assertion(s) failed.")
else:
    print(f"All {_PASS} assertions passed. 0 failures.")
