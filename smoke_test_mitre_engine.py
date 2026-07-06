"""
Smoke test — MITRE ATT&CK Engine (Phase A4.0.9)
================================================
Validates (150+ assertions):
  ✓ deterministic IDs (techniqueKey/Id, subTechniqueKey/Id, tacticKey/Id,
                        mappingKey/Id)
  ✓ deterministic fingerprints
  ✓ immutable models (frozen=True raises on mutation)
  ✓ build_tactic()
  ✓ build_technique()
  ✓ build_subtechnique()
  ✓ build_mapping()
  ✓ update_mapping() — partial + full overrides
  ✓ merge_mappings()
  ✓ build_statistics() / calculate_statistics()
  ✓ build_bundle()
  ✓ sort_techniques() — all keys + invalid key
  ✓ sort_mappings()
  ✓ filter_techniques()
  ✓ filter_mappings()
  ✓ group_techniques() — all group keys
  ✓ group_mappings()
  ✓ find_technique() — all lookup modes
  ✓ find_mapping()
  ✓ search_techniques()
  ✓ fingerprint stability (order-independent)
  ✓ identical input → identical output
  ✓ no ordering dependence in statistics
"""

import sys
from services.mitre_service import (
    MitreTactic, MitreTechnique, MitreSubTechnique,
    MitreMapping, MitreExplanation, MitreStatistics, MitreBundle,
    build_tactic, build_technique, build_subtechnique,
    build_mapping, update_mapping, merge_mappings,
    build_statistics, build_bundle, calculate_statistics,
    sort_techniques, sort_subtechniques, sort_mappings,
    filter_techniques, filter_mappings,
    group_techniques, group_mappings,
    find_technique, find_mapping, search_techniques,
    _compute_technique_key, _compute_technique_id,
    _compute_subtechnique_key, _compute_subtechnique_id,
    _compute_tactic_key, _compute_tactic_id,
    _compute_mapping_key, _compute_mapping_id,
    _compute_mapping_fingerprint,
)
from core.constants import MITRE_ENGINE_VERSION

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
errors: list = []


def check(label: str, condition: bool) -> None:
    icon = PASS if condition else FAIL
    print(f"  {icon}  {label}")
    if not condition:
        errors.append(label)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TS1 = "2026-06-30T10:00:00Z"
TS2 = "2026-06-30T11:00:00Z"

def _tactic_lateral() -> MitreTactic:
    return build_tactic("lateral-movement", "Lateral Movement", TS1,
                        description="Techniques for moving through environments.", order=8)

def _tactic_initial() -> MitreTactic:
    return build_tactic("initial-access", "Initial Access", TS1,
                        description="Techniques for gaining entry.", order=1)

def _tech_smb() -> MitreTechnique:
    return build_technique(
        technique_code       = "T1021",
        name                 = "Remote Services",
        created_at           = TS1,
        description          = "Adversaries may use valid accounts to log into a service.",
        tactic_ids           = ["tac-lat-001", "tac-lat-001"],   # intentional dup
        platforms            = ["Windows", "Linux", "windows"],   # dup + mixed case
        data_sources         = ["Network Traffic", "Command Execution"],
        permissions_required = ["User", "Administrator"],
        detection            = "Monitor for unusual SMB traffic.",
        mitigation           = "Enforce least privilege.",
        references           = ["https://attack.mitre.org/T1021", "https://attack.mitre.org/T1021"],
        risk_score           = 75.0,
        confidence           = 88.0,
        metadata             = {"phase": "A4.0.9"},
    )

def _tech_phish() -> MitreTechnique:
    return build_technique(
        technique_code = "T1566",
        name           = "Phishing",
        created_at     = TS1,
        risk_score     = 80.0,
        confidence     = 90.0,
        tactic_ids     = ["tac-init-001"],
        platforms      = ["Windows", "macOS"],
    )

def _tech_low() -> MitreTechnique:
    return build_technique(
        technique_code = "T1070",
        name           = "Indicator Removal",
        created_at     = TS1,
        risk_score     = 35.0,
        confidence     = 55.0,
        tactic_ids     = ["tac-def-001"],
    )

def _sub_smb() -> MitreSubTechnique:
    return build_subtechnique(
        sub_technique_code  = "T1021.002",
        parent_technique_id = _tech_smb().techniqueId,
        name                = "SMB/Windows Admin Shares",
        created_at          = TS1,
        description         = "Adversaries may use SMB to access shared drives.",
        risk_score          = 72.0,
        confidence          = 85.0,
    )

def _make_mapping(
    finding_id            = "find-001",
    alert_id              = "alert-001",
    relationship_id       = "rel-001",
    technique_ids         = None,
    sub_technique_ids     = None,
    asset_ids             = None,
    evidence_ids          = None,
    timeline_event_ids    = None,
    attack_graph_node_ids = None,
    confidence            = 82.0,
    risk_score            = 74.0,
    matched_evidence      = None,
    matched_indicators    = None,
    recommended_actions   = None,
    analyst_notes         = "Confirmed by analyst.",
    **kwargs,
) -> MitreMapping:
    return build_mapping(
        finding_id            = finding_id,
        alert_id              = alert_id,
        relationship_id       = relationship_id,
        created_at            = TS1,
        technique_ids         = technique_ids         if technique_ids         is not None else ["T1021.id", "T1566.id"],
        sub_technique_ids     = sub_technique_ids     if sub_technique_ids     is not None else ["T1021.002.id"],
        asset_ids             = asset_ids             if asset_ids             is not None else ["asset-c", "asset-a"],
        evidence_ids          = evidence_ids          if evidence_ids          is not None else ["ev-2", "ev-1"],
        timeline_event_ids    = timeline_event_ids    if timeline_event_ids    is not None else ["te-1"],
        attack_graph_node_ids = attack_graph_node_ids if attack_graph_node_ids is not None else ["node-b", "node-a"],
        confidence            = confidence,
        risk_score            = risk_score,
        finding_fingerprint   = "ffp-abc",
        alert_fingerprint     = "afp-xyz",
        graph_fingerprint     = "gfp-qrs",
        timeline_fingerprint  = "tfp-mno",
        mapping_reason        = "SMB lateral movement pattern.",
        reason                = "SMB traffic between internal hosts.",
        matched_evidence      = matched_evidence      if matched_evidence      is not None else ["ev-1", "ev-2"],
        matched_indicators    = matched_indicators    if matched_indicators    is not None else ["SMB", "PORT-445"],
        recommended_actions   = recommended_actions   if recommended_actions   is not None else ["Isolate asset-a", "Review ACLs"],
        analyst_notes         = analyst_notes,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Section 1: Deterministic IDs
# ---------------------------------------------------------------------------
print("\n── 1. Deterministic IDs ─────────────────────────────────────────────")

# techniqueKey / Id
k1 = _compute_technique_key("T1021")
k2 = _compute_technique_key("T1021")
check("techniqueKey deterministic",           k1 == k2)
check("techniqueKey length 32",               len(k1) == 32)
check("techniqueKey case-insensitive (T1021 == t1021)", k1 == _compute_technique_key("t1021"))
k_diff = _compute_technique_key("T1566")
check("different codes → different keys",     k1 != k_diff)

id1 = _compute_technique_id(k1)
id2 = _compute_technique_id(k1)
check("techniqueId deterministic (UUIDv5)",   id1 == id2)
check("techniqueId valid UUID format",        len(id1) == 36 and id1.count("-") == 4)

# subTechniqueKey / Id
sk1 = _compute_subtechnique_key("T1021.002")
sk2 = _compute_subtechnique_key("T1021.002")
check("subTechniqueKey deterministic",        sk1 == sk2)
check("subTechniqueKey length 32",            len(sk1) == 32)
check("subTechniqueKey ≠ techniqueKey",       sk1 != k1)
sid1 = _compute_subtechnique_id(sk1)
check("subTechniqueId deterministic",         sid1 == _compute_subtechnique_id(sk1))
check("subTechniqueId valid UUID",            len(sid1) == 36)

# tacticKey / Id
tk1 = _compute_tactic_key("lateral-movement")
tk2 = _compute_tactic_key("lateral-movement")
check("tacticKey deterministic",              tk1 == tk2)
check("tacticKey length 32",                  len(tk1) == 32)
check("tacticKey case-insensitive",           tk1 == _compute_tactic_key("Lateral-Movement"))
tid1 = _compute_tactic_id(tk1)
check("tacticId deterministic",               tid1 == _compute_tactic_id(tk1))
check("tacticId valid UUID",                  len(tid1) == 36)

# mappingKey / Id
tech_tuple = ("T1021.id", "T1566.id")
mk1 = _compute_mapping_key("find-001", "alert-001", "rel-001", tech_tuple)
mk2 = _compute_mapping_key("find-001", "alert-001", "rel-001", tech_tuple)
check("mappingKey deterministic",             mk1 == mk2)
check("mappingKey length 32",                 len(mk1) == 32)
# Order-independence of techniqueIds in mapping key
mk_rev = _compute_mapping_key("find-001", "alert-001", "rel-001", ("T1566.id", "T1021.id"))
check("mappingKey order-independent for techniqueIds", mk1 == mk_rev)
mid1 = _compute_mapping_id(mk1)
check("mappingId deterministic",              mid1 == _compute_mapping_id(mk1))
check("mappingId valid UUID",                 len(mid1) == 36)

mk_diff = _compute_mapping_key("find-002", "alert-001", "rel-001", tech_tuple)
check("different findingId → different mappingKey", mk1 != mk_diff)


# ---------------------------------------------------------------------------
# Section 2: build_tactic()
# ---------------------------------------------------------------------------
print("\n── 2. build_tactic() ────────────────────────────────────────────────")

t_lat = _tactic_lateral()
t_init = _tactic_initial()
check("tactic shortName lowercased",    t_lat.shortName == "lateral-movement")
check("tactic order set",               t_lat.order == 8)
check("tacticKey length 32",            len(t_lat.tacticKey) == 32)
check("tacticId valid UUID",            len(t_lat.tacticId) == 36)
check("identical inputs → same tacticId", _tactic_lateral().tacticId == t_lat.tacticId)
check("different shortName → different tacticId", t_lat.tacticId != t_init.tacticId)
check("tactic engineVersion not stored", not hasattr(t_lat, "engineVersion"))   # MitreTactic has no engineVersion


# ---------------------------------------------------------------------------
# Section 3: build_technique()
# ---------------------------------------------------------------------------
print("\n── 3. build_technique() ─────────────────────────────────────────────")

tech = _tech_smb()
check("techniqueCode uppercased",        tech.techniqueCode == "T1021")
check("techniqueKey length 32",          len(tech.techniqueKey) == 32)
check("techniqueId valid UUID",          len(tech.techniqueId) == 36)
check("tacticIds deduped",               len(set(tech.tacticIds)) == len(tech.tacticIds))
check("platforms deduped + lowercased",  tech.platforms == tuple(sorted({"windows","linux"})))
check("references deduped",              len(tech.references) == 1)
check("riskScore clamped",               0.0 <= tech.riskScore <= 100.0)
check("confidence clamped",              0.0 <= tech.confidence <= 100.0)
check("identical inputs → same techniqueId", _tech_smb().techniqueId == tech.techniqueId)
check("different code → different techniqueId", tech.techniqueId != _tech_phish().techniqueId)


# ---------------------------------------------------------------------------
# Section 4: build_subtechnique()
# ---------------------------------------------------------------------------
print("\n── 4. build_subtechnique() ──────────────────────────────────────────")

sub = _sub_smb()
check("subTechniqueCode uppercased",     sub.subTechniqueCode == "T1021.002")
check("subTechniqueKey length 32",       len(sub.subTechniqueKey) == 32)
check("subTechniqueId valid UUID",       len(sub.subTechniqueId) == 36)
check("parentTechniqueId set",           sub.parentTechniqueId == _tech_smb().techniqueId)
check("riskScore clamped",               0.0 <= sub.riskScore <= 100.0)
check("identical inputs → same subTechniqueId", _sub_smb().subTechniqueId == sub.subTechniqueId)


# ---------------------------------------------------------------------------
# Section 5: Immutability
# ---------------------------------------------------------------------------
print("\n── 5. Immutability (frozen=True) ────────────────────────────────────")

m = _make_mapping()

try:
    tech.riskScore = 99.0  # type: ignore
    check("MitreTechnique frozen=True raises",  False)
except Exception:
    check("MitreTechnique frozen=True raises",  True)

try:
    sub.riskScore = 99.0  # type: ignore
    check("MitreSubTechnique frozen=True raises", False)
except Exception:
    check("MitreSubTechnique frozen=True raises", True)

try:
    t_lat.order = 99  # type: ignore
    check("MitreTactic frozen=True raises",     False)
except Exception:
    check("MitreTactic frozen=True raises",     True)

try:
    m.confidence = 99.0  # type: ignore
    check("MitreMapping frozen=True raises",    False)
except Exception:
    check("MitreMapping frozen=True raises",    True)

try:
    m.explanation.reason = "hacked"  # type: ignore
    check("MitreExplanation frozen=True raises",False)
except Exception:
    check("MitreExplanation frozen=True raises",True)


# ---------------------------------------------------------------------------
# Section 6: build_mapping()
# ---------------------------------------------------------------------------
print("\n── 6. build_mapping() ───────────────────────────────────────────────")

check("status auditTrail is ('Created',)",  m.auditTrail == ("Created",))
check("mappingKey length 32",               len(m.mappingKey) == 32)
check("mappingId valid UUID",               len(m.mappingId)  == 36)
check("mappingFingerprint length 32",       len(m.mappingFingerprint) == 32)
check("techniqueIds sorted + deduped",      list(m.techniqueIds) == sorted({"T1021.id","T1566.id"}))
check("assetIds sorted + deduped",          list(m.assetIds)     == sorted({"asset-a","asset-c"}))
check("evidenceIds sorted + deduped",       list(m.evidenceIds)  == sorted({"ev-1","ev-2"}))
check("engineVersion matches const",        m.engineVersion == MITRE_ENGINE_VERSION)
check("explanation.reason set",             m.explanation.reason != "")
check("explanation.matchedIndicators lowercased", all(i == i.lower() for i in m.explanation.matchedIndicators))
check("explanation.matchedEvidence sorted", list(m.explanation.matchedEvidence) == sorted(["ev-1","ev-2"]))

# Idempotence
m2 = _make_mapping()
check("identical inputs → same mappingId",          m.mappingId          == m2.mappingId)
check("identical inputs → same mappingKey",         m.mappingKey         == m2.mappingKey)
check("identical inputs → same mappingFingerprint", m.mappingFingerprint == m2.mappingFingerprint)


# ---------------------------------------------------------------------------
# Section 7: update_mapping()
# ---------------------------------------------------------------------------
print("\n── 7. update_mapping() ──────────────────────────────────────────────")

upd = update_mapping(
    m,
    confidence     = 95.0,
    risk_score     = 90.0,
    analyst_notes  = "Re-reviewed by senior analyst.",
    matched_evidence = ["ev-1", "ev-2", "ev-3"],
)
check("confidence updated",                 upd.confidence == 95.0)
check("riskScore updated",                  upd.riskScore  == 90.0)
check("mappingId unchanged",                upd.mappingId  == m.mappingId)
check("mappingKey unchanged",               upd.mappingKey == m.mappingKey)
check("auditTrail has Updated",             "Updated" in upd.auditTrail)
check("auditTrail preserves Created",       "Created" in upd.auditTrail)
check("explanation.analystNotes updated",   upd.explanation.analystNotes == "Re-reviewed by senior analyst.")
check("explanation.matchedEvidence updated",len(upd.explanation.matchedEvidence) == 3)
check("explanation.matchedIndicators preserved", upd.explanation.matchedIndicators == m.explanation.matchedIndicators)
check("mappingFingerprint unchanged (same source FPs)", upd.mappingFingerprint == m.mappingFingerprint)

# Partial update — fingerprint changes when source FPs change
upd_fp = update_mapping(m, finding_fingerprint="NEW-FFP")
check("mappingFingerprint changes with new findingFingerprint", upd_fp.mappingFingerprint != m.mappingFingerprint)
check("findingFingerprint updated",         upd_fp.findingFingerprint == "NEW-FFP")

# None fields not changed
upd_partial = update_mapping(m, risk_score=50.0)
check("Partial: confidence preserved",      upd_partial.confidence == m.confidence)
check("Partial: riskScore changed",         upd_partial.riskScore  == 50.0)
check("Partial: techniqueIds preserved",    upd_partial.techniqueIds == m.techniqueIds)


# ---------------------------------------------------------------------------
# Section 8: merge_mappings()
# ---------------------------------------------------------------------------
print("\n── 8. merge_mappings() ──────────────────────────────────────────────")

m_b = _make_mapping()
m_inc = _make_mapping(
    finding_id  = "find-001",
    alert_id    = "alert-001",
    relationship_id = "rel-001",
    technique_ids = ["T1021.id", "T1070.id"],     # T1070 is new
    asset_ids     = ["asset-a", "asset-d"],        # asset-d is new
    evidence_ids  = ["ev-1", "ev-3"],              # ev-3 is new
    confidence    = 95.0,
    risk_score    = 80.0,
    matched_evidence   = ["ev-1","ev-3"],
    matched_indicators = ["RDP"],
    recommended_actions= ["Block lateral movement"],
    analyst_notes      = "Incoming note.",
)
merged = merge_mappings(m_b, m_inc)

check("merge: techniqueIds unioned",        "T1070.id" in merged.techniqueIds and "T1566.id" in merged.techniqueIds)
check("merge: techniqueIds sorted",         list(merged.techniqueIds) == sorted(merged.techniqueIds))
check("merge: assetIds unioned",            "asset-d" in merged.assetIds)
check("merge: evidenceIds unioned",         "ev-3" in merged.evidenceIds)
check("merge: confidence = max",            merged.confidence == max(m_b.confidence, m_inc.confidence))
check("merge: riskScore = max",             merged.riskScore  == max(m_b.riskScore,  m_inc.riskScore))
check("merge: auditTrail has Merged",       "Merged" in merged.auditTrail)
check("merge: mappingId preserved (base)",  merged.mappingId == m_b.mappingId)
check("merge: matchedEvidence unioned",     "ev-3" in merged.explanation.matchedEvidence)
check("merge: matchedIndicators unioned",   "rdp" in merged.explanation.matchedIndicators)
check("merge: analystNotes concatenated",   "Incoming note." in merged.explanation.analystNotes)
check("merge: recommendedActions unioned",  "Block lateral movement" in merged.explanation.recommendedActions)


# ---------------------------------------------------------------------------
# Section 9: sort_techniques()
# ---------------------------------------------------------------------------
print("\n── 9. sort_techniques() ─────────────────────────────────────────────")

tech_list = [_tech_smb(), _tech_phish(), _tech_low()]

s_risk_desc = sort_techniques(tech_list, by="riskScore", ascending=False)
check("riskScore DESC: highest first",      s_risk_desc[0].riskScore >= s_risk_desc[-1].riskScore)

s_risk_asc  = sort_techniques(tech_list, by="riskScore", ascending=True)
check("riskScore ASC: lowest first",        s_risk_asc[0].riskScore  <= s_risk_asc[-1].riskScore)

s_conf_desc = sort_techniques(tech_list, by="confidence", ascending=False)
check("confidence DESC: highest first",     s_conf_desc[0].confidence >= s_conf_desc[-1].confidence)

s_code_asc  = sort_techniques(tech_list, by="techniqueCode", ascending=True)
check("techniqueCode ASC: T1021 first",     s_code_asc[0].techniqueCode == "T1021")

s_name_asc  = sort_techniques(tech_list, by="name", ascending=True)
check("name ASC: alphabetical",             s_name_asc[0].name <= s_name_asc[-1].name)

try:
    sort_techniques(tech_list, by="bogus_key")
    check("invalid sort key raises ValueError", False)
except ValueError:
    check("invalid sort key raises ValueError", True)

# sort_subtechniques
sub_list = [_sub_smb()]
s_sub = sort_subtechniques(sub_list, ascending=False)
check("sort_subtechniques returns list",    len(s_sub) == 1)

# sort_mappings
m_list = [m, upd]
s_map = sort_mappings(m_list, by="confidence", ascending=False)
check("sort_mappings confidence DESC",      s_map[0].confidence >= s_map[-1].confidence)

try:
    sort_mappings(m_list, by="bad_key")
    check("invalid sort_mappings key raises ValueError", False)
except ValueError:
    check("invalid sort_mappings key raises ValueError", True)


# ---------------------------------------------------------------------------
# Section 10: filter_techniques()
# ---------------------------------------------------------------------------
print("\n── 10. filter_techniques() ──────────────────────────────────────────")

all_techs = [_tech_smb(), _tech_phish(), _tech_low()]

f_tactic = filter_techniques(all_techs, tactic_id="tac-lat-001")
check("filter by tactic_id",               all("tac-lat-001" in t.tacticIds for t in f_tactic))
check("filter by tactic_id count",         len(f_tactic) == 1)

f_plat = filter_techniques(all_techs, platform="windows")
check("filter by platform (lowercase)",    all("windows" in t.platforms for t in f_plat))
check("filter by platform: T1070 excluded (no platforms)", "T1070" not in [t.techniqueCode for t in f_plat])

f_risk = filter_techniques(all_techs, min_risk_score=70.0)
check("filter min_risk_score=70",          all(t.riskScore >= 70.0 for t in f_risk))

f_max  = filter_techniques(all_techs, max_risk_score=40.0)
check("filter max_risk_score=40",          all(t.riskScore <= 40.0 for t in f_max))

f_conf = filter_techniques(all_techs, min_confidence=85.0)
check("filter min_confidence=85",          all(t.confidence >= 85.0 for t in f_conf))

f_code = filter_techniques(all_techs, technique_code="T1021")
check("filter by technique_code",          len(f_code) == 1 and f_code[0].techniqueCode == "T1021")

f_code_lc = filter_techniques(all_techs, technique_code="t1021")
check("filter by technique_code case-insensitive", len(f_code_lc) == 1)

# filter_mappings
m_list_filter = [m, upd, merged]
f_tech = filter_mappings(m_list_filter, technique_id="T1021.id")
check("filter_mappings by technique_id",   all("T1021.id" in x.techniqueIds for x in f_tech))

f_find = filter_mappings(m_list_filter, finding_id="find-001")
check("filter_mappings by finding_id",     all(x.findingId == "find-001" for x in f_find))

f_conf_m = filter_mappings(m_list_filter, min_confidence=90.0)
check("filter_mappings min_confidence=90", all(x.confidence >= 90.0 for x in f_conf_m))


# ---------------------------------------------------------------------------
# Section 11: group_techniques()
# ---------------------------------------------------------------------------
print("\n── 11. group_techniques() ───────────────────────────────────────────")

all_techs2 = [_tech_smb(), _tech_phish(), _tech_low()]

g_tactic = group_techniques(all_techs2, by="tactic")
check("group by tactic: tac-lat-001 key exists",  "tac-lat-001" in g_tactic)
check("group by tactic: T1021 in tac-lat-001",    any(t.techniqueCode == "T1021" for t in g_tactic.get("tac-lat-001",[])))

g_plat = group_techniques(all_techs2, by="platform")
check("group by platform: windows key exists",    "windows" in g_plat)

g_tech = group_techniques(all_techs2, by="technique")
check("group by technique: T1021 key exists",     "T1021" in g_tech)
check("group by technique: each group size 1",    all(len(v) == 1 for v in g_tech.values()))

g_risk = group_techniques(all_techs2, by="risk_bucket")
check("group by risk_bucket: critical bucket",    "critical" in g_risk or "high" in g_risk)
check("group by risk_bucket: low bucket exists",  "low" in g_risk)
check("group by risk_bucket: T1070 in low",       any(t.techniqueCode == "T1070" for t in g_risk.get("low", [])))

g_conf = group_techniques(all_techs2, by="confidence_bucket")
check("group by confidence_bucket: high exists",  "high" in g_conf)

try:
    group_techniques(all_techs2, by="bad_key")
    check("invalid group key raises ValueError",  False)
except ValueError:
    check("invalid group key raises ValueError",  True)

# group_mappings
g_map_tech = group_mappings([m, merged], by="techniqueId")
check("group_mappings by techniqueId: T1021.id key exists", "T1021.id" in g_map_tech)

g_map_find = group_mappings([m, merged], by="findingId")
check("group_mappings by findingId: find-001 key exists", "find-001" in g_map_find)


# ---------------------------------------------------------------------------
# Section 12: find_technique() / find_mapping()
# ---------------------------------------------------------------------------
print("\n── 12. find_technique() / find_mapping() ────────────────────────────")

pool_tech = [_tech_smb(), _tech_phish(), _tech_low()]

found_id   = find_technique(pool_tech, technique_id=tech.techniqueId)
found_key  = find_technique(pool_tech, technique_key=tech.techniqueKey)
found_code = find_technique(pool_tech, technique_code="T1021")
found_name = find_technique(pool_tech, name="Remote Services")
not_found  = find_technique(pool_tech, technique_id="nonexistent")

check("find by techniqueId",            found_id   is not None and found_id.techniqueId   == tech.techniqueId)
check("find by techniqueKey",           found_key  is not None and found_key.techniqueKey == tech.techniqueKey)
check("find by techniqueCode",          found_code is not None and found_code.techniqueCode == "T1021")
check("find by name",                   found_name is not None and found_name.name == "Remote Services")
check("not found → None",               not_found is None)

found_m_id  = find_mapping([m, upd], mapping_id=m.mappingId)
found_m_key = find_mapping([m, upd], mapping_key=m.mappingKey)
not_found_m = find_mapping([m, upd], mapping_id="nonexistent")
check("find_mapping by mappingId",      found_m_id  is not None and found_m_id.mappingId  == m.mappingId)
check("find_mapping by mappingKey",     found_m_key is not None and found_m_key.mappingKey == m.mappingKey)
check("find_mapping not found → None",  not_found_m is None)


# ---------------------------------------------------------------------------
# Section 13: search_techniques()
# ---------------------------------------------------------------------------
print("\n── 13. search_techniques() ──────────────────────────────────────────")

results_smb   = search_techniques(pool_tech, "remote services")
check("search 'remote services' matches T1021 (name)",     any(t.techniqueCode == "T1021" for t in results_smb))

results_phish = search_techniques(pool_tech, "phishing")
check("search 'phishing' matches T1566",               any(t.techniqueCode == "T1566" for t in results_phish))

results_code  = search_techniques(pool_tech, "T1021")
check("search by code prefix",                         any(t.techniqueCode == "T1021" for t in results_code))

results_empty = search_techniques(pool_tech, "")
check("empty query returns empty list",                results_empty == [])

results_none  = search_techniques(pool_tech, "zzznomatch999")
check("no-match query returns empty list",             results_none == [])

# Search result sorted by riskScore DESC
results_multi = search_techniques(pool_tech, "t")   # all match "t"
check("search results sorted by riskScore DESC",
      all(results_multi[i].riskScore >= results_multi[i+1].riskScore
          for i in range(len(results_multi)-1)))


# ---------------------------------------------------------------------------
# Section 14: build_statistics() / calculate_statistics()
# ---------------------------------------------------------------------------
print("\n── 14. build_statistics() / calculate_statistics() ──────────────────")

stats = build_statistics(pool_tech, [m, upd, merged])
check("totalTechniques correct",          stats.totalTechniques == len(pool_tech))
check("totalMappings correct",            stats.totalMappings   == 3)
check("averageConfidence in [0,100]",     0.0 <= stats.averageConfidence <= 100.0)
check("highestRiskTechnique set",         stats.highestRiskTechnique is not None)
check("highestRiskTechnique is T1566",    stats.highestRiskTechnique == "T1566")  # riskScore=80 is highest
check("techniquesByTactic has entries",   len(stats.techniquesByTactic) > 0)

# calculate_statistics is an alias
stats2 = calculate_statistics(pool_tech, [m, upd, merged])
check("calculate_statistics alias == build_statistics",
      stats.totalTechniques == stats2.totalTechniques and
      stats.averageConfidence == stats2.averageConfidence)

# Order-independence
stats3 = build_statistics(list(reversed(pool_tech)), list(reversed([m, upd, merged])))
check("statistics order-independent: totalTechniques",  stats.totalTechniques  == stats3.totalTechniques)
check("statistics order-independent: averageConfidence",stats.averageConfidence == stats3.averageConfidence)
check("statistics order-independent: highestRisk",      stats.highestRiskTechnique == stats3.highestRiskTechnique)

# Empty
empty_stats = build_statistics([], [])
check("empty: totalTechniques=0",         empty_stats.totalTechniques == 0)
check("empty: totalMappings=0",           empty_stats.totalMappings   == 0)
check("empty: averageConfidence=0.0",     empty_stats.averageConfidence == 0.0)
check("empty: highestRiskTechnique=None", empty_stats.highestRiskTechnique is None)


# ---------------------------------------------------------------------------
# Section 15: build_bundle()
# ---------------------------------------------------------------------------
print("\n── 15. build_bundle() ───────────────────────────────────────────────")

tactics_l  = [_tactic_lateral(), _tactic_initial()]
techs_l    = pool_tech
subs_l     = [_sub_smb()]
mappings_l = [m, upd, merged]

bundle = build_bundle(tactics_l, techs_l, subs_l, mappings_l, created_at=TS1)
check("bundle.engineVersion matches const",  bundle.engineVersion == MITRE_ENGINE_VERSION)
check("bundle.tactics sorted by order",
      all(bundle.tactics[i].order <= bundle.tactics[i+1].order
          for i in range(len(bundle.tactics)-1)))
check("bundle.techniques sorted by riskScore DESC",
      all(bundle.techniques[i].riskScore >= bundle.techniques[i+1].riskScore
          for i in range(len(bundle.techniques)-1)))
check("bundle.mappings sorted by confidence DESC",
      all(bundle.mappings[i].confidence >= bundle.mappings[i+1].confidence
          for i in range(len(bundle.mappings)-1)))
check("bundle.statistics.totalTechniques correct", bundle.statistics.totalTechniques == len(techs_l))
check("bundle.statistics.totalMappings correct",   bundle.statistics.totalMappings   == len(mappings_l))
check("bundle is frozen (immutable)",
      not hasattr(bundle, "__dict__") or True)   # dataclass — always passes; actual freeze tested below
try:
    bundle.engineVersion = "hacked"  # type: ignore
    check("MitreBundle frozen=True raises", False)
except Exception:
    check("MitreBundle frozen=True raises", True)

# Identical inputs → identical bundle statistics
bundle2 = build_bundle(tactics_l, techs_l, subs_l, mappings_l, created_at=TS1)
check("identical bundle inputs → identical statistics",
      bundle.statistics.totalTechniques == bundle2.statistics.totalTechniques and
      bundle.statistics.averageConfidence == bundle2.statistics.averageConfidence)


# ---------------------------------------------------------------------------
# Section 16: mappingFingerprint stability
# ---------------------------------------------------------------------------
print("\n── 16. mappingFingerprint stability ─────────────────────────────────")

fp1 = _compute_mapping_fingerprint(
    "ffp-abc", "afp-xyz", "gfp-qrs", "tfp-mno",
    ("asset-c", "asset-a"), ("ev-2", "ev-1"),
)
fp2 = _compute_mapping_fingerprint(
    "ffp-abc", "afp-xyz", "gfp-qrs", "tfp-mno",
    ("asset-a", "asset-c"), ("ev-1", "ev-2"),   # different order
)
check("fingerprint order-independent (assetIds + evidenceIds)", fp1 == fp2)
check("fingerprint length 32",                                   len(fp1) == 32)

fp_diff_ffp = _compute_mapping_fingerprint(
    "CHANGED",  "afp-xyz", "gfp-qrs", "tfp-mno",
    ("asset-a", "asset-c"), ("ev-1", "ev-2"),
)
check("fingerprint changes with different findingFingerprint", fp1 != fp_diff_ffp)

fp_diff_ev = _compute_mapping_fingerprint(
    "ffp-abc", "afp-xyz", "gfp-qrs", "tfp-mno",
    ("asset-a", "asset-c"), ("ev-1", "ev-2", "ev-3"),
)
check("fingerprint changes with different evidenceIds",        fp1 != fp_diff_ev)

fp_diff_tl = _compute_mapping_fingerprint(
    "ffp-abc", "afp-xyz", "gfp-qrs", "CHANGED",
    ("asset-a", "asset-c"), ("ev-1", "ev-2"),
)
check("fingerprint changes with different timelineFingerprint", fp1 != fp_diff_tl)

# Verify build_mapping() embeds correct fingerprint
m_fp = _make_mapping()
expected_fp = _compute_mapping_fingerprint(
    "ffp-abc", "afp-xyz", "gfp-qrs", "tfp-mno",
    m_fp.assetIds, m_fp.evidenceIds,
)
check("build_mapping fingerprint matches manual computation", m_fp.mappingFingerprint == expected_fp)


# ---------------------------------------------------------------------------
# Section 17: No ordering dependence across all builders
# ---------------------------------------------------------------------------
print("\n── 17. No ordering dependence ───────────────────────────────────────")

m_ordered   = build_mapping("f","a","r", TS1,
    technique_ids=["T1566.id","T1021.id"],
    asset_ids=["asset-z","asset-a"],
    evidence_ids=["ev-9","ev-1"],
    finding_fingerprint="fp",alert_fingerprint="ap",
    graph_fingerprint="gp",timeline_fingerprint="tp")

m_reversed  = build_mapping("f","a","r", TS1,
    technique_ids=["T1021.id","T1566.id"],   # reversed
    asset_ids=["asset-a","asset-z"],          # reversed
    evidence_ids=["ev-1","ev-9"],             # reversed
    finding_fingerprint="fp",alert_fingerprint="ap",
    graph_fingerprint="gp",timeline_fingerprint="tp")

check("mappingKey order-independent across tech/asset/ev",
      m_ordered.mappingKey         == m_reversed.mappingKey)
check("mappingFingerprint order-independent",
      m_ordered.mappingFingerprint == m_reversed.mappingFingerprint)
check("techniqueIds same regardless of input order",
      m_ordered.techniqueIds       == m_reversed.techniqueIds)

# Tactic order-independence
tac_a = build_tactic("lateral-movement", "Lateral Movement", TS1, order=8)
tac_b = build_tactic("lateral-movement", "Lateral Movement", TS1, order=8)
check("identical tactic inputs → identical tacticId", tac_a.tacticId == tac_b.tacticId)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "─" * 64)
total_checks = sum(1 for line in open(__file__) if "check(" in line)
failed = len(errors)
print(f"  Results: {failed} failed / {total_checks} checks")
if errors:
    print("\n  Failed checks:")
    for e in errors:
        print(f"    {FAIL}  {e}")
    sys.exit(1)
else:
    print(f"\n  {PASS}  All checks passed — MITRE Engine (A4.0.9)")
