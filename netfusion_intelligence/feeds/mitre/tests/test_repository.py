"""
Unit & Integration tests for MitreRepository & SQLAlchemyIntelligenceRepository MITRE queries.
"""

from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository
from netfusion_intelligence.feeds.mitre.normalizer import MitreNormalizer
from netfusion_intelligence.feeds.mitre.parser import MitreParser
from netfusion_intelligence.feeds.mitre.repository import MitreRepository
from netfusion_intelligence.feeds.mitre.tests.sample_stix import SAMPLE_STIX_BUNDLE


def test_repository_store_and_search():
    repo = SQLAlchemyIntelligenceRepository("sqlite:///:memory:")
    mitre_repo = MitreRepository(repo)

    parsed = MitreParser().parse(SAMPLE_STIX_BUNDLE)
    norm = MitreNormalizer().normalize(parsed)

    version_id = "v2.1-test-001"
    entities = list(norm["entities"].values())
    relationships = norm["relationships"]

    # Store entities & relationships
    res_ent = mitre_repo.store_entities(version_id, entities)
    assert res_ent["inserted"] == 9

    rel_cnt = mitre_repo.store_relationships(version_id, relationships)
    assert rel_cnt == 4

    # Search by ATT&CK ID T1059
    obj = mitre_repo.get_object("T1059", version_id=version_id)
    assert obj is not None
    assert obj["name"] == "Command and Scripting Interpreter"
    assert obj["attack_id"] == "T1059"

    # Search by technique_id T1059 (finds T1059 and its sub-technique T1059.001)
    techs = mitre_repo.search(technique_id="T1059", version_id=version_id)
    assert len(techs) == 2

    # Search by tactic
    exec_techs = mitre_repo.list_techniques(tactic="execution", version_id=version_id)
    assert len(exec_techs) >= 1

    # Search by alias "Fancy Bear"
    groups = mitre_repo.search(alias="Fancy Bear", version_id=version_id)
    assert len(groups) == 1
    assert groups[0]["attack_id"] == "G0007"

    # Search by keyword
    kw_res = mitre_repo.search(query="Mimikatz", version_id=version_id)
    assert len(kw_res) == 1
    assert kw_res[0]["attack_id"] == "S0002"

    # Get relationships for G0007 / APT28
    rels = mitre_repo.get_relationships(source_ref="G0007", version_id=version_id)
    assert len(rels) == 2

    # Get statistics
    stats = mitre_repo.get_statistics(version_id=version_id)
    assert stats["total_objects"] == 9
    assert stats["total_relationships"] == 4
    assert stats["techniques_count"] == 1
    assert stats["subtechniques_count"] == 1
    assert stats["groups_count"] == 1
