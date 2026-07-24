"""
Unit tests for NVD CIIL Identity Mapper (mapper.py).
"""

from netfusion_intelligence.feeds.nvd.mapper import NvdCiilMapper
from netfusion_intelligence.feeds.nvd.normalizer import NvdNormalizer
from netfusion_intelligence.feeds.nvd.tests.sample_nvd import SAMPLE_NVD_CVE_2024_1234
from netfusion_intelligence.identity.repository import IdentityRepository
from netfusion_intelligence.identity.resolver import IdentityResolver
from netfusion_intelligence.repository.sqlalchemy_repository import SQLAlchemyIntelligenceRepository


def test_ciil_mapping():
    sql_repo = SQLAlchemyIntelligenceRepository(db_url="sqlite:///:memory:")
    id_repo = IdentityRepository(":memory:")
    resolver = IdentityResolver(repository=id_repo)
    mapper = NvdCiilMapper(resolver=resolver)
    normalizer = NvdNormalizer()

    cve = normalizer.normalize_cve(SAMPLE_NVD_CVE_2024_1234)
    entity = mapper.resolve_cve_entity(cve, dataset_version="2.0.0")

    assert entity is not None
    assert entity.entity_type == "CVE"
    assert entity.display_name == "CVE-2024-1234"
    assert any(ext.identifier == "CVE-2024-1234" for ext in entity.external_identifiers)

    # Check CWE entity was also created in CIIL
    cwe_entity = resolver.repository.find_by_external_id("CWE", "CWE-89")
    assert len(cwe_entity) > 0
    assert cwe_entity[0].display_name == "CWE-89"
