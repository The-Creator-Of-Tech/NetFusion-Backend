"""
Tests for ATRE Investigation Memory Engine.
"""

from netfusion_ai.reasoning import InvestigationMemoryEngine


def test_memory_store_and_query():
    engine = InvestigationMemoryEngine()
    item = engine.store_memory(
        investigation_id="inv-101",
        pattern_type="WHAT_HAPPENED",
        analyst_confirmations=["APT29 Campaign confirmed"],
        dismissed_hypotheses=["Phishing Vector dismissed"],
        known_false_positives=["DevOps IP 10.0.0.99"],
        lessons_learned=["Monitor MOVEit Transfer endpoints"],
        tags=["MOVEit", "APT29"],
    )

    assert item.memory_id == "mem-inv-101"
    fetched = engine.get_memory("inv-101")
    assert fetched is not None
    assert "APT29 Campaign confirmed" in fetched.analyst_confirmations

    queries = engine.query_memories(pattern_type="WHAT_HAPPENED", tag="MOVEit")
    assert len(queries) == 1
