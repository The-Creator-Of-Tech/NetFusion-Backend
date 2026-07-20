"""
Tests for NetFusion MemoryManager.
"""

import pytest

from netfusion_ai import MemoryManager, ConversationTurn, ContextBuilder


def test_memory_manager_scoping():
    mem = MemoryManager(max_history_turns=5)

    cb = ContextBuilder()
    ctx1 = cb.build_context(investigation={"investigation_id": "INV-1"})
    ctx2 = cb.build_context(investigation={"investigation_id": "INV-2"})

    mem.set_context("INV-1", ctx1)
    mem.set_context("INV-2", ctx2)

    assert mem.get_context("INV-1").investigation["investigation_id"] == "INV-1"
    assert mem.get_context("INV-2").investigation["investigation_id"] == "INV-2"

    turn1 = ConversationTurn(prompt="What happened in INV-1?", response="Phishing email observed.")
    mem.add_turn("INV-1", turn1)

    scope1 = mem.get_or_create_scope("INV-1")
    scope2 = mem.get_or_create_scope("INV-2")

    assert len(scope1.conversation_history) == 1
    assert len(scope2.conversation_history) == 0

    mem.cache_prompt("INV-1", "p1", "Rendered prompt")
    assert mem.get_cached_prompt("INV-1", "p1") == "Rendered prompt"
    assert mem.get_cached_prompt("INV-2", "p1") is None
