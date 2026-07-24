"""
ATRE Memory Engine — NetFusion IL-9
====================================
Tracks investigation memory, analyst confirmations, dismissed hypotheses, false positives, and pattern reuse.
"""

from typing import Dict, List, Optional
import time
from netfusion_ai.reasoning.models import MemoryItem


class InvestigationMemoryEngine:
    """
    Stores and retrieves historical investigation context to refine confidence,
    filter known false positives, and reuse established threat patterns.
    """

    def __init__(self):
        self._store: Dict[str, MemoryItem] = {}

    def store_memory(
        self,
        investigation_id: str,
        pattern_type: str,
        analyst_confirmations: Optional[List[str]] = None,
        dismissed_hypotheses: Optional[List[str]] = None,
        known_false_positives: Optional[List[str]] = None,
        lessons_learned: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> MemoryItem:
        mem_id = f"mem-{investigation_id}"
        item = MemoryItem(
            memory_id=mem_id,
            investigation_id=investigation_id,
            pattern_type=pattern_type,
            analyst_confirmations=analyst_confirmations or [],
            dismissed_hypotheses=dismissed_hypotheses or [],
            known_false_positives=known_false_positives or [],
            lessons_learned=lessons_learned or [],
            tags=tags or [],
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._store[mem_id] = item
        return item

    def get_memory(self, investigation_id: str) -> Optional[MemoryItem]:
        return self._store.get(f"mem-{investigation_id}")

    def query_memories(
        self, pattern_type: Optional[str] = None, tag: Optional[str] = None
    ) -> List[MemoryItem]:
        matches: List[MemoryItem] = []
        for mem in self._store.values():
            if pattern_type and mem.pattern_type != pattern_type:
                continue
            if tag and tag not in mem.tags:
                continue
            matches.append(mem)
        return matches
