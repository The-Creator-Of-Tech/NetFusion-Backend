"""
NetFusion Search Engine
Unified in-memory cross-entity search index across Cases, Investigations,
Evidence, Analyst Notes, Timeline Events, Tasks, Tags, Assets, IOCs, and MITRE mappings.
"""

from typing import Any, Dict, List, Optional, Set

from .domain import AnalystNote, Case, Evidence, Investigation, Task, TimelineEvent


class SearchEngine:
    """Unified multi-domain search engine for investigations and workflow entities."""

    def __init__(self):
        self.cases: List[Case] = []
        self.investigations: List[Investigation] = []
        self.evidence: List[Evidence] = []
        self.notes: List[AnalystNote] = []
        self.timeline_events: List[TimelineEvent] = []
        self.tasks: List[Task] = []

        self._indexed_case_ids: Set[str] = set()
        self._indexed_inv_ids: Set[str] = set()
        self._indexed_evidence_ids: Set[str] = set()
        self._indexed_note_ids: Set[str] = set()
        self._indexed_timeline_ids: Set[str] = set()
        self._indexed_task_ids: Set[str] = set()

    def index_investigation(self, inv: Investigation) -> None:
        """Indexes an investigation and all child entities (tasks, evidence, notes, timeline)."""
        if inv.investigation_id not in self._indexed_inv_ids:
            self.investigations.append(inv)
            self._indexed_inv_ids.add(inv.investigation_id)

        for task in inv.tasks:
            if task.task_id not in self._indexed_task_ids:
                self.tasks.append(task)
                self._indexed_task_ids.add(task.task_id)

        for ev in inv.evidence_list:
            if ev.evidence_id not in self._indexed_evidence_ids:
                self.evidence.append(ev)
                self._indexed_evidence_ids.add(ev.evidence_id)

        for note in inv.notes:
            if note.note_id not in self._indexed_note_ids:
                self.notes.append(note)
                self._indexed_note_ids.add(note.note_id)

        for event in inv.timeline:
            if event.event_id not in self._indexed_timeline_ids:
                self.timeline_events.append(event)
                self._indexed_timeline_ids.add(event.event_id)

    def index_case(self, case: Case) -> None:
        """Indexes a Case and its associated investigations."""
        if case.case_id not in self._indexed_case_ids:
            self.cases.append(case)
            self._indexed_case_ids.add(case.case_id)
        for inv in case.investigations:
            self.index_investigation(inv)

    def search(
        self,
        query: str,
        entity_types: Optional[List[str]] = None,
        tag: Optional[str] = None,
        ioc: Optional[str] = None,
        mitre_id: Optional[str] = None,
    ) -> Dict[str, List[Any]]:
        """
        Executes unified search across indexed entities.
        Returns a dict mapping entity category name to list of matching objects.
        """
        results: Dict[str, List[Any]] = {
            "cases": [],
            "investigations": [],
            "evidence": [],
            "notes": [],
            "timeline": [],
            "tasks": [],
        }

        q = query.lower().strip() if query else ""
        target_types = set(t.lower() for t in entity_types) if entity_types else {"cases", "investigations", "evidence", "notes", "timeline", "tasks"}

        # Search Cases
        if "cases" in target_types:
            for case in self.cases:
                if self._match_case(case, q, tag):
                    results["cases"].append(case)

        # Search Investigations
        if "investigations" in target_types:
            for inv in self.investigations:
                if self._match_investigation(inv, q, tag, ioc, mitre_id):
                    results["investigations"].append(inv)

        # Search Evidence
        if "evidence" in target_types:
            for ev in self.evidence:
                if self._match_evidence(ev, q, tag, ioc):
                    results["evidence"].append(ev)

        # Search Analyst Notes
        if "notes" in target_types:
            for note in self.notes:
                if self._match_note(note, q, tag, ioc, mitre_id):
                    results["notes"].append(note)

        # Search Timeline Events
        if "timeline" in target_types:
            for event in self.timeline_events:
                if self._match_timeline(event, q, tag):
                    results["timeline"].append(event)

        # Search Tasks
        if "tasks" in target_types:
            for task in self.tasks:
                if self._match_task(task, q):
                    results["tasks"].append(task)

        return results

    def _match_case(self, case: Case, q: str, tag: Optional[str]) -> bool:
        if tag and not any(t.name.lower() == tag.lower() for t in case.tags):
            return False
        if not q:
            return True
        return q in case.title.lower() or q in case.summary.lower() or q in case.case_id.lower() or q in case.owner.lower()

    def _match_investigation(
        self,
        inv: Investigation,
        q: str,
        tag: Optional[str],
        ioc: Optional[str],
        mitre_id: Optional[str],
    ) -> bool:
        if tag and not any(t.name.lower() == tag.lower() for t in inv.tags):
            return False
        if mitre_id and not any(m.technique_id.lower() == mitre_id.lower() or m.tactic_id.lower() == mitre_id.lower() for m in inv.mitre_mappings):
            return False
        if ioc:
            found_ioc = any(ioc.lower() in asset.lower() for asset in inv.affected_assets) or any(ioc.lower() in user.lower() for user in inv.affected_users)
            if not found_ioc:
                return False
        if not q:
            return True

        fields_to_check = [
            inv.title,
            inv.summary,
            inv.description,
            inv.investigation_id,
            inv.owner,
            inv.final_verdict or "",
            inv.root_cause or "",
            " ".join(inv.affected_assets),
            " ".join(inv.affected_users),
            " ".join(inv.findings),
        ]
        return any(q in field.lower() for field in fields_to_check)

    def _match_evidence(self, ev: Evidence, q: str, tag: Optional[str], ioc: Optional[str]) -> bool:
        if tag and not any(t.name.lower() == tag.lower() for t in ev.tags):
            return False
        if ioc:
            if not (ioc.lower() in ev.name.lower() or ioc.lower() in ev.description.lower() or ioc.lower() in ev.hash_sha256.lower()):
                return False
        if not q:
            return True
        fields = [ev.name, ev.description, ev.hash_sha256, ev.hash_md5, ev.evidence_id, str(ev.source)]
        return any(q in f.lower() for f in fields)

    def _match_note(
        self,
        note: AnalystNote,
        q: str,
        tag: Optional[str],
        ioc: Optional[str],
        mitre_id: Optional[str],
    ) -> bool:
        if tag and not any(t.name.lower() == tag.lower() for t in note.tags):
            return False
        if ioc and not any(ioc.lower() in r.lower() for r in note.ioc_references):
            return False
        if mitre_id and not any(mitre_id.lower() in r.lower() for r in note.mitre_references):
            return False
        if not q:
            return True
        fields = [note.title, note.content, note.author, " ".join(note.mentions)]
        return any(q in f.lower() for f in fields)

    def _match_timeline(self, event: TimelineEvent, q: str, tag: Optional[str]) -> bool:
        if tag and tag not in event.tags:
            return False
        if not q:
            return True
        fields = [event.summary, event.description, event.actor, event.source, event.event_type]
        return any(q in f.lower() for f in fields)

    def _match_task(self, task: Task, q: str) -> bool:
        if not q:
            return True
        fields = [task.title, task.description, task.assignee or "", task.status.value]
        return any(q in f.lower() for f in fields)
