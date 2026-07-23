"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Repository

In-memory thread-safe repository with indexed multi-criteria search for investigations.
"""

import threading
from typing import Dict, List, Optional, Set

from netfusion_investigation.lifecycle.models import Investigation
from netfusion_investigation.lifecycle.persistence import FilePersistence


class InvestigationRepository:
    """Stores, retrieves, and indexes investigations with advanced multi-attribute search."""

    def __init__(self, persistence: Optional[FilePersistence] = None):
        self._persistence = persistence or FilePersistence()
        self._investigations: Dict[str, Investigation] = {}
        self._lock = threading.RLock()

        # Load persisted data on init
        persisted = self._persistence.list_all()
        for inv in persisted:
            self._investigations[inv.id] = inv

    def add(self, investigation: Investigation) -> Investigation:
        with self._lock:
            self._investigations[investigation.id] = investigation
            self._persistence.save(investigation)
            return investigation

    def get(self, investigation_id: str) -> Optional[Investigation]:
        with self._lock:
            return self._investigations.get(investigation_id)

    def get_by_case_id(self, case_id: str) -> Optional[Investigation]:
        with self._lock:
            for inv in self._investigations.values():
                if inv.case_id.lower() == case_id.lower():
                    return inv
            return None

    def update(self, investigation: Investigation) -> Investigation:
        with self._lock:
            self._investigations[investigation.id] = investigation
            self._persistence.save(investigation)
            return investigation

    def delete(self, investigation_id: str) -> bool:
        with self._lock:
            if investigation_id in self._investigations:
                del self._investigations[investigation_id]
                self._persistence.delete(investigation_id)
                return True
            return False

    def list_all() -> List[Investigation]:
        with self._lock:
            return sorted(list(self._investigations.values()), key=lambda x: x.created_at, reverse=True)

    def search(
        self,
        ioc: Optional[str] = None,
        cve: Optional[str] = None,
        asset: Optional[str] = None,
        threat_actor: Optional[str] = None,
        campaign: Optional[str] = None,
        malware: Optional[str] = None,
        analyst: Optional[str] = None,
        workflow: Optional[str] = None,
        timeline: Optional[str] = None,
        tags: Optional[List[str]] = None,
        case_id: Optional[str] = None,
        query: Optional[str] = None,
    ) -> List[Investigation]:
        with self._lock:
            results = list(self._investigations.values())

            if case_id:
                c_lower = case_id.lower()
                results = [i for i in results if c_lower in i.case_id.lower()]

            if analyst:
                a_lower = analyst.lower()
                results = [i for i in results if a_lower in i.owner.lower()]

            if tags:
                tag_set = {t.lower() for t in tags}
                results = [i for i in results if tag_set.issubset({lbl.lower() for lbl in i.labels})]

            if ioc:
                ioc_l = ioc.lower()
                results = [i for i in results if any(ioc_l in val.lower() for val in i.links.ioc_values)]

            if cve:
                cve_l = cve.lower()
                results = [i for i in results if any(cve_l in val.lower() for val in i.links.cve_ids)]

            if asset:
                asset_l = asset.lower()
                results = [i for i in results if any(asset_l in val.lower() for val in i.links.asset_ids)]

            if threat_actor:
                ta_l = threat_actor.lower()
                results = [i for i in results if any(ta_l in val.lower() for val in i.links.threat_actors)]

            if campaign:
                camp_l = campaign.lower()
                results = [i for i in results if any(camp_l in val.lower() for val in i.links.campaigns)]

            if malware:
                mal_l = malware.lower()
                results = [i for i in results if any(mal_l in val.lower() for val in i.links.malware_families)]

            if workflow:
                wf_l = workflow.lower()
                results = [i for i in results if any(wf_l in val.lower() for val in i.links.workflow_ids)]

            if timeline:
                tl_l = timeline.lower()
                results = [i for i in results if any(tl_l in val.lower() for val in i.links.timeline_event_ids)]

            if query:
                q_l = query.lower()
                filtered = []
                for i in results:
                    if (
                        q_l in i.id.lower()
                        or q_l in i.case_id.lower()
                        or q_l in i.title.lower()
                        or q_l in i.description.lower()
                        or q_l in i.owner.lower()
                        or any(q_l in tag.lower() for tag in i.labels)
                    ):
                        filtered.append(i)
                results = filtered

            results.sort(key=lambda x: x.created_at, reverse=True)
            return results

    def clear(self) -> None:
        with self._lock:
            for inv_id in list(self._investigations.keys()):
                self.delete(inv_id)
