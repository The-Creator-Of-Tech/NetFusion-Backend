"""
XML Parser for official MITRE CAPEC dataset.
Parses the MITRE CAPEC XML catalog into raw Python dicts preserving every available field.
"""

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union

# CAPEC catalog XML namespace
_NS = "http://capec.mitre.org/capec-3"


def _ns(tag: str) -> str:
    return f"{{{_NS}}}{tag}"


def _text(el: Optional[ET.Element]) -> Optional[str]:
    """Returns stripped text content of an element and all its descendants, or None."""
    if el is None:
        return None
    parts: List[str] = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        child_text = _text(child)
        if child_text:
            parts.append(child_text)
        if child.tail:
            parts.append(child.tail.strip())
    result = " ".join(p for p in parts if p)
    return result or None


def _iter_children(parent: ET.Element, tag: str) -> List[ET.Element]:
    return parent.findall(_ns(tag))


def _get_child(parent: ET.Element, tag: str) -> Optional[ET.Element]:
    return parent.find(_ns(tag))


class CapecParser:
    """
    Parses official MITRE CAPEC XML catalog (capec_vX.X.xml) into structured Python dicts.
    Extracts every available field including execution flows, prerequisites, skills, and cross-references.
    """

    def parse(self, raw_data: Union[str, bytes]) -> Dict[str, Any]:
        """
        Parses raw CAPEC XML into structured catalog dict.
        Returns:
            {
              "catalog_version": str,
              "attack_patterns": [raw_pattern_dict, ...],
              "categories": [...],
              "views": [...],
              "external_references": [...],
            }
        """
        if isinstance(raw_data, str):
            raw_data = raw_data.encode("utf-8")

        try:
            root = ET.fromstring(raw_data)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid CAPEC XML: {exc}") from exc

        catalog_version = root.get("Version") or root.get("version") or "unknown"
        date = root.get("Date") or root.get("date") or ""

        attack_patterns: List[Dict[str, Any]] = []
        categories: List[Dict[str, Any]] = []
        views: List[Dict[str, Any]] = []
        ext_refs_raw: List[Dict[str, Any]] = []

        # Attack Patterns
        aps_el = _get_child(root, "Attack_Patterns")
        if aps_el is not None:
            for ap in _iter_children(aps_el, "Attack_Pattern"):
                attack_patterns.append(self._parse_attack_pattern(ap))

        # Categories
        cats_el = _get_child(root, "Categories")
        if cats_el is not None:
            for c in _iter_children(cats_el, "Category"):
                categories.append(self._parse_category(c))

        # Views
        views_el = _get_child(root, "Views")
        if views_el is not None:
            for v in _iter_children(views_el, "View"):
                views.append(self._parse_view(v))

        # External References
        ext_refs_el = _get_child(root, "External_References")
        if ext_refs_el is not None:
            for ref in _iter_children(ext_refs_el, "External_Reference"):
                ext_refs_raw.append(self._parse_external_reference(ref))

        return {
            "catalog_version": catalog_version,
            "date": date,
            "attack_patterns": attack_patterns,
            "categories": categories,
            "views": views,
            "external_references": ext_refs_raw,
            "total_attack_patterns": len(attack_patterns),
        }

    def _parse_attack_pattern(self, ap: ET.Element) -> Dict[str, Any]:
        capec_id = f"CAPEC-{ap.get('ID', '')}"
        name = ap.get("Name", "")
        abstraction = ap.get("Abstraction", "")
        status = ap.get("Status", "")
        likelihood_of_attack = ap.get("Likelihood_Of_Attack", "")
        typical_severity = ap.get("Typical_Severity", "")

        description = _text(_get_child(ap, "Description"))
        extended_description = _text(_get_child(ap, "Extended_Description"))

        # Execution Flow
        execution_flow: List[Dict[str, Any]] = []
        ef_el = _get_child(ap, "Execution_Flow")
        if ef_el is not None:
            for step_el in _iter_children(ef_el, "Attack_Step"):
                step_num_str = _text(_get_child(step_el, "Step"))
                step_num = int(step_num_str) if step_num_str and step_num_str.isdigit() else None
                phase = _text(_get_child(step_el, "Phase"))
                desc = _text(_get_child(step_el, "Description"))
                techniques: List[str] = []
                tech_el = _get_child(step_el, "Technique")
                if tech_el is not None:
                    t = _text(tech_el)
                    if t:
                        techniques.append(t)
                execution_flow.append({
                    "step_number": step_num,
                    "phase": phase,
                    "description": desc,
                    "techniques": techniques,
                })

        # Prerequisites
        prerequisites: List[str] = []
        pre_el = _get_child(ap, "Prerequisites")
        if pre_el is not None:
            for prereq in _iter_children(pre_el, "Prerequisite"):
                t = _text(prereq)
                if t:
                    prerequisites.append(t)

        # Skills Required
        skills_required: List[Dict[str, Any]] = []
        skills_el = _get_child(ap, "Skills_Required")
        if skills_el is not None:
            for skill in _iter_children(skills_el, "Skill"):
                skills_required.append({
                    "level": skill.get("Level"),
                    "description": _text(skill),
                })

        # Resources Required
        resources_required: List[str] = []
        res_el = _get_child(ap, "Resources_Required")
        if res_el is not None:
            for res in _iter_children(res_el, "Resource"):
                t = _text(res)
                if t:
                    resources_required.append(t)

        # Indicators
        indicators: List[str] = []
        ind_el = _get_child(ap, "Indicators")
        if ind_el is not None:
            for ind in _iter_children(ind_el, "Indicator"):
                t = _text(ind)
                if t:
                    indicators.append(t)

        # Consequences
        consequences: List[Dict[str, Any]] = []
        cons_el = _get_child(ap, "Consequences")
        if cons_el is not None:
            for con in _iter_children(cons_el, "Consequence"):
                scope_els = _iter_children(con, "Scope")
                impact_els = _iter_children(con, "Impact")
                note_el = _get_child(con, "Note")
                likelihood_el = _get_child(con, "Likelihood")
                consequences.append({
                    "scope": [_text(s) for s in scope_els if _text(s)],
                    "impact": [_text(i) for i in impact_els if _text(i)],
                    "note": _text(note_el),
                    "likelihood": _text(likelihood_el),
                })

        # Mitigations
        mitigations: List[Dict[str, Any]] = []
        mit_el = _get_child(ap, "Mitigations")
        if mit_el is not None:
            for mit in _iter_children(mit_el, "Mitigation"):
                phase_els = _iter_children(mit, "Phase")
                mitigations.append({
                    "description": _text(_get_child(mit, "Description")) or _text(mit),
                    "phase": [_text(p) for p in phase_els if _text(p)],
                    "strategy": mit.get("Strategy"),
                    "effectiveness": _text(_get_child(mit, "Effectiveness")),
                })

        # Detection
        detection: List[Dict[str, Any]] = []
        det_el = _get_child(ap, "Detection_Methods")
        if det_el is not None:
            for dm in _iter_children(det_el, "Detection_Method"):
                detection.append({
                    "method": _text(_get_child(dm, "Method")),
                    "description": _text(_get_child(dm, "Description")),
                    "effectiveness": _text(_get_child(dm, "Effectiveness")),
                    "effectiveness_notes": _text(_get_child(dm, "Effectiveness_Notes")),
                })

        # Example Instances
        example_instances: List[str] = []
        ex_el = _get_child(ap, "Example_Instances")
        if ex_el is not None:
            for ex in _iter_children(ex_el, "Example"):
                t = _text(ex)
                if t:
                    example_instances.append(t)

        # Related Attack Patterns (CAPEC-to-CAPEC)
        related_attack_patterns: List[Dict[str, Any]] = []
        rap_el = _get_child(ap, "Related_Attack_Patterns")
        if rap_el is not None:
            for rap in _iter_children(rap_el, "Related_Attack_Pattern"):
                capec_ref_id = rap.get("CAPEC_ID")
                if capec_ref_id:
                    related_attack_patterns.append({
                        "capec_id": f"CAPEC-{capec_ref_id}",
                        "nature": rap.get("Nature"),
                        "view_id": rap.get("View_ID"),
                    })

        # Related Weaknesses (CAPEC-to-CWE)
        related_weaknesses: List[str] = []
        rw_el = _get_child(ap, "Related_Weaknesses")
        if rw_el is not None:
            for rw in _iter_children(rw_el, "Related_Weakness"):
                cwe_id = rw.get("CWE_ID")
                if cwe_id:
                    related_weaknesses.append(f"CWE-{cwe_id}")

        # Taxonomy Mappings (incl. ATT&CK)
        taxonomy_mappings: List[Dict[str, Any]] = []
        tax_el = _get_child(ap, "Taxonomy_Mappings")
        if tax_el is not None:
            for tm in _iter_children(tax_el, "Taxonomy_Mapping"):
                taxonomy_mappings.append({
                    "taxonomy_name": tm.get("Taxonomy_Name"),
                    "entry_id": _text(_get_child(tm, "Entry_ID")),
                    "entry_name": _text(_get_child(tm, "Entry_Name")),
                    "mapping_fit": _text(_get_child(tm, "Mapping_Fit")),
                })

        # References
        references: List[Dict[str, Any]] = []
        refs_el = _get_child(ap, "References")
        if refs_el is not None:
            for ref in _iter_children(refs_el, "Reference"):
                references.append({"reference_id": ref.get("External_Reference_ID")})

        # Notes
        notes_el = _get_child(ap, "Notes")
        notes: Optional[str] = None
        if notes_el is not None:
            all_notes = []
            for note in _iter_children(notes_el, "Note"):
                t = _text(note)
                if t:
                    all_notes.append(t)
            notes = " | ".join(all_notes) or None

        return {
            "capec_id": capec_id,
            "name": name,
            "abstraction": abstraction,
            "status": status,
            "description": description,
            "extended_description": extended_description,
            "likelihood_of_attack": likelihood_of_attack,
            "typical_severity": typical_severity,
            "execution_flow": execution_flow,
            "prerequisites": prerequisites,
            "skills_required": skills_required,
            "resources_required": resources_required,
            "indicators": indicators,
            "consequences": consequences,
            "mitigations": mitigations,
            "detection": detection,
            "example_instances": example_instances,
            "related_attack_patterns": related_attack_patterns,
            "related_weaknesses": related_weaknesses,
            "taxonomy_mappings": taxonomy_mappings,
            "references": references,
            "notes": notes,
            "url": f"https://capec.mitre.org/data/definitions/{ap.get('ID', '')}.html",
        }

    def _parse_category(self, c: ET.Element) -> Dict[str, Any]:
        return {
            "capec_id": f"CAPEC-{c.get('ID', '')}",
            "name": c.get("Name", ""),
            "status": c.get("Status", ""),
            "description": _text(_get_child(c, "Summary")),
            "type": "Category",
        }

    def _parse_view(self, v: ET.Element) -> Dict[str, Any]:
        return {
            "view_id": v.get("ID", ""),
            "name": v.get("Name", ""),
            "type": v.get("Type", ""),
            "status": v.get("Status", ""),
            "description": _text(_get_child(v, "Objective")),
        }

    def _parse_external_reference(self, ref: ET.Element) -> Dict[str, Any]:
        reference_id = ref.get("Reference_ID", "")
        authors: List[str] = []
        for author_el in _iter_children(ref, "Author"):
            t = _text(author_el)
            if t:
                authors.append(t)
        return {
            "reference_id": reference_id,
            "author": authors,
            "title": _text(_get_child(ref, "Title")),
            "edition": _text(_get_child(ref, "Edition")),
            "url": _text(_get_child(ref, "URL")),
            "publication_year": _text(_get_child(ref, "Publication_Year")),
            "publisher": _text(_get_child(ref, "Publisher")),
        }
