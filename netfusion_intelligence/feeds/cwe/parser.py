"""
XML Parser for official MITRE CWE dataset.
Parses the MITRE CWE XML catalog into raw Python dicts preserving every available field.
"""

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union

# CWE catalog XML namespace
_NS = "http://cwe.mitre.org/cwe-7"


def _ns(tag: str) -> str:
    """Returns a fully qualified tag with the CWE namespace."""
    return f"{{{_NS}}}{tag}"


def _text(el: Optional[ET.Element]) -> Optional[str]:
    """Returns stripped text content of an element, or None."""
    if el is None:
        return None
    parts: List[str] = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        if child.tail:
            parts.append(child.tail.strip())
        if child.text:
            parts.append(child.text.strip())
    result = " ".join(p for p in parts if p)
    return result or None


def _iter_children(parent: ET.Element, tag: str) -> List[ET.Element]:
    """Returns direct children matching a CWE-namespaced tag."""
    return parent.findall(_ns(tag))


def _get_child(parent: ET.Element, tag: str) -> Optional[ET.Element]:
    return parent.find(_ns(tag))


class CweParser:
    """
    Parses official MITRE CWE XML catalog (cwec_vX.X.xml) into structured Python dicts.
    Extracts every available field.
    """

    def parse(self, raw_data: Union[str, bytes]) -> Dict[str, Any]:
        """
        Parses raw CWE XML bytes/string into structured catalog dict.
        Returns:
            {
              "catalog_version": str,
              "weaknesses": [raw_weakness_dict, ...],
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
            raise ValueError(f"Invalid CWE XML: {exc}") from exc

        # Determine catalog version from attribute
        catalog_version = root.get("Version") or root.get("version") or "unknown"
        date = root.get("Date") or root.get("date") or ""

        weaknesses: List[Dict[str, Any]] = []
        categories: List[Dict[str, Any]] = []
        views: List[Dict[str, Any]] = []
        ext_refs_raw: List[Dict[str, Any]] = []

        # ---- Weaknesses ----
        weaknesses_el = _get_child(root, "Weaknesses")
        if weaknesses_el is not None:
            for w in _iter_children(weaknesses_el, "Weakness"):
                weaknesses.append(self._parse_weakness(w))

        # ---- Categories ----
        categories_el = _get_child(root, "Categories")
        if categories_el is not None:
            for c in _iter_children(categories_el, "Category"):
                categories.append(self._parse_category(c))

        # ---- Views ----
        views_el = _get_child(root, "Views")
        if views_el is not None:
            for v in _iter_children(views_el, "View"):
                views.append(self._parse_view(v))

        # ---- External References ----
        ext_refs_el = _get_child(root, "External_References")
        if ext_refs_el is not None:
            for ref in _iter_children(ext_refs_el, "External_Reference"):
                ext_refs_raw.append(self._parse_external_reference(ref))

        return {
            "catalog_version": catalog_version,
            "date": date,
            "weaknesses": weaknesses,
            "categories": categories,
            "views": views,
            "external_references": ext_refs_raw,
            "total_weaknesses": len(weaknesses),
        }

    def _parse_weakness(self, w: ET.Element) -> Dict[str, Any]:
        cwe_id = f"CWE-{w.get('ID', '')}"
        name = w.get("Name", "")
        abstraction = w.get("Abstraction", "")
        structure = w.get("Structure", "")
        status = w.get("Status", "")

        description = _text(_get_child(w, "Description"))
        extended_description = _text(_get_child(w, "Extended_Description"))
        likelihood_of_exploit = _text(_get_child(w, "Likelihood_Of_Exploit"))
        background_details = _text(_get_child(w, "Background_Details"))

        # Alternate Terms
        alternate_terms: List[str] = []
        at_el = _get_child(w, "Alternate_Terms")
        if at_el is not None:
            for term_el in _iter_children(at_el, "Alternate_Term"):
                t = _text(_get_child(term_el, "Term"))
                if t:
                    alternate_terms.append(t)

        # Modes of Introduction
        modes: List[Dict[str, Any]] = []
        intro_el = _get_child(w, "Modes_Of_Introduction")
        if intro_el is not None:
            for intro in _iter_children(intro_el, "Introduction"):
                phase = _text(_get_child(intro, "Phase"))
                note = _text(_get_child(intro, "Note"))
                modes.append({"phase": phase, "note": note})

        # Applicable Platforms
        platforms: List[Dict[str, Any]] = []
        plat_el = _get_child(w, "Applicable_Platforms")
        if plat_el is not None:
            for plat_type in ["Language", "Technology", "Operating_System", "Architecture"]:
                for p in _iter_children(plat_el, plat_type):
                    platforms.append({
                        "platform_type": plat_type,
                        "name": p.get("Name"),
                        "prevalence": p.get("Prevalence"),
                        "class": p.get("Class"),
                    })

        # Consequences
        consequences: List[Dict[str, Any]] = []
        cons_el = _get_child(w, "Common_Consequences")
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

        # Detection Methods
        detection_methods: List[Dict[str, Any]] = []
        det_el = _get_child(w, "Detection_Methods")
        if det_el is not None:
            for dm in _iter_children(det_el, "Detection_Method"):
                detection_methods.append({
                    "method": _text(_get_child(dm, "Method")),
                    "description": _text(_get_child(dm, "Description")),
                    "effectiveness": _text(_get_child(dm, "Effectiveness")),
                    "effectiveness_notes": _text(_get_child(dm, "Effectiveness_Notes")),
                })

        # Mitigations (Potential_Mitigations)
        mitigations: List[Dict[str, Any]] = []
        mit_el = _get_child(w, "Potential_Mitigations")
        if mit_el is not None:
            for mit in _iter_children(mit_el, "Mitigation"):
                phase_els = _iter_children(mit, "Phase")
                mitigations.append({
                    "phase": [_text(p) for p in phase_els if _text(p)],
                    "description": _text(_get_child(mit, "Description")),
                    "strategy": _text(_get_child(mit, "Strategy")),
                    "effectiveness": _text(_get_child(mit, "Effectiveness")),
                    "effectiveness_notes": _text(_get_child(mit, "Effectiveness_Notes")),
                })

        # Related Weaknesses
        related_weaknesses: List[Dict[str, Any]] = []
        rw_el = _get_child(w, "Related_Weaknesses")
        if rw_el is not None:
            for rw in _iter_children(rw_el, "Related_Weakness"):
                related_weaknesses.append({
                    "cwe_id": f"CWE-{rw.get('CWE_ID', '')}",
                    "nature": rw.get("Nature"),
                    "view_id": rw.get("View_ID"),
                    "ordinal": rw.get("Ordinal"),
                })

        # Taxonomy Mappings
        taxonomy_mappings: List[Dict[str, Any]] = []
        tax_el = _get_child(w, "Taxonomy_Mappings")
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
        refs_el = _get_child(w, "References")
        if refs_el is not None:
            for ref in _iter_children(refs_el, "Reference"):
                references.append({"reference_id": ref.get("External_Reference_ID")})

        # Related Attack Patterns (CAPEC IDs)
        related_attack_patterns: List[str] = []
        rap_el = _get_child(w, "Related_Attack_Patterns")
        if rap_el is not None:
            for rap in _iter_children(rap_el, "Related_Attack_Pattern"):
                capec_id = rap.get("CAPEC_ID")
                if capec_id:
                    related_attack_patterns.append(f"CAPEC-{capec_id}")

        # Affected Resources
        affected_resources: List[str] = []
        ar_el = _get_child(w, "Affected_Resources")
        if ar_el is not None:
            for ar in _iter_children(ar_el, "Affected_Resource"):
                t = _text(ar)
                if t:
                    affected_resources.append(t)

        # Functional Areas
        functional_areas: List[str] = []
        fa_el = _get_child(w, "Functional_Areas")
        if fa_el is not None:
            for fa in _iter_children(fa_el, "Functional_Area"):
                t = _text(fa)
                if t:
                    functional_areas.append(t)

        # Mapping Notes
        mapping_notes_el = _get_child(w, "Mapping_Notes")
        mapping_notes: Optional[str] = None
        if mapping_notes_el is not None:
            usage_el = _get_child(mapping_notes_el, "Usage")
            rationale_el = _get_child(mapping_notes_el, "Rationale")
            comments_el = _get_child(mapping_notes_el, "Comments")
            parts = filter(None, [_text(usage_el), _text(rationale_el), _text(comments_el)])
            mapping_notes = " | ".join(parts) or None

        # Notes
        notes_el = _get_child(w, "Notes")
        notes: Optional[str] = None
        if notes_el is not None:
            all_notes = []
            for note in _iter_children(notes_el, "Note"):
                t = _text(note)
                if t:
                    all_notes.append(t)
            notes = " | ".join(all_notes) or None

        return {
            "cwe_id": cwe_id,
            "name": name,
            "abstraction": abstraction,
            "structure": structure,
            "status": status,
            "description": description,
            "extended_description": extended_description,
            "likelihood_of_exploit": likelihood_of_exploit,
            "background_details": background_details,
            "alternate_terms": alternate_terms,
            "modes_of_introduction": modes,
            "applicable_platforms": platforms,
            "consequences": consequences,
            "detection_methods": detection_methods,
            "mitigations": mitigations,
            "related_weaknesses": related_weaknesses,
            "taxonomy_mappings": taxonomy_mappings,
            "references": references,
            "related_attack_patterns": related_attack_patterns,
            "affected_resources": affected_resources,
            "functional_areas": functional_areas,
            "mapping_notes": mapping_notes,
            "notes": notes,
            "url": f"https://cwe.mitre.org/data/definitions/{w.get('ID', '')}.html",
        }

    def _parse_category(self, c: ET.Element) -> Dict[str, Any]:
        return {
            "cwe_id": f"CWE-{c.get('ID', '')}",
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
