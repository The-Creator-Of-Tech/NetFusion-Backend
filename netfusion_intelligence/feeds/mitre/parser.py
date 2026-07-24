"""
STIX 2.1 Parser for official MITRE ATT&CK Enterprise dataset.
Parses STIX 2.1 JSON bundle into categorized STIX object collections.
"""

import json
from typing import Any, Dict, List, Union


class MitreParser:
    """
    Parses official MITRE ATT&CK STIX 2.1 JSON bundle.
    Extracts tactics, techniques, sub-techniques, groups, software, campaigns, mitigations,
    data sources, data components, assets, and relationships.
    """

    SUPPORTED_STIX_TYPES = {
        "x-mitre-tactic",
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "campaign",
        "course-of-action",
        "x-mitre-data-source",
        "x-mitre-data-component",
        "x-mitre-asset",
        "relationship",
        "marking-definition",
        "identity",
    }

    def parse(self, raw_data: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parses raw STIX string/bytes/dict into structured STIX parsed data structure.
        """
        if isinstance(raw_data, (str, bytes)):
            try:
                bundle = json.loads(raw_data)
            except Exception as ex:
                raise ValueError(f"Invalid JSON in STIX 2.1 bundle payload: {ex}")
        elif isinstance(raw_data, dict):
            bundle = raw_data
        else:
            raise ValueError(f"Unsupported raw data type for parsing: {type(raw_data)}")

        if not isinstance(bundle, dict):
            raise ValueError("Parsed STIX data must be a JSON object")

        b_type = bundle.get("type")
        if b_type != "bundle":
            raise ValueError(f"Expected STIX bundle object with type 'bundle', got '{b_type}'")

        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            raise ValueError("STIX bundle 'objects' field must be a list")

        categorized: Dict[str, List[Dict[str, Any]]] = {}
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            stix_type = obj.get("type", "unknown")
            if stix_type not in categorized:
                categorized[stix_type] = []
            categorized[stix_type].append(obj)

        return {
            "bundle_id": bundle.get("id", ""),
            "spec_version": bundle.get("spec_version", "2.1"),
            "objects": objects,
            "objects_by_type": categorized,
            "tactics": categorized.get("x-mitre-tactic", []),
            "techniques": categorized.get("attack-pattern", []),
            "groups": categorized.get("intrusion-set", []),
            "software": categorized.get("malware", []) + categorized.get("tool", []),
            "malware": categorized.get("malware", []),
            "tools": categorized.get("tool", []),
            "campaigns": categorized.get("campaign", []),
            "mitigations": categorized.get("course-of-action", []),
            "data_sources": categorized.get("x-mitre-data-source", []),
            "data_components": categorized.get("x-mitre-data-component", []),
            "assets": categorized.get("x-mitre-asset", []),
            "relationships": categorized.get("relationship", []),
        }
