"""
NVD JSON 2.0 Parser for NetFusion IL-3 NVD Pipeline.
Parses raw NVD JSON strings, bytes, and dictionary payloads into structured raw CVE dicts.
"""

import json
from typing import Any, Dict, List, Union
from netfusion_intelligence.core.exceptions import ParsingError


class NvdParser:
    """
    Parses official NVD CVE JSON 2.0 API responses and bulk feed objects.
    Extracts raw CVE objects without dropping fields.
    """

    def parse(self, raw_data: Union[str, bytes, Dict[str, Any], List[Any]]) -> Dict[str, Any]:
        """
        Parses raw NVD payload into structured dict containing 'vulnerabilities' list and response metadata.
        """
        if raw_data is None:
            raise ParsingError("Raw NVD payload is None")

        parsed_json: Dict[str, Any] = {}

        if isinstance(raw_data, (str, bytes)):
            try:
                parsed_json = json.loads(raw_data)
            except Exception as e:
                raise ParsingError(f"Failed to parse NVD JSON payload: {e}")
        elif isinstance(raw_data, dict):
            parsed_json = raw_data
        elif isinstance(raw_data, list):
            parsed_json = {"vulnerabilities": raw_data}
        else:
            raise ParsingError(f"Unsupported NVD raw data type: {type(raw_data)}")

        if not isinstance(parsed_json, dict):
            raise ParsingError("Parsed NVD JSON root is not a dictionary")

        # Extract items
        vulns = []
        if "vulnerabilities" in parsed_json and isinstance(parsed_json["vulnerabilities"], list):
            vulns = parsed_json["vulnerabilities"]
        elif "cve" in parsed_json:
            vulns = [parsed_json]
        elif "id" in parsed_json:
            vulns = [{"cve": parsed_json}]

        cve_items = []
        for item in vulns:
            if isinstance(item, dict):
                if "cve" in item and isinstance(item["cve"], dict):
                    cve_items.append(item["cve"])
                elif "id" in item:
                    cve_items.append(item)

        return {
            "format": parsed_json.get("format", "NVD_CVE"),
            "version": parsed_json.get("version", "2.0"),
            "timestamp": parsed_json.get("timestamp"),
            "total_results": parsed_json.get("totalResults", len(cve_items)),
            "results_per_page": parsed_json.get("resultsPerPage", len(cve_items)),
            "start_index": parsed_json.get("startIndex", 0),
            "items": cve_items,
        }
