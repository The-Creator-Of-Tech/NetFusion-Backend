"""
Parser for CISA KEV JSON and CSV catalog feeds.
"""

import csv
import io
import json
from typing import Any, Dict, List, Union


class CisaKevParser:
    """
    Parses raw official CISA KEV content (JSON or CSV) into structured catalog dictionaries.
    Handles future feed format changes and schema variations gracefully.
    """

    def parse(self, raw_data: Union[bytes, str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Parses raw input (bytes, string, or dict) into standardized dict structure.
        Returns dictionary containing metadata and vulnerabilities list.
        """
        if isinstance(raw_data, dict):
            return self._standardize_json_dict(raw_data)

        if isinstance(raw_data, bytes):
            try:
                decoded = raw_data.decode("utf-8")
            except UnicodeDecodeError:
                decoded = raw_data.decode("latin-1")
        else:
            decoded = str(raw_data)

        stripped = decoded.strip()

        # Check if payload is JSON
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed_json = json.loads(stripped)
                if isinstance(parsed_json, dict):
                    return self._standardize_json_dict(parsed_json)
                elif isinstance(parsed_json, list):
                    return {
                        "title": "CISA Known Exploited Vulnerabilities Catalog",
                        "catalogVersion": "1.0",
                        "dateReleased": "",
                        "count": len(parsed_json),
                        "vulnerabilities": parsed_json,
                    }
            except json.JSONDecodeError:
                pass

        # Treat as CSV if not JSON
        return self._parse_csv(stripped)

    def _standardize_json_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Standardizes JSON dict payload.
        """
        vulns = data.get("vulnerabilities") or data.get("records") or data.get("items") or []
        return {
            "title": data.get("title") or data.get("catalogTitle") or "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": str(data.get("catalogVersion") or data.get("catalog_version") or "1.0"),
            "dateReleased": data.get("dateReleased") or data.get("date_released") or "",
            "count": int(data.get("count") or len(vulns)),
            "vulnerabilities": vulns,
        }

    def _parse_csv(self, csv_text: str) -> Dict[str, Any]:
        """
        Parses CSV string into standardized dictionary structure.
        """
        reader = csv.DictReader(io.StringIO(csv_text))
        vulns: List[Dict[str, Any]] = []

        for row in reader:
            if not row:
                continue
            # Normalize column names by removing BOM or whitespace
            cleaned_row = {k.strip().lstrip('\ufeff'): (v.strip() if v else "") for k, v in row.items() if k}
            vulns.append(cleaned_row)

        return {
            "title": "CISA Known Exploited Vulnerabilities Catalog (CSV)",
            "catalogVersion": "1.0",
            "dateReleased": "",
            "count": len(vulns),
            "vulnerabilities": vulns,
        }
