"""
Parser for official FIRST EPSS datasets.
Supports CSV and JSON formats, including header metadata extraction.
"""

import csv
import io
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netfusion_intelligence.feeds.epss.models import EpssScore, EpssDataset

logger = logging.getLogger(__name__)


class EpssParser:
    """
    Parses official FIRST EPSS CSV and JSON payloads into structured EpssScore objects.
    Extracts metadata from CSV header comments.
    """

    def __init__(self):
        self._metadata: Dict[str, Any] = {}

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata

    def parse(self, raw_data: Any) -> Dict[str, Any]:
        """
        Main parser entry point.
        Detects format and routes to appropriate parser.
        Returns dict with 'scores', 'metadata', 'model_version', 'score_date', etc.
        """
        if not raw_data:
            logger.error("EPSS parser received empty data")
            return {"scores": [], "metadata": {}}

        payload = raw_data
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")

        # Auto-detect format
        if payload.strip().startswith("{") or payload.strip().startswith("["):
            return self._parse_json(payload)
        else:
            return self._parse_csv(payload)

    def _parse_csv(self, csv_content: str) -> Dict[str, Any]:
        """
        Parses official EPSS CSV format.
        Extracts metadata from header comments (#model_version, #score_date).
        """
        metadata: Dict[str, Any] = {}
        scores: List[EpssScore] = []

        lines = csv_content.strip().split("\n")
        header_lines = []
        data_lines = []

        # Separate header comments from data rows
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                header_lines.append(stripped)
            else:
                data_lines.append(line)

        # Parse header metadata
        for header in header_lines:
            # Official FIRST EPSS format: #model_version:v2023.03.01,score_date:2024-01-15
            # Single header line may contain multiple comma-separated key:value pairs
            content = header.lstrip("#").strip()
            for part in content.split(","):
                part = part.strip()
                if ":" in part:
                    key, _, value = part.partition(":")
                    metadata[key.strip()] = value.strip()
                    logger.debug(f"EPSS metadata: {key.strip()} = {value.strip()}")

        # Parse CSV data rows
        csv_reader = csv.DictReader(io.StringIO("\n".join(data_lines)))

        for row_idx, row in enumerate(csv_reader, start=1):
            try:
                cve_id = row.get("cve", row.get("CVE", row.get("cve_id", ""))).strip().upper()
                if not cve_id or not cve_id.startswith("CVE-"):
                    logger.warning(f"Row {row_idx}: Invalid CVE ID: {cve_id}")
                    continue

                epss_val = row.get("epss", row.get("EPSS", row.get("score", "0.0"))).strip()
                percentile_val = row.get("percentile", row.get("PERCENTILE", "0.0")).strip()

                epss_score = float(epss_val)
                percentile = float(percentile_val)

                score = EpssScore(
                    cve_id=cve_id,
                    epss_score=epss_score,
                    epss_percentile=percentile,
                    publication_date=metadata.get("score_date", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
                    model_version=metadata.get("model_version", "v2023.03.01"),
                    dataset_version=metadata.get("score_date", ""),
                )

                scores.append(score)

            except ValueError as e:
                logger.warning(f"Row {row_idx}: Failed to parse numeric values: {e}")
                continue
            except Exception as e:
                logger.warning(f"Row {row_idx}: Parse error: {e}")
                continue

        logger.info(f"EPSS CSV parser extracted {len(scores)} scores")

        return {
            "scores": scores,
            "metadata": metadata,
            "model_version": metadata.get("model_version", "v2023.03.01"),
            "score_date": metadata.get("score_date", ""),
            "total_cves": len(scores),
        }

    def _parse_json(self, json_content: str) -> Dict[str, Any]:
        """
        Parses official FIRST EPSS JSON API format.
        Example structure:
        {
          "status": "OK",
          "status-code": 200,
          "data": [
            {
              "cve": "CVE-2023-1234",
              "epss": "0.12345",
              "percentile": "0.85432",
              "date": "2024-01-15",
              "model-version": "v2023.03.01"
            }
          ],
          "total": 1234,
          "offset": 0,
          "limit": 100
        }
        """
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError as e:
            logger.error(f"EPSS JSON parse error: {e}")
            return {"scores": [], "metadata": {}}

        metadata = {
            "status": data.get("status", "UNKNOWN"),
            "status_code": data.get("status-code", data.get("status_code", 0)),
            "total": data.get("total", 0),
            "offset": data.get("offset", 0),
            "limit": data.get("limit", 0),
        }

        scores: List[EpssScore] = []
        data_items = data.get("data", [])

        for item in data_items:
            try:
                cve_id = item.get("cve", "").strip().upper()
                if not cve_id.startswith("CVE-"):
                    logger.warning(f"Invalid CVE ID in JSON: {cve_id}")
                    continue

                epss_score = float(item.get("epss", 0.0))
                percentile = float(item.get("percentile", 0.0))
                date = item.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
                model_ver = item.get("model-version", item.get("model_version", "v2023.03.01"))

                score = EpssScore(
                    cve_id=cve_id,
                    epss_score=epss_score,
                    epss_percentile=percentile,
                    publication_date=date,
                    model_version=model_ver,
                    dataset_version=date,
                )

                scores.append(score)

            except ValueError as e:
                logger.warning(f"JSON item parse error: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected JSON item parse error: {e}")
                continue

        logger.info(f"EPSS JSON parser extracted {len(scores)} scores")

        return {
            "scores": scores,
            "metadata": metadata,
            "model_version": metadata.get("model_version", "v2023.03.01"),
            "score_date": data_items[0].get("date", "") if data_items else "",
            "total_cves": len(scores),
        }
