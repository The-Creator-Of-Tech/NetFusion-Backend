import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union, Optional


class BaseSysmonParser(ABC):
    """
    Abstract Base Class for all Sysmon parsers.
    Converts raw telemetry representations (XML, EVTX, dicts) into standard Sysmon event dictionaries.
    """

    @abstractmethod
    def parse(self, raw_data: Union[str, bytes, List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse raw telemetry input into list of standardized event dictionaries."""
        pass

    @staticmethod
    def parse_hashes(hash_str: Optional[str]) -> Dict[str, str]:
        """
        Parses Sysmon Hashes field into a dictionary.
        Format: 'SHA256=ABC...,MD5=DEF...,IMPHASH=123...'
        """
        if not hash_str:
            return {}
        hashes: Dict[str, str] = {}
        # Match Algo=HashValue pairs
        pairs = re.findall(r"([A-Za-z0-9_-]+)=([A-Fa-f0-9]+)", hash_str)
        for algo, hval in pairs:
            hashes[algo.upper()] = hval
        return hashes

    def standardize_event_dict(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes parsed dictionary fields to standard casing and types.
        """
        standard: Dict[str, Any] = {}

        # Preserve System fields
        event_id = raw_event.get("EventID") or raw_event.get("event_id") or raw_event.get("System", {}).get("EventID")
        try:
            standard["EventID"] = int(event_id) if event_id is not None else 0
        except (ValueError, TypeError):
            standard["EventID"] = 0

        standard["Computer"] = (
            raw_event.get("Computer")
            or raw_event.get("computer")
            or raw_event.get("System", {}).get("Computer", "")
        )
        standard["TimeCreated"] = (
            raw_event.get("TimeCreated")
            or raw_event.get("time_created")
            or raw_event.get("System", {}).get("TimeCreated", "")
        )
        standard["EventRecordID"] = (
            raw_event.get("EventRecordID")
            or raw_event.get("event_record_id")
            or raw_event.get("System", {}).get("EventRecordID", 0)
        )

        # Merge EventData/Data
        event_data = raw_event.get("EventData", raw_event.get("event_data", {}))
        if isinstance(event_data, dict):
            for k, v in event_data.items():
                standard[k] = v
        
        # Copy remaining raw fields not yet set
        for k, v in raw_event.items():
            if k not in ("System", "EventData", "event_data") and k not in standard:
                standard[k] = v

        # Process hashes if present
        if "Hashes" in standard and isinstance(standard["Hashes"], str):
            standard["ParsedHashes"] = self.parse_hashes(standard["Hashes"])
        elif "Hashes" not in standard:
            standard["ParsedHashes"] = {}

        # Cast integer PIDs
        for pid_field in ("ProcessId", "ParentProcessId", "TargetProcessId", "SourceProcessId"):
            if pid_field in standard and standard[pid_field] is not None:
                try:
                    standard[pid_field] = int(standard[pid_field])
                except (ValueError, TypeError):
                    pass

        return standard
