"""
NetFusion Evidence Management & Chain of Custody Engine
Handles evidence creation, multi-algorithm checksum calculation, integrity verification,
append-only Chain of Custody logging, and collector reference mapping.
"""

import hashlib
import time
from typing import Any, Dict, List, Optional, Union

from .domain import CustodyEntry, Evidence
from .enums import EvidenceSource, IntegrityStatus
from .exceptions import EvidenceIntegrityError


class EvidenceManager:
    """Manager for Evidence creation, checksum hashing, chain of custody, and verification."""

    @staticmethod
    def calculate_hashes(data: Union[str, bytes]) -> Dict[str, str]:
        """Calculates SHA256, MD5, and SHA1 hashes for raw artifact data."""
        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        return {
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "md5": hashlib.md5(raw_bytes).hexdigest(),
            "sha1": hashlib.sha1(raw_bytes).hexdigest(),
        }

    @classmethod
    def create_evidence(
        cls,
        name: str,
        investigation_id: str,
        description: str = "",
        source: EvidenceSource = EvidenceSource.OTHER,
        collector_id: Optional[str] = None,
        canonical_object_ref: Optional[Any] = None,
        raw_artifact: Optional[Union[str, bytes]] = None,
        screenshot_path: Optional[str] = None,
        pcap_ref: Optional[Dict[str, Any]] = None,
        evtx_ref: Optional[Dict[str, Any]] = None,
        nmap_scan_ref: Optional[Dict[str, Any]] = None,
        threat_intel_ref: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        notes: str = "Evidence initial ingestion",
    ) -> Evidence:
        """Creates an Evidence object, computes checksum hashes if raw artifact provided, and logs initial custody entry."""
        hash_sha256 = ""
        hash_md5 = ""
        hash_sha1 = ""
        integrity_status = IntegrityStatus.UNVERIFIED

        if raw_artifact is not None:
            hashes = cls.calculate_hashes(raw_artifact)
            hash_sha256 = hashes["sha256"]
            hash_md5 = hashes["md5"]
            hash_sha1 = hashes["sha1"]
            integrity_status = IntegrityStatus.VERIFIED

        initial_custody = CustodyEntry(
            timestamp=time.time(),
            actor=actor,
            action="INGESTED",
            location="INVESTIGATION_VAULT",
            notes=notes,
        )

        evidence = Evidence(
            name=name,
            investigation_id=investigation_id,
            description=description,
            source=source,
            collector_id=collector_id,
            canonical_object_ref=canonical_object_ref,
            raw_artifact=raw_artifact,
            screenshot_path=screenshot_path,
            pcap_ref=pcap_ref,
            evtx_ref=evtx_ref,
            nmap_scan_ref=nmap_scan_ref,
            threat_intel_ref=threat_intel_ref,
            hash_sha256=hash_sha256,
            hash_md5=hash_md5,
            hash_sha1=hash_sha1,
            timestamp=time.time(),
            chain_of_custody=[initial_custody],
            integrity_status=integrity_status,
            verified_at=time.time() if integrity_status == IntegrityStatus.VERIFIED else None,
        )
        return evidence

    @classmethod
    def add_custody_entry(
        cls,
        evidence: Evidence,
        actor: str,
        action: str,
        location: str = "INVESTIGATION_VAULT",
        notes: str = "",
    ) -> CustodyEntry:
        """Appends a new immutable chain of custody log entry."""
        entry = CustodyEntry(
            timestamp=time.time(),
            actor=actor,
            action=action,
            location=location,
            notes=notes,
        )
        evidence.chain_of_custody.append(entry)
        return entry

    @classmethod
    def verify_integrity(cls, evidence: Evidence) -> bool:
        """
        Verifies the checksum integrity of evidence against raw artifact data.
        Returns True if verified, raises EvidenceIntegrityError if tampered.
        """
        if evidence.raw_artifact is None:
            evidence.integrity_status = IntegrityStatus.UNVERIFIED
            return True

        hashes = cls.calculate_hashes(evidence.raw_artifact)
        if (
            evidence.hash_sha256
            and hashes["sha256"] != evidence.hash_sha256
        ):
            evidence.integrity_status = IntegrityStatus.TAMPERED
            raise EvidenceIntegrityError(
                f"Integrity check failed for Evidence '{evidence.name}' ({evidence.evidence_id}). "
                f"Expected SHA256 {evidence.hash_sha256}, computed {hashes['sha256']}."
            )

        evidence.integrity_status = IntegrityStatus.VERIFIED
        evidence.verified_at = time.time()
        return True
