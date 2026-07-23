"""
IL-7 IOC CIIL Mapper.
Maps normalized IocEntity instances to CanonicalEntity (CIIL) records.
Ensures every IOC becomes a first-class canonical entity with proper
external identifier, provenance, and tag lineage.
IOC duplication is prevented via normalized value fingerprinting.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from netfusion_intelligence.feeds.ioc.models import IocEntity, IocType
from netfusion_intelligence.identity.models import (
    CanonicalEntity,
    CanonicalEntityType,
    EntityProvenance,
    ExternalIdentifier,
)

FEED_ID = "netfusion_ioc_v1"
SOURCE = "NetFusion IOC Pipeline"


class IocMapper:
    """
    Maps IocEntity → CanonicalEntity for CIIL registration.
    Each IOC type maps to a specific CanonicalEntityType to avoid
    mixing fine-grained indicators under a single generic bucket.
    """

    # Map IocType to the most appropriate CanonicalEntityType
    _TYPE_MAP: Dict[str, str] = {
        IocType.IPV4.value: CanonicalEntityType.IP_ADDRESS.value,
        IocType.IPV6.value: CanonicalEntityType.IP_ADDRESS.value,
        IocType.DOMAIN.value: CanonicalEntityType.DOMAIN.value,
        IocType.HOSTNAME.value: CanonicalEntityType.DOMAIN.value,
        IocType.URL.value: CanonicalEntityType.URL.value,
        IocType.URI.value: CanonicalEntityType.URL.value,
        IocType.EMAIL.value: CanonicalEntityType.EMAIL.value,
        IocType.MD5.value: CanonicalEntityType.HASH.value,
        IocType.SHA1.value: CanonicalEntityType.HASH.value,
        IocType.SHA256.value: CanonicalEntityType.HASH.value,
        IocType.SHA512.value: CanonicalEntityType.HASH.value,
        IocType.TLS_CERT_FINGERPRINT.value: CanonicalEntityType.CERTIFICATE.value,
        IocType.JA3.value: CanonicalEntityType.SIGNATURE.value,
        IocType.JA3S.value: CanonicalEntityType.SIGNATURE.value,
        IocType.FILE_NAME.value: CanonicalEntityType.FILE.value,
        IocType.FILE_PATH.value: CanonicalEntityType.FILE.value,
        IocType.MUTEX.value: CanonicalEntityType.IOC.value,
        IocType.REGISTRY_KEY.value: CanonicalEntityType.IOC.value,
        IocType.WINDOWS_SERVICE_NAME.value: CanonicalEntityType.IOC.value,
        IocType.WINDOWS_EVENT_ID.value: CanonicalEntityType.IOC.value,
        IocType.USER_AGENT.value: CanonicalEntityType.IOC.value,
        IocType.PROCESS_NAME.value: CanonicalEntityType.IOC.value,
        IocType.COMMAND_LINE.value: CanonicalEntityType.IOC.value,
        IocType.SCHEDULED_TASK.value: CanonicalEntityType.IOC.value,
        IocType.NAMED_PIPE.value: CanonicalEntityType.IOC.value,
        IocType.YARA_RULE_REF.value: CanonicalEntityType.RULE.value,
        IocType.SIGMA_RULE_REF.value: CanonicalEntityType.RULE.value,
        IocType.SURICATA_SID.value: CanonicalEntityType.SIGNATURE.value,
        IocType.SNORT_SID.value: CanonicalEntityType.SIGNATURE.value,
        IocType.ATTACK_DATA_SOURCE.value: CanonicalEntityType.IOC.value,
        IocType.MALWARE_FAMILY.value: CanonicalEntityType.MALWARE.value,
        IocType.CAMPAIGN.value: CanonicalEntityType.ATTACK_CAMPAIGN.value,
        IocType.THREAT_ACTOR_REF.value: CanonicalEntityType.THREAT_ACTOR.value,
    }

    def map_to_canonical(
        self,
        entity: IocEntity,
        dataset_version: str,
        existing_canonical_id: Optional[str] = None,
    ) -> CanonicalEntity:
        """
        Map a single IocEntity to a CanonicalEntity.
        If existing_canonical_id is provided (merge scenario), reuse the UUID.
        """
        canonical_uuid = existing_canonical_id or str(uuid.uuid4())

        provenance = EntityProvenance.create(
            canonical_uuid=canonical_uuid,
            feed=FEED_ID,
            dataset_version=dataset_version,
            original_object_id=entity.ioc_id,
            trust_score=entity.confidence,
        )

        ext_id = ExternalIdentifier(
            source=entity.provider or SOURCE,
            identifier=entity.value,
            identifier_type=entity.ioc_type.upper(),
            confidence=entity.confidence,
            first_seen=self._parse_dt(entity.first_seen),
            last_seen=self._parse_dt(entity.last_seen),
        )

        entity_type = self._TYPE_MAP.get(entity.ioc_type, CanonicalEntityType.IOC.value)
        display_name = f"{entity.ioc_type.upper()}: {entity.value[:120]}"

        tags = self._build_tags(entity)
        metadata = self._build_metadata(entity)

        return CanonicalEntity(
            canonical_uuid=canonical_uuid,
            entity_type=entity_type,
            display_name=display_name,
            aliases=entity.aliases,
            description=entity.description,
            confidence=entity.confidence,
            status="ACTIVE",
            active=True,
            source_count=entity.source_count,
            tags=tags,
            metadata=metadata,
            external_identifiers=(ext_id,),
        )

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    @staticmethod
    def _build_tags(entity: IocEntity) -> Tuple[str, ...]:
        tags = ["ioc", entity.ioc_type]
        if entity.severity and entity.severity != "unknown":
            tags.append(f"severity:{entity.severity}")
        if entity.tlp:
            tags.append(f"tlp:{entity.tlp.lower().replace(':', '_')}")
        if entity.provider:
            tags.append(f"provider:{entity.provider}")
        tags.extend(entity.tags)
        for mf in entity.malware_families:
            tags.append(f"malware:{mf.lower()}")
        for c in entity.campaigns:
            tags.append(f"campaign:{c.lower()}")
        return tuple(dict.fromkeys(tags))  # deduplicate while preserving order

    @staticmethod
    def _build_metadata(entity: IocEntity) -> Dict[str, Any]:
        return {
            "ioc_id": entity.ioc_id,
            "ioc_type": entity.ioc_type,
            "value": entity.value,
            "value_raw": entity.value_raw,
            "severity": entity.severity,
            "confidence": entity.confidence,
            "priority": entity.priority,
            "reputation_score": entity.reputation_score,
            "false_positive_score": entity.false_positive_score,
            "source_count": entity.source_count,
            "first_seen": entity.first_seen,
            "last_seen": entity.last_seen,
            "last_updated": entity.last_updated,
            "expiration": entity.expiration,
            "malware_families": list(entity.malware_families),
            "campaigns": list(entity.campaigns),
            "threat_actors": list(entity.threat_actors),
            "attack_technique_ids": list(entity.attack_technique_ids),
            "capec_ids": list(entity.capec_ids),
            "cwe_ids": list(entity.cwe_ids),
            "cve_ids": list(entity.cve_ids),
            "tlp": entity.tlp,
            "provider": entity.provider,
            "provider_id": entity.provider_id,
            "source_url": entity.source_url,
        }
