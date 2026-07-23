"""
IL-7 IOC Provider Framework.
Abstract base class and concrete providers for MISP, OpenCTI, STIX 2.1,
TAXII, CSV, JSON, YAML, and offline imports.
Every provider implements the IL-1 lifecycle interface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import json
import uuid
from datetime import datetime, timezone


class IocProviderInterface(ABC):
    """
    Abstract base for all IOC intelligence providers.
    Each provider is responsible for fetching raw data in its native format
    and returning it as a list of raw indicator dicts for the parser.
    """

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique provider identifier."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name."""
        pass

    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Provider type: misp | opencti | stix | taxii | csv | json | yaml | manual"""
        pass

    @property
    def default_confidence(self) -> float:
        """Default confidence level for indicators from this provider (0.0-1.0)."""
        return 0.5

    @property
    def default_tlp(self) -> str:
        """Default TLP for indicators from this provider."""
        return "TLP:WHITE"

    @abstractmethod
    def fetch(self) -> Any:
        """Fetch raw data from the source. Returns bytes, str, dict, or list."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_name": self.provider_name,
            "provider_type": self.provider_type,
            "default_confidence": self.default_confidence,
            "default_tlp": self.default_tlp,
        }



class MispProvider(IocProviderInterface):
    """
    MISP (Malware Information Sharing Platform) provider.
    Fetches indicators via MISP REST API or offline MISP JSON export.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        offline_data: Optional[Any] = None,
        confidence: float = 0.8,
        tlp: str = "TLP:AMBER",
    ):
        self._url = url
        self._api_key = api_key
        self._offline_data = offline_data
        self._confidence = confidence
        self._tlp = tlp

    @property
    def provider_id(self) -> str:
        return "misp"

    @property
    def provider_name(self) -> str:
        return "MISP Threat Intelligence"

    @property
    def provider_type(self) -> str:
        return "misp"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        if self._offline_data is not None:
            return self._offline_data
        if not self._url:
            return {"response": {"Attribute": []}}
        import urllib.request, ssl
        req = urllib.request.Request(
            f"{self._url.rstrip('/')}/attributes/restSearch",
            data=json.dumps({"returnFormat": "json", "limit": 10000}).encode(),
            headers={
                "Authorization": self._api_key or "",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
            return json.loads(resp.read())



class StixBundleProvider(IocProviderInterface):
    """
    STIX 2.1 Bundle provider.
    Parses indicators from a STIX 2.1 JSON bundle file or URL.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        offline_data: Optional[Any] = None,
        confidence: float = 0.7,
        tlp: str = "TLP:WHITE",
    ):
        self._url = url
        self._offline_data = offline_data
        self._confidence = confidence
        self._tlp = tlp

    @property
    def provider_id(self) -> str:
        return "stix_bundle"

    @property
    def provider_name(self) -> str:
        return "STIX 2.1 Bundle"

    @property
    def provider_type(self) -> str:
        return "stix"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        if self._offline_data is not None:
            if isinstance(self._offline_data, (bytes, str)):
                return json.loads(self._offline_data)
            return self._offline_data
        if not self._url:
            return {"type": "bundle", "objects": []}
        import urllib.request, ssl
        req = urllib.request.Request(
            self._url,
            headers={"Accept": "application/json", "User-Agent": "NetFusion-IOC/1.0"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
            return json.loads(resp.read())



class OpenCtiExportProvider(IocProviderInterface):
    """
    OpenCTI JSON export provider.
    Processes OpenCTI indicator export (REST API JSON or offline export).
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        offline_data: Optional[Any] = None,
        confidence: float = 0.75,
        tlp: str = "TLP:AMBER",
    ):
        self._url = url
        self._api_key = api_key
        self._offline_data = offline_data
        self._confidence = confidence
        self._tlp = tlp

    @property
    def provider_id(self) -> str:
        return "opencti_export"

    @property
    def provider_name(self) -> str:
        return "OpenCTI Export"

    @property
    def provider_type(self) -> str:
        return "opencti"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        if self._offline_data is not None:
            if isinstance(self._offline_data, (bytes, str)):
                return json.loads(self._offline_data)
            return self._offline_data
        return {"data": {"indicators": {"edges": []}}}


class TaxiiCollectionProvider(IocProviderInterface):
    """
    TAXII 2.x collection provider.
    Fetches STIX 2.1 objects from a TAXII 2.x server collection.
    """

    def __init__(
        self,
        taxii_url: Optional[str] = None,
        collection_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        offline_data: Optional[Any] = None,
        confidence: float = 0.7,
        tlp: str = "TLP:WHITE",
    ):
        self._taxii_url = taxii_url
        self._collection_id = collection_id
        self._username = username
        self._password = password
        self._offline_data = offline_data
        self._confidence = confidence
        self._tlp = tlp

    @property
    def provider_id(self) -> str:
        return f"taxii_{self._collection_id or 'default'}"

    @property
    def provider_name(self) -> str:
        return f"TAXII Collection {self._collection_id or 'default'}"

    @property
    def provider_type(self) -> str:
        return "taxii"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        if self._offline_data is not None:
            if isinstance(self._offline_data, (bytes, str)):
                return json.loads(self._offline_data)
            return self._offline_data
        return {"objects": []}



class CsvProvider(IocProviderInterface):
    """
    CSV indicator provider.
    Supports configurable column mapping for type, value, confidence, severity, etc.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        offline_data: Optional[Any] = None,
        type_column: str = "type",
        value_column: str = "value",
        delimiter: str = ",",
        has_header: bool = True,
        confidence: float = 0.5,
        tlp: str = "TLP:WHITE",
        provider_name_override: Optional[str] = None,
    ):
        self._url = url
        self._offline_data = offline_data
        self._type_column = type_column
        self._value_column = value_column
        self._delimiter = delimiter
        self._has_header = has_header
        self._confidence = confidence
        self._tlp = tlp
        self._provider_name_override = provider_name_override

    @property
    def provider_id(self) -> str:
        return "csv"

    @property
    def provider_name(self) -> str:
        return self._provider_name_override or "CSV Import"

    @property
    def provider_type(self) -> str:
        return "csv"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        """Returns raw CSV bytes or string."""
        if self._offline_data is not None:
            return self._offline_data
        if not self._url:
            return b""
        import urllib.request, ssl, os
        if self._url.startswith("file://"):
            import urllib.parse
            path = urllib.parse.unquote(self._url[7:])
            with open(path, "rb") as fh:
                return fh.read()
        if os.path.exists(self._url):
            with open(self._url, "rb") as fh:
                return fh.read()
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(self._url, timeout=60, context=ctx) as resp:
            return resp.read()


class JsonProvider(IocProviderInterface):
    """Generic JSON indicator provider — expects a list or dict with an indicators array."""

    def __init__(
        self,
        url: Optional[str] = None,
        offline_data: Optional[Any] = None,
        indicators_key: Optional[str] = None,
        confidence: float = 0.5,
        tlp: str = "TLP:WHITE",
        provider_name_override: Optional[str] = None,
    ):
        self._url = url
        self._offline_data = offline_data
        self._indicators_key = indicators_key
        self._confidence = confidence
        self._tlp = tlp
        self._name = provider_name_override or "JSON Import"

    @property
    def provider_id(self) -> str:
        return "json"

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> str:
        return "json"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        if self._offline_data is not None:
            if isinstance(self._offline_data, (bytes, str)):
                return json.loads(self._offline_data)
            return self._offline_data
        if not self._url:
            return []
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(self._url, timeout=60, context=ctx) as resp:
            return json.loads(resp.read())


class YamlProvider(IocProviderInterface):
    """YAML indicator provider."""

    def __init__(
        self,
        url: Optional[str] = None,
        offline_data: Optional[Any] = None,
        confidence: float = 0.5,
        tlp: str = "TLP:WHITE",
        provider_name_override: Optional[str] = None,
    ):
        self._url = url
        self._offline_data = offline_data
        self._confidence = confidence
        self._tlp = tlp
        self._name = provider_name_override or "YAML Import"

    @property
    def provider_id(self) -> str:
        return "yaml"

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> str:
        return "yaml"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        if self._offline_data is not None:
            return self._offline_data
        if not self._url:
            return {}
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(self._url, timeout=60, context=ctx) as resp:
            return resp.read()


class OfflineImportProvider(IocProviderInterface):
    """
    Offline import provider for manual or pre-staged indicator sets.
    Accepts any pre-loaded Python structure (list of dicts, STIX bundle dict, etc.).
    """

    def __init__(
        self,
        data: Any,
        name: str = "Offline Import",
        confidence: float = 0.5,
        tlp: str = "TLP:WHITE",
    ):
        self._data = data
        self._name = name
        self._confidence = confidence
        self._tlp = tlp

    @property
    def provider_id(self) -> str:
        return f"offline_{self._name.lower().replace(' ', '_')}"

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> str:
        return "manual"

    @property
    def default_confidence(self) -> float:
        return self._confidence

    @property
    def default_tlp(self) -> str:
        return self._tlp

    def fetch(self) -> Any:
        return self._data
