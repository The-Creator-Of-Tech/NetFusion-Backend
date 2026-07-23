"""
Downloader for MITRE ATT&CK Enterprise STIX 2.1 dataset.
Supports configurable HTTPS endpoint, file:// URIs, and offline test data.
"""

import json
import os
from typing import Any, Dict, Optional, Union
import urllib.request
import urllib.parse
import ssl

DEFAULT_MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


class MitreDownloader:
    """
    Downloader executing secure download lifecycle for official MITRE ATT&CK STIX 2.1 dataset.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        timeout: float = 300.0,
        verify_tls: bool = True,
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    ):
        self.url = url or DEFAULT_MITRE_ATTACK_URL
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.offline_data = offline_data

    def download(self) -> str:
        """
        Fetches raw STIX 2.1 JSON string from remote URL, file path, or offline buffer.
        """
        if self.offline_data is not None:
            if isinstance(self.offline_data, bytes):
                return self.offline_data.decode("utf-8")
            elif isinstance(self.offline_data, str):
                return self.offline_data
            elif isinstance(self.offline_data, dict):
                return json.dumps(self.offline_data)

        # File URI or local path check
        if self.url.startswith("file://"):
            file_path = urllib.parse.unquote(self.url[7:])
            if file_path.startswith("/") and os.name == "nt" and len(file_path) > 2 and file_path[2] == ":":
                file_path = file_path[1:]
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()

        if os.path.exists(self.url):
            with open(self.url, "r", encoding="utf-8") as f:
                return f.read()

        # HTTP/HTTPS Download
        req = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": "NetFusion-Threat-Intelligence-Agent/2.0",
                "Accept": "application/json, application/stix+json",
            },
        )

        ssl_context = ssl.create_default_context()
        if not self.verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError(f"Failed to download MITRE STIX data: HTTP {response.status}")
            raw_bytes = response.read()
            return raw_bytes.decode("utf-8")
