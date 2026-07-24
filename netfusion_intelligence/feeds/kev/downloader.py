"""
Secure HTTP and Offline Downloader for official CISA KEV catalog datasets.
"""

import json
import os
from typing import Any, Dict, Optional, Union
import urllib.request
import ssl

DEFAULT_CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CISA_KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"


class CisaKevDownloader:
    """
    Handles secure download of official CISA Known Exploited Vulnerabilities catalog (JSON or CSV).
    Supports configurable URLs, TLS verification, timeout, and offline payloads.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        feed_format: str = "json",
        timeout: float = 300.0,
        verify_tls: bool = True,
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
    ):
        self.feed_format = feed_format.lower()
        if url:
            self.url = url
        else:
            self.url = DEFAULT_CISA_KEV_CSV_URL if self.feed_format == "csv" else DEFAULT_CISA_KEV_JSON_URL

        self.timeout = timeout
        self.verify_tls = verify_tls
        self.offline_data = offline_data

    def download(self) -> Any:
        """
        Downloads raw CISA KEV catalog content or returns offline data.
        Returns bytes, string, or parsed dict structure.
        """
        if self.offline_data is not None:
            if isinstance(self.offline_data, (bytes, str, dict)):
                return self.offline_data
            raise ValueError(f"Unsupported offline data type: {type(self.offline_data)}")

        # Check if URL points to a local file path
        if os.path.exists(self.url):
            with open(self.url, "rb") as f:
                return f.read()

        req = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": "NetFusion-Intelligence-Platform/1.0",
                "Accept": "application/json, text/csv, */*",
            },
        )

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
            return response.read()
