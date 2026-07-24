"""
NVD Enterprise Secure Downloader & API Client.
Supports NVD REST API 2.0, API keys, bulk feeds, pagination, and offline imports.
"""

import json
import os
import time
from typing import Any, Dict, Optional, Union
import urllib.parse
import urllib.request
import ssl

from netfusion_intelligence.core.exceptions import FeedExecutionError as SecureDownloadError

DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdDownloader:
    """
    Downloader & API Client for official NVD CVE JSON 2.0 API and bulk feeds.
    Supports authenticated requests via API Key, pagination, retries, and offline data feeds.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 300.0,
        verify_tls: bool = True,
        offline_data: Optional[Union[bytes, str, Dict[str, Any]]] = None,
        max_retries: int = 3,
        results_per_page: int = 2000,
    ):
        self.url = url or os.getenv("NVD_API_URL", DEFAULT_NVD_API_URL)
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.offline_data = offline_data
        self.max_retries = max_retries
        self.results_per_page = results_per_page

    def download(self, params: Optional[Dict[str, Any]] = None) -> Union[str, bytes, Dict[str, Any]]:
        """
        Fetches NVD dataset payload either from offline data or live NVD REST API 2.0.
        Returns raw JSON string, bytes, or dict object.
        """
        # 1. Offline Mode handling
        if self.offline_data is not None:
            if isinstance(self.offline_data, (bytes, str, dict)):
                return self.offline_data
            raise SecureDownloadError("Invalid type provided for offline NVD data source")

        # Check if URL points to a local file path
        if self.url.startswith("file://") or (os.path.exists(self.url) and not self.url.startswith("http")):
            path = self.url.replace("file://", "")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                raise SecureDownloadError(f"Failed to read local NVD data file '{path}': {e}")

        # 2. Online Mode handling via NVD API 2.0
        query_params = params or {}
        if "resultsPerPage" not in query_params and self.results_per_page:
            query_params["resultsPerPage"] = self.results_per_page

        url_parts = list(urllib.parse.urlparse(self.url))
        if query_params:
            query_string = urllib.parse.urlencode(query_params)
            if url_parts[4]:
                url_parts[4] += "&" + query_string
            else:
                url_parts[4] = query_string

        target_url = urllib.parse.urlunparse(url_parts)
        headers = {
            "User-Agent": "NetFusion-Vulnerability-Intelligence/2.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(target_url, headers=headers, method="GET")

        last_err = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    if resp.status not in (200, 201):
                        raise SecureDownloadError(f"NVD API returned HTTP status {resp.status}")
                    content = resp.read()
                    return content.decode("utf-8")
            except Exception as ex:
                last_err = ex
                if attempt < self.max_retries:
                    time.sleep(1.0 * attempt)

        raise SecureDownloadError(f"Failed to download NVD dataset from {self.url} after {self.max_retries} attempts: {last_err}")
