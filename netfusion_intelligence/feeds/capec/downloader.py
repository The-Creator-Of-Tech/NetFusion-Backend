"""
Downloader for MITRE CAPEC XML dataset.
Supports configurable HTTPS endpoint, file:// URIs, and offline test data.
Official source: https://capec.mitre.org/data/xml/capec_latest.xml
"""

import io
import os
import ssl
import urllib.parse
import urllib.request
import zipfile
from typing import Optional, Union

DEFAULT_CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"


class CapecDownloader:
    """
    Executes a secure download lifecycle for the official MITRE CAPEC XML dataset.
    Supports raw XML and ZIP-compressed XML.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        timeout: float = 300.0,
        verify_tls: bool = True,
        offline_data: Optional[Union[bytes, str]] = None,
    ):
        self.url = url or DEFAULT_CAPEC_URL
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.offline_data = offline_data

    def download(self) -> bytes:
        """
        Fetches raw CAPEC XML bytes from remote URL, file path, or offline buffer.
        Automatically decompresses ZIP if required.
        Returns raw XML bytes.
        """
        if self.offline_data is not None:
            raw = self.offline_data if isinstance(self.offline_data, bytes) else self.offline_data.encode("utf-8")
            return self._decompress_if_needed(raw)

        # File URI or local path
        if self.url.startswith("file://"):
            file_path = urllib.parse.unquote(self.url[7:])
            if file_path.startswith("/") and os.name == "nt" and len(file_path) > 2 and file_path[2] == ":":
                file_path = file_path[1:]
            with open(file_path, "rb") as f:
                raw = f.read()
            return self._decompress_if_needed(raw)

        if os.path.exists(self.url):
            with open(self.url, "rb") as f:
                raw = f.read()
            return self._decompress_if_needed(raw)

        # HTTP/HTTPS download
        req = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": "NetFusion-Threat-Intelligence-Agent/2.0",
                "Accept": "application/xml, text/xml, application/zip",
            },
        )
        ssl_context = ssl.create_default_context()
        if not self.verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError(f"Failed to download CAPEC dataset: HTTP {response.status}")
            raw = response.read()

        return self._decompress_if_needed(raw)

    @staticmethod
    def _decompress_if_needed(data: bytes) -> bytes:
        """Decompresses ZIP archive if the data is a ZIP file, otherwise returns as-is."""
        if data[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                if not xml_names:
                    raise ValueError("ZIP archive contains no XML file")
                target = next(
                    (n for n in xml_names if "capec" in n.lower()),
                    xml_names[0],
                )
                return zf.read(target)
        return data
