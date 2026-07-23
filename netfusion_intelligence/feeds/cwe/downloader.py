"""
Downloader for MITRE CWE XML dataset.
Supports configurable HTTPS endpoint, file:// URIs, and offline test data.
Official source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""

import io
import os
import ssl
import urllib.parse
import urllib.request
import zipfile
from typing import Optional, Union

DEFAULT_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


class CweDownloader:
    """
    Executes a secure download lifecycle for the official MITRE CWE XML dataset.
    Supports ZIP-compressed XML (cwec_latest.xml.zip) and raw XML.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        timeout: float = 300.0,
        verify_tls: bool = True,
        offline_data: Optional[Union[bytes, str]] = None,
    ):
        self.url = url or DEFAULT_CWE_URL
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.offline_data = offline_data

    def download(self) -> bytes:
        """
        Fetches raw CWE XML bytes from remote URL, file path, or offline buffer.
        Automatically decompresses ZIP if required.
        Returns raw XML bytes.
        """
        if self.offline_data is not None:
            raw = self.offline_data if isinstance(self.offline_data, bytes) else self.offline_data.encode("utf-8")
            return self._decompress_if_needed(raw, hint="offline")

        # File URI or local path
        if self.url.startswith("file://"):
            file_path = urllib.parse.unquote(self.url[7:])
            if file_path.startswith("/") and os.name == "nt" and len(file_path) > 2 and file_path[2] == ":":
                file_path = file_path[1:]
            with open(file_path, "rb") as f:
                raw = f.read()
            return self._decompress_if_needed(raw, hint=file_path)

        if os.path.exists(self.url):
            with open(self.url, "rb") as f:
                raw = f.read()
            return self._decompress_if_needed(raw, hint=self.url)

        # HTTP/HTTPS download
        req = urllib.request.Request(
            self.url,
            headers={
                "User-Agent": "NetFusion-Threat-Intelligence-Agent/2.0",
                "Accept": "application/zip, application/xml, text/xml",
            },
        )
        ssl_context = ssl.create_default_context()
        if not self.verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError(f"Failed to download CWE dataset: HTTP {response.status}")
            raw = response.read()

        return self._decompress_if_needed(raw, hint=self.url)

    @staticmethod
    def _decompress_if_needed(data: bytes, hint: str = "") -> bytes:
        """Decompresses ZIP archive if the data is a ZIP file, otherwise returns as-is."""
        # ZIP magic bytes: PK\x03\x04
        if data[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Find the XML file inside the archive
                xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                if not xml_names:
                    raise ValueError("ZIP archive contains no XML file")
                # Prefer the main CWE catalog file
                target = next(
                    (n for n in xml_names if "cwec" in n.lower()),
                    xml_names[0],
                )
                return zf.read(target)
        return data
