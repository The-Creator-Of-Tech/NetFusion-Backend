"""
Tests for CweDownloader — offline data, ZIP decompression, file:// URIs, HTTP errors.
"""

import io
import zipfile
import pytest

from netfusion_intelligence.feeds.cwe.downloader import CweDownloader, DEFAULT_CWE_URL
from netfusion_intelligence.feeds.cwe.tests.conftest import MINIMAL_CWE_XML


# ---------------------------------------------------------------------------
# Offline data
# ---------------------------------------------------------------------------

class TestCweDownloaderOffline:

    def test_returns_bytes_from_offline_bytes(self):
        dl = CweDownloader(offline_data=MINIMAL_CWE_XML)
        result = dl.download()
        assert isinstance(result, bytes)
        assert b"Weakness_Catalog" in result

    def test_returns_bytes_from_offline_string(self):
        dl = CweDownloader(offline_data=MINIMAL_CWE_XML.decode("utf-8"))
        result = dl.download()
        assert isinstance(result, bytes)
        assert b"Weakness_Catalog" in result

    def test_decompresses_zipped_offline_data(self):
        """Wraps XML in a ZIP and verifies automatic decompression."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("cwec_v4.15.xml", MINIMAL_CWE_XML)
        zip_bytes = buf.getvalue()

        dl = CweDownloader(offline_data=zip_bytes)
        result = dl.download()
        assert b"Weakness_Catalog" in result

    def test_decompresses_zip_with_multiple_files_picks_cwec(self):
        """When ZIP contains multiple XMLs, the cwec-named one is selected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.xml", b"<root/>")
            zf.writestr("cwec_v4.15.xml", MINIMAL_CWE_XML)
        zip_bytes = buf.getvalue()

        dl = CweDownloader(offline_data=zip_bytes)
        result = dl.download()
        assert b"Weakness_Catalog" in result

    def test_raises_if_zip_has_no_xml(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("notes.txt", b"No XML here")
        zip_bytes = buf.getvalue()

        dl = CweDownloader(offline_data=zip_bytes)
        with pytest.raises(ValueError, match="no XML"):
            dl.download()


# ---------------------------------------------------------------------------
# File path
# ---------------------------------------------------------------------------

class TestCweDownloaderFilePath:

    def test_loads_from_local_file_path(self, tmp_path):
        xml_file = tmp_path / "cwec.xml"
        xml_file.write_bytes(MINIMAL_CWE_XML)

        dl = CweDownloader(url=str(xml_file))
        result = dl.download()
        assert b"Weakness_Catalog" in result

    def test_loads_and_decompresses_zip_from_local_path(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("cwec.xml", MINIMAL_CWE_XML)
        zip_path = tmp_path / "cwec.zip"
        zip_path.write_bytes(buf.getvalue())

        dl = CweDownloader(url=str(zip_path))
        result = dl.download()
        assert b"Weakness_Catalog" in result

    def test_loads_from_file_uri(self, tmp_path):
        xml_file = tmp_path / "cwec.xml"
        xml_file.write_bytes(MINIMAL_CWE_XML)

        uri = xml_file.as_uri()
        dl = CweDownloader(url=uri)
        result = dl.download()
        assert b"Weakness_Catalog" in result


# ---------------------------------------------------------------------------
# Default URL / configuration
# ---------------------------------------------------------------------------

class TestCweDownloaderConfig:

    def test_default_url(self):
        dl = CweDownloader()
        assert dl.url == DEFAULT_CWE_URL

    def test_custom_url_stored(self):
        dl = CweDownloader(url="https://example.com/cwe.xml")
        assert dl.url == "https://example.com/cwe.xml"

    def test_timeout_stored(self):
        dl = CweDownloader(timeout=120.0)
        assert dl.timeout == 120.0

    def test_verify_tls_defaults_true(self):
        dl = CweDownloader()
        assert dl.verify_tls is True

    def test_verify_tls_can_be_disabled(self):
        dl = CweDownloader(verify_tls=False)
        assert dl.verify_tls is False
