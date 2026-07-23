"""
Tests for CapecDownloader — offline data, ZIP decompression, file:// URIs, HTTP errors.
"""

import io
import zipfile
import pytest

from netfusion_intelligence.feeds.capec.downloader import CapecDownloader, DEFAULT_CAPEC_URL
from netfusion_intelligence.feeds.capec.tests.conftest import MINIMAL_CAPEC_XML


class TestCapecDownloaderOffline:

    def test_returns_bytes_from_offline_bytes(self):
        dl = CapecDownloader(offline_data=MINIMAL_CAPEC_XML)
        result = dl.download()
        assert isinstance(result, bytes)
        assert b"Attack_Pattern_Catalog" in result

    def test_returns_bytes_from_offline_string(self):
        dl = CapecDownloader(offline_data=MINIMAL_CAPEC_XML.decode("utf-8"))
        result = dl.download()
        assert isinstance(result, bytes)
        assert b"Attack_Pattern_Catalog" in result

    def test_decompresses_zipped_offline_data(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("capec_v3.9.xml", MINIMAL_CAPEC_XML)
        zip_bytes = buf.getvalue()

        dl = CapecDownloader(offline_data=zip_bytes)
        result = dl.download()
        assert b"Attack_Pattern_Catalog" in result

    def test_decompresses_zip_with_multiple_files_picks_capec(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.xml", b"<root/>")
            zf.writestr("capec_v3.9.xml", MINIMAL_CAPEC_XML)
        zip_bytes = buf.getvalue()

        dl = CapecDownloader(offline_data=zip_bytes)
        result = dl.download()
        assert b"Attack_Pattern_Catalog" in result

    def test_raises_if_zip_has_no_xml(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("notes.txt", b"No XML here")
        zip_bytes = buf.getvalue()

        dl = CapecDownloader(offline_data=zip_bytes)
        with pytest.raises(ValueError, match="no XML"):
            dl.download()


class TestCapecDownloaderFilePath:

    def test_loads_from_local_file_path(self, tmp_path):
        xml_file = tmp_path / "capec.xml"
        xml_file.write_bytes(MINIMAL_CAPEC_XML)

        dl = CapecDownloader(url=str(xml_file))
        result = dl.download()
        assert b"Attack_Pattern_Catalog" in result

    def test_loads_and_decompresses_zip_from_local_path(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("capec.xml", MINIMAL_CAPEC_XML)
        zip_path = tmp_path / "capec.zip"
        zip_path.write_bytes(buf.getvalue())

        dl = CapecDownloader(url=str(zip_path))
        result = dl.download()
        assert b"Attack_Pattern_Catalog" in result

    def test_loads_from_file_uri(self, tmp_path):
        xml_file = tmp_path / "capec.xml"
        xml_file.write_bytes(MINIMAL_CAPEC_XML)

        uri = xml_file.as_uri()
        dl = CapecDownloader(url=uri)
        result = dl.download()
        assert b"Attack_Pattern_Catalog" in result


class TestCapecDownloaderConfig:

    def test_default_url(self):
        dl = CapecDownloader()
        assert dl.url == DEFAULT_CAPEC_URL

    def test_custom_url_stored(self):
        dl = CapecDownloader(url="https://example.com/capec.xml")
        assert dl.url == "https://example.com/capec.xml"

    def test_timeout_stored(self):
        dl = CapecDownloader(timeout=120.0)
        assert dl.timeout == 120.0

    def test_verify_tls_defaults_true(self):
        dl = CapecDownloader()
        assert dl.verify_tls is True

    def test_verify_tls_can_be_disabled(self):
        dl = CapecDownloader(verify_tls=False)
        assert dl.verify_tls is False
