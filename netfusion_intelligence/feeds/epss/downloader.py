"""
Downloader for official FIRST EPSS datasets.
Supports official daily CSV datasets and compressed downloads.
"""

import gzip
import io
import logging
from typing import Any, Optional, Union
import requests

logger = logging.getLogger(__name__)

# Official FIRST EPSS endpoints
DEFAULT_EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
DEFAULT_EPSS_ALL_CSV_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
DEFAULT_EPSS_JSON_URL = "https://api.first.org/data/v1/epss"


class EpssDownloader:
    """
    Downloads official FIRST EPSS datasets.
    Supports compressed CSV and JSON formats.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        feed_format: str = "csv",
        timeout: float = 600.0,
        verify_tls: bool = True,
        offline_data: Optional[Union[bytes, str]] = None,
    ):
        self.url = url or DEFAULT_EPSS_CSV_URL
        self.feed_format = feed_format.lower()
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.offline_data = offline_data

    def download(self) -> bytes:
        """
        Downloads EPSS dataset from configured URL or uses offline data.
        Returns raw bytes (potentially compressed).
        """
        if self.offline_data:
            logger.info("Using offline EPSS data")
            if isinstance(self.offline_data, str):
                return self.offline_data.encode("utf-8")
            return self.offline_data

        logger.info(f"Downloading EPSS dataset from {self.url}")

        try:
            response = requests.get(
                self.url,
                timeout=self.timeout,
                verify=self.verify_tls,
                headers={
                    "User-Agent": "NetFusion-Intelligence/1.0 (EPSS Enterprise Pipeline)",
                    "Accept": "*/*",
                },
            )
            response.raise_for_status()

            content = response.content
            logger.info(f"Downloaded {len(content)} bytes from EPSS feed")

            # Decompress if gzipped
            if self.url.endswith(".gz"):
                try:
                    content = gzip.decompress(content)
                    logger.info(f"Decompressed to {len(content)} bytes")
                except Exception as e:
                    logger.warning(f"Failed to decompress gzip content: {e}, using raw content")

            return content

        except requests.exceptions.Timeout:
            logger.error(f"EPSS download timeout after {self.timeout}s")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"EPSS download failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during EPSS download: {e}")
            raise

    def download_historical(self, date: str) -> bytes:
        """
        Downloads historical EPSS dataset for a specific date.
        Date format: YYYY-MM-DD
        """
        historical_url = DEFAULT_EPSS_ALL_CSV_URL.format(date=date.replace("-", ""))
        logger.info(f"Downloading historical EPSS data for {date}")

        original_url = self.url
        self.url = historical_url

        try:
            return self.download()
        finally:
            self.url = original_url

    def download_json_api(self, cve_id: Optional[str] = None, limit: int = 100, offset: int = 0) -> bytes:
        """
        Downloads EPSS data from the official FIRST JSON API.
        Supports querying specific CVEs or paginated bulk retrieval.
        """
        params = {
            "limit": limit,
            "offset": offset,
        }

        if cve_id:
            params["cve"] = cve_id

        logger.info(f"Downloading EPSS JSON API data: {params}")

        try:
            response = requests.get(
                DEFAULT_EPSS_JSON_URL,
                params=params,
                timeout=self.timeout,
                verify=self.verify_tls,
                headers={
                    "User-Agent": "NetFusion-Intelligence/1.0 (EPSS Enterprise Pipeline)",
                    "Accept": "application/json",
                },
            )
            response.raise_for_status()

            content = response.content
            logger.info(f"Downloaded {len(content)} bytes from EPSS JSON API")

            return content

        except requests.exceptions.RequestException as e:
            logger.error(f"EPSS JSON API download failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during EPSS JSON API download: {e}")
            raise
