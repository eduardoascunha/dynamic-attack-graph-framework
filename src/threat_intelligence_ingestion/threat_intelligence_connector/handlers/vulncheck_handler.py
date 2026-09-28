"""
VulnCheck API handler for data retrieval and validation.
"""

import io
import json
import gzip
import requests
import zipfile

from typing import Any, Generator
from pydantic import HttpUrl

from ..utils.logger import Logger
from ..utils.settings import Settings


class VulnCheckAPIHandler:
    """
    Handles VulnCheck API data retrieval and parsing.
    """

    def __init__(self, settings: Settings):
        """
        Initialize handler with app config.
        Args:
            settings (Settings): App config with API credentials.
        """
        self._log = Logger.get_logger()
        self._config = settings

    def _retrieve_backup_url(self, api_endpoint: HttpUrl) -> str:
        """
        Get backup URL from VulnCheck API endpoint.
        Args:
            api_endpoint (HttpUrl): API endpoint.
        Returns:
            str: Download URL.
        Raises:
            requests.exceptions.RequestException: On HTTP error.
            ValueError: On invalid response.
        """
        try:
            api_response = requests.get(
                str(api_endpoint),
                headers={
                    "Authorization": (
                        f"Bearer {self._config.VULNCHECK.api_token.get_secret_value()}"
                        if self._config.VULNCHECK.api_token
                        else ""
                    )
                },
                timeout=30,
            )
            api_response.raise_for_status()

        except requests.exceptions.RequestException as req_error:
            self._log.error(
                "API request failed for %s: %s",
                api_endpoint,
                req_error,
            )
            raise

        if not api_response.content:
            self._log.error("Received empty response from API")
            raise ValueError("Empty API response")

        try:
            response_payload = api_response.json()["data"][0]
            return str(response_payload["url"])

        except (ValueError, KeyError, IndexError) as parse_error:
            self._log.error("Failed to parse API response: %s", parse_error)
            raise ValueError("Invalid API response format") from parse_error

    def read_zip_file(
        self, api_endpoint: HttpUrl
    ) -> Generator[dict[str, Any], None, None]:
        """
        Download and yield JSON objects from VulnCheck ZIP archive.
        Args:
            api_endpoint (HttpUrl): API endpoint for backup.
        Yields:
            dict[str, Any]: Parsed JSON objects.
        Raises:
            requests.RequestException: On download error.
            zipfile.BadZipFile: On invalid ZIP.
            OSError: On file errors.
        """
        try:
            backup_url = self._retrieve_backup_url(api_endpoint)
            self._log.info("Downloading archive...")
            self._log.debug("Archive URL: %s", backup_url)

            download_response = requests.get(backup_url, timeout=60)
            download_response.raise_for_status()

            self._log.info("Extracting and parsing JSON files...")
            downloaded_data = io.BytesIO(download_response.content)

            with zipfile.ZipFile(downloaded_data) as archive:
                for file_entry in archive.infolist():
                    with archive.open(file_entry) as compressed_file:
                        file_content = compressed_file.read()

                        if "missing" in file_entry.filename:
                            self._log.debug(
                                "Skipping incomplete file: %s",
                                file_entry.filename,
                            )
                            continue

                        if (
                            file_entry.filename.endswith(".gz")
                            and "missing" not in file_entry.filename
                        ):
                            file_content = gzip.decompress(file_content)

                        try:
                            json_data = json.loads(file_content.decode("utf-8"))

                            if isinstance(json_data, list):
                                for item in json_data:
                                    yield item
                            else:
                                yield json_data

                        except (UnicodeDecodeError, json.JSONDecodeError) as json_error:
                            self._log.error(
                                "JSON parsing failed for %s: %s",
                                file_entry.filename,
                                json_error,
                            )
                            continue

        except (zipfile.BadZipFile, OSError) as archive_error:
            self._log.error("Archive processing failed: %s", archive_error)
            raise
