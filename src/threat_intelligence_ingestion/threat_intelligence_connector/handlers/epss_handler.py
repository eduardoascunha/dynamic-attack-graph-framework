"""
First.org EPSS Handler for fetching and processing EPSS scores.
"""

import csv
import gzip
import requests

from io import BytesIO

from ..utils.logger import Logger
from ..models.config.epss_config import Epss
from ..database.schemas.epss_schema import EpssSchema


class EpssHandler:
    """
    Handles EPSS data fetch and DB preparation from First.org.
    """

    def __init__(self, settings: Epss):
        """
        Initialize with EPSS settings (CSV URL config).
        """
        self.__logger = Logger.get_logger()
        self.__settings = settings

    def fetch_and_prepare_epss_data(self) -> list[EpssSchema]:
        """
        Fetch and prepare EPSS data for DB insert.
        Returns:
            list[EpssSchema]: Ready for DB insert.
        Raises:
            ValueError: If no CSV URL in config.
        """
        if self.__settings.csv_url is None:
            self.__logger.error("No EPSS CSV URL provided in the configuration.")
            raise ValueError("No EPSS CSV URL provided in the configuration.")

        epss_data = self.__fetch_epss_data(str(self.__settings.csv_url))
        return self.__map_epss_list_to_db_format(epss_data)

    def __fetch_epss_data(self, epss_csv_url: str) -> list[str]:
        """
        Download and decompress EPSS CSV data from URL.
        Args:
            epss_csv_url (str): EPSS CSV URL.
        Returns:
            list[str]: EPSS data lines.
        Raises:
            requests.exceptions.RequestException: On HTTP error.
            ValueError: On gzip read error.
        """
        self.__logger.info("Downloading EPSS data...")

        try:
            response = requests.get(epss_csv_url, timeout=30)
        except requests.exceptions.RequestException as e:
            self.__logger.error("Failed to retrieve EPSS gzip content: %s", e)
            raise

        try:
            with gzip.open(BytesIO(response.content), "rb") as fgz:
                data = fgz.read().decode().splitlines(True)
        except ValueError as e:
            self.__logger.error(f"Failed to read EPSS gzip content. Invalid file. {e}")
            raise
        self.__logger.info(
            "EPSS data downloaded successfully, %i entries.", len(data) - 2
        )
        return data

    def __map_epss_list_to_db_format(self, epss_list: list[str]) -> list[EpssSchema]:
        """
        Convert EPSS CSV lines to DB model instances.
        Args:
            epss_list (list[str]): CSV lines.
        Returns:
            list[EpssSchema]: DB model instances.
        """
        reader = csv.reader(epss_list)
        epss_full_list = list(reader)[2:]  # skip the headers

        result: list[EpssSchema] = []
        for epss_lst in epss_full_list:
            try:
                result.append(
                    EpssSchema(
                        cve_id=epss_lst[0],
                        epss_score=float(epss_lst[1]),
                        epss_percentile=float(epss_lst[2]),
                    )
                )
            except (ValueError, IndexError) as e:
                self.__logger.error("Failed to parse EPSS entry: %s", e)

        return result
