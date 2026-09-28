"""
VulnCheck KEV Handler: Processes KEV data from VulnCheck API for database storage.
"""

from datetime import datetime
from typing import Any

from ..utils.logger import Logger
from ..database.schemas.kev_schema import KevSchema
from ..models.config.kev_config import KEV
from ..models.config.vulncheck_config import VulnCheck
from .vulncheck_handler import VulnCheckAPIHandler


class KevHandler:
    """
    Handles Known Exploited Vulnerabilities (KEV) catalog processing.
    """

    def __init__(self, kev_settings: VulnCheck, vulncheck_handler: VulnCheckAPIHandler):
        """
        Initialize with config and VulnCheck API handler.
        Args:
            kev_settings: VulnCheck config with KEV endpoint.
            vulncheck_handler: VulnCheck API handler.
        """
        self._log = Logger.get_logger()
        self._api_config = kev_settings
        self._api_client = vulncheck_handler

    def fetch_and_prepare_kev_data(self) -> list[KevSchema]:
        """
        Download, validate, and transform KEV data for DB.
        Returns:
            list[KevSchema]: Ready for DB insert.
        Raises:
            RuntimeError: If no valid records found.
        """
        raw_kev_data: list[dict[str, Any]] = list(
            self._api_client.read_zip_file(
                api_endpoint=self._api_config.api_kev_endpoint
            )
        )

        validated_models: list[KEV] = []
        for _, kev_record in enumerate(raw_kev_data):
            try:
                validated_models.append(KEV(**kev_record))
            except Exception as validation_error:
                self._log.error(
                    "KEV validation failed: %s",
                    validation_error,
                )

        if not validated_models:
            raise RuntimeError("No valid KEV records found in feed")

        return self._transform_to_database_format(validated_models)

    def _transform_to_database_format(self, kev_list: list[KEV]) -> list[KevSchema]:
        """
        Convert KEV models to DB schema objects, skipping invalid entries.
        Args:
            kev_list: Validated KEV models.
        Returns:
            list[KevSchema]: DB-ready KEV objects.
        """
        schema_records: list[KevSchema] = []

        for kev_entry in kev_list:
            try:
                if not kev_entry.cve:
                    continue

                exploitation_data = kev_entry.vulncheck_reported_exploitation
                if not exploitation_data:
                    continue

                date_added_value = None
                if kev_entry.date_added:
                    try:
                        if isinstance(kev_entry.date_added, str):
                            date_str = kev_entry.date_added.replace("Z", "+00:00")
                            date_added_value = datetime.fromisoformat(date_str).date()
                        else:
                            date_added_value = kev_entry.date_added
                    except (ValueError, AttributeError) as e:
                        self._log.warning(
                            "Failed to parse date for KEV entry '%s': %s",
                            kev_entry.date_added,
                            e,
                        )

                # Convert knownRansomwareCampaignUse to boolean
                ransomware_use = False
                if kev_entry.knownRansomwareCampaignUse:
                    ransomware_use = str(
                        kev_entry.knownRansomwareCampaignUse
                    ).lower() in ["true", "yes", "1", "known"]

                schema_records.append(
                    KevSchema(
                        cve_id=kev_entry.cve[0],
                        product=kev_entry.product,
                        date_added=date_added_value,
                        known_ransomware_use=ransomware_use,
                    )
                )

            except Exception as transform_error:
                self._log.debug(
                    "Skipping KEV entry %s: %s",
                    kev_entry.cve[0] if kev_entry.cve else "unknown",
                    transform_error,
                )

        return schema_records
