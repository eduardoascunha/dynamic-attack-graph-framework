"""
Controller module for orchestrating threat intelligence data ingestion and synchronization.
"""

from pydantic import FilePath

from ..utils.logger import Logger
from ..utils.settings import Settings
from ..handlers.epss_handler import EpssHandler
from ..handlers.kev_handler import KevHandler
from ..handlers.cve_handler import CveHandler
from ..handlers.vulncheck_handler import VulnCheckAPIHandler
from ..database.postgres_repository import PostgresRepository
from ..database.schemas.cve_cpe_mapping_schema import CveCpeMappingSchema


class ThreatIntelligenceController:
    """
    Orchestrates threat intelligence data ingestion and sync.
    """

    def __init__(self, config_path: FilePath) -> None:
        """
        Initialize controller with config and handlers.
        Args:
            config_path (FilePath): Path to TOML config file.
        Raises:
            psycopg.errors.DatabaseError: On DB connection error.
            pydantic.ValidationError: On config parse error.
            Exception: On other errors.
        """

        self._log = Logger.get_logger()

        try:
            self._app_config: Settings = Settings(config_path)
            self._log.debug(f"Configuration loaded from {config_path}")

        except Exception as init_error:
            self._log.error(
                f"Configuration loading failed: {init_error}", exc_info=True
            )
            raise

        try:
            self._api_handler = VulnCheckAPIHandler(self._app_config)
            self._log.debug("VulnCheck API handler initialized")

            self._epss_handler = EpssHandler(self._app_config.EPSS)
            self._log.debug("EPSS handler initialized")

            self._kev_handler = KevHandler(
                self._app_config.VULNCHECK, self._api_handler
            )
            self._log.debug("KEV handler initialized")

            self._cve_handler = CveHandler(
                self._app_config.VULNCHECK, self._api_handler
            )
            self._log.debug("CVE handler initialized")

        except Exception as handler_error:
            self._log.error(f"Handler initialization error: {handler_error}")
            raise

    def sync_vulnerability_data(self) -> None:
        """
        Run CVE, EPSS, and KEV sync.
        """
        self._log.info("Starting vulnerability data synchronization...")

        try:
            # Synchronize CVE data (most time-consuming)
            self._synchronize_cve_records()
            self._log.info("CVE synchronization complete")

            # Synchronize EPSS scores
            self._synchronize_epss_scores()
            self._log.info("EPSS synchronization complete")

            # Synchronize KEV catalog
            self._synchronize_kev_catalog()
            self._log.info("KEV synchronization complete")

            self._log.info("All vulnerability data synchronized successfully")

        except Exception as sync_error:
            self._log.error(f"Vulnerability data synchronization failed: {sync_error}")
            raise

    def _synchronize_epss_scores(self) -> None:
        """
        Sync EPSS scores using upsert (insert new, update existing).
        Raises:
            Exception: On sync error.
        """
        try:
            self._log.info("Starting EPSS score synchronization...")
            epss_records = self._epss_handler.fetch_and_prepare_epss_data()

            if not epss_records:
                self._log.warning("No EPSS records to synchronize")
                return

            with PostgresRepository(self._app_config.DATABASE) as repository:
                repository.upsert_many(epss_records)

            self._log.info(f"Successfully upserted {len(epss_records)} EPSS records")

        except Exception as epss_error:
            self._log.error(f"EPSS synchronization error: {epss_error}")
            raise

    def _synchronize_kev_catalog(self) -> None:
        """
        Sync KEV catalog using upsert (insert new, update existing).
        Raises:
            Exception: On sync error.
        """
        try:
            self._log.info("Starting KEV catalog synchronization...")
            kev_records = self._kev_handler.fetch_and_prepare_kev_data()

            if not kev_records:
                self._log.warning("No KEV records to synchronize")
                return

            with PostgresRepository(self._app_config.DATABASE) as repository:
                repository.upsert_many(kev_records)

            self._log.info(f"Successfully upserted {len(kev_records)} KEV records")

        except Exception as kev_error:
            self._log.error(f"KEV synchronization error: {kev_error}")
            raise

    def _synchronize_cve_records(self) -> None:
        """
        Import CVE records and CVE-CPE mappings in batches using upsert.
        Inserts new records, updates existing records, ignores duplicates for mappings.
        Raises:
            Exception: On import error.
        """
        try:
            self._log.info("Starting CVE data import...")

            total_cves_upserted = 0
            total_mappings_inserted = 0

            with PostgresRepository(self._app_config.DATABASE) as repository:
                for cve_batch, mapping_batch in self._cve_handler.fetch_and_prepare_cve_data():
                    if not cve_batch and not mapping_batch:
                        continue

                    # Upsert CVE records (insert new, update existing)
                    if cve_batch:
                        repository.upsert_many(cve_batch)
                        total_cves_upserted += len(cve_batch)
                        self._log.debug(f"Upserted batch: {len(cve_batch)} CVE records")

                    # Insert CVE-CPE mappings with ON CONFLICT DO NOTHING for duplicate prevention
                    if mapping_batch:
                        repository.bulk_insert_mappings_on_conflict_do_nothing(
                            CveCpeMappingSchema, mapping_batch, chunk_size=5000
                        )
                        total_mappings_inserted += len(mapping_batch)
                        self._log.debug(
                            f"Inserted batch: {len(mapping_batch)} CVE-CPE mappings"
                        )

            self._log.info(f"Successfully upserted {total_cves_upserted} total CVE records")
            self._log.info(f"Successfully inserted {total_mappings_inserted} total CVE-CPE mappings")

        except Exception as cve_error:
            self._log.error(f"CVE import error: {cve_error}")
            raise
