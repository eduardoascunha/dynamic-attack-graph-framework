"""
Quality Gate Handler: validates that the threat-intelligence database is
sufficiently populated before the correlation pipeline runs.
"""

from sqlalchemy import text

from ..database.postgres_repository import PostgresRepository
from ..models.config.database_config import Database
from ..models.config.quality_gate_config import QualityGate
from ..utils.logger import Logger


class QualityGateError(RuntimeError):
    """Raised when the threat-intelligence database fails the quality gate."""


class QualityGateHandler:
    """
    Enforces minimum row counts on the threat-intelligence tables.

    Table names are drawn from a fixed internal mapping (never from user input),
    so the count queries are not exposed to SQL injection.
    """

    def __init__(self, db_config: Database, thresholds: QualityGate) -> None:
        """
        Args:
            db_config: Database connection configuration.
            thresholds: Minimum row counts required per table.
        """
        self._log = Logger.get_logger()
        self._db_config = db_config
        self._thresholds = thresholds

    def _count_rows(self, repo: PostgresRepository, table: str) -> int:
        """Return the number of rows in threat_intel.<table>."""
        result = repo.execute_query(text(f"SELECT count(*) FROM threat_intel.{table}"))
        return int(result[0][0]) if result else 0

    def enforce(self) -> None:
        """
        Query each threat-intelligence table and abort the pipeline if any of
        them holds fewer rows than the configured minimum.

        Raises:
            QualityGateError: If one or more tables are under-populated.
        """
        minimums = {
            "cves": self._thresholds.min_cves,
            "cve_cpe_mapping": self._thresholds.min_cve_cpe_mapping,
            "epss": self._thresholds.min_epss,
            "kev": self._thresholds.min_kev,
        }

        failures: list[str] = []
        with PostgresRepository(self._db_config) as repo:
            for table, minimum in minimums.items():
                count = self._count_rows(repo, table)
                self._log.info(
                    "Quality gate: threat_intel.%s has %d rows (minimum %d)",
                    table,
                    count,
                    minimum,
                )
                if count < minimum:
                    failures.append(
                        f"threat_intel.{table}: {count} rows < required {minimum}"
                    )

        if failures:
            message = (
                "Threat intelligence quality gate failed; database is "
                "under-populated: " + "; ".join(failures)
            )
            self._log.error(message)
            raise QualityGateError(message)

        self._log.info("Threat intelligence quality gate passed.")
