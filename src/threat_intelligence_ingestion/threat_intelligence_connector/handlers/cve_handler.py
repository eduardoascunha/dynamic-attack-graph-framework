"""
VulnCheck NVD CVE Handler: Processes NVD CVE and CVSS data from VulnCheck API.
"""

from datetime import datetime
from typing import Any, Generator, Iterable

from ..database.schemas.cve_schema import CveSchema
from ..models.config.vulncheck_config import VulnCheck
from ..models.config.cve_config import NvdCve
from ..utils.logger import Logger
from .vulncheck_handler import VulnCheckAPIHandler


class CveHandler:
    """
    Handles NVD CVE data processing from VulnCheck API.
    """

    def __init__(self, settings: VulnCheck, vulncheck_handler: VulnCheckAPIHandler):
        """
        Initialize with VulnCheck config and API handler.
        Args:
            settings (VulnCheck): VulnCheck config.
            vulncheck_handler (VulnCheckAPIHandler): VulnCheck API handler.
        """
        self._log = Logger.get_logger()
        self._api_config = settings
        self._api_client = vulncheck_handler

    def fetch_and_prepare_cve_data(
        self,
    ) -> Generator[tuple[list[CveSchema], list[dict[str, Any]]], None, None]:
        """
        Download, parse, and yield batches of CVE data and CVE-CPE mappings for DB insert.
        Yields:
            tuple[list[CveSchema], list[dict[str, Any]]]: CVE objects and mapping dicts.
        Raises:
            RuntimeError: If no CVE data found.
        """
        json_files = self._api_client.read_zip_file(
            api_endpoint=self._api_config.api_nvd_endpoint
        )

        batches = (batch for batch in self._parse_nvd_json_files(json_files) if batch)
        first = next(batches, None)
        if first is None:
            raise RuntimeError("No CVE data produced from VulnCheck NVD feed")
        yield first
        for batch in batches:
            yield batch

    def _parse_nvd_json_files(
        self, json_files: Iterable[dict[str, Any]]
    ) -> Generator[tuple[list[CveSchema], list[dict[str, Any]]], None, None]:
        """
        Parse multiple NVD JSON files to batches of CVE schema objects and mappings.
        Args:
            json_files (Iterable[dict[str, Any]]): Iterable of NVD JSON dicts.
        Yields:
            tuple[list[CveSchema], list[dict[str, Any]]]: Batches of CVE objects and mapping dicts.
        """
        for json_file in json_files:
            yield self._parse_nvd_json_file(json_file)

    def _parse_nvd_json_file(
        self, json_file: dict[str, Any]
    ) -> tuple[list[CveSchema], list[dict[str, Any]]]:
        """
        Parse one NVD JSON file to CVE schema objects and mapping dicts.
        Processes in memory-efficient manner.
        Args:
            json_file (dict[str, Any]): Parsed NVD JSON.
        Returns:
            tuple[list[CveSchema], list[dict[str, Any]]]: CVE objects and mapping dicts.
        """
        nvd = self._load_nvd(json_file)
        if not nvd:
            return [], []

        cve_lst: list[CveSchema] = []
        mapping_lst: list[dict[str, Any]] = []

        for vulnerability in nvd.vulnerabilities:
            cve_data = self._get_valid_cve(vulnerability)
            if not cve_data:
                continue

            result = self._process_vulnerability(vulnerability)
            if result:
                cve, mappings = result
                cve_lst.append(cve)
                mapping_lst.extend(mappings)

        return cve_lst, mapping_lst

    def _load_nvd(self, json_file: dict[str, Any]) -> NvdCve | None:
        """
        Validate and load NVD JSON.
        Args:
            json_file (dict[str, Any]): Raw JSON.
        Returns:
            NvdCve | None: Valid NVD model or None.
        """
        try:
            return NvdCve(**json_file)
        except Exception as exc:
            self._log.error("Invalid NVD JSON structure: %s", exc)
            return None

    def _get_valid_cve(self, vulnerability: Any) -> Any | None:
        """
        Validate and extract CVE data from vulnerability.
        Args:
            vulnerability (Any): Vulnerability object.
        Returns:
            Any | None: CVE data or None.
        """
        cve_data: Any | None = getattr(vulnerability, "cve", None)

        if not cve_data:
            self._log.debug("Skipping vulnerability: missing CVE object")
            return None

        summary: str = getattr(cve_data, "summary", "") or ""

        if "rejected" in summary.lower():
            self._log.debug("Skipping rejected CVE %s", getattr(cve_data, "id", "?"))
            return None

        return cve_data

    def _process_vulnerability(self, vulnerability: Any) -> tuple[CveSchema, list[dict[str, Any]]] | None:
        """
        Convert a vulnerability entry to CveSchema and CPE mapping dicts.
        Args:
            vulnerability (Any): Vulnerability object.
        Returns:
            tuple[CveSchema, list[dict[str, Any]]] | None: CVE schema and mapping dicts or None.
        """
        cve, cve_id = self._extract_cve_and_id(vulnerability)
        if cve is None or cve_id is None:
            return None

        published, modified, cvss_score, cvss_vector = self._extract_cve_metadata(
            cve, cve_id
        )

        cpes = (
            cve.vcVulnerableCPEs
            if hasattr(cve, "vcVulnerableCPEs") and cve.vcVulnerableCPEs
            else []
        )

        cve_obj = CveSchema(
            cve_id=cve_id,
            published_date=published,
            last_modified_date=modified,
            cvss_score_3_1=cvss_score,
            cvss_vector_3_1=cvss_vector,
        )
        
        unique_cpes = set(cpes)  # Remove duplicate CPE strings
        mapping_dicts = [
            {"cve_id": cve_id, "cpe": cpe}
            for cpe in unique_cpes
        ]
        
        return cve_obj, mapping_dicts

    def _extract_cve_and_id(self, vulnerability: Any) -> tuple[Any | None, str | None]:
        """
        Extract the CVE object and its ID from a vulnerability.
        Returns (cve, cve_id) or (None, None) if missing.
        """
        try:
            cve = vulnerability.cve
            cve_id = cve.id
            return cve, cve_id
        except AttributeError:
            self._log.error("Invalid vulnerability structure: missing CVE root")
            return None, None

    def _extract_cve_metadata(
        self, cve: Any, cve_id: str
    ) -> tuple[datetime | None, datetime | None, float | None, str | None]:
        """
        Extract published/modified dates and CVSS 3.x score/vector from a CVE object.
        Returns (published, modified, cvss_score, cvss_vector).
        """
        # Parse timestamps
        published = None
        if hasattr(cve, "published") and cve.published:
            try:
                date_str = (
                    cve.published.replace("Z", "+00:00")
                    if "Z" in cve.published
                    else cve.published
                )
                published = datetime.fromisoformat(date_str)
            except (ValueError, TypeError):
                pass

        modified = None
        if hasattr(cve, "lastModified") and cve.lastModified:
            try:
                date_str = (
                    cve.lastModified.replace("Z", "+00:00")
                    if "Z" in cve.lastModified
                    else cve.lastModified
                )
                modified = datetime.fromisoformat(date_str)
            except (ValueError, TypeError):
                pass

        # Extract CVSS 3.1 score and vector
        cvss_score = None
        cvss_vector = None
        try:
            # Try CVSS 3.1 first
            metric = (
                cve.get_cvss31_metric() if hasattr(cve, "get_cvss31_metric") else None
            )
            if metric and hasattr(metric, "cvssData"):
                cvss_score = getattr(metric.cvssData, "baseScore", None)
                cvss_vector = getattr(metric.cvssData, "vectorString", None)

            # Fallback to CVSS 3.0 if 3.1 not available
            if cvss_score is None:
                metric = (
                    cve.get_cvss30_metric()
                    if hasattr(cve, "get_cvss30_metric")
                    else None
                )
                if metric and hasattr(metric, "cvssData"):
                    cvss_score = getattr(metric.cvssData, "baseScore", None)
                    cvss_vector = getattr(metric.cvssData, "vectorString", None)
        except Exception as exc:
            self._log.debug("Failed to extract CVSS3 for %s: %s", cve_id, exc)

        return published, modified, cvss_score, cvss_vector
