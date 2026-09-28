"""
Enriches attack graph vulnerability leaf nodes with threat intelligence.

Queries the threat_intel PostgreSQL database for EPSS exploitation probability,
CISA KEV status, and CVSSv3.1 base scores for every unique CVE referenced by
leaf nodes in the graph.
"""

import logging
from typing import Optional

from sqlalchemy import select

from ..database.postgres_repository import PostgresRepository
from ..database.schemas.cves_schema import CvesSchema
from ..database.schemas.epss_schema import EpssSchema
from ..database.schemas.kev_schema import KevSchema
from ..models.asset_cpe_mapping import AssetCpeMapping
from ..models.attack_graph import AttackGraph
from ..models.config.post_processing_config import PostProcessing
from ..models.enriched_node import EnrichedVulnerability, ThreatEnrichment
from ..utils.cvss_parser import CVSSParser
from ..utils.logger import Logger


class GraphEnricher:
    """
    Enriches attack graph vulnerabilities with threat intelligence from database.
    
    Fetches EPSS, KEV, and CVSS data for all leaf node CVEs.
    """

    def __init__(self, repo: PostgresRepository) -> None:
        self._repo = repo
        self._log = Logger.get_logger()
        self._cvss_parser = CVSSParser()

    def enrich(
        self,
        graph: AttackGraph,
        config: PostProcessing,
        asset_mapping: Optional[AssetCpeMapping] = None,
    ) -> dict[int, EnrichedVulnerability]:
        """
        Map node IDs to EnrichedVulnerability for all graph leaf nodes.

        Per-asset criticality and CIA weights are resolved from *asset_mapping*
        when provided; missing entries fall back to the global config defaults.
        CVEs not in database get zero-valued ThreatEnrichment.
        """
        cve_ids = list(graph.unique_cves)
        self._log.info("Fetching threat enrichment for %d unique CVEs", len(cve_ids))

        enrichment_map = self._fetch_enrichment(cve_ids)
        self._log.info(
            "Enrichment data fetched for %d / %d CVEs",
            len(enrichment_map),
            len(cve_ids),
        )

        result: dict[int, EnrichedVulnerability] = {}
        for node in graph.leaf_nodes:
            if not node.cve_id:
                continue

            enrichment = enrichment_map.get(
                node.cve_id,
                ThreatEnrichment(cve_id=node.cve_id),
            )

            default_criticality = config.asset_criticality
            default_cia = config.cia_weights
            if asset_mapping is not None:
                criticality_level = asset_mapping.get_criticality(
                    node.asset or "", default_criticality
                )
                cia_weights = asset_mapping.get_cia_weights(
                    node.asset or "", default_cia
                )
            else:
                criticality_level = default_criticality
                cia_weights = default_cia

            result[node.id] = EnrichedVulnerability(
                node_id=node.id,
                cve_id=node.cve_id,
                asset=node.asset or "",
                software=node.software or "",
                exploit_type=node.exploit_type or "",
                impact=node.impact or "",
                enrichment=enrichment,
                asset_criticality=criticality_level.factor,
                cia_weights=cia_weights
            )

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_enrichment(self, cve_ids: list[str]) -> dict[str, ThreatEnrichment]:
        """Batch-fetch CVSS, EPSS, and KEV data for given CVE IDs."""
        enrichment_map: dict[str, ThreatEnrichment] = {}
        if not cve_ids:
            return enrichment_map

        cvss_rows = self._repo.execute_query(
            select(
                CvesSchema.cve_id,
                CvesSchema.cvss_score_3_1,
                CvesSchema.cvss_vector_3_1,
            ).where(CvesSchema.cve_id.in_(cve_ids))
        )

        for cve_id, cvss_score, cvss_vector in cvss_rows:
            cia_impact = self._cvss_parser.parse(cvss_vector)
            enrichment_map[cve_id] = ThreatEnrichment(
                cve_id=cve_id,
                cvss_score=cvss_score or 0.0,
                cvss_vector=cvss_vector,
                cia_impact=cia_impact,
            )

        epss_rows = self._repo.execute_query(
            select(
                EpssSchema.cve_id,
                EpssSchema.epss_score,
                EpssSchema.epss_percentile,
            ).where(EpssSchema.cve_id.in_(cve_ids))
        )

        for cve_id, epss_score, epss_percentile in epss_rows:
            if cve_id in enrichment_map:
                enrichment_map[cve_id].epss_score = epss_score or 0.0
                enrichment_map[cve_id].epss_percentile = epss_percentile or 0.0
            else:
                enrichment_map[cve_id] = ThreatEnrichment(
                    cve_id=cve_id,
                    epss_score=epss_score or 0.0,
                    epss_percentile=epss_percentile or 0.0,
                )

        kev_rows = self._repo.execute_query(
            select(KevSchema.cve_id, KevSchema.known_ransomware_use).where(
                KevSchema.cve_id.in_(cve_ids)
            )
        )

        for cve_id, ransomware in kev_rows:
            if cve_id in enrichment_map:
                enrichment_map[cve_id].kev_status = True
                enrichment_map[cve_id].kev_ransomware = bool(ransomware)
            else:
                enrichment_map[cve_id] = ThreatEnrichment(
                    cve_id=cve_id,
                    kev_status=True,
                    kev_ransomware=bool(ransomware),
                )

        return enrichment_map
