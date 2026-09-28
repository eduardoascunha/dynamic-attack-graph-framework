"""
Data models for enriched vulnerability nodes.

Each leaf node in the attack graph is paired with a ThreatEnrichment
record pulled from the threat-intelligence database (EPSS, KEV, CVSS).
"""

import logging
from dataclasses import dataclass
from typing import Optional

from ..utils.cvss_parser import CIAImpact
from ..models.config.post_processing_config import CIAWeights
from ..utils.logger import Logger


@dataclass
class ThreatEnrichment:
    """
    Threat intelligence data for a CVE: EPSS, CVSS, KEV status, and CIA impact.
    """

    cve_id: str
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    kev_status: bool = False
    kev_ransomware: bool = False
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    cia_impact: CIAImpact = None

    def __post_init__(self):
        if self.cia_impact is None:
            self.cia_impact = CIAImpact()


@dataclass
class EnrichedVulnerability:
    """
    Attack graph leaf node enriched with threat intelligence and asset context.
    
    Combines EPSS, CVSS, KEV, CIA impacts, and asset criticality into a
    unified risk score (0-10 scale).
    """

    node_id: int
    cve_id: str
    asset: str
    software: str
    exploit_type: str
    impact: str
    enrichment: ThreatEnrichment
    asset_criticality: float
    cia_weights: CIAWeights = None

    def __post_init__(self):
        if self.cia_weights is None:
            self.cia_weights = CIAWeights()
        self._log = Logger.get_logger()
        # Memoization caches: both values are pure functions of immutable
        # dataclass fields, but are accessed many times per path during risk
        # scoring. Compute each once to avoid O(paths x leaves) recomputation
        # (and the associated DEBUG log flood).
        self._cia_multiplier_cache: Optional[float] = None
        self._base_risk_computed: bool = False
        self._base_risk_cache: Optional[float] = None

    @property
    def cia_multiplier(self) -> float:
        """
        Calculate CIA triad multiplier based on CVSS impact and configured
        priority levels.

        Returns multiplier in range [0.5, 1.5]:
        - 0.5: No impact on prioritized dimensions (downgrade)
        - 1.0: Neutral (no CIA impact or no prioritization)
        - 1.5: Full impact on the prioritized dimensions (boost)

        When all three CIA dimensions share the same priority level there is no
        relative prioritization, so the multiplier stays neutral (1.0).
        """
        if self._cia_multiplier_cache is None:
            self._cia_multiplier_cache = self._compute_cia_multiplier()
        return self._cia_multiplier_cache

    def _compute_cia_multiplier(self) -> float:
        if self.enrichment.cia_impact.is_neutral():
            self._log.debug("[%s] No CIA impact data, multiplier=1.0", self.cve_id)
            return 1.0

        # Equal priority on all dimensions => no prioritization => neutral
        if (self.cia_weights.confidentiality
                == self.cia_weights.integrity
                == self.cia_weights.availability):
            self._log.debug("[%s] CIA priorities equal, multiplier=1.0", self.cve_id)
            return 1.0

        w_c = self.cia_weights.confidentiality.weight
        w_i = self.cia_weights.integrity.weight
        w_a = self.cia_weights.availability.weight

        total_weight = w_c + w_i + w_a
        if total_weight <= 0:
            self._log.debug("[%s] CIA disabled (weights=0), multiplier=1.0", self.cve_id)
            return 1.0

        weighted_impact = (
            self.enrichment.cia_impact.confidentiality * w_c
            + self.enrichment.cia_impact.integrity * w_i
            + self.enrichment.cia_impact.availability * w_a
        )

        normalized = weighted_impact / total_weight
        multiplier = 0.5 + normalized  # [0, 1] -> [0.5, 1.5]

        self._log.debug(
            "[%s] CIA: I(%.1f,%.1f,%.1f) x W(%s=%.2f,%s=%.2f,%s=%.2f) = %.3f -> mult=%.3f",
            self.cve_id,
            self.enrichment.cia_impact.confidentiality,
            self.enrichment.cia_impact.integrity,
            self.enrichment.cia_impact.availability,
            self.cia_weights.confidentiality.value,
            w_c,
            self.cia_weights.integrity.value,
            w_i,
            self.cia_weights.availability.value,
            w_a,
            normalized,
            multiplier,
        )
        return multiplier

    @property
    def base_risk_score(self) -> Optional[float]:
        """
        Individual vulnerability risk score (0-10 scale).

        Formula: EPSS x (CVSS/10) x KEV_mult x CIA_mult x 10
        - KEV multiplier: 1.5 if in CISA KEV, else 1.0
        - CIA multiplier: 0.5 to 1.5 based on impact/weights

        The result is memoized: ``None`` is a valid value (missing CVSS data),
        so a separate ``_base_risk_computed`` flag guards the cache.
        """
        if not self._base_risk_computed:
            self._base_risk_cache = self._compute_base_risk_score()
            self._base_risk_computed = True
        return self._base_risk_cache

    def _compute_base_risk_score(self) -> Optional[float]:
        if not self.enrichment.cvss_vector:
            return None
        
        kev_mult = 1.5 if self.enrichment.kev_status else 1.0
        
        raw = (
            min(1.0, self.enrichment.epss_score)
            * (self.enrichment.cvss_score / 10.0)
            * kev_mult
            * self.cia_multiplier
        )
        score = round(min(10.0, raw * 10.0), 4)
        
        self._log.debug(
            "[%s] Risk: EPSS(%.3f)×CVSS(%.1f)×KEV(%.1f)×CIA(%.3f) = %.4f",
            self.cve_id,
            self.enrichment.epss_score,
            self.enrichment.cvss_score,
            kev_mult,
            self.cia_multiplier,
            score,
        )
        return score
