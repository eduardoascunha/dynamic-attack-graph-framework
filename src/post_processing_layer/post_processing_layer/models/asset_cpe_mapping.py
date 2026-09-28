"""
Pydantic models for the asset_cpe_mapping.json schema (post-processing view).

Only the fields relevant to risk analysis are modelled here: asset identity,
criticality score, and per-asset CIA weights.  CPE/service details are
consumed by the environment-correlation layer and are intentionally ignored.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from .config.post_processing_config import CIAWeights, CriticalityLevel
from ..utils.logger import Logger


class AssetRiskProfile(BaseModel):
    """Risk-relevant fields for a single asset entry."""

    asset: str = Field(..., description="Unique asset identifier")
    criticality: Optional[CriticalityLevel] = Field(
        default=None,
        description="Asset criticality level (LOW/MEDIUM/HIGH/CRITICAL). Overrides the config default.",
    )
    cia_weights: Optional[CIAWeights] = Field(
        default=None,
        description="Per-asset CIA priority levels. Overrides global cia_weights.",
    )


class AssetCpeMapping(BaseModel):
    """
    Parsed view of asset_cpe_mapping.json focused on risk analysis inputs.

    Unknown keys (services, client_software, …) are silently ignored via
    Pydantic's model_config extra='ignore' so this model stays forward-
    compatible with fields added by the environment-correlation layer.
    """

    model_config = {"extra": "ignore"}

    assets: list[AssetRiskProfile] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def get_criticality(
        self, asset_name: str, default: CriticalityLevel
    ) -> CriticalityLevel:
        """Return per-asset criticality level or *default* when not specified."""
        for entry in self.assets:
            if entry.asset == asset_name and entry.criticality is not None:
                return entry.criticality
        return default

    def get_cia_weights(self, asset_name: str, default: CIAWeights) -> CIAWeights:
        """Return per-asset CIA weights or *default* when not specified."""
        for entry in self.assets:
            if entry.asset == asset_name and entry.cia_weights is not None:
                return entry.cia_weights
        return default

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "AssetCpeMapping":
        """
        Load and parse an asset_cpe_mapping.json file.

        Returns an empty mapping (all assets fall back to config defaults)
        when the file is missing or malformed, so the pipeline is never
        blocked by an optional input file.
        """
        log: logging.Logger = Logger.get_logger()
        mapping_path = Path(path)

        if not mapping_path.exists():
            log.warning(
                "asset_cpe_mapping.json not found at %s — "
                "using config defaults for all asset criticality/CIA weights.",
                mapping_path,
            )
            return cls()

        try:
            raw = json.loads(mapping_path.read_text(encoding="utf-8"))
            # Accept both the full root object {"assets": [...]} and a bare list
            if isinstance(raw, list):
                raw = {"assets": raw}
            mapping = cls.model_validate(raw)
            log.info(
                "Loaded asset risk profiles from %s (%d assets)",
                mapping_path,
                len(mapping.assets),
            )
            return mapping
        except Exception as exc:
            log.error(
                "Failed to parse %s: %s — using config defaults.",
                mapping_path,
                exc,
            )
            return cls()
