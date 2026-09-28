"""
Post-processing layer configuration model.
"""

from enum import Enum

from pydantic import BaseModel, Field


class CriticalityLevel(str, Enum):
    """
    Qualitative asset criticality level.

    Replaces opaque 0.0-1.0 floats with named tiers. Each level maps to a
    fixed numeric factor applied to the path risk score so that the meaning
    of a level is explicit and reproducible.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def factor(self) -> float:
        """Numeric risk factor used in path scoring (criticality multiplier)."""
        return {
            CriticalityLevel.LOW: 0.4,
            CriticalityLevel.MEDIUM: 0.7,
            CriticalityLevel.HIGH: 1.0,
            CriticalityLevel.CRITICAL: 1.3,
        }[self]


class PriorityLevel(str, Enum):
    """
    Qualitative importance level for a single CIA dimension.

    Replaces opaque 0.0-1.0 weights with named tiers. Levels are interpreted
    *relatively*: when all three CIA dimensions share the same level there is
    no prioritization and the CIA multiplier stays neutral (1.0).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def weight(self) -> float:
        """Numeric weight used in the CIA-priority weighted average."""
        return {
            PriorityLevel.LOW: 0.25,
            PriorityLevel.MEDIUM: 0.5,
            PriorityLevel.HIGH: 1.0,
        }[self]


class CIAWeights(BaseModel):
    """
    Per-dimension CIA priority levels (LOW/MEDIUM/HIGH) for risk prioritization.

    All dimensions at the same level means "no prioritization" (neutral). Set
    one dimension higher than the others to boost vulnerabilities that impact
    the dimension you care about most for a given asset.
    """

    confidentiality: PriorityLevel = Field(
        default=PriorityLevel.MEDIUM,
        description="Priority for confidentiality (LOW/MEDIUM/HIGH).",
    )
    integrity: PriorityLevel = Field(
        default=PriorityLevel.MEDIUM,
        description="Priority for integrity (LOW/MEDIUM/HIGH).",
    )
    availability: PriorityLevel = Field(
        default=PriorityLevel.MEDIUM,
        description="Priority for availability (LOW/MEDIUM/HIGH).",
    )


class PostProcessing(BaseModel):
    """Post-processing and risk analysis pipeline configuration."""

    graph_dir: str = Field(
        default="/gen_graph",
        description="Directory with MulVAL output (VERTICES.CSV, ARCS.CSV).",
    )
    work_dir: str = Field(
        default="/post_processing",
        description="Output dir for JSON reports; previous reports used for delta.",
    )
    top_paths_count: int = Field(
        default=10,
        ge=1,
        description="Number of top-risk paths in summary.",
    )
    asset_criticality: CriticalityLevel = Field(
        default=CriticalityLevel.MEDIUM,
        description="Global default asset criticality level (LOW/MEDIUM/HIGH/CRITICAL). Per-asset values are defined in asset_cpe_mapping.json.",
    )
    cia_weights: CIAWeights = Field(
        default_factory=CIAWeights,
        description="Global CIA priority levels used as fallback when an asset has no override in asset_cpe_mapping.json.",
    )
    max_path_depth: int = Field(
        default=30,
        ge=1,
        description="Maximum DFS depth for path enumeration (cycle guard).",
    )
    generate_summary_graph: bool = Field(
        default=True,
        description=(
            "When true, also emit a condensed host-level 'global view' attack "
            "graph (AttackGraph_summarized.{dot,png,pdf}) alongside the detailed "
            "annotated graph. The detailed outputs are always produced."
        ),
    )
    summary_max_paths: int = Field(
        default=200,
        ge=1,
        description=(
            "Cap on the number of highest-risk paths aggregated into the "
            "summary graph. The summary collapses paths onto per-host nodes, "
            "so a high cap reveals the full reachable topology; lower it only "
            "if the global view becomes too dense."
        ),
    )
