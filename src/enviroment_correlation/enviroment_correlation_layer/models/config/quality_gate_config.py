"""Quality gate configuration model."""

from pydantic import BaseModel, Field


class QualityGate(BaseModel):
    """
    Minimum row counts each threat-intelligence table must contain before the
    pipeline is allowed to run.

    These thresholds act as a pre-flight sanity check: if the database is empty
    or only partially populated (e.g. an ingestion run failed halfway), the
    counts fall below these floors and the pipeline is aborted instead of
    producing an attack graph from incomplete intelligence. The defaults are
    conservative floors chosen below the current production volumes.
    """

    min_cves: int = Field(
        default=300_000, ge=0, description="Minimum rows in threat_intel.cves."
    )
    min_cve_cpe_mapping: int = Field(
        default=30_000_000,
        ge=0,
        description="Minimum rows in threat_intel.cve_cpe_mapping.",
    )
    min_epss: int = Field(
        default=300_000, ge=0, description="Minimum rows in threat_intel.epss."
    )
    min_kev: int = Field(
        default=4_000, ge=0, description="Minimum rows in threat_intel.kev."
    )
