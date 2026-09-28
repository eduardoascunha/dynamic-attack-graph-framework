"""
Data models for risk analysis and delta reporting outputs.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PathRiskScore:
    """
    Risk score and metadata for a single root-to-leaf attack path.

    Attributes:
        path_id:            SHA-256–derived short identifier (16 hex chars).
        goal_label:         Prolog label of the root OR node (attacker goal).
        nodes:              Ordered list of node IDs from goal to leaf.
        leaf_cves:          CVE IDs of all vulnerability leaves on this path.
        risk_score:         Aggregated path risk score (0.0–10.0), or None if undefined.
        highest_risk_vuln:  CVE ID of the most dangerous leaf on the path.
        path_length:        Total number of nodes in the path.
        kev_on_path:        True if any leaf is in the CISA KEV catalogue.
        max_epss_on_path:   Highest EPSS score among leaves on this path.
        max_cvss_on_path:   Highest CVSSv3.1 score among leaves on this path.
    """

    path_id: str
    goal_label: str
    nodes: list[int]
    leaf_cves: list[str]
    risk_score: Optional[float]
    highest_risk_vuln: Optional[str]
    path_length: int
    kev_on_path: bool
    max_epss_on_path: float
    max_cvss_on_path: float


@dataclass
class RiskReport:
    """
    Complete dynamic risk analysis report for a single attack graph snapshot.

    Contains all enumerated paths and pre-computed top-N ranking.
    Serialisable to JSON via ``to_dict()``.
    """

    generated_at: str
    graph_version: str
    total_nodes: int
    total_leaf_nodes: int
    total_vulnerability_leaf_nodes: int
    unique_cves: int
    paths: list[PathRiskScore] = field(default_factory=list)
    top_paths: list[PathRiskScore] = field(default_factory=list)
    enrichment_coverage: float = 0.0  # fraction of CVEs with threat data

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary."""
        return {
            "generated_at": self.generated_at,
            "graph_version": self.graph_version,
            "summary": {
                "total_nodes": self.total_nodes,
                "total_leaf_nodes": self.total_leaf_nodes,
                "total_vulnerability_leaf_nodes": self.total_vulnerability_leaf_nodes,
                "unique_cves": self.unique_cves,
                "total_attack_paths": len(self.paths),
                "enrichment_coverage_pct": round(self.enrichment_coverage * 100, 1),
            },
            "top_attack_paths": [
                {
                    "path_id": p.path_id,
                    "goal": p.goal_label,
                    "risk_score": p.risk_score,
                    "path_length": p.path_length,
                    "leaf_cves": p.leaf_cves,
                    "highest_risk_vuln": p.highest_risk_vuln,
                    "kev_on_path": p.kev_on_path,
                    "max_epss": p.max_epss_on_path,
                    "max_cvss": p.max_cvss_on_path,
                }
                for p in self.top_paths
            ],
            "all_paths": [
                {
                    "path_id": p.path_id,
                    "goal": p.goal_label,
                    "risk_score": p.risk_score,
                    "path_length": p.path_length,
                    "leaf_cves": p.leaf_cves,
                    "kev_on_path": p.kev_on_path,
                }
                for p in self.paths
            ],
        }


@dataclass
class DeltaReport:
    """
    Comparison between the current and the most recently archived risk report.

    Enables analysts to observe how evolving threat intelligence influences
    attack-path prioritisation over time.

    Attributes:
        generated_at:         ISO-8601 timestamp of this analysis run.
        previous_version:     graph_version hash of the previous snapshot
                              (None if this is the first run).
        current_version:      graph_version hash of the current analysis.
        new_cves:             CVEs present now but absent in the last snapshot.
        removed_cves:         CVEs absent now but present in the last snapshot.
        risk_score_change:    Δ in average top-path risk score vs. last run.
        new_top_paths:        Path IDs that entered the top-N ranking.
        removed_top_paths:    Path IDs that left the top-N ranking.
        kev_additions:        CVEs newly added to the CISA KEV catalogue.
    """

    generated_at: str
    previous_version: Optional[str]
    current_version: str
    new_cves: list[str]
    removed_cves: list[str]
    risk_score_change: float
    new_top_paths: list[str]
    removed_top_paths: list[str]
    kev_additions: list[str]

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "previous_version": self.previous_version,
            "current_version": self.current_version,
            "vulnerability_delta": {
                "new_cves": self.new_cves,
                "removed_cves": self.removed_cves,
            },
            "risk_change": {
                "average_top_path_score_delta": round(self.risk_score_change, 4),
                "new_top_paths": self.new_top_paths,
                "removed_top_paths": self.removed_top_paths,
            },
            "kev_additions": self.kev_additions,
        }
