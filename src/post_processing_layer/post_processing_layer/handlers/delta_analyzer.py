"""
Delta analysis between successive risk analysis snapshots.

Compares the current RiskReport against the most recent ``risk_analysis_*.json``
file already present in the work directory. No separate registry is needed —
every run writes its combined report to ``work_dir`` and the next run reads the
newest one back for comparison.

Surfaces changes in:
  - CVE surface area (new / removed vulnerabilities)
  - Attack-path risk rankings (paths entering or leaving the top-N)
  - Average top-path risk score change
  - CVEs newly catalogued by CISA KEV
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..models.risk_report import DeltaReport, RiskReport
from ..utils.logger import Logger

_REPORT_PREFIX = "risk_analysis_"
_REPORT_SUFFIX = ".json"

class DeltaAnalyzer:
    """
    Produces a DeltaReport by comparing the current RiskReport with the
    most recent report already present in the work directory.
    """

    def __init__(self) -> None:
        self._log: logging.Logger = Logger.get_logger()

    def analyze(self, current: RiskReport, work_dir: str) -> DeltaReport:
        """
        Compare current against the latest existing report in work_dir.

        Args:
            current:  The freshly computed RiskReport.
            work_dir: Directory where ``risk_analysis_*.json`` files are written.
                      The most recent file (by name, which is timestamp-ordered)
                      is used as the comparison baseline.

        Returns:
            DeltaReport describing changes vs. the previous run.
            If no previous report exists a baseline DeltaReport is returned.
        """
        work_path = Path(work_dir)
        work_path.mkdir(parents=True, exist_ok=True)

        previous = self._load_latest_report(work_path)

        if previous is None:
            self._log.info("No previous report found in %s — baseline delta", work_dir)
            return self._baseline_delta(current)

        return self._compute_delta(current, previous)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_delta(
        self, current: RiskReport, previous_combined: dict
    ) -> DeltaReport:
        """Compare current report with previous combined report."""
        prev = previous_combined.get("risk_report", previous_combined)

        # CVE surface changes — derived from all_paths (no extra fields needed)
        prev_cves = {
            cve
            for p in prev.get("all_paths", [])
            for cve in p.get("leaf_cves", [])
        }
        curr_cves = {cve for p in current.paths for cve in p.leaf_cves}
        new_cves = sorted(curr_cves - prev_cves)
        removed_cves = sorted(prev_cves - curr_cves)

        # Top-path ranking changes
        prev_top_ids = {p["path_id"] for p in prev.get("top_attack_paths", [])}
        curr_top_ids = {p.path_id for p in current.top_paths}
        new_top = sorted(curr_top_ids - prev_top_ids)
        removed_top = sorted(prev_top_ids - curr_top_ids)

        # Average risk score change
        prev_avg = _avg_score_list(prev.get("top_attack_paths", []))
        curr_avg = _avg_score_report(current)
        risk_change = round(curr_avg - prev_avg, 4)

        # KEV catalogue additions — derived from all_paths
        prev_kev = {
            cve
            for p in prev.get("all_paths", [])
            if p.get("kev_on_path")
            for cve in p.get("leaf_cves", [])
        }
        curr_kev = {cve for p in current.paths if p.kev_on_path for cve in p.leaf_cves}
        kev_additions = sorted(curr_kev - prev_kev)

        previous_version = prev.get("graph_version")

        self._log.info(
            "Delta: +%d new CVEs, -%d removed; risk Δ=%.2f; "
            "%d new top paths; %d KEV additions",
            len(new_cves),
            len(removed_cves),
            risk_change,
            len(new_top),
            len(kev_additions),
        )

        return DeltaReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            previous_version=previous_version,
            current_version=current.graph_version,
            new_cves=new_cves,
            removed_cves=removed_cves,
            risk_score_change=risk_change,
            new_top_paths=new_top,
            removed_top_paths=removed_top,
            kev_additions=kev_additions,
        )

    def _baseline_delta(self, current: RiskReport) -> DeltaReport:
        """Return a no-comparison delta for the very first run."""
        return DeltaReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            previous_version=None,
            current_version=current.graph_version,
            new_cves=sorted({cve for p in current.paths for cve in p.leaf_cves}),
            removed_cves=[],
            risk_score_change=0.0,
            new_top_paths=[p.path_id for p in current.top_paths],
            removed_top_paths=[],
            kev_additions=sorted(
                {cve for p in current.paths if p.kev_on_path for cve in p.leaf_cves}
            ),
        )

    def _load_latest_report(self, work_path: Path) -> Optional[dict]:
        """Return the parsed JSON of the most recent risk_analysis_*.json, or None."""
        reports = sorted(work_path.glob(f"{_REPORT_PREFIX}*{_REPORT_SUFFIX}"))
        if not reports:
            return None
        latest = reports[-1]
        self._log.info("Loading previous report for delta: %s", latest.name)
        with open(latest, "r", encoding="utf-8") as f:
            return json.load(f)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _avg_score_list(paths: list[dict]) -> float:
    """Calculate average risk score from JSON path list, excluding None/null values."""
    if not paths:
        return 0.0
    scores = [p.get("risk_score") for p in paths if p.get("risk_score") is not None]
    return sum(scores) / len(scores) if scores else 0.0


def _avg_score_report(report: RiskReport) -> float:
    """Calculate average risk score from RiskReport, excluding None values."""
    if not report.top_paths:
        return 0.0
    scores = [p.risk_score for p in report.top_paths if p.risk_score is not None]
    return sum(scores) / len(scores) if scores else 0.0

