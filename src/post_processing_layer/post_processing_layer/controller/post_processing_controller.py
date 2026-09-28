"""
Main controller for the post-processing and dynamic risk analysis layer.

Orchestrates the five-step pipeline:
  1. Parse the MulVAL attack graph (VERTICES.CSV + ARCS.CSV).
  2. Enrich vulnerability leaf nodes with EPSS, KEV, and CVSS threat data.
  3. Enumerate attack paths and compute path-level risk scores.
  4. Run delta analysis against the previous snapshot and persist the report.
  5. Annotate graph with detailed risk metrics and render visualizations (PDF/PNG).
  6. Optionally emit a condensed host-level "global view" graph (toggle via
     POST_PROCESSING.generate_summary_graph).
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..database.postgres_repository import PostgresRepository
from ..handlers.delta_analyzer import DeltaAnalyzer
from ..handlers.graph_annotator import GraphAnnotator
from ..handlers.graph_summarizer import GraphSummarizer
from ..handlers.graph_enricher import GraphEnricher
from ..handlers.graph_parser import GraphParser
from ..handlers.risk_scorer import RiskScorer
from ..models.asset_cpe_mapping import AssetCpeMapping
from ..utils.logger import Logger
from ..utils.settings import Settings


class PostProcessingController:
    """
    Runs the complete post-processing pipeline for a single MulVAL graph run.
    """

    def __init__(self, config_path: str) -> None:
        self._log: logging.Logger = Logger.get_logger()
        self._settings = Settings(config_path)
        self._parser = GraphParser()
        self._scorer = RiskScorer()
        self._delta = DeltaAnalyzer()
        self._annotator = GraphAnnotator()
        self._summarizer = GraphSummarizer()

    def run(
        self,
        graph_dir: str,
        work_dir: str,
        asset_mapping_path: str | None = None,
        include_legend: bool = True,
    ) -> None:
        """
        Execute the full post-processing pipeline.

        Args:
            graph_dir: Directory containing MulVAL output (VERTICES.CSV, ARCS.CSV)
                       and the ``scenario.P`` snapshot that produced that graph.
            work_dir:  Output directory for risk analysis JSON reports.
                       Existing "risk_analysis_*.json" files here are used for
                       delta comparison against the previous run.
            asset_mapping_path: Path to the asset_cpe_mapping.json file that
                       carries per-asset criticality and CIA weights.  When
                       absent the pipeline falls back to global config defaults.
            include_legend: Whether the detailed graph includes its embedded
                color and shape legend.

        Returns:
            Absolute path of the written JSON report file.
        """
        self._log.info("Post-Processing Pipeline Start")

        # ----------------------------------------------------------------
        # 1 — Parse attack graph
        # ----------------------------------------------------------------
        self._log.info("Parsing attack graph from %s", graph_dir)
        graph = self._parser.parse(graph_dir)

        # ----------------------------------------------------------------
        # 2 — Enrich nodes with threat data
        # ----------------------------------------------------------------
        self._log.info(
            "Enriching %d leaf nodes (%d unique CVEs)",
            len(graph.leaf_nodes),
            len(graph.unique_cves),
        )
        asset_mapping = AssetCpeMapping.load(asset_mapping_path) if asset_mapping_path else AssetCpeMapping()
        with PostgresRepository(self._settings.DATABASE) as repo:
            enricher = GraphEnricher(repo)
            enriched = enricher.enrich(graph, self._settings.POST_PROCESSING, asset_mapping)

        # ----------------------------------------------------------------
        # 3 — Compute path risk scores - risk report
        # ----------------------------------------------------------------
        self._log.info("Scoring attack paths")
        scenario_path = self._scenario_for_scoring(graph_dir)
        risk_report = self._scorer.score(
            graph, enriched, self._settings.POST_PROCESSING, scenario_path
        )

        # ----------------------------------------------------------------
        # 4 — Delta analysis against previous report in work_dir - delta report
        # ----------------------------------------------------------------
        self._log.info("Delta analysis against previous report")
        delta_report = self._delta.analyze(risk_report, work_dir)

        # ----------------------------------------------------------------
        # Write combined JSON report
        # ----------------------------------------------------------------
        output_path = self._write_report(risk_report, delta_report, work_dir)
        self._log.info(
            "Post-Processing Pipeline Complete — report: %s", output_path
        )

        # ----------------------------------------------------------------
        # 5 — Annotate graph and render PDF / PNG
        # ----------------------------------------------------------------
        self._log.info("Annotating attack graph and rendering images")
        render_outputs = self._annotator.annotate(
            risk_report, graph_dir, work_dir, include_legend=include_legend
        )
        for fmt, path in render_outputs.items():
            self._log.info("  [%s] %s", fmt.upper(), path)

        # ----------------------------------------------------------------
        # 6 — Condensed host-level "global view" graph (optional)
        # ----------------------------------------------------------------
        if self._settings.POST_PROCESSING.generate_summary_graph:
            self._log.info("Generating condensed host-level summary graph")
            summary_outputs = self._summarizer.summarize(
                risk_report,
                graph,
                work_dir,
                max_paths=self._settings.POST_PROCESSING.summary_max_paths,
            )
            for fmt, path in summary_outputs.items():
                self._log.info("  [SUMMARY %s] %s", fmt.upper(), path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _scenario_for_scoring(self, graph_dir: str) -> str | None:
        """
        Return the scenario file used to resolve attack goals.

        The orchestrator writes ``scenario.P`` next to the graph artifacts
        whenever it (re)generates the graph, so this snapshot is always the
        exact scenario that produced the graph in ``graph_dir``. It is the
        single source of truth for goal resolution; the live scenario is never
        consulted here because it may have drifted ahead of the graph.

        Returns None when the snapshot is absent, letting the scorer fall back
        to graph-topology heuristics.
        """
        graph_scenario = Path(graph_dir) / "scenario.P"
        if graph_scenario.exists():
            self._log.info(
                "Using graph-producing scenario for goal resolution: %s",
                graph_scenario,
            )
            return str(graph_scenario)

        self._log.warning(
            "No scenario.P found in %s for goal resolution. "
            "Falling back to graph topology heuristics.",
            graph_dir,
        )
        return None

    def _write_report(self, risk_report, delta_report, work_dir: str) -> Path:
        work_path = Path(work_dir)
        work_path.mkdir(parents=True, exist_ok=True)

        # Archive any existing risk_analysis reports before writing the new one
        existing_reports = list(work_path.glob("risk_analysis*.json"))
        if existing_reports:
            registry_path = work_path / "registry"
            registry_path.mkdir(parents=True, exist_ok=True)
            for report in existing_reports:
                dest = registry_path / report.name
                report.rename(dest)
                self._log.debug("Archived previous report to %s", dest)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        output_file = work_path / f"risk_analysis_{timestamp}.json"

        combined = {
            "risk_report": risk_report.to_dict(),
            "delta_report": delta_report.to_dict(),
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)

        self._log.debug("Written combined report to %s", output_file)
        return output_file
