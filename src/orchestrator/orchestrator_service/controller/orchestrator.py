"""
Orchestrator Controller: Manages MulVAL attack graph generation workflow.
"""

import shutil
from pathlib import Path
from typing import Optional

from ..utils.logger import Logger
from ..utils.settings import Settings
from ..handlers.scenario_comparator import ScenarioComparator
from ..handlers.mulval_executor import MulValExecutor, NoAttackPathsFoundError


class Orchestrator:
    """
    Orchestrates attack graph generation by comparing scenarios and triggering MulVAL.
    """

    _REQUIRED_GRAPH_OUTPUTS = (
        "AttackGraph.dot",
        "AttackGraph.xml",
        "VERTICES.CSV",
        "ARCS.CSV",
    )

    def __init__(self, config_path: str) -> None:
        """
        Initialize orchestrator with handlers.
        
        Args:
            config_path: Path to TOML config file.
        """
        self._log = Logger.get_logger()
        self.settings = Settings(toml_path=config_path)
        self._log.info(f"Loaded configuration from {config_path}")
        
        self.comparator = ScenarioComparator()
        self.mulval = MulValExecutor(
            mulval_root=self.settings.ORCHESTRATOR.mulval_root,
            timeout_seconds=self.settings.ORCHESTRATOR.graph_timeout_seconds
        )
        
        self._log.debug("Orchestrator initialized")

    def orchestrate(
        self,
        mapped_scenario: str,
        graph_output_dir: str = "/gen_graph",
        force_regenerate: bool = False,
    ) -> None:
        """
        Orchestrate attack graph generation.

        MulVAL runs only when the scenario changes or force_regenerate is set.

        Args:
            mapped_scenario: Path to the mapped scenario file.
            graph_output_dir: Directory for MulVAL-generated graph output.
            force_regenerate: Force MulVAL regeneration even if no changes.
        """
        self._log.info(f"Starting orchestration for {mapped_scenario}")

        graph_dir = Path(graph_output_dir)
        graph_dir.mkdir(parents=True, exist_ok=True)

        mapped_path = Path(mapped_scenario)
        if not mapped_path.exists():
            self._log.error(f"Mapped scenario not found: {mapped_scenario}")
            raise FileNotFoundError(f"Mapped scenario not found: {mapped_scenario}")

        mulval_ran, mulval_ok = self._run_mulval_step(
            mapped_path,
            graph_dir,
            force_regenerate,
        )
        if not mulval_ok:
            self._log.error("MulVAL graph generation failed.")
            raise RuntimeError("MulVAL graph generation failed")

        mulval_status = "ran" if mulval_ran else "skipped (no changes detected)"
        self._log.info(
            "MulVAL graph generation completed successfully — MulVAL: %s",
            mulval_status,
        )

    def _run_mulval_step(
        self,
        mapped_path: Path,
        graph_dir: Path,
        force_regenerate: bool,
    ) -> tuple[bool, bool]:
        """
        Decide whether MulVAL needs to run and execute it if necessary.

        Returns:
            Tuple of (mulval_ran, success) where mulval_ran indicates whether
            MulVAL was invoked, and success indicates whether a valid graph exists.
        """
        existing_graph = self._find_existing_graph(graph_dir)

        if existing_graph and not force_regenerate:
            self._log.info(f"Existing graph found: {existing_graph}")
            return self._maybe_regenerate(mapped_path, graph_dir)

        reason = "Force regeneration requested." if force_regenerate else "No existing graph found."
        self._log.info(f"{reason} Generating graph...")
        ok = self._generate_graph(mapped_path, graph_dir)
        return True, ok

    def _maybe_regenerate(
        self,
        mapped_path: Path,
        graph_dir: Path,
    ) -> tuple[bool, bool]:
        """
        Compare current scenario against cached version and regenerate on critical changes.

        Returns:
            Tuple of (mulval_ran, success) where mulval_ran indicates whether
            MulVAL was invoked, and success indicates whether a valid graph exists.
        """
        previous_scenario = self._find_previous_scenario(graph_dir)

        if not previous_scenario:
            self._log.warning(
                "No previous scenario found for comparison. Regenerating graph..."
            )
            ok = self._generate_graph(mapped_path, graph_dir)
            return True, ok

        self._log.info(f"Comparing with previous scenario: {previous_scenario}")
        has_critical_changes = self.comparator.has_critical_changes(
            str(previous_scenario),
            str(mapped_path),
        )

        if has_critical_changes:
            self._log.info(
                "Scenario fact changes detected. Regenerating graph..."
            )
            ok = self._generate_graph(mapped_path, graph_dir)
            return True, ok

        self._log.info("No critical changes detected. Skipping MulVAL regeneration.")
        return False, True

    def _find_existing_graph(self, graph_dir: Path) -> Optional[Path]:
        """
        Check if a reusable attack graph output exists.
        
        Args:
            graph_dir: Directory to check for graphs.
            
        Returns:
            Path to AttackGraph.dot when all required outputs exist, else None.
        """
        missing_outputs = [
            output_name
            for output_name in self._REQUIRED_GRAPH_OUTPUTS
            if not (graph_dir / output_name).exists()
        ]
        if missing_outputs:
            self._log.info(
                "Graph output directory is incomplete; missing required artifacts: %s",
                ", ".join(missing_outputs),
            )
            return None

        return graph_dir / "AttackGraph.dot"
    
    def _find_previous_scenario(self, graph_dir: Path) -> Optional[Path]:
        """
        Find the scenario that produced the current graph.

        This snapshot is written next to the graph artifacts whenever MulVAL
        regenerates the graph, so it always matches the graph currently in
        ``graph_dir``. It is the single source of truth for both regeneration
        comparison and downstream goal resolution.

        Args:
            graph_dir: Directory containing graphs.

        Returns:
            Path to the graph-producing scenario or None.
        """
        scenario_cache = graph_dir / "scenario.P"
        if scenario_cache.exists():
            return scenario_cache
        return None
    
    def _generate_graph(
        self,
        scenario_path: Path,
        graph_dir: Path,
    ) -> bool:
        """
        Generate attack graph using MulVAL.
        
        Args:
            scenario_path: Path to scenario file.
            graph_dir: Output directory for graph.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            self._log.info(f"Generating attack graph for {scenario_path}")
            
            success = self.mulval.generate_graph(
                str(scenario_path),
                str(graph_dir),
            )
            
            if success:
                scenario_cache = graph_dir / "scenario.P"
                shutil.copy2(scenario_path, scenario_cache)
                self._log.info(f"Cached graph-producing scenario: {scenario_cache}")
                self._log.info("Attack graph generated successfully")
                return True
            
            self._log.error("Attack graph generation failed")
            return False
        except NoAttackPathsFoundError:
            raise
                
        except Exception as e:
            self._log.error(f"Error generating graph: {e}", exc_info=True)
            return False
       