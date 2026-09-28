"""
Path-level risk scoring for enriched attack graphs.

Enumerates all root-to-leaf paths in the AND/OR attack graph via DFS and
computes a composite risk score for each path based on:

    - EPSS exploitation probability of leaf vulnerability nodes
    - CVSSv3.1 base severity score
    - CISA KEV status (1.5x multiplier when present)
    - Asset criticality weight (configured per host)
    - Path directness factor (shorter paths → more direct → higher risk)

Risk score formula (per path):
    best_leaf_risk  = max(base_risk_score for each enriched leaf on path)
    directness      = 1 / log2(path_length + 2)
    path_risk       = min(10.0, best_leaf_risk * asset_criticality * (1 + directness))
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from math import log2
from pathlib import Path

from ..models.attack_graph import AttackGraph
from ..models.config.post_processing_config import PostProcessing
from ..models.enriched_node import EnrichedVulnerability
from ..models.risk_report import PathRiskScore, RiskReport
from ..utils.logger import Logger


class RiskScorer:
    """
    Enumerates attack paths and produces a ``RiskReport`` with per-path scores
    and a ranked top-N summary.
    """

    def __init__(self) -> None:
        self._log: logging.Logger = Logger.get_logger()

    def score(
        self,
        graph: AttackGraph,
        enriched: dict[int, EnrichedVulnerability],
        config: PostProcessing,
        scenario_path: str | None = None,
    ) -> RiskReport:
        """
        Enumerate all attack paths and compute risk scores.

        Args:
            graph:    Parsed attack graph.
            enriched: Node-ID → EnrichedVulnerability map from GraphEnricher.
            config:   Pipeline configuration (top_paths_count, max_path_depth).

        Returns:
            RiskReport containing scored paths sorted by descending risk.
        """
        all_paths: list[PathRiskScore] = []
        seen_signatures: set[str] = set()
        goal_nodes = self._resolve_goal_nodes(graph, scenario_path)

        for goal_node in goal_nodes:
            raw_paths = self._enumerate_paths(
                goal_node.id, graph, config.max_path_depth
            )
            self._log.debug(
                "Goal '%s': %d raw paths from DFS", goal_node.label, len(raw_paths)
            )
            for path_nodes in raw_paths:
                sig = _path_signature(path_nodes)
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                scored = self._score_path(
                    goal_node.label, path_nodes, graph, enriched
                )
                if scored is not None:
                    all_paths.append(scored)

        # Sort: undefined risk first (needs review), then high to low risk
        all_paths.sort(
            key=lambda p: (1, 0.0) if p.risk_score is None else (0, p.risk_score),
            reverse=True
        )
        top_paths = all_paths[: config.top_paths_count]

        unique_cves = graph.unique_cves
        enriched_cves = {v.cve_id for v in enriched.values()}
        coverage = (
            len(enriched_cves & unique_cves) / len(unique_cves) if unique_cves else 0.0
        )

        report = RiskReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            graph_version=_graph_version(graph),
            total_nodes=len(graph.nodes),
            total_leaf_nodes=len(graph.leaf_nodes),
            total_vulnerability_leaf_nodes=len(graph.vulnerability_leaf_nodes),
            unique_cves=len(unique_cves),
            paths=all_paths,
            top_paths=top_paths,
            enrichment_coverage=coverage,
        )
        top_score = top_paths[0].risk_score if top_paths else None
        self._log.info(
            "Risk scoring done: %d paths enumerated, top score=%s, coverage=%.1f%%",
            len(all_paths),
            f"{top_score:.4f}" if top_score is not None else "undefined",
            coverage * 100,
        )
        return report

    def _resolve_goal_nodes(
        self,
        graph: AttackGraph,
        scenario_path: str | None,
    ) -> list:
        """Resolve graph goal nodes from attackGoal(...) statements when available."""
        fallback_goals = graph.goal_nodes
        if not scenario_path:
            return fallback_goals

        scenario_file = Path(scenario_path)
        if not scenario_file.exists():
            self._log.warning(
                "Scenario file not found for goal resolution: %s. Falling back to graph roots.",
                scenario_path,
            )
            return fallback_goals

        goal_terms = self._extract_attack_goals(scenario_file)
        if not goal_terms:
            self._log.warning(
                "No attackGoal statements found in %s. Falling back to graph roots.",
                scenario_path,
            )
            return fallback_goals

        resolved = []
        for node in graph.nodes.values():
            if node.node_type != "OR":
                continue
            if any(_terms_match(goal_term, node.label) for goal_term in goal_terms):
                resolved.append(node)

        if resolved:
            self._log.info(
                "Resolved %d goal node(s) from %s",
                len(resolved),
                scenario_path,
            )
            return sorted(resolved, key=lambda node: node.id)

        self._log.warning(
            "No graph OR nodes matched attackGoal statements from %s. Falling back to graph roots.",
            scenario_path,
        )
        return fallback_goals

    def _extract_attack_goals(self, scenario_file: Path) -> list[str]:
        """Return attackGoal terms from the cached scenario file."""
        goals: list[str] = []
        pattern = re.compile(r"attackGoal\((.+)\)\s*\.")

        with open(scenario_file, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("/*") or line.startswith("%"):
                    continue
                match = pattern.search(line)
                if match:
                    goals.append(match.group(1).strip())

        return goals

    # ------------------------------------------------------------------
    # Path enumeration (DFS)
    # ------------------------------------------------------------------

    def _enumerate_paths(
        self, start: int, graph: AttackGraph, max_depth: int
    ) -> list[list[int]]:
        """Return all simple root-to-leaf paths reachable from start."""
        results: list[list[int]] = []
        self._dfs(start, graph, [start], set(), results, max_depth)
        return results

    def _dfs(
        self,
        node_id: int,
        graph: AttackGraph,
        current_path: list[int],
        visited: set[int],
        results: list[list[int]],
        max_depth: int,
    ) -> None:
        node = graph.nodes.get(node_id)
        if node is None or len(current_path) > max_depth:
            return

        if node.is_leaf:
            results.append(list(current_path))
            return

        children = graph.children.get(node_id, [])
        if not children:
            # Dead-end non-leaf (e.g. unsatisfied precondition) — record as-is
            results.append(list(current_path))
            return

        for child_id in children:
            if child_id not in visited:
                visited.add(child_id)
                current_path.append(child_id)
                self._dfs(child_id, graph, current_path, visited, results, max_depth)
                current_path.pop()
                visited.discard(child_id)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_path(
        self,
        goal_label: str,
        path_nodes: list[int],
        graph: AttackGraph,
        enriched: dict[int, EnrichedVulnerability],
    ) -> PathRiskScore | None:
        """Compute PathRiskScore for a single enumerated path."""
        leaf_nodes = [graph.nodes[n] for n in path_nodes if graph.nodes[n].is_leaf]
        if not leaf_nodes:
            return None

        leaf_cves = [n.cve_id for n in leaf_nodes if n.cve_id]
        enriched_leaves = [enriched[n.id] for n in leaf_nodes if n.id in enriched]

        if enriched_leaves:
            # Filter leaves that have defined risk scores
            scored_leaves = [v for v in enriched_leaves if v.base_risk_score is not None]
            
            if scored_leaves:
                max_epss = max(v.enrichment.epss_score for v in scored_leaves)
                max_cvss = max(v.enrichment.cvss_score for v in scored_leaves)
                kev_on_path = any(v.enrichment.kev_status for v in scored_leaves)
                best = max(scored_leaves, key=lambda v: v.base_risk_score)
                asset_criticality = max(v.asset_criticality for v in scored_leaves)

                # Shorter paths are more directly exploitable -> higher directness bonus
                directness = 1.0 / log2(len(path_nodes) + 2)
                path_risk = round(
                    min(10.0, best.base_risk_score * asset_criticality * (1.0 + directness)),
                    4,
                )
                highest_risk_vuln: str | None = best.cve_id
            else:
                # All vulnerabilities lack CVSS data - undefined risk
                max_epss = max((v.enrichment.epss_score for v in enriched_leaves), default=0.0)
                max_cvss = 0.0
                kev_on_path = any(v.enrichment.kev_status for v in enriched_leaves)
                highest_risk_vuln = leaf_cves[0] if leaf_cves else None
                path_risk = None  # Explicitly undefined
        else:
            # No CVE on this path: it reaches the goal purely through
            # non-vulnerability facts (access/config), so there is no
            # vulnerability-based risk to quantify -> score 0.0 (ranked last).
            # This is deliberately distinct from the None case above, which
            # flags paths with known CVEs whose CVSS data is missing and
            # therefore genuinely needs human investigation.
            max_epss = 0.0
            max_cvss = 0.0
            kev_on_path = False
            highest_risk_vuln = leaf_cves[0] if leaf_cves else None
            path_risk = 0.0

        return PathRiskScore(
            path_id=_path_signature(path_nodes)[:16],
            goal_label=goal_label,
            nodes=path_nodes,
            leaf_cves=leaf_cves,
            risk_score=path_risk,
            highest_risk_vuln=highest_risk_vuln,
            path_length=len(path_nodes),
            kev_on_path=kev_on_path,
            max_epss_on_path=max_epss,
            max_cvss_on_path=max_cvss,
        )


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _path_signature(path_nodes: list[int]) -> str:
    """Stable SHA-256 hex digest for a path (used as a deduplication key)."""
    return hashlib.sha256(str(path_nodes).encode()).hexdigest()


def _graph_version(graph: AttackGraph) -> str:
    """Short SHA-256 hash of all node labels — acts as a graph content fingerprint."""
    content = "|".join(
        f"{n.id}:{n.label}"
        for n in sorted(graph.nodes.values(), key=lambda x: x.id)
    )
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _split_top_level_args(args: str) -> list[str]:
    """Split a term argument list on top-level commas only."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0

    for char in args:
        if char == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        current.append(char)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_term(expr: str) -> tuple[str, list]:
    """Parse a simple Prolog-style term into a functor and argument terms."""
    expr = expr.strip()
    if not expr.endswith(")") or "(" not in expr:
        return expr, []

    open_idx = expr.find("(")
    functor = expr[:open_idx].strip()
    inner = expr[open_idx + 1 : -1].strip()
    args = [_parse_term(part) for part in _split_top_level_args(inner)]
    return functor, args


def _terms_match(goal_expr: str, node_expr: str) -> bool:
    """Return True when a scenario attackGoal term matches a graph node label."""
    goal_functor, goal_args = _parse_term(goal_expr)
    node_functor, node_args = _parse_term(node_expr)

    if goal_functor == "_":
        return True

    if goal_args or node_args:
        if goal_functor != node_functor or len(goal_args) != len(node_args):
            return False
        return all(
            _terms_match(_term_to_string(goal_arg), _term_to_string(node_arg))
            for goal_arg, node_arg in zip(goal_args, node_args)
        )

    return goal_functor == node_functor


def _term_to_string(term: tuple[str, list]) -> str:
    """Serialize a parsed term back to string for recursive matching."""
    functor, args = term
    if not args:
        return functor
    return f"{functor}({', '.join(_term_to_string(arg) for arg in args)})"
