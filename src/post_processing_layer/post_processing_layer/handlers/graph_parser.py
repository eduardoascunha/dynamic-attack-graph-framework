"""
Parser for MulVAL attack graph output files.

Reads VERTICES.CSV and ARCS.CSV produced by MulVAL and constructs an
AttackGraph instance with populated adjacency maps.

CSV formats
-----------
VERTICES.CSV : ``id,"label","node_type",is_leaf``
ARCS.CSV     : ``dst_id,src_id,-1``
    - Arc semantics: ``dst`` depends on ``src``; ``src`` is a child of ``dst``.
"""

import csv
import logging
from pathlib import Path

from ..models.attack_graph import AttackGraph, AttackNode
from ..utils.logger import Logger


class GraphParser:
    """
    Parses MulVAL output VERTICES.CSV and ARCS.CSV into an AttackGraph.
    """

    def __init__(self) -> None:
        self._log: logging.Logger = Logger.get_logger()

    def parse(self, graph_dir: str) -> AttackGraph:
        """
        Build an AttackGraph from MulVAL output in *graph_dir*.

        Args:
            graph_dir: Path to the directory containing VERTICES.CSV and ARCS.CSV.

        Returns:
            Populated AttackGraph with nodes, children, and parents maps.

        Raises:
            FileNotFoundError: If either required file is missing.
        """
        graph_path = Path(graph_dir)
        vertices_file = graph_path / "VERTICES.CSV"
        arcs_file = graph_path / "ARCS.CSV"

        if not vertices_file.exists():
            raise FileNotFoundError(f"VERTICES.CSV not found in {graph_dir}")
        if not arcs_file.exists():
            raise FileNotFoundError(f"ARCS.CSV not found in {graph_dir}")

        nodes = self._parse_vertices(vertices_file)
        children, parents = self._parse_arcs(arcs_file, nodes)

        graph = AttackGraph(nodes=nodes, children=children, parents=parents)
        self._log.info(
            "Parsed attack graph: %d nodes (%d leaves, %d unique CVEs), %d edges",
            len(nodes),
            len(graph.leaf_nodes),
            len(graph.unique_cves),
            sum(len(v) for v in children.values()),
        )
        return graph

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_vertices(self, path: Path) -> dict[int, AttackNode]:
        nodes: dict[int, AttackNode] = {}
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 4:
                    continue
                try:
                    node_id = int(row[0])
                    label = row[1].strip()
                    node_type = row[2].strip()
                    is_leaf = row[3].strip() == "1"
                    nodes[node_id] = AttackNode(
                        id=node_id,
                        label=label,
                        node_type=node_type,
                        is_leaf=is_leaf,
                    )
                except (ValueError, IndexError) as exc:
                    self._log.warning("Skipping malformed vertex row %s: %s", row, exc)
        return nodes

    def _parse_arcs(
        self, path: Path, nodes: dict[int, AttackNode]
    ) -> tuple[dict[int, list[int]], dict[int, list[int]]]:
        children: dict[int, list[int]] = {n: [] for n in nodes}
        parents: dict[int, list[int]] = {n: [] for n in nodes}

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    continue
                try:
                    dst = int(row[0])
                    src = int(row[1])
                    if dst in nodes and src in nodes:
                        children[dst].append(src)
                        parents[src].append(dst)
                except ValueError as exc:
                    self._log.warning("Skipping malformed arc row %s: %s", row, exc)

        return children, parents
