"""
Data models for the MulVAL attack graph representation.
Nodes are parsed from VERTICES.CSV; edges from ARCS.CSV.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackNode:
    """
    Represents a single node in the MulVAL attack graph.

    Leaf nodes correspond to vulExists/2-5 Prolog facts and are enriched
    with CVE-level threat intelligence. OR/AND nodes represent reachability
    predicates and rule applications respectively.
    """

    id: int
    label: str
    node_type: str  # "OR" or "AND"
    is_leaf: bool

    # Populated by _parse_vuln_label() for vulExists LEAF nodes
    cve_id: Optional[str] = None
    asset: Optional[str] = None
    software: Optional[str] = None
    exploit_type: Optional[str] = None   # remoteExploit | remoteClient | localExploit
    impact: Optional[str] = None         # privEscalation | etc.

    _VULN_PATTERN: re.Pattern = field(
        default=re.compile(
            r"vulExists\(([^,]+),\s*'([^']+)',\s*([^,]+),\s*([^,]+),\s*([^)]+)\)"
        ),
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.is_leaf:
            self._parse_vuln_label()

    def _parse_vuln_label(self) -> None:
        """Extract CVE metadata from a vulExists(...) label string."""
        match = self._VULN_PATTERN.match(self.label.strip())
        if match:
            self.asset = match.group(1).strip()
            self.cve_id = match.group(2).strip()
            self.software = match.group(3).strip()
            self.exploit_type = match.group(4).strip()
            self.impact = match.group(5).strip()


@dataclass
class AttackGraph:
    """
    Directed acyclic AND/OR graph produced by MulVAL.

    Edge semantics (derived from ARCS.CSV ``dst,src,-1`` format):
    - ``children[dst]`` contains the prerequisite nodes that must hold for
      ``dst`` to be derivable.
    - ``parents[src]`` lists nodes that depend on ``src``.
    """

    nodes: dict[int, AttackNode] = field(default_factory=dict)
    children: dict[int, list[int]] = field(default_factory=dict)   # dst -> [src, ...]
    parents: dict[int, list[int]] = field(default_factory=dict)    # src -> [dst, ...]

    @property
    def goal_nodes(self) -> list[AttackNode]:
        """Root OR nodes (no parents) — the final attacker objectives."""
        return [
            n
            for node_id, n in self.nodes.items()
            if not self.parents.get(node_id) and n.node_type == "OR"
        ]

    @property
    def leaf_nodes(self) -> list[AttackNode]:
        """All leaf nodes in the graph, including facts and vulnerabilities."""
        return [n for n in self.nodes.values() if n.is_leaf]

    @property
    def vulnerability_leaf_nodes(self) -> list[AttackNode]:
        """Leaf nodes that represent vulnerabilities or threat-model vulnerabilities."""
        return [n for n in self.leaf_nodes if n.label.strip().startswith("vulExists(")]

    @property
    def unique_cves(self) -> set[str]:
        """All unique CVE identifiers referenced by leaf nodes."""
        return {n.cve_id for n in self.vulnerability_leaf_nodes if n.cve_id}
