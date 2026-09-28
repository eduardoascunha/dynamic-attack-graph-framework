"""
Host-level attack-graph summarizer ("global view").

This module produces a *condensed* attack graph that collapses the full,
node-level MulVAL graph onto a per-host topology. For complex scenarios the
detailed annotated graph becomes hard to read; the summary answers the
operational questions at a glance:

    - Which hosts does the attacker traverse on the dangerous paths?
    - In what order (lateral movement / pivoting)?
    - What privilege does the attacker gain on each host (user / root)?
    - Which hosts are the most critical chokepoints?

Design notes
------------
This summarizer is intentionally **self-contained and decoupled** from the
detailed ``GraphAnnotator``. It consumes only the two stable, public data
models of the layer:

    - ``RiskReport``   (top-ranked attack paths, each carrying ordered node IDs)
    - ``AttackGraph``  (node id -> predicate label)

It never mutates them and never touches the detailed annotator's outputs.
If the rest of the post-processing layer is rewritten, this module keeps
working as long as those two models keep their current shape.

Outputs (in ``work_dir``), in addition to — never replacing — the detailed
``AttackGraph_annotated.*`` files:

    - ``AttackGraph_summarized.dot``
    - ``AttackGraph_summarized.png``
    - ``AttackGraph_summarized.pdf``

Colour legend (matches the detailed graph's risk palette)
    - #C85A54 : risk >= 7.0   (critical)
    - #CC7A50 : risk >= 4.0   (high)
    - #D4A574 : risk >= 2.0   (medium)
    - #7A9BAE : risk <  2.0   (low / informational)
    - #C8979E : attacker goal host (target)
    - #DCDCDC : attacker origin (internet / external zone)
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from ..models.attack_graph import AttackGraph
from ..models.risk_report import PathRiskScore, RiskReport
from ..utils.logger import Logger


# ---------------------------------------------------------------------------
# Predicate / host extraction helpers
# ---------------------------------------------------------------------------

# Strip an optional MulVAL DOT wrapper "N:predicate(args):leaf" down to the
# bare predicate. The CSV-sourced labels are already bare, but we stay robust
# to either form.
_WRAPPER_RE = re.compile(r"^\d+:(.+):\d+$")

# Predicates whose FIRST argument names the host the attacker acts upon.
_HOST_FIRST_ARG = re.compile(
    r"^(?:execCode|netAccess|canAccessHost|vulExists|accessFile|"
    r"accessMaliciousInput|networkServiceInfo|nfsExportInfo|"
    r"logInService)\(\s*(\w+)"
)
# hasAccount(user, host, role) -> host is the SECOND argument.
_HAS_ACCOUNT = re.compile(r"^hasAccount\(\s*[^,]+,\s*(\w+)")
# attackerLocated(zone) -> the attacker's origin zone (treated as a host).
_ATTACKER_LOCATED = re.compile(r"^attackerLocated\(\s*(\w+)\s*\)")
# execCode(host, privilege) -> capture the privilege gained.
_EXEC_CODE = re.compile(r"^execCode\(\s*(\w+)\s*,\s*(\w+)\s*\)")
# vulExists(host, 'CVE-...', ...) -> capture the CVE id on that host.
_VULN_CVE = re.compile(r"^vulExists\(\s*(\w+)\s*,\s*'(CVE-[\w-]+)'", re.IGNORECASE)

# Privilege ranking so we can keep the *highest* level reached on a host.
_PRIV_RANK = {"root": 3, "admin": 3, "user": 2, "guest": 1}


def _core_pred(label: str) -> str:
    """Return the bare predicate from a (possibly wrapped) MulVAL label."""
    label = label.strip()
    m = _WRAPPER_RE.match(label)
    return m.group(1).strip() if m else label


def _node_host(label: str) -> Optional[str]:
    """Map a node label to the host it concerns, or None for relations/rules."""
    pred = _core_pred(label)
    m = _ATTACKER_LOCATED.match(pred)
    if m:
        return m.group(1)
    m = _HAS_ACCOUNT.match(pred)
    if m:
        return m.group(1)
    m = _HOST_FIRST_ARG.match(pred)
    if m:
        return m.group(1)
    return None


def _node_privilege(label: str) -> Optional[str]:
    """Return the privilege level from an execCode(host, priv) node, if any."""
    m = _EXEC_CODE.match(_core_pred(label))
    return m.group(2) if m else None


def _node_cve(label: str) -> Optional[str]:
    """Return the CVE id from a vulExists(host, 'CVE-...', ...) node, if any."""
    m = _VULN_CVE.match(_core_pred(label))
    return m.group(2).upper() if m else None


def _is_attacker_origin(label: str) -> bool:
    """True if the node declares the attacker's starting location."""
    return _ATTACKER_LOCATED.match(_core_pred(label)) is not None


# ---------------------------------------------------------------------------
# Aggregated host / edge state
# ---------------------------------------------------------------------------

class _HostInfo:
    """Accumulated risk context for a single host in the summary graph."""

    __slots__ = ("name", "max_risk", "kev", "is_origin", "is_goal", "privilege", "cves")

    def __init__(self, name: str) -> None:
        self.name = name
        self.max_risk: float = 0.0
        self.kev: bool = False
        self.is_origin: bool = False
        self.is_goal: bool = False
        self.privilege: Optional[str] = None
        self.cves: set[str] = set()

    def observe_risk(self, risk: float, kev: bool) -> None:
        if risk > self.max_risk:
            self.max_risk = risk
        if kev:
            self.kev = True

    def observe_privilege(self, priv: Optional[str]) -> None:
        if priv is None:
            return
        if self.privilege is None or _PRIV_RANK.get(priv, 0) > _PRIV_RANK.get(self.privilege, 0):
            self.privilege = priv


class _EdgeInfo:
    """Accumulated context for a host -> host transition (lateral movement)."""

    __slots__ = ("max_risk", "count", "kev")

    def __init__(self) -> None:
        self.max_risk: float = 0.0
        self.count: int = 0
        self.kev: bool = False

    def observe(self, risk: float, kev: bool) -> None:
        self.count += 1
        if risk > self.max_risk:
            self.max_risk = risk
        if kev:
            self.kev = True


# ---------------------------------------------------------------------------
# Summarizer
# ---------------------------------------------------------------------------

class GraphSummarizer:
    """
    Builds a condensed host-level attack graph from a ``RiskReport``.

    Public surface mirrors ``GraphAnnotator`` for a consistent controller
    contract: a single ``summarize()`` call returns the produced file paths.
    """

    _COLOR_CRITICAL = "#C85A54"
    _COLOR_HIGH = "#CC7A50"
    _COLOR_MEDIUM = "#D4A574"
    _COLOR_LOW = "#7A9BAE"
    _COLOR_GOAL = "#C8979E"
    _COLOR_ORIGIN = "#DCDCDC"

    def __init__(self) -> None:
        self._log: logging.Logger = Logger.get_logger()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summarize(
        self,
        report: RiskReport,
        graph: AttackGraph,
        work_dir: str,
        max_paths: int | None = None,
    ) -> dict[str, str]:
        """
        Produce the condensed host-level graph and render it.

        Args:
            report:    Completed ``RiskReport`` (uses all enumerated paths).
            graph:     Parsed ``AttackGraph`` (node id -> label lookup).
            work_dir:  Destination directory for the summary output files.
            max_paths: Cap on the number of highest-risk paths collapsed into
                       the summary. Aggregating the full path set reveals the
                       whole attacker-reachable host topology; the cap only
                       guards against pathological sizes. ``None`` uses all.

        Returns:
            Dict with keys ``dot``/``pdf``/``png`` -> absolute file paths
            (image keys present only if rendering succeeded). Empty dict if
            there is nothing to summarize.
        """
        source = report.paths or report.top_paths
        if not source:
            self._log.info("No paths available — skipping summary graph")
            return {}

        paths = source[:max_paths] if max_paths else source
        hosts, edges = self._aggregate(paths, graph)
        if not hosts:
            self._log.info("No host-attributable nodes — skipping summary graph")
            return {}

        work_path = Path(work_dir)
        work_path.mkdir(parents=True, exist_ok=True)

        dot_path = work_path / "AttackGraph_summarized.dot"
        dot_path.write_text(
            self._render_dot(hosts, edges), encoding="utf-8"
        )
        self._log.info(
            "Summarized graph: %d hosts, %d transitions from top %d paths",
            len(hosts), len(edges), len(paths),
        )

        outputs: dict[str, str] = {"dot": str(dot_path)}
        for fmt in ("pdf", "png"):
            out_file = work_path / f"AttackGraph_summarized.{fmt}"
            if self._render(dot_path, out_file, fmt):
                outputs[fmt] = str(out_file)
        return outputs

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def _aggregate(
        self,
        paths: list[PathRiskScore],
        graph: AttackGraph,
    ) -> tuple[dict[str, _HostInfo], dict[tuple[str, str], _EdgeInfo]]:
        """Collapse the given paths into per-host nodes and host->host edges."""
        hosts: dict[str, _HostInfo] = {}
        edges: dict[tuple[str, str], _EdgeInfo] = {}

        for path in paths:
            sequence = self._host_sequence(path, graph, hosts)
            if not sequence:
                continue

            # Mark the final host in the attacker's progression as a goal host.
            hosts[sequence[-1]].is_goal = True

            # Build lateral-movement edges between consecutive distinct hosts.
            risk = path.risk_score or 0.0
            for src, dst in zip(sequence, sequence[1:]):
                edges.setdefault((src, dst), _EdgeInfo()).observe(risk, path.kev_on_path)

        return hosts, edges

    def _host_sequence(
        self,
        path: PathRiskScore,
        graph: AttackGraph,
        hosts: dict[str, _HostInfo],
    ) -> list[str]:
        """
        Walk a single path in attacker order, update per-host state, and return
        the ordered list of distinct hosts traversed (consecutive duplicates
        collapsed).
        """
        risk = path.risk_score or 0.0
        kev = path.kev_on_path
        sequence: list[str] = []

        # report.nodes are ordered goal -> leaf; reverse to follow the
        # attacker's progression (entry/origin -> goal).
        for node_id in reversed(path.nodes):
            node = graph.nodes.get(node_id)
            if node is None:
                continue
            host = _node_host(node.label)
            if host is None:
                continue

            info = hosts.get(host)
            if info is None:
                info = hosts[host] = _HostInfo(host)
            info.observe_risk(risk, kev)
            info.observe_privilege(_node_privilege(node.label))
            cve = _node_cve(node.label)
            if cve:
                info.cves.add(cve)
            if _is_attacker_origin(node.label):
                info.is_origin = True

            if not sequence or sequence[-1] != host:
                sequence.append(host)

        return sequence

    # ------------------------------------------------------------------
    # Colour helpers
    # ------------------------------------------------------------------

    def _risk_color(self, risk: float) -> str:
        if risk >= 7.0:
            return self._COLOR_CRITICAL
        if risk >= 4.0:
            return self._COLOR_HIGH
        if risk >= 2.0:
            return self._COLOR_MEDIUM
        return self._COLOR_LOW

    # ------------------------------------------------------------------
    # DOT generation
    # ------------------------------------------------------------------

    def _render_dot(
        self,
        hosts: dict[str, _HostInfo],
        edges: dict[tuple[str, str], _EdgeInfo],
    ) -> str:
        lines: list[str] = [
            "digraph AttackSummary {",
            "\trankdir=LR;",
            '\tbgcolor="white";',
            '\tlabel="Attack Graph — Host-Level Global View";',
            "\tlabelloc=t;",
            '\tfontname="Arial Bold";',
            "\tfontsize=18;",
            "\tnodesep=0.5;",
            "\tranksep=0.9;",
            '\tnode [fontname="Arial", style="filled,rounded", shape=box, penwidth=1.5];',
            '\tedge [fontname="Arial", fontsize=10, penwidth=2.0];',
            "",
        ]
        lines.extend(self._legend_lines())
        lines.append("")

        for name, info in hosts.items():
            lines.append("\t" + self._host_node_line(name, info))
        lines.append("")

        for (src, dst), edge in edges.items():
            lines.append("\t" + self._edge_line(src, dst, edge))

        lines.append("}")
        return "\n".join(lines) + "\n"

    def _host_node_line(self, name: str, info: _HostInfo) -> str:
        node_id = self._node_id(name)

        if info.is_origin:
            fill = self._COLOR_ORIGIN
            shape = "ellipse"
        elif info.is_goal:
            fill = self._COLOR_GOAL
            shape = "ellipse"
        else:
            fill = self._risk_color(info.max_risk)
            shape = "box"

        rows = [f"<B>{_esc(name)}</B>"]
        if info.privilege:
            tag = "[KEV] " if info.kev else ""
            rows.append(f'<FONT POINT-SIZE="10">{tag}priv: {_esc(info.privilege)}</FONT>')
        if not info.is_origin:
            rows.append(f'<FONT POINT-SIZE="10">risk: {info.max_risk:.2f}</FONT>')
        if info.cves:
            shown = sorted(info.cves)
            head = ", ".join(shown[:2])
            more = f" +{len(shown) - 2}" if len(shown) > 2 else ""
            rows.append(f'<FONT POINT-SIZE="9">{_esc(head)}{more}</FONT>')

        label = "<" + "<BR/>".join(rows) + ">"
        return f'{node_id} [label={label},shape={shape},fillcolor="{fill}"];'

    def _edge_line(self, src: str, dst: str, edge: _EdgeInfo) -> str:
        color = self._risk_color(edge.max_risk)
        kev = "[KEV] " if edge.kev else ""
        plural = "s" if edge.count > 1 else ""
        label = f"{kev}risk: {edge.max_risk:.2f}\\n({edge.count} path{plural})"
        return (
            f'{self._node_id(src)} -> {self._node_id(dst)} '
            f'[label="{label}",color="{color}"];'
        )

    def _legend_lines(self) -> list[str]:
        header = (
            '\t\t\t\t<TR><TD COLSPAN="4" BGCOLOR="#1A1A1A">'
            '<FONT COLOR="white" POINT-SIZE="13"><B>Host-Level Global View</B></FONT>'
            '</TD></TR>'
        )
        risk_hdr = (
            '\t\t\t\t<TR><TD COLSPAN="4" BGCOLOR="#333333">'
            '<FONT COLOR="white">Host risk (max on path)</FONT></TD></TR>'
        )
        risk_row = (
            '\t\t\t\t<TR>'
            '<TD BGCOLOR="#C85A54"><FONT COLOR="white">Critical &#8805;7</FONT></TD>'
            '<TD BGCOLOR="#CC7A50">High &#8805;4</TD>'
            '<TD BGCOLOR="#D4A574">Medium &#8805;2</TD>'
            '<TD BGCOLOR="#7A9BAE"><FONT COLOR="white">Low &lt;2</FONT></TD>'
            '</TR>'
        )
        shape_hdr = (
            '\t\t\t\t<TR><TD COLSPAN="4" BGCOLOR="#333333">'
            '<FONT COLOR="white">Special hosts</FONT></TD></TR>'
        )
        shape_row = (
            '\t\t\t\t<TR>'
            '<TD BGCOLOR="#DCDCDC" COLSPAN="2">Origin (ellipse)</TD>'
            '<TD BGCOLOR="#C8979E" COLSPAN="2">Goal (ellipse)</TD>'
            '</TR>'
        )
        format_row = (
            '\t\t\t\t<TR><TD COLSPAN="4" ALIGN="LEFT">'
            '<I>Arrows = lateral movement; label shows max risk &amp; path count</I>'
            '</TD></TR>'
        )
        return [
            "\tsubgraph cluster_legend {",
            '\t\tlabel="";',
            '\t\tstyle="filled";',
            '\t\tfillcolor="#F5F5F5";',
            '\t\tcolor="#999999";',
            '\t\tlegend [shape=plaintext,fillcolor="#F5F5F5",label=<',
            '\t\t\t<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="5">',
            header,
            risk_hdr,
            risk_row,
            shape_hdr,
            shape_row,
            format_row,
            "\t\t\t</TABLE>>];",
            "\t}",
        ]

    @staticmethod
    def _node_id(host: str) -> str:
        """Stable, DOT-safe quoted node identifier for a host name."""
        return '"' + host.replace('"', "") + '"'

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self, dot_file: Path, out_file: Path, fmt: str) -> bool:
        """Invoke the ``dot`` CLI to render *dot_file* -> *out_file*."""
        cmd = ["dot", f"-T{fmt}", str(dot_file), "-o", str(out_file)]
        # PNG defaults to 96 dpi (blurry); render at high dpi. PDF is vector.
        if fmt == "png":
            cmd.insert(1, "-Gdpi=300")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                self._log.error(
                    "Summary dot rendering failed (%s): %s", fmt, result.stderr.strip()
                )
                return False
            self._log.info("Rendered summary %s -> %s", fmt.upper(), out_file)
            return True
        except FileNotFoundError:
            self._log.warning("Graphviz 'dot' not found — cannot render summary %s", fmt)
            return False
        except subprocess.TimeoutExpired:
            self._log.error("Summary dot rendering timed out for %s", fmt)
            return False


def _esc(text: str) -> str:
    """Escape characters that are special inside a Graphviz HTML-like label."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
