"""
Attack-graph annotator.

Reads the MulVAL-generated ``AttackGraph.dot``, overlays risk information
from a ``RiskReport``, writes an annotated ``.dot`` to the working directory,
copies the original ``.dot`` there as well, and renders PDF + PNG images via
the ``dot`` Graphviz CLI tool.

Colour legend
--------------------------------------------
- DarkCoral   (#D97066) : CVE is in the CISA Known Exploited Vulnerabilities catalogue
- BurntOrange (#CC7A50) : Critical severity  (CVSS ≥ 9.0, not KEV)
- Tan         (#D4A574) : High severity      (CVSS ≥ 7.0)
- LightTan    (#E8D5B7) : Medium severity    (CVSS ≥ 4.0)
- LightGray   (#D8D8D8) : Low / no CVSS data (but appears in a path)
- Lavender    (#B8A9C9) : STRIDE threat-model vulnerability (no CVE, bare atom)
- RosyBrown   (#C8979E) : Goal node (attacker objective, diamond shape)
- SteelBlue   (#9DB4C0) : AND-rule nodes (ellipse shape)
- White       (#FFFFFF) : Fact / infrastructure leaf nodes (box, no CVE)
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

from ..models.risk_report import PathRiskScore, RiskReport
from ..utils.logger import Logger


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"'(CVE-[\w-]+)'", re.IGNORECASE)
# Matches a vulExists node whose vulnerability identifier is a bare atom
# (no surrounding single quotes) — i.e. a STRIDE-derived fact, not a CVE.
# Example label fragment: vulExists(mailServer,missingAuditLogs,mountd,...)
_STRIDE_VULN_RE = re.compile(
    r'vulExists\([^,]+,([a-z]\w*),',
    re.IGNORECASE,
)
# Matches a full node declaration line, e.g.:
#   \t14 [label="...",shape=box];
_NODE_LINE_RE = re.compile(
    r'^(\s*)(\d+)\s*\[([^\]]+)\];(.*)$'
)
# Matches an edge line, e.g.:
#   \t5 -> 4;
_EDGE_LINE_RE = re.compile(
    r'^(\s*)(\d+)\s*->\s*(\d+);(.*)$'
)

# ---------------------------------------------------------------------------
# Label humanization helpers
# ---------------------------------------------------------------------------

# Strips the leading node-id and trailing leaf-flag from a MulVAL label:
#   "14:execCode(host,root):0"  →  "execCode(host,root)"
_LABEL_CORE_RE = re.compile(r'^\d+:(.+):\d+$')

# Per-predicate patterns used by _humanize_label
_HL_VULN_CVE = re.compile(
    r"vulExists\(([^,]+),\s*'(CVE-[^']+)',\s*([^,]+),\s*([^,]+),\s*([^)]+)\)",
    re.IGNORECASE,
)
_HL_VULN_STRIDE = re.compile(
    r"vulExists\(([^,]+),\s*([A-Za-z]\w*),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)"
)
_HL_RULE          = re.compile(r'RULE\s+\d+\s*\((.+)\)$')
_HL_EXEC_CODE     = re.compile(r'execCode\(([^,]+),([^)]+)\)')
_HL_NET_ACCESS    = re.compile(r'netAccess\(([^,]+),([^,]+),([^)]+)\)')
_HL_CAN_ACCESS    = re.compile(r'canAccessHost\(([^)]+)\)')
_HL_ACCESS_FILE   = re.compile(r"accessFile\(([^,]+),([^,]+),([^)]+)\)")
_HL_PRINCIPAL     = re.compile(r'principalCompromised\(([^)]+)\)')
_HL_MAL_INPUT     = re.compile(r'accessMaliciousInput\(([^,]+),([^,]+),([^)]+)\)')
_HL_HACL          = re.compile(r'hacl\(([^,]+),([^,]+),([^,]+),([^)]+)\)')
_HL_NFS_EXPORT    = re.compile(r"nfsExportInfo\(([^,]+),([^,]+),([^,]+),([^)]+)\)")
_HL_ATTACKER      = re.compile(r'attackerLocated\(([^)]+)\)')
_HL_NET_SERVICE   = re.compile(r'networkServiceInfo\(([^,]+),([^,]+),([^,]+),([^,]+),([^)]+)\)')
_HL_HAS_ACCOUNT   = re.compile(r'hasAccount\(([^,]+),([^,]+),([^)]+)\)')
_HL_INCOMPETENT   = re.compile(r'inCompetent\(([^)]+)\)')
_HL_GENERIC       = re.compile(r'(\w+)\((.+)\)$', re.DOTALL)

_EXPLOIT_LABELS: dict[str, str] = {
    "remoteExploit": "Remote Exploit",
    "localExploit":  "Local Exploit",
    "remoteClient":  "Client-Side Exploit",
}
_IMPACT_LABELS: dict[str, str] = {
    "privEscalation": "Privilege Escalation",
    "read":           "Read Access",
    "write":          "Write Access",
    "dos":            "Denial of Service",
    "bypassAuth":     "Auth Bypass",
}


def _camel_to_words(name: str) -> str:
    """Convert camelCase or snake_case identifier to sentence-case words."""
    name = name.replace("_", " ")
    name = re.sub(r"([A-Z])", r" \1", name)
    result = " ".join(w for w in name.split() if w)
    return result.capitalize()


def _fmt_exploit(exploit: str) -> str:
    return _EXPLOIT_LABELS.get(exploit, _camel_to_words(exploit))


def _fmt_impact(impact: str) -> str:
    return _IMPACT_LABELS.get(impact, _camel_to_words(impact))


def _fmt_stride_name(threat_id: str) -> str:
    """Convert threat_tN_description or camelCase STRIDE id to human-readable."""
    m = re.match(r"threat_t\d+_(.+)", threat_id, re.IGNORECASE)
    if m:
        return m.group(1).replace("_", " ").capitalize()
    return _camel_to_words(threat_id)


def _humanize_fact_pred(pred: str) -> Optional[str]:
    """
    Humanize infrastructure-fact and access predicates.
    Called by ``_humanize_label`` to keep cognitive complexity in check.
    """
    m = _HL_MAL_INPUT.match(pred)
    if m:
        host, victim, sw = (g.strip() for g in m.groups())
        return f"Malicious Input\\nHost: {host} | victim: {victim} via {sw}"

    m = _HL_HACL.match(pred)
    if m:
        src, dst, proto, port = (g.strip() for g in m.groups())
        return f"Firewall Rule\\n{src} → {dst} | {proto}:{port}"

    m = _HL_NFS_EXPORT.match(pred)
    if m:
        host, path, mode, client = (g.strip() for g in m.groups())
        return f"NFS Export\\nHost: {host} | {path} ({mode}) → {client}"

    m = _HL_ATTACKER.match(pred)
    if m:
        return f"Attacker Origin\\n{m.group(1).strip()}"

    m = _HL_NET_SERVICE.match(pred)
    if m:
        host, sw, proto, port, user = (g.strip() for g in m.groups())
        return f"Service\\nHost: {host} | {sw} {proto}:{port} ({user})"

    m = _HL_HAS_ACCOUNT.match(pred)
    if m:
        user, host, role = (g.strip() for g in m.groups())
        return f"Account\\n{user} on {host} ({role})"

    m = _HL_INCOMPETENT.match(pred)
    if m:
        return f"Vulnerable User\\n{m.group(1).strip()}"

    m = _HL_GENERIC.match(pred)
    if m:
        return f"{_camel_to_words(m.group(1))}\\n{m.group(2).strip()}"

    return None


def _humanize_label(raw_label: str) -> str:
    """
    Convert a raw MulVAL DOT node label ("N:predicate(args):leaf") into a
    human-readable multi-line string suitable for Graphviz rendering.

    Line breaks are represented as literal ``\\n`` (backslash + n) so that
    Graphviz renders them as centred newlines inside the node.
    """
    m = _LABEL_CORE_RE.match(raw_label.strip())
    pred = m.group(1) if m else raw_label.strip()

    # --- vulExists with CVE ID ---
    m2 = _HL_VULN_CVE.match(pred)
    if m2:
        host, cve, sw, exploit, impact = (g.strip() for g in m2.groups())
        return (
            f"{cve.upper()}\\n"
            f"Host: {host} | {sw}\\n"
            f"{_fmt_exploit(exploit)} → {_fmt_impact(impact)}"
        )

    # --- vulExists with STRIDE threat ---
    m2 = _HL_VULN_STRIDE.match(pred)
    if m2:
        host, threat_id, sw, exploit, impact = (g.strip() for g in m2.groups())
        return (
            f"STRIDE: {_fmt_stride_name(threat_id)}\\n"
            f"Host: {host} | {sw}\\n"
            f"{_fmt_exploit(exploit)} → {_fmt_impact(impact)}"
        )

    # --- RULE N (description) ---
    m2 = _HL_RULE.match(pred)
    if m2:
        return m2.group(1).capitalize()

    # --- execCode(host, user) ---
    m2 = _HL_EXEC_CODE.match(pred)
    if m2:
        host, user = m2.group(1).strip(), m2.group(2).strip()
        return f"Execute Code\\nHost: {host} | as: {user}"

    # --- netAccess(host, protocol, port) ---
    m2 = _HL_NET_ACCESS.match(pred)
    if m2:
        host, proto, port = (g.strip() for g in m2.groups())
        return f"Network Access\\nHost: {host} | {proto}:{port}"

    # --- canAccessHost(host) ---
    m2 = _HL_CAN_ACCESS.match(pred)
    if m2:
        return f"Can Access Host\\n{m2.group(1).strip()}"

    # --- accessFile(host, mode, path) ---
    m2 = _HL_ACCESS_FILE.match(pred)
    if m2:
        host, mode, path = (g.strip() for g in m2.groups())
        return f"File Access\\nHost: {host} | {mode}: {path}"

    # --- principalCompromised(user) ---
    m2 = _HL_PRINCIPAL.match(pred)
    if m2:
        return f"Principal Compromised\\n{m2.group(1).strip()}"

    # --- All remaining infrastructure/fact predicates ---
    return _humanize_fact_pred(pred) or pred


def _cve_from_label(label_value: str) -> Optional[str]:
    """Return the first CVE-ID embedded in a Graphviz label string, or None."""
    m = _CVE_RE.search(label_value)
    return m.group(1).upper() if m else None


def _extract_attr(attr_string: str, name: str) -> Optional[str]:
    """Pull the value of attribute *name* from a raw attribute string.

    Handles both quoted (``name="value"``) and unquoted (``name=value``)
    forms, as MulVAL emits shape/style without quotes.
    """
    pat = re.compile(
        rf'\b{re.escape(name)}\s*=\s*(?:"([^"]*)"|([\w#]+))'
    )
    m = pat.search(attr_string)
    if not m:
        return None
    # group(1) is the quoted capture, group(2) is the unquoted capture
    return m.group(1) if m.group(1) is not None else m.group(2)


def _set_attr(attr_string: str, name: str, value: str) -> str:
    """
    Add or replace an attribute in a raw Graphviz attribute string.

    The value is always double-quoted.
    """
    pat = re.compile(rf'\b{re.escape(name)}\s*=\s*"[^"]*"')
    replacement = f'{name}="{value}"'
    if pat.search(attr_string):
        return pat.sub(replacement, attr_string)
    return attr_string + f',{replacement}'


# ---------------------------------------------------------------------------
# Per-CVE aggregated risk data
# ---------------------------------------------------------------------------

class _CVERisk:
    __slots__ = ("cve_id", "max_risk", "kev", "max_cvss", "max_epss", "kev_ransomware")

    def __init__(self, cve_id: str) -> None:
        self.cve_id = cve_id
        self.max_risk: float = 0.0
        self.kev: bool = False
        self.kev_ransomware: bool = False
        self.max_cvss: float = 0.0
        self.max_epss: float = 0.0

    def update(self, path: PathRiskScore) -> None:
        risk_score = path.risk_score or 0.0
        if risk_score > self.max_risk:
            self.max_risk = risk_score
        if path.kev_on_path:
            self.kev = True
        if path.max_cvss_on_path > self.max_cvss:
            self.max_cvss = path.max_cvss_on_path
        if path.max_epss_on_path > self.max_epss:
            self.max_epss = path.max_epss_on_path

    def fillcolor(self) -> str:
        if self.kev:
            return "#D97066"
        if self.max_cvss >= 9.0:
            return "#CC7A50"
        if self.max_cvss >= 7.0:
            return "#D4A574"
        if self.max_cvss >= 4.0:
            return "#E8D5B7"
        return "#D8D8D8"

    def tooltip(self) -> str:
        kev_flag = "YES" if self.kev else "no"
        return (
            f"{self.cve_id} | "
            f"Risk: {self.max_risk:.2f} | "
            f"CVSS: {self.max_cvss:.1f} | "
            f"EPSS: {self.max_epss:.4f} | "
            f"KEV: {kev_flag}"
        )

    def detailed_label_suffix(self) -> str:
        """Generate detailed label suffix with all risk metrics."""
        kev_marker = "[KEV]" if self.kev else ""
        ransomware_marker = " [RW]" if self.kev_ransomware else ""
        return (
            f"\\nRisk: {self.max_risk:.2f}/10 {kev_marker}{ransomware_marker}"
            f"\\nCVSS: {self.max_cvss:.1f} | EPSS: {self.max_epss:.4f}"
        )

def _build_cve_risk_map(report: RiskReport) -> dict[str, _CVERisk]:
    """Aggregate risk data from all scored paths into a per-CVE map."""
    cve_map: dict[str, _CVERisk] = {}
    for path in report.paths:
        for cve_id in path.leaf_cves:
            if cve_id not in cve_map:
                cve_map[cve_id] = _CVERisk(cve_id)
            cve_map[cve_id].update(path)
    return cve_map


def _build_edge_usage_map(report: RiskReport) -> dict[tuple[int, int], dict]:
    """
    Build edge usage statistics from top paths.
    
    Returns:
        Map of (src, dst) -> {count, max_risk, paths_using_edge}
    """
    edge_map: dict[tuple[int, int], dict] = {}
    
    # Only consider top paths for edge highlighting
    for path in report.top_paths:
        # Create edges from consecutive nodes in path
        for i in range(len(path.nodes) - 1):
            src = path.nodes[i]
            dst = path.nodes[i + 1]
            edge_key = (src, dst)
            
            if edge_key not in edge_map:
                edge_map[edge_key] = {
                    "count": 0,
                    "max_risk": 0.0,
                    "path_ids": []
                }
            
            edge_map[edge_key]["count"] += 1
            risk = path.risk_score or 0.0
            if risk > edge_map[edge_key]["max_risk"]:
                edge_map[edge_key]["max_risk"] = risk
            edge_map[edge_key]["path_ids"].append(path.path_id[:8])
    
    return edge_map


# ---------------------------------------------------------------------------
# Main annotator
# ---------------------------------------------------------------------------

class GraphAnnotator:
    """
    Annotates the MulVAL ``AttackGraph.dot`` with per-CVE risk colouring and
    renders it to PDF and PNG.
    """

    # Colours for non-CVE node types
    _GOAL_COLOUR   = "#C8979E"   # diamond – attacker goal (rosy brown)
    _RULE_COLOUR   = "#9DB4C0"   # ellipse – AND/OR rule node (steel blue)
    _STRIDE_COLOUR = "#B8A9C9"   # box with bare-atom vuln – STRIDE threat (lavender)
    _FACT_COLOUR   = "#FFFFFF"   # box without CVE – infrastructure fact

    def __init__(self) -> None:
        self._log: logging.Logger = Logger.get_logger()

    def annotate(
        self,
        report: RiskReport,
        graph_dir: str,
        work_dir: str,
        include_legend: bool = True,
    ) -> dict[str, str]:
        """
        Annotate the attack graph and render it.

        Args:
            report:    Completed ``RiskReport`` from the scoring step.
            graph_dir: Directory containing the original MulVAL output
                       (``AttackGraph.dot``).
            work_dir:  Destination directory for all output files.
            include_legend: Whether to add the embedded color and shape legend.

        Returns:
            Dictionary with keys ``dot``, ``pdf``, ``png`` mapping to the
            absolute paths of the produced files (PDF/PNG only if rendering
            succeeded).
        """
        src_dot = Path(graph_dir) / "AttackGraph.dot"
        if not src_dot.exists():
            self._log.warning(
                "AttackGraph.dot not found in %s — skipping annotation", graph_dir
            )
            return {}

        work_path = Path(work_dir)
        work_path.mkdir(parents=True, exist_ok=True)

        # Build per-CVE risk data
        cve_map = _build_cve_risk_map(report)
        self._log.info(
            "Annotating graph: %d CVEs with risk data", len(cve_map)
        )

        # Build edge usage map from top paths
        edge_map = _build_edge_usage_map(report)
        self._log.info(
            "Annotating %d critical edges from top %d paths",
            len(edge_map),
            len(report.top_paths)
        )

        # Annotate and write
        annotated_dot = work_path / "AttackGraph_annotated.dot"
        self._annotate_dot(
            src_dot, annotated_dot, cve_map, edge_map, report, include_legend
        )

        # Render
        outputs: dict[str, str] = {"dot": str(annotated_dot)}
        for fmt in ("pdf", "png"):
            out_file = work_path / f"AttackGraph_annotated.{fmt}"
            ok = self._render(annotated_dot, out_file, fmt)
            if ok:
                outputs[fmt] = str(out_file)

        return outputs

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _generate_legend(self, report: RiskReport) -> list[str]:
        """Generate a comprehensive legend subgraph showing color and shape meanings."""
        top_risk = report.top_paths[0].risk_score or 0.0 if report.top_paths else 0.0
        avg_risk = (
            sum(path.risk_score or 0.0 for path in report.paths) / len(report.paths)
            if report.paths
            else 0.0
        )
        
        legend = [
            '\t// ========== LEGEND ==========\n',
            '\tsubgraph cluster_legend {\n',
            '\t\tlabel="Attack Graph Risk Analysis Legend";\n',
            '\t\tfontsize=16;\n',
            '\t\tfontname="Arial Bold";\n',
            '\t\tstyle=filled;\n',
            '\t\tcolor="#333333";\n',
            '\t\tfillcolor="#F5F5F5";\n',
            '\n',
            '\t\tlegend_info [shape=plaintext,label=<\n',
            '\t\t\t<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="6">\n',
            '\t\t\t\t<TR><TD COLSPAN="3" BGCOLOR="#1a1a1a"><FONT COLOR="white" POINT-SIZE="14"><B>RISK ANALYSIS SUMMARY</B></FONT></TD></TR>\n',
            f'\t\t\t\t<TR><TD ALIGN="LEFT"><B>Total Attack Paths:</B></TD><TD COLSPAN="2">{len(report.paths)}</TD></TR>\n',
            f'\t\t\t\t<TR><TD ALIGN="LEFT"><B>Unique CVEs:</B></TD><TD COLSPAN="2">{report.unique_cves}</TD></TR>\n',
            f'\t\t\t\t<TR><TD ALIGN="LEFT"><B>Maximum Risk:</B></TD><TD COLSPAN="2"><FONT COLOR="#C85A54"><B>{top_risk:.2f}/10</B></FONT></TD></TR>\n',
            f'\t\t\t\t<TR><TD ALIGN="LEFT"><B>Average Risk:</B></TD><TD COLSPAN="2"><B>{avg_risk:.2f}/10</B></TD></TR>\n',
            f'\t\t\t\t<TR><TD ALIGN="LEFT"><B>Coverage:</B></TD><TD COLSPAN="2">{report.enrichment_coverage*100:.1f}%</TD></TR>\n',
            '\n',
            '\t\t\t\t<TR><TD COLSPAN="3" BGCOLOR="#1a1a1a"><FONT COLOR="white" POINT-SIZE="12"><B>NODE COLORS (Colorblind-Friendly)</B></FONT></TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#D97066" WIDTH="120"><B>KEV</B></TD><TD COLSPAN="2" ALIGN="LEFT">CISA Known Exploited Vulnerability (active exploitation)</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#CC7A50"><B>Critical</B></TD><TD COLSPAN="2" ALIGN="LEFT">Critical Severity: CVSS ≥ 9.0</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#D4A574"><B>High</B></TD><TD COLSPAN="2" ALIGN="LEFT">High Severity: CVSS ≥ 7.0</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#E8D5B7"><B>Medium</B></TD><TD COLSPAN="2" ALIGN="LEFT">Medium Severity: CVSS ≥ 4.0</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#D8D8D8"><B>Low</B></TD><TD COLSPAN="2" ALIGN="LEFT">Low Severity: CVSS &lt; 4.0</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#C8979E"><B>Goal</B></TD><TD COLSPAN="2" ALIGN="LEFT">Attacker Goal / Final Objective</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#B8A9C9"><B>STRIDE</B></TD><TD COLSPAN="2" ALIGN="LEFT">STRIDE Threat Model Vulnerability</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#9DB4C0"><B>Rule</B></TD><TD COLSPAN="2" ALIGN="LEFT">AND/OR Logic Rule</TD></TR>\n',
            '\t\t\t\t<TR><TD BGCOLOR="#FFFFFF"><B>Fact</B></TD><TD COLSPAN="2" ALIGN="LEFT">Infrastructure Fact (no CVE)</TD></TR>\n',
            '\n',
            '\t\t\t\t<TR><TD COLSPAN="3" BGCOLOR="#1a1a1a"><FONT COLOR="white" POINT-SIZE="12"><B>NODE SHAPES</B></FONT></TD></TR>\n',
            '\t\t\t\t<TR><TD><B>Diamond</B></TD><TD COLSPAN="2" ALIGN="LEFT">OR Node (reachable state or goal)</TD></TR>\n',
            '\t\t\t\t<TR><TD><B>Ellipse</B></TD><TD COLSPAN="2" ALIGN="LEFT">AND Node (inference rule)</TD></TR>\n',
            '\t\t\t\t<TR><TD><B>Box</B></TD><TD COLSPAN="2" ALIGN="LEFT">Leaf (vulnerability or fact)</TD></TR>\n',
            '\n',
            '\t\t\t\t<TR><TD COLSPAN="3" BGCOLOR="#1a1a1a"><FONT COLOR="white" POINT-SIZE="12"><B>EDGE COLORS</B></FONT></TD></TR>\n',
            '\t\t\t\t<TR><TD><FONT COLOR="#C85A54"><B>Dark Coral</B></FONT></TD><TD COLSPAN="2" ALIGN="LEFT">High Risk ≥ 7.0</TD></TR>\n',
            '\t\t\t\t<TR><TD><FONT COLOR="#CC7A50"><B>Burnt Orange</B></FONT></TD><TD COLSPAN="2" ALIGN="LEFT">Medium-High Risk ≥ 4.0</TD></TR>\n',
            '\t\t\t\t<TR><TD><FONT COLOR="#D4A574"><B>Tan</B></FONT></TD><TD COLSPAN="2" ALIGN="LEFT">Medium Risk ≥ 2.0</TD></TR>\n',
            '\t\t\t\t<TR><TD><FONT COLOR="#7A9BAE"><B>Steel Blue</B></FONT></TD><TD COLSPAN="2" ALIGN="LEFT">Low Risk &lt; 2.0</TD></TR>\n',
            '\t\t\t\t<TR><TD COLSPAN="3" ALIGN="LEFT"><I>Label format: "risk: X.X (N paths)"</I></TD></TR>\n',
            '\n',
            '\t\t\t\t<TR><TD COLSPAN="3" BGCOLOR="#1a1a1a"><FONT COLOR="white" POINT-SIZE="12"><B>METRICS</B></FONT></TD></TR>\n',
            '\t\t\t\t<TR><TD><B>Risk Score</B></TD><TD COLSPAN="2" ALIGN="LEFT">Risk rating (0-10): EPSS × CVSS × KEV × Criticality</TD></TR>\n',
            '\t\t\t\t<TR><TD><B>CVSS</B></TD><TD COLSPAN="2" ALIGN="LEFT">Common Vulnerability Scoring System v3.1 (0-10)</TD></TR>\n',
            '\t\t\t\t<TR><TD><B>EPSS</B></TD><TD COLSPAN="2" ALIGN="LEFT">Exploit Prediction Scoring System (0-1): exploitation probability</TD></TR>\n',
            '\t\t\t\t<TR><TD><B>KEV</B></TD><TD COLSPAN="2" ALIGN="LEFT">CISA Known Exploited Vulnerabilities: 1.5× multiplier</TD></TR>\n',
            '\t\t\t</TABLE>\n',
            '\t\t>];\n',
            '\t}\n',
            '\n',
        ]
        return legend

    def _annotate_node(
        self,
        attrs: str,
        label: str,
        shape: str,
        cve_map: dict[str, _CVERisk],
    ) -> str:
        """Annotate a single node with risk coloring and tooltips."""
        cve_id = _cve_from_label(label)
        human_label = _humanize_label(label)

        if cve_id and cve_id in cve_map:
            return self._annotate_cve_node(attrs, human_label, cve_map[cve_id])
        elif shape == "diamond":
            attrs = self._set_node_style(attrs, self._GOAL_COLOUR)
            return _set_attr(attrs, "label", human_label)
        elif shape == "ellipse":
            attrs = self._set_node_style(attrs, self._RULE_COLOUR)
            return _set_attr(attrs, "label", human_label)
        elif _STRIDE_VULN_RE.search(label):
            return self._annotate_stride_node(attrs, label, human_label)
        else:
            attrs = self._set_node_style(attrs, self._FACT_COLOUR)
            return _set_attr(attrs, "label", human_label)

    def _annotate_cve_node(self, attrs: str, human_label: str, risk: _CVERisk) -> str:
        """Annotate a CVE vulnerability node with risk data."""
        attrs = _set_attr(attrs, "style", "filled")
        attrs = _set_attr(attrs, "fillcolor", risk.fillcolor())
        attrs = _set_attr(attrs, "tooltip", risk.tooltip())
        new_label = human_label + risk.detailed_label_suffix()
        return _set_attr(attrs, "label", new_label)

    def _annotate_stride_node(self, attrs: str, raw_label: str, human_label: str) -> str:
        """Annotate a STRIDE threat model node."""
        attrs = _set_attr(attrs, "style", "filled")
        attrs = _set_attr(attrs, "fillcolor", self._STRIDE_COLOUR)
        stride_match = _STRIDE_VULN_RE.search(raw_label)
        tooltip = f"STRIDE threat: {stride_match.group(1)}" if stride_match else "STRIDE threat"
        attrs = _set_attr(attrs, "tooltip", tooltip)
        return _set_attr(attrs, "label", human_label)

    def _set_node_style(self, attrs: str, fillcolor: str) -> str:
        """Set basic node styling with fill color."""
        attrs = _set_attr(attrs, "style", "filled")
        return _set_attr(attrs, "fillcolor", fillcolor)

    def _get_edge_color(self, risk: float) -> str:
        """Determine edge color based on risk level."""
        if risk >= 7.0:
            return "#C85A54"
        elif risk >= 4.0:
            return "#CC7A50"
        elif risk >= 2.0:
            return "#D4A574"
        else:
            return "#7A9BAE"

    def _format_edge_line(
        self,
        indent: str,
        src_id: str,
        dst_id: str,
        tail: str,
        edge_info: dict,
    ) -> str:
        """Format an edge line with risk information."""
        max_risk = edge_info["max_risk"]
        count = edge_info["count"]
        color = self._get_edge_color(max_risk)
        label = f"risk: {max_risk:.2f}\\n({count} path{'s' if count > 1 else ''})"
        return (
            f'{indent}{src_id} -> {dst_id} '
            f'[label="{label}",color="{color}",fontsize=9];{tail}\n'
        )

    def _annotate_dot(
        self,
        src: Path,
        dst: Path,
        cve_map: dict[str, _CVERisk],
        edge_map: dict[tuple[int, int], dict],
        report: RiskReport,
        include_legend: bool,
    ) -> None:
        """Parse src .dot, annotate each node and edge, write to dst."""
        lines = src.read_text(encoding="utf-8").splitlines(keepends=True)
        out_lines: list[str] = []
        graph_started = False

        for line in lines:
            # Add legend after the opening "digraph G {" when requested.
            if not graph_started and line.strip().startswith("digraph"):
                out_lines.append(line)
                graph_started = True
                if include_legend:
                    out_lines.extend(self._generate_legend(report))
                continue

            # Process node lines
            m = _NODE_LINE_RE.match(line.rstrip("\n"))
            if m is not None:
                indent, node_id, attrs, tail = m.groups()
                label = _extract_attr(attrs, "label") or ""
                shape = _extract_attr(attrs, "shape") or ""
                attrs = self._annotate_node(attrs, label, shape, cve_map)
                out_lines.append(f"{indent}{node_id} [{attrs}];{tail}\n")
                continue

            # Process edge lines
            e = _EDGE_LINE_RE.match(line.rstrip("\n"))
            if e is not None:
                indent, src_id, dst_id, tail = e.groups()
                # The DOT and the DFS path store edges in opposite orientations
                # (MulVAL arrows point leaf -> goal; paths run goal -> leaf), so
                # match either direction to stay robust to arrow orientation.
                edge_info = edge_map.get((int(src_id), int(dst_id))) or edge_map.get(
                    (int(dst_id), int(src_id))
                )

                if edge_info is not None:
                    out_lines.append(
                        self._format_edge_line(indent, src_id, dst_id, tail, edge_info)
                    )
                else:
                    out_lines.append(line)
                continue

            # All other lines (closing brace, etc.)
            out_lines.append(line)

        dst.write_text("".join(out_lines), encoding="utf-8")
        self._log.debug("Written annotated .dot to %s", dst)

    def _render(self, dot_file: Path, out_file: Path, fmt: str) -> bool:
        """
        Invoke the ``dot`` CLI to render *dot_file* into *out_file*.

        Returns True on success, False on failure (non-fatal).
        """
        cmd = ["dot", f"-T{fmt}", str(dot_file), "-o", str(out_file)]
        # Raster formats default to 96 dpi which looks blurry; bump it for a
        # crisp PNG. PDF is vector and unaffected.
        if fmt == "png":
            cmd.insert(1, "-Gdpi=300")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                self._log.error(
                    "dot rendering failed (%s): %s", fmt, result.stderr.strip()
                )
                return False
            self._log.info("Rendered %s → %s", fmt.upper(), out_file)
            return True
        except FileNotFoundError:
            self._log.warning(
                "Graphviz 'dot' not found — cannot render %s", fmt
            )
            return False
        except subprocess.TimeoutExpired:
            self._log.error("dot rendering timed out for %s", fmt)
            return False
