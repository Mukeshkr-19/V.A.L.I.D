"""Render bounded Markdown from deterministic summaries and supplied evidence."""

from __future__ import annotations

import html
import re
import unicodedata

from valid import guidance
from valid.models import Explanation, Finding, RiskSummary

MAX_VISIBLE_FINDINGS = 10
MAX_FIELD_CHARS = 300
MAX_EVIDENCE_ITEMS = 3
MAX_COVERAGE_ITEMS = 10
_PUNCTUATION = frozenset("*_{}[]()#+-!|~:/") | {chr(92), chr(96)}
_PRIVATE_PATH = re.compile(r"(?<![A-Za-z0-9_])(?:/(?:Users|home|private|tmp)/|[A-Za-z]:\\)[^\s,;]*")
_TOKEN = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}|(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+)")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s,;]+"
)


def _safe_text(value: str, max_chars: int = MAX_FIELD_CHARS) -> str:
    """Make one bounded text field inert in Markdown and strip common secrets."""
    value = _PRIVATE_PATH.sub("[private path]", str(value))
    value = _TOKEN.sub("[redacted]", value)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + "=[redacted]", value)
    value = "".join(" " if char.isspace() else char for char in value)
    value = "".join(char for char in value if not unicodedata.category(char).startswith("C"))
    if len(value) > max_chars:
        value = value[:max_chars] + "..."
    value = value.replace("@", "[at]")
    escaped = html.escape(value, quote=True)
    return "".join("&#" + str(ord(char)) + ";" if char in _PUNCTUATION else char for char in escaped)


def _index_explanations(findings: list[Finding], explanations: list[Explanation]) -> dict[str, Explanation]:
    allowed = {finding.finding_id: finding for finding in findings}
    if len(allowed) != len(findings):
        raise ValueError("Duplicate finding ID in report input")
    indexed = {}
    for explanation in explanations:
        finding = allowed.get(explanation.finding_id)
        if finding is None or explanation.finding_id in indexed:
            raise ValueError("Unknown or duplicate explanation finding ID")
        evidence = {item.evidence_id for item in finding.evidence}
        if len(explanation.evidence_ids) != len(set(explanation.evidence_ids)):
            raise ValueError("Duplicate explanation evidence ID")
        if set(explanation.evidence_ids) != evidence:
            raise ValueError("Explanation must cite exactly its supplied evidence IDs")
        if explanation.evidence_strength != finding.evidence_strength:
            raise ValueError("Explanation changed evidence strength")
        indexed[explanation.finding_id] = explanation
    if set(indexed) != set(allowed):
        raise ValueError("Missing finding explanation")
    return indexed


def _finding_key(finding: Finding) -> tuple:
    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    return (
        priority[finding.priority],
        finding.location.path,
        finding.resource.address if finding.resource and finding.resource.address else "",
        finding.source.tool,
        finding.source.rule_id,
        finding.finding_id,
    )


def render(summary: RiskSummary, findings: list[Finding], explanations: list[Explanation]) -> str:
    """Render a single static-source report; do not recompute the verdict."""
    indexed = _index_explanations(findings, explanations)
    ai_count = sum(explanation.origin == "ai" for explanation in explanations)
    lines = [
        "<!-- valid-report -->",
        "## V.A.L.I.D. Review - " + summary.status,
        "",
        "**Coverage:** Terraform source tree; static analysis only.",
        "**Counts:** detector findings; different scanners may describe the same underlying risk.",
        "**Score:** " + str(summary.score) + " (deterministic policy; score alone does not choose the verdict).",
        "**Explanations:** supplied guidance; explanations do not change findings or the verdict.",
        "",
        "**Severity counts:** " + " · ".join(_safe_text(key) + ": " + str(summary.counts[key]) for key in sorted(summary.counts)),
        "**Categories:** " + " · ".join(_safe_text(key) + ": " + str(summary.category_counts[key]) for key in sorted(summary.category_counts)),
        "",
    ]
    if ai_count:
        lines.extend([
            "**Review mode: AI-assisted.** " + str(ai_count) + " detector findings have generated advice; "
            + str(len(findings) - ai_count) + " use basic guidance.",
            "AI impact and action text is advisory. Citations validate its references, not every generated claim; review proposed edits before using them.", "",
        ])
    else:
        lines.extend([
            "**Review mode: basic.** Generated AI advice is unavailable or not configured; deterministic evidence and guidance remain available.", "",
        ])
    if summary.status == "INCOMPLETE":
        lines.extend(["**Required analysis is incomplete. Resolve the coverage failures and rerun before relying on this review.**", ""])
    groups = (
        ("Required stage failures", summary.coverage.required_failed_stages),
        ("Required coverage gaps", summary.coverage.required_gaps),
        ("Optional coverage gaps", summary.coverage.optional_gaps),
        ("Verdict reasons", summary.reasons),
    )
    for title, values in groups:
        if not values:
            continue
        unique = sorted(set(values))
        lines.append("### " + title)
        lines.extend("- " + _safe_text(value) for value in unique[:MAX_COVERAGE_ITEMS])
        if len(unique) > MAX_COVERAGE_ITEMS:
            lines.append("- " + str(len(unique) - MAX_COVERAGE_ITEMS) + " additional entries are available in summary.json.")
        lines.append("")
    if findings and summary.status != "INCOMPLETE":
        lines.extend(["### Fix plan", "", "Grouped by the same resource and known rule family; ordered by deterministic priority. Detector findings and their identities are preserved.", ""])
        representatives = guidance.ordered_representatives(findings)
        members = {guidance.group_key(group[0]): group for group in guidance.groups(findings)}
        for position, finding in enumerate(representatives[:MAX_VISIBLE_FINDINGS], 1):
            group = members[guidance.group_key(finding)]
            explanation = next((indexed[f.finding_id] for f in group if indexed[f.finding_id].origin == "ai"), indexed[finding.finding_id])
            kind = "AI advice" if explanation.origin == "ai" else "basic guidance"
            lines.append(str(position) + ". **" + _safe_text(explanation.title) + "** (" + kind + ")")
            if finding.resource and finding.resource.address:
                lines.append("   Resource: " + _safe_text(finding.resource.address))
            lines.append("   " + _safe_text(explanation.recommended_action, max_chars=1000))
            lines.append("   Evidence: " + ", ".join(_safe_text(f.finding_id) for f in group))
            if len(group) > 1:
                lines.append("   " + str(len(group)) + " corroborating detector findings; one proposed edit.")
            example = guidance.edit_example(finding)
            if example:
                snippet, note = example
                lines.extend(["", "   Reviewed edit example (not executed):", "", "   ```hcl", *["   " + line for line in snippet.splitlines()], "   ```", "", "   " + _safe_text(note, max_chars=600), ""])
            lines.append("")
        lines.extend(["After editing, rerun V.A.L.I.D. with a fresh output directory. A passing gate does not replace human review.", "", "### Detector evidence", ""])
    ordered = sorted(findings, key=_finding_key)
    if not ordered:
        lines.append(
            "No findings were supplied; analysis is incomplete."
            if summary.status == "INCOMPLETE"
            else "No detector findings were supplied. This static scan does not prove that infrastructure is safe."
        )
        lines.append("")
    for position, finding in enumerate(ordered[:MAX_VISIBLE_FINDINGS], 1):
        explanation = indexed[finding.finding_id]
        lines.append("### " + str(position) + ". " + _safe_text(explanation.title))
        lines.append("- **Priority / policy / evidence:** " + " / ".join(_safe_text(value) for value in (finding.priority, finding.policy_mode, finding.evidence_strength)))
        lines.append("- **Source:** " + _safe_text(finding.source.tool) + " / " + _safe_text(finding.source.rule_id))
        lines.append("- **Scanner severity / origin:** " + _safe_text(finding.source.scanner_severity) + " / " + _safe_text(finding.source.severity_origin))
        location = finding.location.path
        if finding.location.start_line is not None:
            location += ":" + str(finding.location.start_line)
        lines.append("- **Location:** " + _safe_text(location))
        if finding.resource and finding.resource.address:
            lines.append("- **Resource:** " + _safe_text(finding.resource.address))
        if finding.priority == "unknown":
            lines.append("- **Severity mapping:** unknown; review is required.")
        if finding.evidence_strength == "not_evaluated":
            lines.append("- **Coverage:** not evaluated; this is not a confirmed violation.")
        lines.append("- **Evidence:**")
        for item in sorted(finding.evidence, key=lambda evidence: evidence.evidence_id)[:MAX_EVIDENCE_ITEMS]:
            lines.append("  - " + _safe_text(item.evidence_id) + ": " + _safe_text(item.summary))
        if len(finding.evidence) > MAX_EVIDENCE_ITEMS:
            lines.append("  - Additional evidence is available in findings.json.")
        lines.append("- **Advice source:** " + ("AI-generated; requires review" if explanation.origin == "ai" else "basic deterministic guidance"))
        lines.append("- **Potential impact:** " + _safe_text(explanation.why_it_matters, max_chars=1200))
        lines.append("- **Proposed action:** " + _safe_text(explanation.recommended_action, max_chars=1600))
        lines.append("")
    overflow = len(ordered) - MAX_VISIBLE_FINDINGS
    if overflow > 0:
        lines.extend([
            "<details>",
            "<summary>" + str(overflow) + " additional detector findings</summary>",
            "",
            "Full findings and evidence are available in findings.json.",
            "",
            "</details>",
            "",
        ])
    lines.append("_Static evidence only. No deployment, merge, or change validation was performed by this report._")
    return _bounded_report(lines)


def _bounded_report(lines: list[str]) -> str:
    """Fit a PR-comment budget without cutting through field escapes."""
    full = "\n".join(lines) + "\n"
    if len(full.encode("utf-8")) <= 60000:
        return full
    kept = []
    used = 0
    details_open = False
    for line in lines:
        size = len((line + "\n").encode("utf-8"))
        if used + size > 59000:
            break
        kept.append(line)
        used += size
        if line == "<details>":
            details_open = True
        elif line == "</details>":
            details_open = False
    if details_open:
        kept.append("</details>")
    kept.extend(["", "Report preview truncated to fit the PR comment. Full evidence is available in findings.json and summary.json.", ""])
    return "\n".join(kept)
