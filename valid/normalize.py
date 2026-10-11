"""Canonical normalization and deterministic finding identity.

Converts raw Checkov failed checks and custom rule findings into canonical
findings with stable deterministic identifiers, then merges duplicates and
orders the result. Identifier generation for finding_id, fingerprint, and
evidence_id lives here; shared models in valid.models are never edited here.

Identity derivation:
  identity = {"tool", "rule_id", "path", "resource_type", "resource_address"}
  fingerprint = sha256(canonical_json(identity)).hexdigest()
  finding_id = "f_" + fingerprint[:16]
  evidence_id = "e_" + sha256(finding_id + "|" + kind + "|"
                              + canonical_json(summary)).hexdigest()[:16]

canonical_json normalizes CRLF/CR to LF recursively, then dumps with
sort_keys=True, separators=(",", ":") and ensure_ascii=False.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from valid.models import (
    EvidenceItem,
    Finding,
    FindingSource,
    Location,
    RawScanResult,
    Recommendation,
    ResourceRef,
    ValidConfig,
)

EVIDENCE_KINDS = ("scanner", "literal_hcl", "coverage_gap")

_CUSTOM_TOOL = "valid"
_CUSTOM_VERSION = "0.1.0"

# Checkov severities arrive in SCREAMING_CASE ("HIGH") or already lowercase.
# Anything unrecognized maps to "unknown"; severity is never inferred from
# prose, only from this explicit token table.
_SCANNER_SEVERITY_TOKENS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "unknown",
    "": "unknown",
}

_UNMAPPED_CATEGORY = "governance"
_UNMAPPED_TEMPLATE = "scanner_review"
_UNMAPPED_POLICY_MODE = "warn"


def _normalize_strings(value: Any) -> Any:
    """Recursively normalize CRLF/CR line endings to LF (strings only)."""
    if isinstance(value, str):
        return value.replace("\r\n", "\n").replace("\r", "\n")
    if isinstance(value, dict):
        return {key: _normalize_strings(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_strings(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for every hash in this module."""
    return json.dumps(
        _normalize_strings(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _identity_of(
    source: FindingSource,
    location: Location,
    resource: ResourceRef | None,
) -> dict[str, str]:
    return {
        "tool": source.tool,
        "rule_id": source.rule_id,
        "path": location.path,
        "resource_type": resource.type if resource and resource.type else "",
        "resource_address": resource.address if resource and resource.address else "",
    }


def fingerprint_of(
    source: FindingSource,
    location: Location,
    resource: ResourceRef | None,
) -> str:
    """Full identity SHA-256 hex digest for a finding identity."""
    return hashlib.sha256(
        canonical_json(_identity_of(source, location, resource)).encode("utf-8")
    ).hexdigest()


def finding_id_of(
    source: FindingSource,
    location: Location,
    resource: ResourceRef | None,
) -> str:
    """Short stable finding id: f_ + first 16 hex chars of the fingerprint."""
    return "f_" + fingerprint_of(source, location, resource)[:16]


def evidence_id_of(finding_id: str, kind: str, summary: str) -> str:
    """Deterministic evidence id bound to its parent finding identity."""
    text = finding_id + "|" + kind + "|" + canonical_json(summary)
    return "e_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def make_finding(
    *,
    source: FindingSource,
    location: Location,
    resource: ResourceRef | None,
    category: Any,
    priority: Any,
    evidence_strength: Any,
    evidence_summaries: list[tuple[str, str]],
    recommendation: Recommendation,
    policy_mode: Any,
    change_action: Any = "unknown",
) -> Finding:
    """Build a Finding with canonical deterministic identifiers.

    Evidence items are sorted by evidence_id so repeated construction from
    the same inputs is byte-stable. No random, time, or machine data is used.
    """
    if not isinstance(evidence_summaries, list) or not evidence_summaries:
        raise ValueError("evidence_summaries must be a non-empty list")
    for entry in evidence_summaries:
        if (
            not isinstance(entry, (list, tuple))
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
            or not entry[1]
        ):
            raise ValueError(
                "each evidence summary must be a (kind, non-empty summary) pair"
            )
        if entry[0] not in EVIDENCE_KINDS:
            raise ValueError("unknown evidence kind: %r" % (entry[0],))

    fingerprint = fingerprint_of(source, location, resource)
    fid = "f_" + fingerprint[:16]
    evidence = sorted(
        (
            EvidenceItem(
                evidence_id=evidence_id_of(fid, kind, summary),
                kind=kind,
                summary=summary,
            )
            for kind, summary in evidence_summaries
        ),
        key=lambda item: item.evidence_id,
    )
    return Finding(
        finding_id=fid,
        fingerprint=fingerprint,
        source=source,
        location=location,
        resource=resource,
        category=category,
        priority=priority,
        evidence_strength=evidence_strength,
        change_action=change_action,
        evidence=list(evidence),
        recommendation=recommendation,
        policy_mode=policy_mode,
    )


def _usable_scanner_severity(raw: Any) -> str | None:
    """Map a raw scanner severity token, or None when unusable."""
    if not isinstance(raw, str):
        return None
    mapped = _SCANNER_SEVERITY_TOKENS.get(raw.strip().lower())
    if mapped in (None, "unknown"):
        return None
    return mapped


def _canonical_checkov_path(raw: Any) -> str:
    """Resolve a Checkov file path to a source-relative forward-slash path.

    Interprets Checkov's root-relative "/main.tf" marker by stripping one
    leading slash. Private absolute_file_path values are never consulted by
    callers; anything still absolute, empty, or escaping ("..") is rejected
    so the CLI can mark the run INCOMPLETE instead of emitting bad paths.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError("checkov record is missing a file path")
    path = raw.replace("\\", "/").strip()
    if path.startswith("./"):
        path = path[2:]
    if path.startswith("/"):
        path = path[1:]
    if not path or path.startswith("/") or "/../" in ("/" + path + "/"):
        raise ValueError("checkov record has an out-of-root file path: %r" % (raw,))
    segments = path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise ValueError("checkov record has an invalid file path: %r" % (raw,))
    return path


def _resource_from_checkov(raw: Any) -> ResourceRef | None:
    """Derive a ResourceRef from a Checkov resource value, if possible."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        rtype = raw.get("type")
        address = raw.get("address")
        if not rtype and not address:
            return None
        return ResourceRef(
            type=rtype if isinstance(rtype, str) and rtype else None,
            address=address if isinstance(address, str) and address else None,
        )
    if isinstance(raw, str) and raw:
        if "." in raw:
            rtype = raw.split(".", 1)[0]
            if not rtype:
                raise ValueError(
                    "checkov record has a malformed resource: %r" % (raw,)
                )
            return ResourceRef(type=rtype, address=raw)
        return ResourceRef(type=None, address=raw)
    return None


def _lines_from_checkov(raw: Any) -> tuple[int | None, int | None]:
    """Extract ordered positive line numbers; anything else means null."""
    candidates = raw if isinstance(raw, (list, tuple)) else None
    if candidates is not None and len(candidates) == 2:
        start, end = candidates
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and not isinstance(start, bool)
            and not isinstance(end, bool)
            and start > 0
            and end > 0
            and start <= end
        ):
            return start, end
    return None, None


def _checkov_record_finding(
    record: Any,
    raw_checkov: RawScanResult,
    config: ValidConfig,
) -> Finding:
    """Convert one raw Checkov failed-check dict into a canonical Finding."""
    if not isinstance(record, dict):
        raise ValueError("checkov failed check must be an object")
    rule_id = record.get("check_id") or record.get("bc_check_id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("checkov failed check is missing check_id")

    scanner_severity = _usable_scanner_severity(
        record.get("severity", record.get("bc_severity"))
    )
    policy = config.checkov_severity_map.get(rule_id)
    if policy is not None:
        priority = policy.priority
        category = policy.category
        policy_mode = policy.policy_mode
        template_id = policy.template_id
        severity_origin = "rule_map"
    else:
        # Unmapped checks keep usable scanner severity for the record but
        # never infer priority from prose: priority stays unknown with a
        # warn triage policy.
        priority = "unknown"
        category = _UNMAPPED_CATEGORY
        policy_mode = _UNMAPPED_POLICY_MODE
        template_id = _UNMAPPED_TEMPLATE
        severity_origin = "scanner" if scanner_severity else "defaulted"

    path = _canonical_checkov_path(
        record.get("file_path", record.get("repo_file_path"))
    )
    resource = _resource_from_checkov(record.get("resource"))
    start_line, end_line = _lines_from_checkov(record.get("file_line_range"))

    check_name = record.get("check_name")
    name = check_name if isinstance(check_name, str) and check_name else rule_id
    resource_label = (
        resource.address
        if resource and isinstance(resource.address, str) and resource.address
        else "unresolved resource"
    )
    summary = "Checkov %s (%s) failed for %s in %s" % (
        rule_id,
        name,
        resource_label,
        path,
    )
    return make_finding(
        source=FindingSource(
            tool=raw_checkov.tool,
            version=raw_checkov.version,
            rule_id=rule_id,
            scanner_severity=scanner_severity or "unknown",
            severity_origin=severity_origin,
        ),
        location=Location(path=path, start_line=start_line, end_line=end_line),
        resource=resource,
        category=category,
        priority=priority,
        evidence_strength="deterministic",
        evidence_summaries=[("scanner", summary)],
        recommendation=Recommendation(template_id=template_id),
        policy_mode=policy_mode,
    )


def _merge_same_identity(first: Finding, second: Finding) -> Finding:
    """Merge duplicate same-source findings or raise on conflicting metadata."""

    def comparable(finding: Finding) -> tuple[Any, ...]:
        resource = finding.resource
        return (
            finding.source.tool,
            finding.source.version,
            finding.source.rule_id,
            finding.source.scanner_severity,
            finding.source.severity_origin,
            finding.location.path,
            finding.location.start_line,
            finding.location.end_line,
            # None and empty resource fields describe the same identity.
            resource.type if resource and resource.type else "",
            resource.address if resource and resource.address else "",
            finding.category,
            finding.priority,
            finding.evidence_strength,
            finding.change_action,
            finding.recommendation.template_id,
            finding.policy_mode,
        )

    if comparable(first) != comparable(second):
        raise ValueError(
            "conflicting duplicate findings for fingerprint %s "
            "(rule %s/%s at %s)"
            % (
                first.fingerprint,
                first.source.tool,
                first.source.rule_id,
                first.location.path,
            )
        )
    merged_evidence = sorted(
        {item.evidence_id: item for item in (*first.evidence, *second.evidence)}.values(),
        key=lambda item: item.evidence_id,
    )
    return Finding(
        finding_id=first.finding_id,
        fingerprint=first.fingerprint,
        source=first.source,
        location=first.location,
        resource=first.resource,
        category=first.category,
        priority=first.priority,
        evidence_strength=first.evidence_strength,
        change_action=first.change_action,
        evidence=list(merged_evidence),
        recommendation=first.recommendation,
        policy_mode=first.policy_mode,
    )


def normalize(
    raw_checkov: RawScanResult,
    custom_findings: list[Finding],
    config: ValidConfig,
) -> list[Finding]:
    """Merge Checkov and custom findings into stable canonical order.

    Repeat findings within one source are deduplicated by fingerprint with
    deterministic evidence-ID merging; contradictory duplicates raise
    ValueError. Findings from different sources always stay separate to
    preserve singular source provenance. Any invalid required scanner data
    raises ValueError so the CLI can mark the run INCOMPLETE.
    """
    if not isinstance(raw_checkov, RawScanResult):
        raise ValueError("normalize requires a RawScanResult")
    if not isinstance(config, ValidConfig):
        raise ValueError("normalize requires a ValidConfig")
    if raw_checkov.status != "complete":
        raise ValueError(
            "checkov scan did not complete (status=%r)" % (raw_checkov.status,)
        )
    if raw_checkov.parsing_errors:
        raise ValueError(
            "checkov reported %d parsing error(s)" % len(raw_checkov.parsing_errors)
        )
    if not isinstance(raw_checkov.failed_checks, list):
        raise ValueError("checkov failed_checks must be a list")
    if not isinstance(custom_findings, list):
        raise ValueError("custom_findings must be a list")
    for entry in custom_findings:
        if not isinstance(entry, Finding):
            raise ValueError("custom_findings must contain Finding objects")

    converted = [
        _checkov_record_finding(record, raw_checkov, config)
        for record in raw_checkov.failed_checks
    ]
    merged: dict[str, Finding] = {}
    for finding in (*converted, *custom_findings):
        existing = merged.get(finding.fingerprint)
        merged[finding.fingerprint] = (
            finding
            if existing is None
            else _merge_same_identity(existing, finding)
        )
    return sorted(
        merged.values(),
        key=lambda item: (
            item.location.path,
            item.resource.address
            if item.resource and item.resource.address
            else "",
            item.source.tool,
            item.source.rule_id,
            item.finding_id,
        ),
    )
