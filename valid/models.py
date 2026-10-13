"""Shared schemas for findings, coverage, configuration, and risk summaries."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, get_args

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

EvidenceStrength = Literal["deterministic", "strong_heuristic", "weak_heuristic", "not_evaluated"]
Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]
ChangeAction = Literal["create", "update", "delete", "replace", "unknown"]
PolicyMode = Literal["block", "warn", "inform"]
Category = Literal["security", "reliability", "governance", "cost_risk"]
Status = Literal["PASS", "REVIEW", "HIGH RISK", "INCOMPLETE"]

SEVERITIES: tuple[str, ...] = get_args(Severity)
CATEGORIES: tuple[str, ...] = get_args(Category)

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def _non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must be a non-empty string")
    return value


def _source_relative_path(value: str) -> str:
    """Accept only canonical forward-slash paths relative to the scan root."""
    if not value or not value.strip():
        raise ValueError("path must be non-empty")
    if "\x00" in value:
        raise ValueError("path must not contain NUL")
    if "\\" in value:
        raise ValueError("path must use forward slashes")
    if value.startswith("/") or _WINDOWS_DRIVE.match(value):
        raise ValueError("path must be relative to the scan root")
    if value == ".":
        return value
    for segment in value.split("/"):
        if segment in ("", ".", ".."):
            raise ValueError("path must be canonical with no empty, '.' or '..' segments")
    return value


NonEmptyStr = Annotated[str, AfterValidator(_non_blank)]
RelativePath = Annotated[str, AfterValidator(_source_relative_path)]
LineNumber = Annotated[int, Field(ge=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_assignment=True)


def _check_line_order(start: int | None, end: int | None) -> None:
    if start is not None and end is not None and end < start:
        raise ValueError("end_line must be greater than or equal to start_line")


class FindingSource(StrictModel):
    tool: NonEmptyStr
    version: NonEmptyStr
    rule_id: NonEmptyStr
    scanner_severity: Severity
    severity_origin: Literal["scanner", "rule_map", "custom_rule", "defaulted"]


class Location(StrictModel):
    path: RelativePath
    start_line: LineNumber | None = None
    end_line: LineNumber | None = None

    @model_validator(mode="after")
    def _ordered_lines(self) -> Location:
        _check_line_order(self.start_line, self.end_line)
        return self


class ResourceRef(StrictModel):
    type: NonEmptyStr | None = None
    address: NonEmptyStr | None = None


class EvidenceItem(StrictModel):
    evidence_id: NonEmptyStr
    kind: Literal["scanner", "literal_hcl", "coverage_gap"]
    summary: str


class Recommendation(StrictModel):
    template_id: NonEmptyStr


class Finding(StrictModel):
    finding_id: NonEmptyStr
    fingerprint: NonEmptyStr
    source: FindingSource
    location: Location
    resource: ResourceRef | None
    category: Category
    priority: Severity
    evidence_strength: EvidenceStrength
    change_action: ChangeAction = "unknown"
    evidence: list[EvidenceItem]
    recommendation: Recommendation
    policy_mode: PolicyMode


class Explanation(StrictModel):
    finding_id: NonEmptyStr
    evidence_ids: list[NonEmptyStr]
    title: str
    why_it_matters: str
    recommended_action: str
    evidence_strength: EvidenceStrength
    origin: Literal["template", "ai"] = "template"


class Coverage(StrictModel):
    required_failed_stages: list[str] = Field(default_factory=list)
    required_gaps: list[str] = Field(default_factory=list)
    optional_gaps: list[str] = Field(default_factory=list)
    evaluated_files: list[RelativePath] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)


class RulePolicy(StrictModel):
    priority: Severity
    category: Category
    policy_mode: PolicyMode
    template_id: NonEmptyStr


class ValidConfig(StrictModel):
    required_tags: list[NonEmptyStr] = Field(default_factory=lambda: ["owner", "environment"])
    taggable_resource_types: list[NonEmptyStr] = Field(
        default_factory=lambda: ["aws_security_group", "aws_instance", "aws_db_instance"]
    )
    blocking_priorities: list[Severity] = Field(default_factory=lambda: ["high", "critical"])
    checkov_severity_map: dict[NonEmptyStr, RulePolicy] = Field(default_factory=dict)
    max_visible_findings: NonNegativeInt = 10
    scanner_timeout_seconds: Annotated[int, Field(gt=0)] = 120
    checkov_command: Annotated[list[NonEmptyStr], Field(min_length=1)] = Field(
        default_factory=lambda: ["checkov"]
    )
    schema_version: Literal["1.0.0"] = "1.0.0"


class RawScanResult(StrictModel):
    status: Literal["complete", "error"]
    tool: NonEmptyStr = "checkov"
    version: NonEmptyStr = "3.3.8"
    failed_checks: list[dict[str, Any]] = Field(default_factory=list)
    parsing_errors: list[str] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    return_code: int | None = None
    diagnostics: list[str] = Field(default_factory=list)


class CustomScanResult(StrictModel):
    findings: list[Finding] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)


class RiskSummary(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    status: Status
    score: NonNegativeInt
    counts: dict[str, NonNegativeInt]
    category_counts: dict[str, NonNegativeInt]
    top_priority: Severity | None
    coverage: Coverage
    reasons: list[str]

    @model_validator(mode="after")
    def _complete_count_keys(self) -> RiskSummary:
        if set(self.counts) != set(SEVERITIES):
            raise ValueError("counts must contain exactly the six severities")
        if set(self.category_counts) != set(CATEGORIES):
            raise ValueError("category_counts must contain exactly the four categories")
        return self
