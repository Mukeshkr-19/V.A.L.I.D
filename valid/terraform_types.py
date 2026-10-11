"""Typed representation of literal Terraform blocks used by custom rules."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from valid.models import (
    Coverage,
    LineNumber,
    NonEmptyStr,
    RelativePath,
    StrictModel,
    _check_line_order,
)


class ResourceBlock(StrictModel):
    block_type: Literal["resource", "provider"]
    resource_type: NonEmptyStr
    name: NonEmptyStr
    address: NonEmptyStr
    path: RelativePath
    start_line: LineNumber | None = None
    end_line: LineNumber | None = None
    literal_attributes: dict[str, Any] = Field(default_factory=dict)
    unresolved_attributes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _ordered_lines(self) -> ResourceBlock:
        _check_line_order(self.start_line, self.end_line)
        return self


ParsedTerraform = dict[str, list[ResourceBlock]]


class ParsedScan(StrictModel):
    parsed: dict[RelativePath, list[ResourceBlock]] = Field(default_factory=dict)
    coverage: Coverage = Field(default_factory=Coverage)
