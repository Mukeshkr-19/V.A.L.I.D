"""Group corroborating detectors and supply reviewed Terraform edit examples."""
from __future__ import annotations

from valid.models import Finding

_RULE_FAMILIES = {
    "CKV_AWS_24": "open_ssh", "DG-AWS-NET-001": "open_ssh",
    "CKV_AWS_293": "rds_deletion_protection", "DG-AWS-RDS-001": "rds_deletion_protection",
    "DG-AWS-TAG-001": "missing_tags",
}
_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def group_key(finding: Finding) -> tuple:
    family = _RULE_FAMILIES.get(finding.source.rule_id)
    if not family or not finding.resource or not finding.resource.address:
        return (finding.finding_id,)
    return (family, finding.location.path, finding.resource.address, finding.evidence_strength,
            finding.priority, finding.policy_mode)


def groups(findings: list[Finding]) -> list[list[Finding]]:
    indexed: dict[tuple, list[Finding]] = {}
    for finding in findings:
        indexed.setdefault(group_key(finding), []).append(finding)
    return list(indexed.values())


def ordered_representatives(findings: list[Finding]) -> list[Finding]:
    """Prefer built-in evidence, then review blocking issues before warnings."""
    representatives = [min(group, key=lambda f: (f.source.tool != "valid", f.finding_id))
                       for group in groups(findings)]
    return sorted(representatives, key=lambda f: (_PRIORITY[f.priority], f.location.path,
                                                 f.resource.address if f.resource else "", f.finding_id))


def edit_example(finding: Finding) -> tuple[str, str] | None:
    """Trusted attribute examples, never provider-written executable code."""
    if finding.evidence_strength != "deterministic":
        return None
    family = _RULE_FAMILIES.get(finding.source.rule_id)
    if family == "open_ssh":
        return ('cidr_blocks = [var.approved_admin_cidr]',
                'Edit the existing SSH ingress block. Define approved_admin_cidr using your approved administration network; do not substitute a guessed CIDR.')
    if family == "rds_deletion_protection":
        return ('deletion_protection = true',
                'Edit the existing RDS resource. Confirm this safeguard matches the database lifecycle requirements, then rerun the scan.')
    if family == "missing_tags":
        return ('tags = {\n  owner       = "<responsible-team>"\n  environment = "<environment>"\n}',
                'Replace both placeholders with real values and preserve existing tags. Provider defaults may also satisfy the check when resolvable.')
    return None
