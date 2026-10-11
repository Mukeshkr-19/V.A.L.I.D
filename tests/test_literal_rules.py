"""Tests for the literal HCL parser and the three custom rules.

The suite is written against the frozen rule and coverage behaviour.  When the
shared foundation (``valid.models``, ``valid.terraform_types``,
``valid.normalize``) is not yet importable, the integration tests are skipped
with an explicit reason instead of being reported as passing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from valid.scanners import literal_hcl  # noqa: E402

RULE_NET = literal_hcl.RULE_NET
RULE_TAG = literal_hcl.RULE_TAG
RULE_RDS = literal_hcl.RULE_RDS


# ---------------------------------------------------------------------------
# Foundation availability
# ---------------------------------------------------------------------------


def _foundation_ready() -> tuple[bool, str]:
    try:
        import valid.models  # noqa: F401
        import valid.normalize  # noqa: F401
        import valid.terraform_types  # noqa: F401
    except Exception as exc:
        return False, f"shared foundation unavailable: {type(exc).__name__}: {exc}"
    return True, ""


FOUNDATION_OK, FOUNDATION_REASON = _foundation_ready()
requires_foundation = pytest.mark.skipif(
    not FOUNDATION_OK, reason=f"foundation not importable: {FOUNDATION_REASON}"
)

requires_hcl2 = pytest.mark.skipif(
    literal_hcl.hcl2 is None, reason="hcl2 parser not installed"
)


def _config():
    from valid.models import ValidConfig

    return ValidConfig()


@pytest.fixture
def config():
    return _config()


def _write(tmp_path: Path, text: str, name: str = "main.tf") -> Path:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def _parse(tmp_path: Path, config):
    return literal_hcl.parse(tmp_path, config)


def _rule_ids(result, rule_id: str) -> list:
    """Confirmed findings for *rule_id* (coverage gaps excluded)."""
    return [
        finding
        for finding in result.findings
        if finding.source.rule_id == rule_id
        and finding.priority != "unknown"
    ]


def _gaps(result) -> list[str]:
    return list(result.coverage.required_gaps)


def _merged_status(parsed, result, config) -> str:
    """Risk status over the merged parse + scan coverage.

    ``scan(parsed)`` only receives the block map, so parse-stage gaps live on
    the ParsedScan; the merged coverage is what a caller actually summarizes.
    """
    from valid.models import Coverage
    from valid.risk import summarize

    merged = Coverage(
        required_failed_stages=[],
        required_gaps=[*parsed.coverage.required_gaps, *result.coverage.required_gaps],
        optional_gaps=[*parsed.coverage.optional_gaps, *result.coverage.optional_gaps],
        evaluated_files=parsed.coverage.evaluated_files,
        diagnostics=[*parsed.coverage.diagnostics, *result.coverage.diagnostics],
    )
    return summarize(result.findings, merged, config).status


# ---------------------------------------------------------------------------
# Terraform fixtures
# ---------------------------------------------------------------------------

RISKY_NETWORK = """
resource "aws_security_group" "open" {
  name = "open"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

FIXED_NETWORK = """
resource "aws_security_group" "closed" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

RANGE_INGRESS = """
resource "aws_security_group" "range" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

ALL_PROTOCOL_INGRESS = """
resource "aws_security_group" "anyproto" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

ALL_PROTOCOL_ZERO_PORTS = """
resource "aws_security_group" "anyproto" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

PUBLIC_SECOND_CIDR = """
resource "aws_security_group" "two_cidrs" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

NUMERIC_TCP_INGRESS = """
resource "aws_security_group" "numeric_tcp" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "6"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

NUMERIC_UDP_INGRESS = """
resource "aws_security_group" "numeric_udp" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "17"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

DYNAMIC_PORT_INGRESS = """
variable "admin_port" {
  type = number
}

resource "aws_security_group" "dynamic_port" {
  ingress {
    from_port   = var.admin_port
    to_port     = var.admin_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

DYNAMIC_PROTOCOL_INGRESS = """
variable "ingress_protocol" {
  type = string
}

resource "aws_security_group" "dynamic_protocol" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = var.ingress_protocol
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

MIXED_CIDR_INGRESS = """
variable "other_cidr" {
  type = string
}

resource "aws_security_group" "mixed" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0", var.other_cidr]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

EGRESS_ONLY = """
resource "aws_security_group" "egress_only" {
  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

NON_SSH_INGRESS = """
resource "aws_security_group" "https_only" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

STANDALONE_INGRESS_RULE = """
resource "aws_security_group" "base" {
  tags = {
    owner       = "platform"
    environment = "prod"
  }
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.base.id
}
"""

STANDALONE_EGRESS_RULE = """
resource "aws_security_group" "base" {
  tags = {
    owner       = "platform"
    environment = "prod"
  }
}

resource "aws_security_group_rule" "out" {
  type              = "egress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.base.id
}
"""

VPC_INGRESS_RULE = """
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = "sg-123"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

MISSING_TAGS = """
resource "aws_instance" "bare" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
"""

EMPTY_TAGS = """
resource "aws_instance" "blank" {
  ami           = "ami-123"
  instance_type = "t3.micro"

  tags = {
    owner       = ""
    environment = "prod"
  }
}
"""

PROVIDER_DEFAULT_TAGS = """
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      owner       = "platform"
      environment = "prod"
    }
  }
}

resource "aws_instance" "inherits" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
"""

PROVIDER_TAG_OVERRIDE = """
provider "aws" {
  default_tags {
    tags = {
      owner       = "platform"
      environment = "prod"
    }
  }
}

resource "aws_instance" "overrides" {
  ami           = "ami-123"
  instance_type = "t3.micro"

  tags = {
    environment = "staging"
  }
}
"""

UNRESOLVED_TAGS = """
resource "aws_instance" "dynamic_tags" {
  ami           = "ami-123"
  instance_type = "t3.micro"

  tags = {
    owner       = var.owner
    environment = "prod"
  }
}
"""

UNRESOLVED_CIDR = """
resource "aws_security_group" "dynamic_cidr" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

RDS_UNPROTECTED = """
resource "aws_db_instance" "db" {
  identifier          = "app"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  deletion_protection = false

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

RDS_PROTECTED = """
resource "aws_db_instance" "db" {
  identifier          = "app"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  deletion_protection = true

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

RDS_ABSENT = """
resource "aws_db_instance" "db" {
  identifier     = "app"
  engine         = "postgres"
  instance_class = "db.t3.micro"

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

RDS_DYNAMIC = """
variable "protect" {
  type = bool
}

resource "aws_db_instance" "db" {
  identifier          = "app"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  deletion_protection = var.protect

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

COMMENTED = """
# Owner: platform team
resource "aws_security_group" "web" {
  name = "web" # inline comment

  /*
     multi-line block comment
     ingress {
       from_port = 22
     }
  */

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

MALFORMED = 'resource "aws_security_group" "broken" {\n'

MODULE_CONTENT = """
module "vpc" {
  source = "./modules/vpc"
}

resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.micro"

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

UNRELATED_VARIABLE = """
variable "ami" {
  default = "ami-123"
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_instance" "app" {
  ami           = var.ami
  instance_type = "t3.micro"

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""


UNKNOWN_PROVIDER_ALIAS = """
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "app" {
  provider      = aws.typo
  ami           = "ami-123"
  instance_type = "t3.micro"

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

DYNAMIC_INGRESS_BLOCK = """
variable "ingress_rules" {
  type = list(string)
}

resource "aws_security_group" "dynamic" {
  name = "dynamic"

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

DYNAMIC_EGRESS_BLOCK = """
variable "egress_rules" {
  type = list(string)
}

resource "aws_security_group" "dynamic_egress" {
  name = "dynamic_egress"

  dynamic "egress" {
    for_each = var.egress_rules
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

DYNAMIC_STANDALONE_DIRECTION = """
variable "rule_direction" {
  type = string
}

resource "aws_security_group_rule" "ssh" {
  type        = var.rule_direction
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
"""

UNRECOGNIZED_PROTOCOL = """
resource "aws_security_group" "odd_protocol" {
  name = "odd_protocol"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "unrecognized"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
"""

DECLARED_UNSUPPORTED_PROVIDER_NAME = """
provider "aws_db" {
  default_tags {
    tags = {
      owner       = "platform"
      environment = "prod"
    }
  }
}

resource "aws_db_instance" "app" {
  identifier          = "app"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  deletion_protection = true
}
"""


# ---------------------------------------------------------------------------
# Parser-level unit tests (no foundation required)
# ---------------------------------------------------------------------------


@requires_hcl2
class TestCidrAndPortHelpers:
    """DG-AWS-NET-001 primitive evaluation."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("0.0.0.0/0", True),
            ('"0.0.0.0/0"', True),
            ("0.0.0.0/1", False),
            ("10.0.0.0/8", False),
            ("192.168.1.0/24", False),
            ("${var.cidr}", False),
            ("", False),
            ("not-a-cidr", False),
            ("::/0", False),
        ],
    )
    def test_public_cidr_detection(self, value, expected):
        assert literal_hcl._is_public_ipv4_cidr(value) is expected

    @pytest.mark.parametrize(
        "from_port,to_port,expected",
        [
            (22, 22, True),
            (0, 65535, True),
            (0, 22, True),
            (22, 22, True),
            (20, 25, True),
            (23, 25, False),
            (10, 21, False),
            (None, 22, False),
            (22, "${var.upper}", False),
        ],
    )
    def test_ssh_port_range(self, from_port, to_port, expected):
        assert literal_hcl._permits_ssh(from_port, to_port) is expected

    @pytest.mark.parametrize(
        "protocol,expected",
        [
            ("-1", True),
            ('"-1"', True),
            ("all", True),
            ("ALL", True),
            ("tcp", False),
            ("udp", False),
            ("6", False),
        ],
    )
    def test_protocol_tokens(self, protocol, expected):
        assert literal_hcl._is_any_protocol(protocol) is expected

    def test_tcp22_with_explicit_tcp(self):
        assert literal_hcl._permits_tcp22(22, 22, "tcp") is True

    def test_tcp22_with_quoted_tcp(self):
        assert literal_hcl._permits_tcp22(22, 22, '"tcp"') is True

    def test_tcp22_with_absent_protocol(self):
        assert literal_hcl._permits_tcp22(22, 22, None) is True

    def test_tcp22_with_all_protocol(self):
        assert literal_hcl._permits_tcp22(22, 22, "-1") is True

    def test_udp22_is_not_tcp(self):
        assert literal_hcl._permits_tcp22(22, 22, "udp") is False

    def test_egress_helper_is_not_used_for_ingress(self):
        assert literal_hcl._standalone_rule({"type": "egress"}) is None
        assert literal_hcl._standalone_rule({"type": "ingress"}) == {"type": "ingress"}

    def test_all_protocol_permits_tcp22_regardless_of_port_bounds(self):
        assert literal_hcl._permits_tcp22(0, 0, "-1") is True

    def test_numeric_tcp_protocol_permits_tcp22(self):
        assert literal_hcl._permits_tcp22(22, 22, "6") is True

    def test_protocol_list_containing_tcp_permits_tcp22(self):
        assert literal_hcl._permits_tcp22(22, 22, ["udp", "tcp"]) is True

    def test_other_numeric_protocols_do_not_permit_tcp22(self):
        assert literal_hcl._permits_tcp22(22, 22, "17") is False

    @pytest.mark.parametrize("token", ["udp", "17", "icmp", "1", "icmpv6", "58"])
    def test_known_non_tcp_protocols_are_clean(self, token):
        assert literal_hcl._tcp22_verdict(22, 22, token) == ("clean", "")

    def test_unrecognized_literal_protocol_is_undecidable(self):
        verdict, reason = literal_hcl._tcp22_verdict(22, 22, "unrecognized")
        assert verdict == "unknown"
        assert "not a recognized literal protocol" in reason

    def test_dynamic_port_bounds_are_undecidable(self):
        assert literal_hcl._tcp22_verdict(
            "${var.admin_port}", "${var.admin_port}", "tcp"
        ) == ("unknown", "port bounds are not resolvable literally")

    def test_dynamic_protocol_is_undecidable(self):
        assert literal_hcl._tcp22_verdict(22, 22, "${var.protocol}") == (
            "unknown",
            "protocol is not resolvable literally",
        )

    def test_absent_port_bounds_are_undecidable(self):
        assert literal_hcl._tcp22_verdict(None, None, "tcp")[0] == "unknown"


@requires_hcl2
class TestTagAndRdsHelpers:
    """DG-AWS-TAG-001 and DG-AWS-RDS-001 primitive evaluation."""

    def test_tag_present_and_nonempty(self):
        assert literal_hcl._tag_value({"owner": "platform"}, "owner") == (True, True)

    def test_tag_absent(self):
        assert literal_hcl._tag_value({"owner": "platform"}, "environment") == (False, False)

    def test_tag_empty_string(self):
        assert literal_hcl._tag_value({"owner": ""}, "owner") == (True, False)

    def test_tag_interpolated(self):
        assert literal_hcl._tag_value({"owner": "${var.owner}"}, "owner") == (True, False)

    def test_resource_tags_override_provider_defaults(self):
        merged, unresolved = literal_hcl._merged_tags(
            {"tags": {"environment": "staging"}},
            {"owner": "platform", "environment": "prod"},
        )
        assert merged["environment"] == "staging"
        assert merged["owner"] == "platform"
        assert unresolved == []

    def test_provider_defaults_apply_when_resource_has_no_tags(self):
        merged, unresolved = literal_hcl._merged_tags({}, {"owner": "platform"})
        assert merged == {"owner": "platform"}
        assert unresolved == []

    def test_unresolved_tag_value_is_reported(self):
        merged, unresolved = literal_hcl._merged_tags(
            {"tags": {"owner": "${var.owner}"}}, {"environment": "prod"}
        )
        assert unresolved == ["owner"]
        assert "owner" not in merged


@requires_hcl2
class TestMalformedHcl:
    """Malformed HCL must raise a visible CoverageGap."""

    def test_malformed_raises_coverage_gap(self):
        parser = literal_hcl._require_hcl2()
        with pytest.raises(literal_hcl.CoverageGap) as excinfo:
            literal_hcl._load_document(parser, MALFORMED)
        assert "malformed HCL" in str(excinfo.value)

    @pytest.mark.parametrize(
        "text",
        [
            'resource "a" "b" { x = }\n',
            "this is not hcl at all\n",
            "resource {\n",
        ],
    )
    def test_malformed_variants_raise(self, text):
        parser = literal_hcl._require_hcl2()
        with pytest.raises(literal_hcl.CoverageGap):
            literal_hcl._load_document(parser, text)

    def test_empty_file_parses_to_empty_document(self):
        parser = literal_hcl._require_hcl2()
        assert literal_hcl._load_document(parser, "") == {}


# ---------------------------------------------------------------------------
# Integration tests (require the shared foundation)
# ---------------------------------------------------------------------------


@requires_foundation
class TestParse:
    """parse() -> ParsedScan behaviour."""

    def test_resource_block_fields(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        result = literal_hcl.parse(tmp_path, config)
        blocks = result.parsed["main.tf"]
        sg = blocks[0]
        assert sg.block_type == "resource"
        assert sg.resource_type == "aws_security_group"
        assert sg.name == "open"
        assert sg.address == "aws_security_group.open"
        assert sg.path == "main.tf"
        assert sg.start_line == 2
        assert sg.end_line == 17

    def test_line_numbers_are_relative_to_file(self, tmp_path, config):
        _write(tmp_path, FIXED_NETWORK)
        result = literal_hcl.parse(tmp_path, config)
        block = result.parsed["main.tf"][0]
        assert block.start_line == 2
        assert block.end_line == 14
        assert block.start_line < block.end_line

    def test_provider_default_tags_are_literal(self, tmp_path, config):
        _write(tmp_path, PROVIDER_DEFAULT_TAGS)
        result = literal_hcl.parse(tmp_path, config)
        providers = [b for b in result.parsed["main.tf"] if b.block_type == "provider"]
        assert providers[0].literal_attributes["default_tags"] == {
            "owner": "platform",
            "environment": "prod",
        }
        assert providers[0].address == "provider.aws"

    def test_aliased_provider_address(self, tmp_path, config):
        _write(
            tmp_path,
            """
provider "aws" {
  alias  = "west"
  region = "us-west-2"
  default_tags {
    tags = {
      owner = "platform"
    }
  }
}
""",
        )
        result = literal_hcl.parse(tmp_path, config)
        provider = result.parsed["main.tf"][0]
        assert provider.address == "provider.aws.west"
        assert provider.name == "west"

    def test_unresolved_attribute_is_named(self, tmp_path, config):
        _write(tmp_path, UNRESOLVED_CIDR)
        result = literal_hcl.parse(tmp_path, config)
        sg = result.parsed["main.tf"][0]
        assert "ingress" in sg.unresolved_attributes
        assert "${var.allowed_cidr}" in str(sg.literal_attributes.get("ingress"))

    def test_unrelated_variable_reference_is_recorded(self, tmp_path, config):
        _write(tmp_path, UNRELATED_VARIABLE)
        result = literal_hcl.parse(tmp_path, config)
        instance = next(
            b for b in result.parsed["main.tf"] if b.resource_type == "aws_instance"
        )
        assert "ami" in instance.unresolved_attributes

    def test_module_content_is_a_required_gap(self, tmp_path, config):
        _write(tmp_path, MODULE_CONTENT)
        result = literal_hcl.parse(tmp_path, config)
        assert any("module.vpc" in gap for gap in result.coverage.required_gaps)
        assert all(
            b.block_type in {"resource", "provider"}
            for b in result.parsed["main.tf"]
        )

    def test_malformed_file_becomes_required_gap(self, tmp_path, config):
        _write(tmp_path, MALFORMED)
        result = literal_hcl.parse(tmp_path, config)
        assert any("malformed HCL" in gap for gap in result.coverage.required_gaps)
        assert result.coverage.evaluated_files == []

    def test_malformed_file_does_not_raise(self, tmp_path, config):
        _write(tmp_path, MALFORMED)
        _write(tmp_path, RISKY_NETWORK, name="good.tf")
        result = literal_hcl.parse(tmp_path, config)
        assert result.coverage.evaluated_files == ["good.tf"]
        assert "main.tf" not in result.parsed
        assert any("main.tf" in gap for gap in result.coverage.required_gaps)

    def test_empty_directory_is_required_gap(self, tmp_path, config):
        result = literal_hcl.parse(tmp_path, config)
        assert any("no Terraform files" in gap for gap in result.coverage.required_gaps)

    def test_missing_path_raises_coverage_gap(self, tmp_path, config):
        with pytest.raises(literal_hcl.CoverageGap):
            literal_hcl.parse(tmp_path / "nope", config)

    def test_comment_only_syntax_still_parses(self, tmp_path, config):
        _write(tmp_path, COMMENTED)
        result = literal_hcl.parse(tmp_path, config)
        assert result.coverage.required_gaps == []
        block = result.parsed["main.tf"][0]
        assert block.address == "aws_security_group.web"


@requires_foundation
class TestNetworkRule:
    """DG-AWS-NET-001 high/block behaviour."""

    def test_public_ssh_is_found(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_NET)
        assert len(findings) == 1
        assert findings[0].priority == "high"
        assert findings[0].policy_mode == "block"
        assert findings[0].source.scanner_severity == "high"
        assert findings[0].source.severity_origin == "custom_rule"
        assert findings[0].source.tool == "valid"
        assert findings[0].recommendation.template_id == "open_ssh"

    def test_private_cidr_is_clean(self, tmp_path, config):
        _write(tmp_path, FIXED_NETWORK)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []

    def test_port_range_containing_22_is_found(self, tmp_path, config):
        _write(tmp_path, RANGE_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1

    def test_all_protocol_ingress_is_found(self, tmp_path, config):
        _write(tmp_path, ALL_PROTOCOL_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1

    def test_cidr_list_keeps_every_entry(self, tmp_path, config):
        # The parser wraps the real CIDR list in an outer container; unwrapping
        # only that container must keep both entries.
        _write(tmp_path, PUBLIC_SECOND_CIDR)
        parsed = _parse(tmp_path, config)
        sg = next(b for b in parsed.parsed["main.tf"] if b.block_type == "resource")
        ingress = sg.literal_attributes["ingress"][0]
        assert literal_hcl._container(ingress["cidr_blocks"]) == [
            "10.0.0.0/8",
            "0.0.0.0/0",
        ]

    def test_public_second_cidr_in_a_list_is_found(self, tmp_path, config):
        _write(tmp_path, PUBLIC_SECOND_CIDR)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1
        assert _gaps(result) == []

    def test_all_protocol_with_zero_port_bounds_is_found(self, tmp_path, config):
        _write(tmp_path, ALL_PROTOCOL_ZERO_PORTS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1
        assert _gaps(result) == []

    def test_numeric_tcp_protocol_is_found(self, tmp_path, config):
        _write(tmp_path, NUMERIC_TCP_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1
        assert _gaps(result) == []

    def test_non_tcp_numeric_protocol_is_clean(self, tmp_path, config):
        _write(tmp_path, NUMERIC_UDP_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert _gaps(result) == []

    def test_dynamic_port_on_public_ingress_is_a_required_gap(self, tmp_path, config):
        _write(tmp_path, DYNAMIC_PORT_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert any(
            "TCP 22 exposure cannot be determined literally" in gap
            for gap in _gaps(result)
        )

    def test_dynamic_protocol_on_public_ingress_is_a_required_gap(
        self, tmp_path, config
    ):
        _write(tmp_path, DYNAMIC_PROTOCOL_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert any(
            "TCP 22 exposure cannot be determined literally" in gap
            for gap in _gaps(result)
        )

    def test_public_cidr_with_a_dynamic_entry_reports_both(self, tmp_path, config):
        _write(tmp_path, MIXED_CIDR_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1
        assert any("CIDR is not resolvable literally" in gap for gap in _gaps(result))

    def test_egress_is_excluded(self, tmp_path, config):
        _write(tmp_path, EGRESS_ONLY)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []

    def test_non_ssh_port_is_clean(self, tmp_path, config):
        _write(tmp_path, NON_SSH_INGRESS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []

    def test_standalone_ingress_rule_is_found(self, tmp_path, config):
        _write(tmp_path, STANDALONE_INGRESS_RULE)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_NET)
        assert len(findings) == 1
        assert findings[0].resource.address == "aws_security_group_rule.ssh"

    def test_standalone_egress_rule_is_excluded(self, tmp_path, config):
        _write(tmp_path, STANDALONE_EGRESS_RULE)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []

    def test_vpc_ingress_rule_is_found(self, tmp_path, config):
        _write(tmp_path, VPC_INGRESS_RULE)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_NET)
        assert len(findings) == 1
        assert findings[0].resource.address == "aws_vpc_security_group_ingress_rule.ssh"

    def test_unresolved_cidr_is_a_required_gap_not_a_finding(self, tmp_path, config):
        _write(tmp_path, UNRESOLVED_CIDR)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert any("CIDR is not resolvable literally" in gap for gap in _gaps(result))

    def test_commented_ingress_is_not_matched(self, tmp_path, config):
        _write(tmp_path, COMMENTED)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_NET)) == 1

    def test_finding_has_stable_identity(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        first = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        second = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(first, RULE_NET)[0].finding_id == _rule_ids(second, RULE_NET)[0].finding_id

    def test_finding_location_matches_resource(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        finding = _rule_ids(result, RULE_NET)[0]
        assert finding.location.path == "main.tf"
        assert finding.location.start_line == 2
        assert finding.location.end_line == 17


@requires_foundation
class TestTagRule:
    """DG-AWS-TAG-001 medium/warn behaviour."""

    def test_missing_tags_are_found(self, tmp_path, config):
        _write(tmp_path, MISSING_TAGS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_TAG)
        assert len(findings) == 1
        assert findings[0].priority == "medium"
        assert findings[0].policy_mode == "warn"
        assert findings[0].source.scanner_severity == "medium"

    def test_empty_tag_value_is_found(self, tmp_path, config):
        _write(tmp_path, EMPTY_TAGS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_TAG)) == 1

    def test_complete_tags_are_clean(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_TAG) == []

    def test_provider_default_tags_satisfy_the_rule(self, tmp_path, config):
        _write(tmp_path, PROVIDER_DEFAULT_TAGS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_TAG) == []

    def test_resource_override_still_satisfies_the_rule(self, tmp_path, config):
        _write(tmp_path, PROVIDER_TAG_OVERRIDE)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_TAG) == []

    def test_unresolved_tag_value_is_a_required_gap(self, tmp_path, config):
        _write(tmp_path, UNRESOLVED_TAGS)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        gaps = _gaps(result)
        assert any("tag 'owner' value is not resolvable literally" in gap for gap in gaps)
        # An unknown tag value is reported structurally (unknown +
        # not_evaluated coverage finding) and is never simultaneously claimed
        # as a deterministically missing tag.
        assert _rule_ids(result, RULE_TAG) == []
        unknown = [f for f in result.findings if f.priority == "unknown"]
        assert unknown
        assert all(f.source.rule_id == "DG-COVERAGE-GAP" for f in unknown)
        assert all(f.evidence_strength == "not_evaluated" for f in unknown)
        assert any("owner" in item.summary for f in unknown for item in f.evidence)

    @pytest.mark.parametrize(
        "resource_type",
        ["aws_security_group", "aws_instance", "aws_db_instance"],
    )
    def test_all_three_taggable_types_are_supported(self, tmp_path, config, resource_type):
        _write(
            tmp_path,
            f"""
resource "{resource_type}" "untagged" {{
  name = "x"
}}
""",
        )
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_TAG)
        assert len(findings) == 1
        assert findings[0].resource.address == f"{resource_type}.untagged"

    def test_aliased_only_provider_uses_implied_empty_default(self, tmp_path, config):
        # A resource without a ``provider`` argument uses the default provider
        # configuration, never an aliased one.  With only aliased providers
        # declared, that default configuration is implied to be empty, so the
        # missing tags are a deterministic finding, not an unresolved-alias gap.
        _write(
            tmp_path,
            """
provider "aws" {
  alias = "west"
  default_tags {
    tags = {
      owner       = "platform"
      environment = "prod"
    }
  }
}

resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
""",
        )
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_TAG)
        assert len(findings) == 1
        assert findings[0].resource.address == "aws_instance.app"
        assert _gaps(result) == []

    def test_aliased_default_tags_are_not_borrowed_by_default_resources(
        self, tmp_path, config
    ):
        # The aliased configuration carries complete default_tags; a resource
        # that does not reference the alias must not inherit them.
        _write(
            tmp_path,
            """
provider "aws" {
  alias = "west"
  default_tags {
    tags = {
      owner       = "platform"
      environment = "prod"
    }
  }
}

resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
""",
        )
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert len(_rule_ids(result, RULE_TAG)) == 1

    def test_explicit_alias_association_uses_that_configuration(
        self, tmp_path, config
    ):
        _write(
            tmp_path,
            """
provider "aws" {
  alias = "west"
  default_tags {
    tags = {
      owner       = "platform"
      environment = "prod"
    }
  }
}

resource "aws_instance" "app" {
  provider      = aws.west
  ami           = "ami-123"
  instance_type = "t3.micro"
}
""",
        )
        parsed = _parse(tmp_path, config)
        block = next(b for b in parsed.parsed["main.tf"] if b.block_type == "resource")
        assert block.literal_attributes["provider"] == "aws.west"
        assert "provider" not in block.unresolved_attributes
        result = literal_hcl.scan(parsed.parsed, config)
        assert _rule_ids(result, RULE_TAG) == []
        assert _gaps(result) == []

    def test_dynamic_provider_reference_is_a_required_gap(self, tmp_path, config):
        _write(
            tmp_path,
            """
variable "provider_alias" {
  type = string
}

resource "aws_instance" "app" {
  provider      = var.provider_alias
  ami           = "ami-123"
  instance_type = "t3.micro"
}
""",
        )
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_TAG) == []
        assert any(
            "provider reference is not resolvable literally" in gap
            for gap in _gaps(result)
        )

    def test_taggable_resource_types_come_from_config(self, tmp_path):
        from valid.models import ValidConfig

        narrow = ValidConfig(taggable_resource_types=["aws_instance"])
        _write(
            tmp_path,
            """
resource "aws_db_instance" "untagged" {
  engine = "postgres"
}
""",
        )
        result = literal_hcl.scan(_parse(tmp_path, narrow).parsed, narrow)
        assert _rule_ids(result, RULE_TAG) == []

    def test_required_tags_come_from_config(self, tmp_path):
        from valid.models import ValidConfig

        custom = ValidConfig(required_tags=["cost_centre"])
        _write(
            tmp_path,
            """
resource "aws_instance" "app" {
  tags = {
    owner       = "platform"
    environment = "prod"
  }
}
""",
        )
        result = literal_hcl.scan(_parse(tmp_path, custom).parsed, custom)
        assert len(_rule_ids(result, RULE_TAG)) == 1


@requires_foundation
class TestRdsRule:
    """DG-AWS-RDS-001 high/block behaviour."""

    def test_explicit_false_is_found(self, tmp_path, config):
        _write(tmp_path, RDS_UNPROTECTED)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        findings = _rule_ids(result, RULE_RDS)
        assert len(findings) == 1
        assert findings[0].priority == "high"
        assert findings[0].policy_mode == "block"
        assert findings[0].recommendation.template_id == "rds_deletion_protection"

    def test_explicit_true_is_clean(self, tmp_path, config):
        _write(tmp_path, RDS_PROTECTED)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_RDS) == []
        assert _gaps(result) == []

    def test_absent_is_not_evaluated_gap(self, tmp_path, config):
        _write(tmp_path, RDS_ABSENT)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_RDS) == []
        assert any("deletion_protection not set" in gap for gap in _gaps(result))

    def test_dynamic_is_not_evaluated_gap(self, tmp_path, config):
        _write(tmp_path, RDS_DYNAMIC)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_RDS) == []
        assert any(
            "deletion_protection value is not resolvable literally" in gap
            for gap in _gaps(result)
        )

    def test_no_fourth_rds_rule_is_emitted(self, tmp_path, config):
        _write(tmp_path, RDS_UNPROTECTED)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        rule_ids = {f.source.rule_id for f in result.findings if f.priority != "unknown"}
        assert rule_ids <= {RULE_NET, RULE_TAG, RULE_RDS, "DG-COVERAGE-GAP"}


@requires_foundation
class TestCoverageGapFindings:
    """Coverage gaps must surface as visible not_evaluated findings."""

    def test_gap_finding_is_unknown_not_evaluated_warn(self, tmp_path, config):
        _write(tmp_path, UNRESOLVED_CIDR)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        gaps = [f for f in result.findings if f.priority == "unknown"]
        assert gaps
        assert all(f.evidence_strength == "not_evaluated" for f in gaps)
        assert all(f.policy_mode == "warn" for f in gaps)

    def test_module_gap_makes_merged_coverage_incomplete(self, tmp_path, config):
        # A module gap lives on parse() coverage, while the frozen scan(parsed)
        # entry point only receives the block map.  The merged parser + custom
        # coverage is therefore what has to make the scan INCOMPLETE; module
        # content is never modelled as a resource/provider block.
        _write(tmp_path, MODULE_CONTENT)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        assert any("module.vpc" in gap for gap in parsed.coverage.required_gaps)
        assert all(
            block.block_type in {"resource", "provider"}
            for block in parsed.parsed["main.tf"]
        )
        from valid.models import Coverage
        from valid.risk import summarize

        merged = Coverage(
            required_failed_stages=[],
            required_gaps=[*parsed.coverage.required_gaps, *result.coverage.required_gaps],
            optional_gaps=[*parsed.coverage.optional_gaps, *result.coverage.optional_gaps],
            evaluated_files=parsed.coverage.evaluated_files,
            diagnostics=[*parsed.coverage.diagnostics, *result.coverage.diagnostics],
        )
        assert summarize(result.findings, merged, config).status == "INCOMPLETE"

    def test_unrelated_variable_reference_is_not_a_rule_failure(self, tmp_path, config):
        _write(tmp_path, UNRELATED_VARIABLE)
        result = literal_hcl.scan(_parse(tmp_path, config).parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert _rule_ids(result, RULE_TAG) == []
        assert _rule_ids(result, RULE_RDS) == []

    def test_findings_are_sorted_deterministically(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        _write(tmp_path, MISSING_TAGS, name="tags.tf")
        _write(tmp_path, RDS_UNPROTECTED, name="db.tf")
        parsed = _parse(tmp_path, config).parsed
        first = literal_hcl.scan(parsed, config)
        second = literal_hcl.scan(parsed, config)
        assert [f.finding_id for f in first.findings] == [
            f.finding_id for f in second.findings
        ]

    def test_scan_does_not_mutate_input(self, tmp_path, config):
        _write(tmp_path, RISKY_NETWORK)
        parsed = _parse(tmp_path, config).parsed
        before = json.dumps(
            {k: [b.address for b in v] for k, v in parsed.items()}, sort_keys=True
        )
        literal_hcl.scan(parsed, config)
        after = json.dumps(
            {k: [b.address for b in v] for k, v in parsed.items()}, sort_keys=True
        )
        assert before == after


@requires_foundation
class TestRequiredCoverageFollowup:
    """Confirmed coverage misses: an unresolvable construct must never look clean."""

    def test_unknown_explicit_provider_alias_is_a_required_gap(self, tmp_path, config):
        # Complete resource tags must not hide an association to an alias that no
        # provider block declares; the association itself is unresolved.
        _write(tmp_path, UNKNOWN_PROVIDER_ALIAS)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        assert _rule_ids(result, RULE_TAG) == []
        assert any(
            "provider alias 'aws.typo' is not declared" in gap for gap in _gaps(result)
        )
        assert _merged_status(parsed, result, config) == "INCOMPLETE"

    def test_dynamic_ingress_block_is_a_required_gap(self, tmp_path, config):
        # ``dynamic "ingress"`` is a real parser structure whose content comes
        # from a ``for_each`` expression; literal analysis cannot evaluate it.
        _write(tmp_path, DYNAMIC_INGRESS_BLOCK)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert any(
            "dynamic ingress block is not evaluated" in gap for gap in _gaps(result)
        )
        assert _merged_status(parsed, result, config) == "INCOMPLETE"

    def test_dynamic_egress_is_not_a_required_gap(self, tmp_path, config):
        # Known egress exclusion is preserved: a dynamic egress block cannot
        # create inbound exposure, so it stays out of the rule's scope.
        _write(tmp_path, DYNAMIC_EGRESS_BLOCK)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert _gaps(result) == []

    def test_dynamic_standalone_direction_is_a_required_gap(self, tmp_path, config):
        _write(tmp_path, DYNAMIC_STANDALONE_DIRECTION)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert any(
            "direction is not resolvable literally" in gap for gap in _gaps(result)
        )
        assert _merged_status(parsed, result, config) == "INCOMPLETE"

    def test_unrecognized_literal_protocol_is_a_required_gap(self, tmp_path, config):
        _write(tmp_path, UNRECOGNIZED_PROTOCOL)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        assert _rule_ids(result, RULE_NET) == []
        assert any(
            "not a recognized literal protocol" in gap for gap in _gaps(result)
        )
        assert _merged_status(parsed, result, config) == "INCOMPLETE"

    def test_declared_provider_name_does_not_redirect_the_aws_mapping(
        self, tmp_path, config
    ):
        # A stray ``provider "aws_db"`` must not supply default_tags to an
        # ``aws_db_instance``; the implicit AWS mapping is grounded in ``aws``.
        _write(tmp_path, DECLARED_UNSUPPORTED_PROVIDER_NAME)
        parsed = _parse(tmp_path, config)
        result = literal_hcl.scan(parsed.parsed, config)
        findings = _rule_ids(result, RULE_TAG)
        assert len(findings) == 1
        assert findings[0].resource.address == "aws_db_instance.app"
        assert _gaps(result) == []
        assert literal_hcl._provider_local_name("aws_db_instance") == "aws"
        assert literal_hcl._provider_local_name("custom_widget") is None


@requires_foundation
class TestMissingPrerequisite:
    """An unavailable foundation must be reported honestly."""

    def test_foundation_presence_is_recorded(self):
        assert isinstance(FOUNDATION_OK, bool)
        assert isinstance(FOUNDATION_REASON, str)
