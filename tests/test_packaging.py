"""Packaging checks: the trusted Checkov policy ships as package data identical to the root config."""

import tomllib
from importlib import resources
from pathlib import Path

import yaml

import valid.cli
import valid.models
from valid.models import ValidConfig

ROOT = Path(__file__).resolve().parents[1]
ROOT_POLICY = ROOT / "config" / "checkov_severity.yaml"
PACKAGE_POLICY = resources.files("valid").joinpath("data", "checkov_severity.yaml")


def test_package_policy_is_byte_identical_to_root_policy():
    assert PACKAGE_POLICY.is_file()
    assert PACKAGE_POLICY.read_bytes() == ROOT_POLICY.read_bytes()


def test_package_policy_validates_with_required_mappings():
    config = ValidConfig.model_validate(yaml.safe_load(PACKAGE_POLICY.read_text(encoding="utf-8")))
    assert set(valid.cli.REQUIRED_POLICY_IDS) <= set(config.checkov_severity_map)
    assert config.checkov_severity_map["CKV_AWS_24"].template_id == "open_ssh"
    assert config.checkov_severity_map["CKV_AWS_293"].template_id == "rds_deletion_protection"


def test_cli_loads_policy_from_package_data_not_source_tree():
    policy = Path(str(valid.cli.POLICY_FILE))
    assert policy == Path(str(PACKAGE_POLICY))
    assert policy.relative_to(Path(valid.cli.__file__).parent).parts == ("data", "checkov_severity.yaml")
    config = valid.cli.load_policy(valid.models, yaml)
    assert set(valid.cli.REQUIRED_POLICY_IDS) <= set(config.checkov_severity_map)


def test_pyproject_ships_policy_as_package_data():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = project["tool"]["setuptools"]["package-data"]["valid"]
    assert "data/checkov_severity.yaml" in package_data
    assert project["project"]["requires-python"] == ">=3.12,<3.13"
    assert project["project"]["optional-dependencies"]["scan"] == ["checkov==3.3.8"]
