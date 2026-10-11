from __future__ import annotations

import json

import pytest

from gcp_compliance_auditor.models import Severity
from gcp_compliance_auditor.rules import (
    AuditRules,
    RuleValidationError,
    load_rules,
)


def test_load_rules_from_json(test_rules_path):
    rules = load_rules(test_rules_path)

    assert rules.name == "Test least-privilege baseline"
    assert rules.version == "1.0.0-test"
    assert rules.iam.key_max_age_days == 90
    assert rules.storage.require_cmek is True
    assert rules.storage.approved_kms_keys


def test_load_rules_from_yaml_uses_safe_supported_schema(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        """
ruleset:
  name: Minimal YAML
  version: 2
iam:
  key_max_age_days: 30
  max_roles_per_member: null
storage:
  require_cmek: false
severity_overrides:
  IAM_STALE_SERVICE_ACCOUNT_KEY: HIGH
""".lstrip(),
        encoding="utf-8",
    )

    rules = load_rules(path)

    assert rules.name == "Minimal YAML"
    assert rules.version == "2"
    assert rules.iam.key_max_age_days == 30
    assert rules.iam.max_roles_per_member is None
    assert rules.severity_for("IAM_STALE_SERVICE_ACCOUNT_KEY") is Severity.HIGH


@pytest.mark.parametrize(
    "payload, expected",
    [
        ({"iam": {"key_max_age_days": 0}}, "positive integer"),
        ({"iam": {"max_roles_per_member": -1}}, "non-negative integer"),
        ({"storage": {"require_cmek": "yes"}}, "true or false"),
        ({"iam": {"disallowed_service_account_roles": "roles/owner"}}, "array"),
    ],
)
def test_rule_validation_rejects_invalid_values(payload, expected):
    with pytest.raises(RuleValidationError, match=expected):
        AuditRules.from_dict(payload)


def test_unknown_severity_rule_is_rejected():
    with pytest.raises(RuleValidationError, match="Unknown rule ID"):
        AuditRules.from_dict({"severity_overrides": {"MADE_UP_RULE": "CRITICAL"}})


def test_unknown_severity_value_is_rejected():
    with pytest.raises(RuleValidationError, match="must be one of"):
        AuditRules.from_dict({"severity_overrides": {"STORAGE_PUBLIC_ACCESS": "LOW"}})


def test_empty_and_non_object_rule_files_are_rejected(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(RuleValidationError, match="Invalid rule file"):
        load_rules(empty)

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(RuleValidationError, match="root must be an object"):
        load_rules(array)


def test_rule_serialization_is_json_ready_and_deterministic(test_rules):
    first = test_rules.to_dict()
    second = test_rules.to_dict()

    assert first == second
    assert json.loads(json.dumps(first)) == first
    assert list(first) == ["ruleset", "iam", "storage", "severity_overrides"]


def test_none_threshold_disables_limit_without_changing_other_defaults():
    rules = AuditRules.from_dict(
        {
            "iam": {
                "max_roles_per_member": None,
                "max_permissions_per_member": None,
                "max_permissions_per_role": None,
            }
        }
    )

    assert rules.iam.max_roles_per_member is None
    assert rules.iam.max_permissions_per_member is None
    assert rules.iam.max_permissions_per_role is None
    assert rules.iam.key_max_age_days == 90
