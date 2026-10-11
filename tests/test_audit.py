from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from gcp_compliance_auditor.audit import audit_snapshot
from gcp_compliance_auditor.models import AuditSnapshot, Severity
from gcp_compliance_auditor.rules import AuditRules

NOW = datetime(2026, 8, 22, 8, 0, tzinfo=timezone.utc)
SA = "serviceAccount:worker@test-project.iam.gserviceaccount.com"


def rules_for(*, iam: dict | None = None, storage: dict | None = None, **extra):
    iam_values = {
        "disallowed_service_account_roles": ["roles/owner", "roles/editor"],
        "key_max_age_days": 90,
        "user_managed_keys_only": True,
        "include_disabled_keys": False,
        "max_roles_per_member": None,
        "max_permissions_per_member": None,
        "max_permissions_per_role": None,
    }
    iam_values.update(iam or {})
    storage_values = {
        "public_principals": ["allUsers", "allAuthenticatedUsers"],
        "require_uniform_bucket_level_access": True,
        "require_default_encryption": True,
        "require_cmek": False,
        "approved_kms_keys": [],
        "approved_kms_key_prefixes": [],
    }
    storage_values.update(storage or {})
    return AuditRules.from_dict(
        {
            "ruleset": {"name": "Unit test", "version": "1"},
            "iam": iam_values,
            "storage": storage_values,
            **extra,
        }
    )


def snapshot_for(
    *,
    bindings: list | None = None,
    service_accounts: list | None = None,
    buckets: list | None = None,
    role_permissions: dict | None = None,
):
    return AuditSnapshot.from_dict(
        {
            "project_id": "test-project",
            "collected_at": "2026-08-22T08:00:00Z",
            "iam_policy": {"bindings": bindings or []},
            "service_accounts": service_accounts or [],
            "buckets": buckets or [],
            "role_permissions": role_permissions or {},
        }
    )


def rule_ids(result) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def private_bucket(**updates) -> dict:
    bucket = {
        "name": "private-bucket",
        "iam_policy": {"bindings": []},
        "acl": [],
        "default_object_acl": [],
        "iam_configuration": {
            "uniform_bucket_level_access": {"enabled": True},
            "public_access_prevention": "enforced",
        },
        "encryption": {"default_kms_key_name": None},
    }
    bucket.update(updates)
    return bucket


@pytest.mark.parametrize("role", ["roles/owner", "roles/editor"])
def test_owner_and_editor_on_standard_service_account_are_critical(role):
    result = audit_snapshot(
        snapshot_for(bindings=[{"role": role, "members": [SA]}]),
        rules_for(),
        NOW,
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "IAM_PRIVILEGED_SERVICE_ACCOUNT"
    )
    assert finding.severity is Severity.CRITICAL
    assert finding.principal == SA
    assert finding.evidence["assigned_role"] == role


def test_privileged_human_is_not_mislabeled_as_service_account_violation():
    result = audit_snapshot(
        snapshot_for(bindings=[{"role": "roles/owner", "members": ["user:admin@example.com"]}]),
        rules_for(),
        NOW,
    )

    assert "IAM_PRIVILEGED_SERVICE_ACCOUNT" not in rule_ids(result)


@pytest.mark.parametrize(
    "allowlist",
    [
        [SA],
        ["worker@test-project.iam.gserviceaccount.com"],
        ["serviceAccount:worker*@test-project.iam.gserviceaccount.com"],
    ],
)
def test_privileged_service_account_allowlist_accepts_exact_bare_and_glob(allowlist):
    result = audit_snapshot(
        snapshot_for(
            bindings=[{"role": "roles/owner", "members": [SA]}],
            service_accounts=[
                {
                    "email": "worker@test-project.iam.gserviceaccount.com",
                    "keys": [
                        {
                            "name": "projects/test/serviceAccounts/worker/keys/old",
                            "key_type": "USER_MANAGED",
                            "valid_after_time": "2026-01-01T00:00:00Z",
                        }
                    ],
                }
            ],
        ),
        rules_for(iam={"privileged_service_account_allowlist": allowlist}),
        NOW,
    )

    assert "IAM_PRIVILEGED_SERVICE_ACCOUNT" not in rule_ids(result)
    assert "IAM_STALE_SERVICE_ACCOUNT_KEY" in rule_ids(result), (
        "A privileged-role exception must not suppress the independent key-age check"
    )


def _account_with_key(*, age_days: int, key_type: str = "USER_MANAGED", disabled=False):
    created = NOW - timedelta(days=age_days)
    return {
        "email": "worker@test-project.iam.gserviceaccount.com",
        "keys": [
            {
                "name": "projects/test/serviceAccounts/worker/keys/key-1",
                "key_type": key_type,
                "valid_after_time": created.isoformat(),
                "disabled": disabled,
            }
        ],
    }


def test_user_managed_key_older_than_90_days_is_medium():
    result = audit_snapshot(
        snapshot_for(service_accounts=[_account_with_key(age_days=91)]),
        rules_for(),
        NOW,
    )

    finding = next(
        finding for finding in result.findings if finding.rule_id == "IAM_STALE_SERVICE_ACCOUNT_KEY"
    )
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["age_days"] == 91
    assert finding.evidence["maximum_age_days"] == 90


def test_key_at_exact_age_boundary_is_not_stale():
    result = audit_snapshot(
        snapshot_for(service_accounts=[_account_with_key(age_days=90)]),
        rules_for(),
        NOW,
    )
    assert "IAM_STALE_SERVICE_ACCOUNT_KEY" not in rule_ids(result)


@pytest.mark.parametrize(
    "account",
    [
        _account_with_key(age_days=365, key_type="SYSTEM_MANAGED"),
        _account_with_key(age_days=365, disabled=True),
    ],
)
def test_system_managed_and_disabled_keys_are_excluded_by_default(account):
    result = audit_snapshot(snapshot_for(service_accounts=[account]), rules_for(), NOW)
    assert "IAM_STALE_SERVICE_ACCOUNT_KEY" not in rule_ids(result)


@pytest.mark.parametrize("principal", ["allUsers", "allAuthenticatedUsers"])
@pytest.mark.parametrize("source", ["iam", "acl", "default_acl"])
def test_public_bucket_is_critical_across_supported_access_sources(principal, source):
    bucket = private_bucket()
    if source == "iam":
        bucket["iam_policy"] = {
            "bindings": [{"role": "roles/storage.objectViewer", "members": [principal]}]
        }
    elif source == "acl":
        bucket["acl"] = [{"entity": principal, "role": "READER"}]
    else:
        bucket["default_object_acl"] = [{"entity": principal, "role": "READER"}]

    result = audit_snapshot(snapshot_for(buckets=[bucket]), rules_for(), NOW)

    finding = next(
        finding for finding in result.findings if finding.rule_id == "STORAGE_PUBLIC_ACCESS"
    )
    assert finding.severity is Severity.CRITICAL
    assert finding.resource_name == "private-bucket"
    assert finding.principal == principal


def test_public_bucket_exemption_does_not_suppress_ubla_check():
    bucket = private_bucket(
        name="published-assets",
        iam_policy={"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        iam_configuration={
            "uniform_bucket_level_access": {"enabled": False},
            "public_access_prevention": "inherited",
        },
    )
    result = audit_snapshot(
        snapshot_for(buckets=[bucket]),
        rules_for(storage={"exempt_public_buckets": ["published-*"]}),
        NOW,
    )

    assert "STORAGE_PUBLIC_ACCESS" not in rule_ids(result)
    assert "STORAGE_UNIFORM_ACCESS_DISABLED" in rule_ids(result)


def test_uniform_bucket_level_access_disabled_is_high():
    bucket = private_bucket(
        iam_configuration={
            "uniform_bucket_level_access": {"enabled": False},
            "public_access_prevention": "enforced",
        }
    )
    result = audit_snapshot(snapshot_for(buckets=[bucket]), rules_for(), NOW)

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "STORAGE_UNIFORM_ACCESS_DISABLED"
    )
    assert finding.severity is Severity.HIGH


def test_missing_cmek_is_only_a_violation_when_cmek_is_required():
    snapshot = snapshot_for(buckets=[private_bucket()])

    optional = audit_snapshot(snapshot, rules_for(storage={"require_cmek": False}), NOW)
    required = audit_snapshot(snapshot, rules_for(storage={"require_cmek": True}), NOW)

    assert "CMEK_NOT_CONFIGURED" not in rule_ids(optional)
    assert "STORAGE_ENCRYPTION_DISABLED" not in rule_ids(optional)
    assert "CMEK_NOT_CONFIGURED" in rule_ids(required)
    assert "STORAGE_ENCRYPTION_DISABLED" not in rule_ids(required)


@pytest.mark.parametrize(
    "key,rules_update",
    [
        (
            "projects/security/locations/global/keyRings/storage/cryptoKeys/exact",
            {
                "approved_kms_keys": [
                    "projects/security/locations/global/keyRings/storage/cryptoKeys/exact"
                ]
            },
        ),
        (
            "projects/security/locations/asia-south1/keyRings/approved/cryptoKeys/data",
            {
                "approved_kms_key_prefixes": [
                    "projects/security/locations/asia-south1/keyRings/approved/cryptoKeys/"
                ]
            },
        ),
    ],
)
def test_approved_kms_exact_name_and_prefix_pass(key, rules_update):
    bucket = private_bucket(encryption={"default_kms_key_name": key})
    result = audit_snapshot(
        snapshot_for(buckets=[bucket]),
        rules_for(storage={"require_cmek": True, **rules_update}),
        NOW,
    )

    assert "CMEK_NOT_CONFIGURED" not in rule_ids(result)
    assert "UNAPPROVED_KMS_KEY" not in rule_ids(result)


def test_unapproved_kms_key_is_high():
    bucket = private_bucket(
        encryption={
            "default_kms_key_name": "projects/wrong/locations/global/keyRings/r/cryptoKeys/k"
        }
    )
    result = audit_snapshot(
        snapshot_for(buckets=[bucket]),
        rules_for(
            storage={
                "require_cmek": True,
                "approved_kms_key_prefixes": [
                    "projects/security/locations/global/keyRings/approved/cryptoKeys/"
                ],
            }
        ),
        NOW,
    )

    finding = next(
        finding for finding in result.findings if finding.rule_id == "UNAPPROVED_KMS_KEY"
    )
    assert finding.severity is Severity.HIGH


def test_role_count_threshold_counts_distinct_roles():
    bindings = [
        {"role": role, "members": [SA]}
        for role in ("roles/viewer", "roles/logging.viewer", "roles/browser")
    ]
    result = audit_snapshot(
        snapshot_for(bindings=bindings),
        rules_for(iam={"max_roles_per_member": 2}),
        NOW,
    )

    finding = next(
        finding for finding in result.findings if finding.rule_id == "IAM_ROLE_THRESHOLD_EXCEEDED"
    )
    assert finding.evidence["role_count"] == 3
    assert finding.evidence["maximum_allowed_roles"] == 2


def test_member_permission_threshold_uses_unique_permission_union():
    bindings = [
        {"role": "roles/custom.a", "members": [SA]},
        {"role": "roles/custom.b", "members": [SA]},
    ]
    result = audit_snapshot(
        snapshot_for(
            bindings=bindings,
            role_permissions={
                "roles/custom.a": ["permission.one", "permission.shared"],
                "roles/custom.b": ["permission.two", "permission.shared"],
            },
        ),
        rules_for(iam={"max_permissions_per_member": 2}),
        NOW,
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "IAM_PERMISSION_THRESHOLD_EXCEEDED" and finding.principal == SA
    )
    assert finding.evidence["permission_count"] == 3


def test_threshold_exemption_suppresses_thresholds_not_privileged_role():
    bindings = [
        {"role": "roles/owner", "members": [SA]},
        {"role": "roles/viewer", "members": [SA]},
    ]
    result = audit_snapshot(
        snapshot_for(bindings=bindings),
        rules_for(
            iam={
                "max_roles_per_member": 1,
                "threshold_exempt_principals": ["serviceAccount:worker@*"],
            }
        ),
        NOW,
    )

    assert "IAM_ROLE_THRESHOLD_EXCEEDED" not in rule_ids(result)
    assert "IAM_PRIVILEGED_SERVICE_ACCOUNT" in rule_ids(result)


def test_clean_snapshot_has_zero_findings_and_complete_summary(clean_snapshot_dict, test_rules):
    snapshot = AuditSnapshot.from_dict(clean_snapshot_dict)
    result = audit_snapshot(snapshot, test_rules, NOW)

    assert result.findings == ()
    assert result.compliant is True
    assert result.summary.violations == 0
    assert result.summary.projects_scanned == 1
    assert result.summary.service_accounts_scanned == 1
    assert result.summary.buckets_scanned == 1
    assert result.summary.severity_counts == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
    }


def test_result_schema_and_finding_ids_are_deterministic(violations_snapshot_dict, test_rules):
    snapshot = AuditSnapshot.from_dict(violations_snapshot_dict)

    first = audit_snapshot(snapshot, test_rules, NOW).to_dict()
    second = audit_snapshot(snapshot, test_rules, NOW).to_dict()

    assert first == second
    assert list(first) == [
        "schema_version",
        "generated_at",
        "project_id",
        "source",
        "ruleset",
        "summary",
        "findings",
    ]
    assert first["schema_version"] == "1.0"
    assert first["generated_at"] == "2026-08-22T08:00:00Z"
    assert first["summary"]["violations"] == len(first["findings"])
    assert len({item["finding_id"] for item in first["findings"]}) == len(first["findings"])
    assert json.loads(json.dumps(first)) == first
    for finding in first["findings"]:
        assert set(finding) == {
            "finding_id",
            "rule_id",
            "category",
            "severity",
            "title",
            "description",
            "project_id",
            "resource",
            "principal",
            "evidence",
            "recommendation",
            "frameworks",
        }
        assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}
        assert finding["frameworks"], finding["rule_id"]


def test_severity_override_changes_only_configured_rule():
    result = audit_snapshot(
        snapshot_for(bindings=[{"role": "roles/owner", "members": [SA]}]),
        rules_for(severity_overrides={"IAM_PRIVILEGED_SERVICE_ACCOUNT": "MEDIUM"}),
        NOW,
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "IAM_PRIVILEGED_SERVICE_ACCOUNT"
    )
    assert finding.severity is Severity.MEDIUM
