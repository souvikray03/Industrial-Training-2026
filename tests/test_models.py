from __future__ import annotations

import json

import pytest

from gcp_compliance_auditor.models import (
    AuditSnapshot,
    SnapshotValidationError,
)


def test_raw_project_iam_policy_is_accepted_as_iam_only_snapshot():
    snapshot = AuditSnapshot.from_dict(
        {
            "version": 1,
            "bindings": [{"role": "roles/viewer", "members": ["group:audit@example.com"]}],
        },
        source="offline-iam-only",
    )

    assert snapshot.project_id == "unknown-project"
    assert snapshot.source == "offline-iam-only"
    assert snapshot.iam_policy.bindings[0].role == "roles/viewer"
    assert snapshot.service_accounts == ()
    assert snapshot.buckets == ()


def test_gcp_camel_case_fields_are_normalized():
    snapshot = AuditSnapshot.from_dict(
        {
            "projectId": "camel-project",
            "collectedAt": "2026-08-22T13:30:00+05:30",
            "iamPolicy": {"bindings": []},
            "serviceAccounts": [
                {
                    "email": "worker@camel-project.iam.gserviceaccount.com",
                    "displayName": "Worker",
                    "keys": [
                        {
                            "name": "projects/camel-project/serviceAccounts/worker/keys/1",
                            "keyType": "USER_MANAGED",
                            "validAfterTime": "2026-08-01T00:00:00Z",
                        }
                    ],
                }
            ],
            "buckets": [
                {
                    "name": "camel-bucket",
                    "iamPolicy": {"bindings": []},
                    "iamConfiguration": {
                        "uniformBucketLevelAccess": {"enabled": True},
                        "publicAccessPrevention": "enforced",
                    },
                    "encryption": {
                        "defaultKmsKeyName": (
                            "projects/security/locations/global/keyRings/r/cryptoKeys/k"
                        )
                    },
                }
            ],
        }
    )

    serialized = snapshot.to_dict()
    assert serialized["collected_at"] == "2026-08-22T08:00:00Z"
    assert snapshot.service_accounts[0].display_name == "Worker"
    assert snapshot.service_accounts[0].keys[0].key_type == "USER_MANAGED"
    assert snapshot.buckets[0].uniform_bucket_level_access is True
    assert snapshot.buckets[0].default_kms_key_name.endswith("/cryptoKeys/k")


def test_missing_cmek_means_unspecified_key_not_disabled_encryption():
    snapshot = AuditSnapshot.from_dict(
        {
            "project_id": "encrypted-by-google",
            "buckets": [
                {
                    "name": "google-managed-key-bucket",
                    "iam_policy": {"bindings": []},
                    "iam_configuration": {"uniform_bucket_level_access": {"enabled": True}},
                    "encryption": {"default_kms_key_name": None},
                }
            ],
        }
    )

    bucket = snapshot.buckets[0]
    assert bucket.encryption_enabled is None
    assert bucket.default_kms_key_name is None


def test_unknown_private_key_fields_are_not_serialized():
    secret = "-----BEGIN PRIVATE KEY-----never-serialize-me"
    snapshot = AuditSnapshot.from_dict(
        {
            "project_id": "safe-project",
            "service_accounts": [
                {
                    "email": "worker@safe-project.iam.gserviceaccount.com",
                    "keys": [
                        {
                            "name": "projects/safe-project/serviceAccounts/worker/keys/1",
                            "valid_after_time": "2026-08-01T00:00:00Z",
                            "privateKeyData": secret,
                        }
                    ],
                }
            ],
        }
    )

    assert secret not in json.dumps(snapshot.to_dict())


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"project_id": "p", "service_accounts": "not-an-array"}, "must be an array"),
        ({"project_id": "p", "buckets": [{}]}, "Bucket name"),
        (
            {
                "project_id": "p",
                "iam_policy": {"bindings": [{"role": "", "members": []}]},
            },
            "role must be",
        ),
        ({"project_id": "p", "collected_at": "yesterday"}, "Invalid ISO-8601"),
    ],
)
def test_malformed_snapshots_fail_closed(payload, message):
    with pytest.raises(SnapshotValidationError, match=message):
        AuditSnapshot.from_dict(payload)
