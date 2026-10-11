from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from gcp_compliance_auditor.collectors.gcp import GCPAPIError, GCPCollector


class Request:
    def __init__(self, value: Any = None, error: Exception | None = None) -> None:
        self.value = value
        self.error = error

    def execute(self, num_retries: int = 0) -> Any:
        assert num_retries == 2
        if self.error is not None:
            raise self.error
        return self.value


@dataclass
class Response:
    status: int
    reason: str


class APIException(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__("intentionally opaque")
        self.resp = Response(status, reason)


class ResourceManagerProjects:
    def getIamPolicy(self, **kwargs):  # noqa: N802
        assert kwargs["resource"] == "example-project"
        assert kwargs["body"]["options"]["requestedPolicyVersion"] == 3
        return Request(
            {
                "version": 3,
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["group:auditors@example.com"],
                    }
                ],
            }
        )


class ResourceManager:
    def projects(self):
        return ResourceManagerProjects()


class IAMKeys:
    def list(self, **kwargs):
        assert kwargs["keyTypes"] == ["USER_MANAGED"]
        return Request(
            {
                "keys": [
                    {
                        "name": f"{kwargs['name']}/keys/key-1",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": "2026-01-01T00:00:00Z",
                    }
                ]
            }
        )


class IAMServiceAccounts:
    def list(self, **kwargs):
        assert kwargs["name"] == "projects/example-project"
        return Request(
            {
                "accounts": [
                    {
                        "name": (
                            "projects/example-project/serviceAccounts/"
                            "worker@example-project.iam.gserviceaccount.com"
                        ),
                        "email": "worker@example-project.iam.gserviceaccount.com",
                        "displayName": "Worker",
                    }
                ]
            }
        )

    def keys(self):
        return IAMKeys()


class IAMProjects:
    def serviceAccounts(self):  # noqa: N802
        return IAMServiceAccounts()


class IAMRoles:
    def get(self, **kwargs):
        role = kwargs["name"]
        permissions = {
            "roles/viewer": ["resourcemanager.projects.get"],
            "roles/storage.objectViewer": [
                "storage.objects.get",
                "storage.objects.list",
            ],
        }
        return Request({"name": role, "includedPermissions": permissions[role]})


class IAM:
    def projects(self):
        return IAMProjects()

    def roles(self):
        return IAMRoles()


class StorageBuckets:
    def list(self, **kwargs):
        assert kwargs["projection"] == "noAcl"
        return Request({"items": [{"name": "public-data"}, {"name": "secure-data"}]})

    def get(self, **kwargs):
        name = kwargs["bucket"]
        if name == "public-data":
            return Request(
                {
                    "name": name,
                    "location": "US",
                    "iamConfiguration": {
                        "uniformBucketLevelAccess": {"enabled": False},
                        "publicAccessPrevention": "inherited",
                    },
                }
            )
        return Request(
            {
                "name": name,
                "location": "ASIA-SOUTH1",
                "iamConfiguration": {
                    "uniformBucketLevelAccess": {"enabled": True},
                    "publicAccessPrevention": "enforced",
                },
                "encryption": {
                    "defaultKmsKeyName": (
                        "projects/security/locations/asia-south1/keyRings/storage/cryptoKeys/data"
                    )
                },
            }
        )

    def getIamPolicy(self, **kwargs):  # noqa: N802
        assert kwargs["optionsRequestedPolicyVersion"] == 3
        if kwargs["bucket"] == "public-data":
            return Request(
                {
                    "bindings": [
                        {
                            "role": "roles/storage.objectViewer",
                            "members": ["allUsers"],
                        }
                    ]
                }
            )
        return Request({"bindings": []})


class LegacyACLs:
    def __init__(self, *, default: bool = False) -> None:
        self.default = default

    def list(self, **kwargs):
        assert kwargs["bucket"] == "public-data"
        if self.default:
            return Request({"items": []})
        return Request({"items": [{"entity": "allUsers", "role": "READER"}]})


class Storage:
    def buckets(self):
        return StorageBuckets()

    def bucketAccessControls(self):  # noqa: N802
        return LegacyACLs()

    def defaultObjectAccessControls(self):  # noqa: N802
        return LegacyACLs(default=True)


def test_live_collector_normalizes_all_supported_resources_without_secrets():
    snapshot = GCPCollector(
        "example-project",
        service_clients={
            "cloudresourcemanager": ResourceManager(),
            "iam": IAM(),
            "storage": Storage(),
        },
    ).collect()

    assert snapshot["project_id"] == "example-project"
    assert snapshot["iam_policy"]["bindings"][0]["role"] == "roles/viewer"
    assert snapshot["role_permissions"] == {
        "roles/storage.objectViewer": ["storage.objects.get", "storage.objects.list"],
        "roles/viewer": ["resourcemanager.projects.get"],
    }
    account = snapshot["service_accounts"][0]
    assert account["email"] == "worker@example-project.iam.gserviceaccount.com"
    assert account["keys"][0]["key_type"] == "USER_MANAGED"

    public_bucket, secure_bucket = snapshot["buckets"]
    assert public_bucket["acl"] == [{"entity": "allUsers", "role": "READER"}]
    assert public_bucket["encryption"] == {
        "enabled": True,
        "default_kms_key_name": None,
        "key_management": "google_managed",
    }
    assert secure_bucket["acl"] == []
    assert secure_bucket["iam_configuration"]["public_access_prevention"] == "enforced"
    assert secure_bucket["encryption"]["key_management"] == "customer_managed"


def test_live_collector_turns_api_failures_into_safe_operational_errors():
    class DeniedProjects:
        def getIamPolicy(self, **kwargs):  # noqa: N802
            return Request(error=APIException(403, "Permission denied"))

    class DeniedResourceManager:
        def projects(self):
            return DeniedProjects()

    collector = GCPCollector(
        "example-project",
        service_clients={
            "cloudresourcemanager": DeniedResourceManager(),
            "iam": IAM(),
            "storage": Storage(),
        },
    )

    with pytest.raises(GCPAPIError) as raised:
        collector.collect()

    message = str(raised.value)
    assert "HTTP 403" in message
    assert "Permission denied" in message
    assert "intentionally opaque" not in message


def test_legacy_acl_http_400_is_treated_as_ubla_race():
    collector = GCPCollector(
        "example-project",
        service_clients={
            "cloudresourcemanager": ResourceManager(),
            "iam": IAM(),
            "storage": Storage(),
        },
    )

    entries = collector._legacy_acl(  # noqa: SLF001 - focused race regression test
        Request(error=APIException(400, "Uniform bucket-level access is enabled")),
        "Reading legacy ACL",
    )

    assert entries == []
