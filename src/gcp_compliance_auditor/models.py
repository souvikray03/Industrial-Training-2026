"""Typed domain models for offline and live GCP compliance snapshots.

The normalizers in this module intentionally accept both the canonical snapshot
format used by this project and the camelCase fields returned by Google APIs.
They do not perform any network access.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

JSONValue = Any


class SnapshotValidationError(ValueError):
    """Raised when an input snapshot cannot be normalized safely."""


class Severity(str, Enum):
    """Supported policy severities, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"

    @property
    def rank(self) -> int:
        return {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}[self]


def parse_datetime(value: Any, *, field_name: str = "timestamp") -> datetime | None:
    """Parse a datetime or ISO-8601 string and normalize it to UTC."""

    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise SnapshotValidationError(
                f"Invalid ISO-8601 value for {field_name}: {value!r}"
            ) from exc
    else:
        raise SnapshotValidationError(
            f"Expected an ISO-8601 string for {field_name}, got {type(value).__name__}"
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def datetime_to_iso(value: datetime | None) -> str | None:
    """Serialize a datetime in stable RFC 3339 UTC form."""

    if value is None:
        return None
    normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise SnapshotValidationError(f"{field_name} must be an object")
    return value


def _sequence(value: Any, *, field_name: str) -> Sequence[Any]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SnapshotValidationError(f"{field_name} must be an array")
    return value


def _strings(value: Any, *, field_name: str) -> tuple[str, ...]:
    values = _sequence(value, field_name=field_name)
    result: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise SnapshotValidationError(f"{field_name} must contain non-empty strings")
        result.append(item.strip())
    return tuple(result)


def _optional_bool(value: Any, *, field_name: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "enabled", "enforced"}:
            return True
        if normalized in {"false", "no", "0", "disabled", "inherited"}:
            return False
    raise SnapshotValidationError(f"{field_name} must be a boolean")


@dataclass(frozen=True, slots=True)
class IAMBinding:
    role: str
    members: tuple[str, ...]
    condition: Mapping[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IAMBinding:
        role = data.get("role")
        if not isinstance(role, str) or not role.strip():
            raise SnapshotValidationError("IAM binding role must be a non-empty string")
        members = _strings(data.get("members", ()), field_name=f"members for {role}")
        raw_condition = data.get("condition")
        condition = (
            None
            if raw_condition is None
            else dict(_mapping(raw_condition, field_name=f"condition for {role}"))
        )
        return cls(role=role.strip(), members=members, condition=condition)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"role": self.role, "members": list(self.members)}
        if self.condition is not None:
            value["condition"] = dict(self.condition)
        return value


@dataclass(frozen=True, slots=True)
class IAMPolicySnapshot:
    bindings: tuple[IAMBinding, ...] = ()
    version: int | None = None
    etag: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> IAMPolicySnapshot:
        policy = _mapping(data, field_name="iam_policy")
        bindings = tuple(
            IAMBinding.from_dict(_mapping(item, field_name="IAM binding"))
            for item in _sequence(policy.get("bindings", ()), field_name="IAM bindings")
        )
        raw_version = policy.get("version")
        version = int(raw_version) if raw_version is not None else None
        raw_etag = policy.get("etag")
        etag = str(raw_etag) if raw_etag is not None else None
        return cls(bindings=bindings, version=version, etag=etag)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"bindings": [item.to_dict() for item in self.bindings]}
        if self.version is not None:
            value["version"] = self.version
        if self.etag is not None:
            value["etag"] = self.etag
        return value


@dataclass(frozen=True, slots=True)
class ServiceAccountKeySnapshot:
    name: str
    valid_after_time: datetime | None = None
    valid_before_time: datetime | None = None
    key_type: str = "USER_MANAGED"
    key_origin: str | None = None
    disabled: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ServiceAccountKeySnapshot:
        name = data.get("name") or data.get("id") or data.get("key_id") or data.get("keyId")
        if not isinstance(name, str) or not name.strip():
            raise SnapshotValidationError("Service account key name must be a non-empty string")
        valid_after = data.get("valid_after_time", data.get("validAfterTime"))
        if valid_after is None:
            valid_after = data.get("create_time", data.get("createTime"))
        valid_before = data.get("valid_before_time", data.get("validBeforeTime"))
        key_type = data.get("key_type", data.get("keyType", "USER_MANAGED"))
        key_origin = data.get("key_origin", data.get("keyOrigin"))
        disabled = _optional_bool(data.get("disabled", False), field_name="key.disabled")
        return cls(
            name=name.strip(),
            valid_after_time=parse_datetime(valid_after, field_name="key.valid_after_time"),
            valid_before_time=parse_datetime(valid_before, field_name="key.valid_before_time"),
            key_type=str(key_type or "USER_MANAGED").upper(),
            key_origin=str(key_origin) if key_origin is not None else None,
            disabled=bool(disabled),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "key_type": self.key_type,
            "key_origin": self.key_origin,
            "valid_after_time": datetime_to_iso(self.valid_after_time),
            "valid_before_time": datetime_to_iso(self.valid_before_time),
            "disabled": self.disabled,
        }


@dataclass(frozen=True, slots=True)
class ServiceAccountSnapshot:
    email: str
    display_name: str | None = None
    disabled: bool = False
    keys: tuple[ServiceAccountKeySnapshot, ...] = ()
    assigned_roles: tuple[str, ...] = ()

    @property
    def principal(self) -> str:
        return f"serviceAccount:{self.email}"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ServiceAccountSnapshot:
        email = data.get("email") or data.get("service_account_email") or data.get("accountId")
        if not isinstance(email, str) or not email.strip():
            raw_name = data.get("name")
            if isinstance(raw_name, str) and "/serviceAccounts/" in raw_name:
                email = raw_name.rsplit("/serviceAccounts/", 1)[-1]
            else:
                raise SnapshotValidationError("Service account email must be a non-empty string")
        display_name = data.get("display_name", data.get("displayName"))
        disabled = _optional_bool(
            data.get("disabled", False), field_name="service_account.disabled"
        )
        keys = tuple(
            ServiceAccountKeySnapshot.from_dict(_mapping(item, field_name="service account key"))
            for item in _sequence(data.get("keys", ()), field_name="service account keys")
        )
        assigned_roles = data.get("assigned_roles", data.get("roles", ()))
        return cls(
            email=email.strip(),
            display_name=str(display_name) if display_name is not None else None,
            disabled=bool(disabled),
            keys=keys,
            assigned_roles=_strings(assigned_roles, field_name=f"roles for {email}"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "display_name": self.display_name,
            "disabled": self.disabled,
            "assigned_roles": list(self.assigned_roles),
            "keys": [key.to_dict() for key in self.keys],
        }


@dataclass(frozen=True, slots=True)
class ACLGrant:
    entity: str
    role: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ACLGrant:
        entity = data.get("entity") or data.get("member")
        if not isinstance(entity, str) or not entity.strip():
            raise SnapshotValidationError("Bucket ACL entity must be a non-empty string")
        role = data.get("role")
        return cls(entity=entity.strip(), role=str(role) if role is not None else None)

    def to_dict(self) -> dict[str, Any]:
        return {"entity": self.entity, "role": self.role}


@dataclass(frozen=True, slots=True)
class BucketSnapshot:
    name: str
    location: str | None = None
    iam_policy: IAMPolicySnapshot = field(default_factory=IAMPolicySnapshot)
    acl: tuple[ACLGrant, ...] = ()
    default_object_acl: tuple[ACLGrant, ...] = ()
    uniform_bucket_level_access: bool | None = None
    public_access_prevention: str | None = None
    encryption_enabled: bool | None = None
    default_kms_key_name: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BucketSnapshot:
        name = data.get("name") or data.get("id")
        if not isinstance(name, str) or not name.strip():
            raise SnapshotValidationError("Bucket name must be a non-empty string")

        policy_data = data.get("iam_policy", data.get("iamPolicy"))
        if policy_data is None and "iam_bindings" in data:
            policy_data = {"bindings": data.get("iam_bindings")}

        iam_configuration = _mapping(
            data.get("iam_configuration", data.get("iamConfiguration", {})),
            field_name=f"iam_configuration for bucket {name}",
        )
        uniform_config = iam_configuration.get(
            "uniform_bucket_level_access",
            iam_configuration.get("uniformBucketLevelAccess"),
        )
        if isinstance(uniform_config, Mapping):
            uniform_value = uniform_config.get("enabled")
        else:
            uniform_value = uniform_config
        if uniform_value is None:
            uniform_value = data.get(
                "uniform_bucket_level_access", data.get("uniformBucketLevelAccess")
            )

        public_access_prevention = iam_configuration.get(
            "public_access_prevention",
            iam_configuration.get("publicAccessPrevention"),
        )
        if public_access_prevention is None:
            public_access_prevention = data.get(
                "public_access_prevention", data.get("publicAccessPrevention")
            )

        encryption_value = data.get("encryption", {})
        if isinstance(encryption_value, bool):
            encryption = {}
            encryption_enabled_value: Any = encryption_value
        else:
            encryption = _mapping(encryption_value, field_name=f"encryption for bucket {name}")
            encryption_enabled_value = encryption.get("enabled")
        if encryption_enabled_value is None:
            encryption_enabled_value = data.get(
                "encryption_enabled", data.get("defaultEncryptionEnabled")
            )
        kms_name = encryption.get("default_kms_key_name", encryption.get("defaultKmsKeyName"))
        if kms_name is None:
            kms_name = data.get("default_kms_key_name", data.get("defaultKmsKeyName"))

        acl_values = data.get("acl", ())
        default_acl_values = data.get("default_object_acl", data.get("defaultObjectAcl", ()))
        return cls(
            name=name.strip(),
            location=str(data["location"]) if data.get("location") is not None else None,
            iam_policy=IAMPolicySnapshot.from_dict(policy_data),
            acl=tuple(
                ACLGrant.from_dict(_mapping(item, field_name=f"ACL for bucket {name}"))
                for item in _sequence(acl_values, field_name=f"ACL for bucket {name}")
            ),
            default_object_acl=tuple(
                ACLGrant.from_dict(_mapping(item, field_name=f"default ACL for bucket {name}"))
                for item in _sequence(
                    default_acl_values, field_name=f"default ACL for bucket {name}"
                )
            ),
            uniform_bucket_level_access=_optional_bool(
                uniform_value, field_name=f"uniform bucket access for {name}"
            ),
            public_access_prevention=(
                str(public_access_prevention).lower()
                if public_access_prevention is not None
                else None
            ),
            encryption_enabled=_optional_bool(
                encryption_enabled_value, field_name=f"encryption.enabled for {name}"
            ),
            default_kms_key_name=str(kms_name) if kms_name else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "iam_policy": self.iam_policy.to_dict(),
            "acl": [grant.to_dict() for grant in self.acl],
            "default_object_acl": [grant.to_dict() for grant in self.default_object_acl],
            "iam_configuration": {
                "uniform_bucket_level_access": {"enabled": self.uniform_bucket_level_access},
                "public_access_prevention": self.public_access_prevention,
            },
            "encryption": {
                "enabled": self.encryption_enabled,
                "default_kms_key_name": self.default_kms_key_name,
            },
        }


def _normalize_role_permissions(data: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    raw = data.get("role_permissions", data.get("rolePermissions", {}))
    normalized: dict[str, tuple[str, ...]] = {}
    if isinstance(raw, Mapping):
        for role, value in raw.items():
            if isinstance(value, Mapping):
                value = value.get("includedPermissions", value.get("permissions", ()))
            normalized[str(role)] = _strings(value, field_name=f"permissions for {role}")
    elif raw is not None:
        raise SnapshotValidationError("role_permissions must be an object")

    raw_roles = data.get("role_definitions", data.get("roleDefinitions", ()))
    for item in _sequence(raw_roles, field_name="role_definitions"):
        role_data = _mapping(item, field_name="role definition")
        role = role_data.get("name") or role_data.get("role")
        if not role:
            raise SnapshotValidationError("Role definition name must be a non-empty string")
        permissions = role_data.get(
            "included_permissions", role_data.get("includedPermissions", ())
        )
        normalized[str(role)] = _strings(permissions, field_name=f"permissions for {role}")
    return normalized


@dataclass(frozen=True, slots=True)
class AuditSnapshot:
    project_id: str
    iam_policy: IAMPolicySnapshot = field(default_factory=IAMPolicySnapshot)
    service_accounts: tuple[ServiceAccountSnapshot, ...] = ()
    buckets: tuple[BucketSnapshot, ...] = ()
    role_permissions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    collected_at: datetime | None = None
    source: str = "offline"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, source: str = "offline") -> AuditSnapshot:
        if not isinstance(data, Mapping):
            raise SnapshotValidationError("Snapshot root must be an object")
        project_id = data.get("project_id", data.get("projectId"))
        if project_id is None:
            project = data.get("project")
            if isinstance(project, Mapping):
                project_id = project.get("projectId", project.get("project_id", project.get("id")))
        if project_id is None:
            project_id = "unknown-project"
        if not isinstance(project_id, str) or not project_id.strip():
            raise SnapshotValidationError("project_id must be a non-empty string")

        policy_data = data.get("iam_policy", data.get("project_iam_policy"))
        if policy_data is None:
            policy_data = data.get("iamPolicy")
        # A direct `gcloud projects get-iam-policy --format=json` export has
        # bindings at the document root and no snapshot envelope.
        if policy_data is None and "bindings" in data:
            policy_data = data

        service_accounts = tuple(
            ServiceAccountSnapshot.from_dict(_mapping(item, field_name="service account"))
            for item in _sequence(
                data.get("service_accounts", data.get("serviceAccounts", ())),
                field_name="service_accounts",
            )
        )
        buckets = tuple(
            BucketSnapshot.from_dict(_mapping(item, field_name="bucket"))
            for item in _sequence(data.get("buckets", ()), field_name="buckets")
        )
        return cls(
            project_id=project_id.strip(),
            iam_policy=IAMPolicySnapshot.from_dict(policy_data),
            service_accounts=service_accounts,
            buckets=buckets,
            role_permissions=_normalize_role_permissions(data),
            collected_at=parse_datetime(
                data.get("collected_at", data.get("collectedAt")),
                field_name="collected_at",
            ),
            source=str(data.get("source", source)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "collected_at": datetime_to_iso(self.collected_at),
            "source": self.source,
            "iam_policy": self.iam_policy.to_dict(),
            "service_accounts": [account.to_dict() for account in self.service_accounts],
            "buckets": [bucket.to_dict() for bucket in self.buckets],
            "role_permissions": {
                role: list(permissions)
                for role, permissions in sorted(self.role_permissions.items())
            },
        }


@dataclass(frozen=True, slots=True)
class FrameworkControl:
    framework: str
    control_id: str
    title: str

    def to_dict(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "title": self.title,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    rule_id: str
    category: str
    severity: Severity
    title: str
    description: str
    resource_type: str
    resource_name: str
    project_id: str
    principal: str | None
    evidence: Mapping[str, Any]
    recommendation: str
    frameworks: tuple[FrameworkControl, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "project_id": self.project_id,
            "resource": {"type": self.resource_type, "name": self.resource_name},
            "principal": self.principal,
            "evidence": dict(self.evidence),
            "recommendation": self.recommendation,
            "frameworks": [control.to_dict() for control in self.frameworks],
        }


@dataclass(frozen=True, slots=True)
class AuditSummary:
    total_resources_scanned: int
    projects_scanned: int
    iam_bindings_scanned: int
    service_accounts_scanned: int
    service_account_keys_scanned: int
    buckets_scanned: int
    checks_evaluated: int
    violations: int
    severity_counts: Mapping[str, int]
    compliant: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_resources_scanned": self.total_resources_scanned,
            "projects_scanned": self.projects_scanned,
            "iam_bindings_scanned": self.iam_bindings_scanned,
            "service_accounts_scanned": self.service_accounts_scanned,
            "service_account_keys_scanned": self.service_account_keys_scanned,
            "buckets_scanned": self.buckets_scanned,
            "checks_evaluated": self.checks_evaluated,
            "violations": self.violations,
            "severity_counts": dict(self.severity_counts),
            "compliant": self.compliant,
        }


@dataclass(frozen=True, slots=True)
class AuditResult:
    schema_version: str
    project_id: str
    generated_at: datetime
    source: str
    ruleset_name: str
    ruleset_version: str
    summary: AuditSummary
    findings: tuple[Finding, ...]

    @property
    def compliant(self) -> bool:
        return self.summary.compliant

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": datetime_to_iso(self.generated_at),
            "project_id": self.project_id,
            "source": self.source,
            "ruleset": {
                "name": self.ruleset_name,
                "version": self.ruleset_version,
            },
            "summary": self.summary.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
