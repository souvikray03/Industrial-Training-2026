"""Configuration loading and validation for compliance rules."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Severity


class RuleValidationError(ValueError):
    """Raised when a rule file is malformed or internally inconsistent."""


_MISSING = object()


DEFAULT_SEVERITIES: Mapping[str, Severity] = {
    "IAM_PRIVILEGED_SERVICE_ACCOUNT": Severity.CRITICAL,
    "IAM_STALE_SERVICE_ACCOUNT_KEY": Severity.MEDIUM,
    "IAM_ROLE_THRESHOLD_EXCEEDED": Severity.MEDIUM,
    "IAM_PERMISSION_THRESHOLD_EXCEEDED": Severity.HIGH,
    "STORAGE_PUBLIC_ACCESS": Severity.CRITICAL,
    "STORAGE_UNIFORM_ACCESS_DISABLED": Severity.HIGH,
    "STORAGE_ENCRYPTION_DISABLED": Severity.HIGH,
    "CMEK_NOT_CONFIGURED": Severity.HIGH,
    "UNAPPROVED_KMS_KEY": Severity.HIGH,
}


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise RuleValidationError(f"{name} must be an object")
    return value


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise RuleValidationError(f"{name} must be an array of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise RuleValidationError(f"{name} must contain non-empty strings")
        result.append(item.strip())
    return tuple(result)


def _boolean(value: Any, name: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise RuleValidationError(f"{name} must be true or false")


def _positive_int(value: Any, name: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuleValidationError(f"{name} must be a positive integer")
    return value


def _optional_limit(value: Any, name: str, default: int | None) -> int | None:
    if value is _MISSING:
        return default
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuleValidationError(f"{name} must be null or a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class IAMRules:
    disallowed_service_account_roles: tuple[str, ...] = (
        "roles/owner",
        "roles/editor",
    )
    privileged_service_account_allowlist: tuple[str, ...] = ()
    threshold_exempt_principals: tuple[str, ...] = ()
    key_max_age_days: int = 90
    user_managed_keys_only: bool = True
    include_disabled_keys: bool = False
    max_roles_per_member: int | None = 10
    max_permissions_per_member: int | None = 500
    max_permissions_per_role: int | None = 1000

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IAMRules:
        defaults = cls()
        disallowed = data.get(
            "disallowed_service_account_roles",
            data.get("disallowed_roles", defaults.disallowed_service_account_roles),
        )
        allowlist = data.get(
            "privileged_service_account_allowlist",
            data.get("admin_service_accounts", defaults.privileged_service_account_allowlist),
        )
        return cls(
            disallowed_service_account_roles=_string_tuple(
                disallowed, "iam.disallowed_service_account_roles"
            ),
            privileged_service_account_allowlist=_string_tuple(
                allowlist, "iam.privileged_service_account_allowlist"
            ),
            threshold_exempt_principals=_string_tuple(
                data.get("threshold_exempt_principals", defaults.threshold_exempt_principals),
                "iam.threshold_exempt_principals",
            ),
            key_max_age_days=_positive_int(
                data.get("key_max_age_days"),
                "iam.key_max_age_days",
                defaults.key_max_age_days,
            ),
            user_managed_keys_only=_boolean(
                data.get("user_managed_keys_only"),
                "iam.user_managed_keys_only",
                defaults.user_managed_keys_only,
            ),
            include_disabled_keys=_boolean(
                data.get("include_disabled_keys"),
                "iam.include_disabled_keys",
                defaults.include_disabled_keys,
            ),
            max_roles_per_member=_optional_limit(
                data.get(
                    "max_roles_per_member",
                    data.get("maximum_allowed_roles", _MISSING),
                ),
                "iam.max_roles_per_member",
                defaults.max_roles_per_member,
            ),
            max_permissions_per_member=_optional_limit(
                data.get(
                    "max_permissions_per_member",
                    data.get("maximum_allowed_permissions", _MISSING),
                ),
                "iam.max_permissions_per_member",
                defaults.max_permissions_per_member,
            ),
            max_permissions_per_role=_optional_limit(
                data.get("max_permissions_per_role", _MISSING),
                "iam.max_permissions_per_role",
                defaults.max_permissions_per_role,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "disallowed_service_account_roles": list(self.disallowed_service_account_roles),
            "privileged_service_account_allowlist": list(self.privileged_service_account_allowlist),
            "threshold_exempt_principals": list(self.threshold_exempt_principals),
            "key_max_age_days": self.key_max_age_days,
            "user_managed_keys_only": self.user_managed_keys_only,
            "include_disabled_keys": self.include_disabled_keys,
            "max_roles_per_member": self.max_roles_per_member,
            "max_permissions_per_member": self.max_permissions_per_member,
            "max_permissions_per_role": self.max_permissions_per_role,
        }


@dataclass(frozen=True, slots=True)
class StorageRules:
    public_principals: tuple[str, ...] = ("allUsers", "allAuthenticatedUsers")
    exempt_public_buckets: tuple[str, ...] = ()
    exempt_uniform_access_buckets: tuple[str, ...] = ()
    exempt_encryption_buckets: tuple[str, ...] = ()
    require_uniform_bucket_level_access: bool = True
    require_default_encryption: bool = True
    require_cmek: bool = False
    approved_kms_keys: tuple[str, ...] = ()
    approved_kms_key_prefixes: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StorageRules:
        defaults = cls()
        return cls(
            public_principals=_string_tuple(
                data.get("public_principals", defaults.public_principals),
                "storage.public_principals",
            ),
            exempt_public_buckets=_string_tuple(
                data.get("exempt_public_buckets", defaults.exempt_public_buckets),
                "storage.exempt_public_buckets",
            ),
            exempt_uniform_access_buckets=_string_tuple(
                data.get(
                    "exempt_uniform_access_buckets",
                    defaults.exempt_uniform_access_buckets,
                ),
                "storage.exempt_uniform_access_buckets",
            ),
            exempt_encryption_buckets=_string_tuple(
                data.get("exempt_encryption_buckets", defaults.exempt_encryption_buckets),
                "storage.exempt_encryption_buckets",
            ),
            require_uniform_bucket_level_access=_boolean(
                data.get("require_uniform_bucket_level_access"),
                "storage.require_uniform_bucket_level_access",
                defaults.require_uniform_bucket_level_access,
            ),
            require_default_encryption=_boolean(
                data.get(
                    "require_default_encryption",
                    data.get("mandatory_bucket_encryption"),
                ),
                "storage.require_default_encryption",
                defaults.require_default_encryption,
            ),
            require_cmek=_boolean(
                data.get("require_cmek"), "storage.require_cmek", defaults.require_cmek
            ),
            approved_kms_keys=_string_tuple(
                data.get("approved_kms_keys", defaults.approved_kms_keys),
                "storage.approved_kms_keys",
            ),
            approved_kms_key_prefixes=_string_tuple(
                data.get("approved_kms_key_prefixes", defaults.approved_kms_key_prefixes),
                "storage.approved_kms_key_prefixes",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_principals": list(self.public_principals),
            "exempt_public_buckets": list(self.exempt_public_buckets),
            "exempt_uniform_access_buckets": list(self.exempt_uniform_access_buckets),
            "exempt_encryption_buckets": list(self.exempt_encryption_buckets),
            "require_uniform_bucket_level_access": self.require_uniform_bucket_level_access,
            "require_default_encryption": self.require_default_encryption,
            "require_cmek": self.require_cmek,
            "approved_kms_keys": list(self.approved_kms_keys),
            "approved_kms_key_prefixes": list(self.approved_kms_key_prefixes),
        }


@dataclass(frozen=True, slots=True)
class AuditRules:
    name: str = "GCP Least-Privilege Baseline"
    version: str = "1.0.0"
    iam: IAMRules = field(default_factory=IAMRules)
    storage: StorageRules = field(default_factory=StorageRules)
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditRules:
        defaults = cls()
        root = _mapping(data, "rules")
        ruleset = _mapping(root.get("ruleset", root.get("metadata", {})), "ruleset")
        name = ruleset.get("name", root.get("name", defaults.name))
        version = ruleset.get("version", root.get("version", defaults.version))
        if not isinstance(name, str) or not name.strip():
            raise RuleValidationError("ruleset.name must be a non-empty string")
        if not isinstance(version, (str, int, float)):
            raise RuleValidationError("ruleset.version must be a string or number")

        iam_data = dict(_mapping(root.get("iam", {}), "iam"))
        storage_data = dict(_mapping(root.get("storage", {}), "storage"))
        # Accept a few obvious flat aliases without weakening validation of the
        # canonical nested schema.
        for key in (
            "disallowed_roles",
            "key_max_age_days",
            "maximum_allowed_roles",
            "maximum_allowed_permissions",
        ):
            if key in root and key not in iam_data:
                iam_data[key] = root[key]
        for key in ("mandatory_bucket_encryption", "require_cmek"):
            if key in root and key not in storage_data:
                storage_data[key] = root[key]

        raw_severities = _mapping(
            root.get("severity_overrides", root.get("severities", {})),
            "severity_overrides",
        )
        severities: dict[str, Severity] = {}
        for rule_id, raw_severity in raw_severities.items():
            normalized_rule_id = str(rule_id).strip().upper()
            if normalized_rule_id not in DEFAULT_SEVERITIES:
                raise RuleValidationError(f"Unknown rule ID in severity_overrides: {rule_id!r}")
            try:
                severities[normalized_rule_id] = Severity(str(raw_severity).upper())
            except ValueError as exc:
                allowed = ", ".join(item.value for item in Severity)
                raise RuleValidationError(
                    f"Severity for {rule_id} must be one of: {allowed}"
                ) from exc

        return cls(
            name=name.strip(),
            version=str(version),
            iam=IAMRules.from_dict(iam_data),
            storage=StorageRules.from_dict(storage_data),
            severity_overrides=severities,
        )

    def severity_for(self, rule_id: str) -> Severity:
        try:
            return self.severity_overrides.get(rule_id, DEFAULT_SEVERITIES[rule_id])
        except KeyError as exc:
            raise RuleValidationError(f"Unknown rule ID: {rule_id}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "ruleset": {"name": self.name, "version": self.version},
            "iam": self.iam.to_dict(),
            "storage": self.storage.to_dict(),
            "severity_overrides": {
                rule_id: severity.value
                for rule_id, severity in sorted(self.severity_overrides.items())
            },
        }


def load_rules(path: str | Path | None = None) -> AuditRules:
    """Load and validate a JSON or YAML rules document.

    Passing ``None`` returns the built-in safe baseline. JSON is parsed with the
    standard library; YAML support is provided by the project's PyYAML runtime
    dependency.
    """

    if path is None:
        return AuditRules()
    rule_path = Path(path)
    try:
        text = rule_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleValidationError(f"Unable to read rule file {rule_path}: {exc}") from exc

    try:
        if rule_path.suffix.lower() == ".json":
            raw = json.loads(text)
        else:
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - packaging guard
                raise RuleValidationError("PyYAML is required to read YAML rule files") from exc
            raw = yaml.safe_load(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuleValidationError(f"Invalid rule file {rule_path}: {exc}") from exc

    if raw is None:
        raise RuleValidationError(f"Rule file {rule_path} is empty")
    if not isinstance(raw, Mapping):
        raise RuleValidationError("Rule file root must be an object")
    return AuditRules.from_dict(raw)
