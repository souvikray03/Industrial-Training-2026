"""Deterministic least-privilege and Cloud Storage compliance evaluation."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .framework import frameworks_for
from .models import (
    AuditResult,
    AuditSnapshot,
    AuditSummary,
    Finding,
    Severity,
    datetime_to_iso,
)
from .rules import AuditRules


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _matches(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _principal_matches(principal: str, patterns: tuple[str, ...]) -> bool:
    if _matches(principal, patterns):
        return True
    if principal.startswith("serviceAccount:"):
        return _matches(principal.split(":", 1)[1], patterns)
    return False


def _service_account_email(principal: str) -> str | None:
    prefix = "serviceAccount:"
    if principal.startswith(prefix) and len(principal) > len(prefix):
        return principal[len(prefix) :]
    return None


def _finding_id(
    rule_id: str,
    project_id: str,
    resource_type: str,
    resource_name: str,
    principal: str | None,
    identity: str,
) -> str:
    canonical = json.dumps(
        [rule_id, project_id, resource_type, resource_name, principal, identity],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16].upper()
    return f"FND-{digest}"


class ComplianceAuditor:
    """Evaluate a normalized snapshot against an immutable rule set."""

    def __init__(self, rules: AuditRules, now: datetime | None = None) -> None:
        self.rules = rules
        self.now = _utc(now or datetime.now(timezone.utc))

    def _finding(
        self,
        *,
        snapshot: AuditSnapshot,
        rule_id: str,
        category: str,
        title: str,
        description: str,
        resource_type: str,
        resource_name: str,
        principal: str | None,
        evidence: Mapping[str, Any],
        recommendation: str,
        identity: str = "",
    ) -> Finding:
        return Finding(
            finding_id=_finding_id(
                rule_id,
                snapshot.project_id,
                resource_type,
                resource_name,
                principal,
                identity,
            ),
            rule_id=rule_id,
            category=category,
            severity=self.rules.severity_for(rule_id),
            title=title,
            description=description,
            resource_type=resource_type,
            resource_name=resource_name,
            project_id=snapshot.project_id,
            principal=principal,
            evidence=dict(evidence),
            recommendation=recommendation,
            frameworks=frameworks_for(rule_id),
        )

    def audit(self, snapshot: AuditSnapshot) -> AuditResult:
        findings: list[Finding] = []
        checks_evaluated = 0

        member_roles: dict[str, set[str]] = defaultdict(set)
        conditional_assignments: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
        for binding in snapshot.iam_policy.bindings:
            for member in binding.members:
                member_roles[member].add(binding.role)
                if binding.condition is not None:
                    conditional_assignments[(member, binding.role)].append(binding.condition)
        for bucket in snapshot.buckets:
            for binding in bucket.iam_policy.bindings:
                for member in binding.members:
                    member_roles[member].add(binding.role)
                    if binding.condition is not None:
                        conditional_assignments[(member, binding.role)].append(binding.condition)
        for account in snapshot.service_accounts:
            member_roles[account.principal].update(account.assigned_roles)

        disallowed_roles = set(self.rules.iam.disallowed_service_account_roles)
        for principal in sorted(member_roles):
            service_account_email = _service_account_email(principal)
            for role in sorted(member_roles[principal]):
                if service_account_email is None or role not in disallowed_roles:
                    continue
                checks_evaluated += 1
                if _principal_matches(
                    principal, self.rules.iam.privileged_service_account_allowlist
                ):
                    continue
                conditions = conditional_assignments.get((principal, role), [])
                findings.append(
                    self._finding(
                        snapshot=snapshot,
                        rule_id="IAM_PRIVILEGED_SERVICE_ACCOUNT",
                        category="IAM",
                        title="Privileged primitive role assigned to service account",
                        description=(
                            f"Service account {service_account_email} has {role}, which "
                            "violates the configured least-privilege policy."
                        ),
                        resource_type="service_account",
                        resource_name=service_account_email,
                        principal=principal,
                        evidence={
                            "role": role,
                            "assigned_role": role,
                            "disallowed_roles": sorted(disallowed_roles),
                            "conditional": bool(conditions),
                            "conditions": [dict(item) for item in conditions],
                        },
                        recommendation=(
                            "Remove the primitive Owner/Editor grant and replace it with "
                            "the smallest predefined or custom role required by the workload."
                        ),
                        identity=role,
                    )
                )

        for principal in sorted(member_roles):
            if _principal_matches(principal, self.rules.iam.threshold_exempt_principals):
                continue
            roles = sorted(member_roles[principal])
            role_limit = self.rules.iam.max_roles_per_member
            if role_limit is not None:
                checks_evaluated += 1
                if len(roles) > role_limit:
                    findings.append(
                        self._finding(
                            snapshot=snapshot,
                            rule_id="IAM_ROLE_THRESHOLD_EXCEEDED",
                            category="IAM",
                            title="IAM role threshold exceeded",
                            description=(
                                f"Principal {principal} has {len(roles)} roles; the configured "
                                f"maximum is {role_limit}."
                            ),
                            resource_type="iam_principal",
                            resource_name=principal,
                            principal=principal,
                            evidence={
                                "roles": roles,
                                "role_count": len(roles),
                                "maximum_roles": role_limit,
                                "maximum_allowed_roles": role_limit,
                            },
                            recommendation=(
                                "Review the principal's duties, remove redundant grants, and "
                                "replace broad combinations with a narrowly scoped custom role."
                            ),
                            identity="role-count",
                        )
                    )

            permission_limit = self.rules.iam.max_permissions_per_member
            resolved_roles = [role for role in roles if role in snapshot.role_permissions]
            if permission_limit is not None and resolved_roles:
                checks_evaluated += 1
                permissions = sorted(
                    {
                        permission
                        for role in resolved_roles
                        for permission in snapshot.role_permissions[role]
                    }
                )
                if len(permissions) > permission_limit:
                    unresolved_roles = sorted(set(roles) - set(resolved_roles))
                    findings.append(
                        self._finding(
                            snapshot=snapshot,
                            rule_id="IAM_PERMISSION_THRESHOLD_EXCEEDED",
                            category="IAM",
                            title="IAM permission threshold exceeded",
                            description=(
                                f"Principal {principal} resolves to at least {len(permissions)} "
                                f"unique permissions; the configured maximum is {permission_limit}."
                            ),
                            resource_type="iam_principal",
                            resource_name=principal,
                            principal=principal,
                            evidence={
                                "permission_count": len(permissions),
                                "maximum_allowed_permissions": permission_limit,
                                "resolved_roles": resolved_roles,
                                "unresolved_roles": unresolved_roles,
                                "count_is_lower_bound": bool(unresolved_roles),
                            },
                            recommendation=(
                                "Reduce the principal's effective permission set and resolve any "
                                "unexpanded roles before approving an exception."
                            ),
                            identity="permission-count",
                        )
                    )

        role_permission_limit = self.rules.iam.max_permissions_per_role
        if role_permission_limit is not None:
            for role in sorted(snapshot.role_permissions):
                checks_evaluated += 1
                permissions = set(snapshot.role_permissions[role])
                if len(permissions) <= role_permission_limit:
                    continue
                findings.append(
                    self._finding(
                        snapshot=snapshot,
                        rule_id="IAM_PERMISSION_THRESHOLD_EXCEEDED",
                        category="IAM",
                        title="IAM role permission threshold exceeded",
                        description=(
                            f"Role {role} contains {len(permissions)} unique permissions; the "
                            f"configured per-role maximum is {role_permission_limit}."
                        ),
                        resource_type="iam_role",
                        resource_name=role,
                        principal=None,
                        evidence={
                            "permission_count": len(permissions),
                            "maximum_allowed_permissions_per_role": role_permission_limit,
                        },
                        recommendation=(
                            "Split the role by job function or replace it with narrower predefined "
                            "or custom roles."
                        ),
                        identity="role-permission-count",
                    )
                )

        for account in sorted(snapshot.service_accounts, key=lambda item: item.email):
            for key in sorted(account.keys, key=lambda item: item.name):
                if self.rules.iam.user_managed_keys_only and key.key_type.upper() != "USER_MANAGED":
                    continue
                if key.disabled and not self.rules.iam.include_disabled_keys:
                    continue
                if key.valid_after_time is None:
                    continue
                checks_evaluated += 1
                age_seconds = max(0, int((self.now - _utc(key.valid_after_time)).total_seconds()))
                maximum_seconds = self.rules.iam.key_max_age_days * 86_400
                if age_seconds <= maximum_seconds:
                    continue
                age_days = round(age_seconds / 86_400, 2)
                findings.append(
                    self._finding(
                        snapshot=snapshot,
                        rule_id="IAM_STALE_SERVICE_ACCOUNT_KEY",
                        category="IAM",
                        title="Service account key exceeds rotation age",
                        description=(
                            f"Key {key.name} is {age_days} days old; the configured maximum is "
                            f"{self.rules.iam.key_max_age_days} days."
                        ),
                        resource_type="service_account_key",
                        resource_name=key.name,
                        principal=account.principal,
                        evidence={
                            "service_account": account.email,
                            "key_type": key.key_type,
                            "key_origin": key.key_origin,
                            "disabled": key.disabled,
                            "valid_after_time": datetime_to_iso(key.valid_after_time),
                            "valid_before_time": datetime_to_iso(key.valid_before_time),
                            "evaluated_at": datetime_to_iso(self.now),
                            "age_days": age_days,
                            "maximum_age_days": self.rules.iam.key_max_age_days,
                        },
                        recommendation=(
                            "Replace and delete the old user-managed key. Prefer attached service "
                            "accounts or Workload Identity Federation to avoid long-lived keys."
                        ),
                        identity=key.name,
                    )
                )

        public_principals = set(self.rules.storage.public_principals)
        for bucket in sorted(snapshot.buckets, key=lambda item: item.name):
            public_evidence: list[dict[str, str | None]] = []
            for binding in bucket.iam_policy.bindings:
                for member in binding.members:
                    if member in public_principals:
                        public_evidence.append(
                            {"source": "iam_policy", "principal": member, "role": binding.role}
                        )
            for grant in bucket.acl:
                if grant.entity in public_principals:
                    public_evidence.append(
                        {"source": "bucket_acl", "principal": grant.entity, "role": grant.role}
                    )
            for grant in bucket.default_object_acl:
                if grant.entity in public_principals:
                    public_evidence.append(
                        {
                            "source": "default_object_acl",
                            "principal": grant.entity,
                            "role": grant.role,
                        }
                    )

            checks_evaluated += 1
            if public_evidence and not _matches(
                bucket.name, self.rules.storage.exempt_public_buckets
            ):
                public_evidence.sort(
                    key=lambda item: (
                        str(item["principal"]),
                        str(item["source"]),
                        str(item["role"]),
                    )
                )
                exposed_principals = sorted({str(item["principal"]) for item in public_evidence})
                findings.append(
                    self._finding(
                        snapshot=snapshot,
                        rule_id="STORAGE_PUBLIC_ACCESS",
                        category="STORAGE",
                        title="Publicly accessible Cloud Storage bucket",
                        description=(
                            f"Bucket {bucket.name} grants access to public principal(s): "
                            f"{', '.join(exposed_principals)}."
                        ),
                        resource_type="storage_bucket",
                        resource_name=bucket.name,
                        principal=", ".join(exposed_principals),
                        evidence={
                            "public_grants": public_evidence,
                            "public_access_prevention": bucket.public_access_prevention,
                        },
                        recommendation=(
                            "Remove public principals from IAM and ACLs, enable Public Access "
                            "Prevention, and grant access only to named principals."
                        ),
                        identity=",".join(exposed_principals),
                    )
                )

            if self.rules.storage.require_uniform_bucket_level_access:
                checks_evaluated += 1
                if bucket.uniform_bucket_level_access is False and not _matches(
                    bucket.name,
                    self.rules.storage.exempt_uniform_access_buckets,
                ):
                    findings.append(
                        self._finding(
                            snapshot=snapshot,
                            rule_id="STORAGE_UNIFORM_ACCESS_DISABLED",
                            category="STORAGE",
                            title="Uniform bucket-level access is disabled",
                            description=(
                                f"Bucket {bucket.name} permits legacy object/bucket ACL behavior "
                                "because uniform bucket-level access is disabled."
                            ),
                            resource_type="storage_bucket",
                            resource_name=bucket.name,
                            principal=None,
                            evidence={
                                "uniform_bucket_level_access": False,
                                "public_access_prevention": bucket.public_access_prevention,
                            },
                            recommendation=(
                                "Migrate required ACL grants to bucket IAM and enable uniform "
                                "bucket-level access."
                            ),
                            identity="uniform-access",
                        )
                    )

            encryption_exempt = _matches(bucket.name, self.rules.storage.exempt_encryption_buckets)
            if self.rules.storage.require_default_encryption and not encryption_exempt:
                checks_evaluated += 1
                # A missing flag is intentionally not considered disabled: GCS
                # encrypts all data at rest by default. Only an explicit false
                # assertion in a normalized external snapshot triggers this rule.
                if bucket.encryption_enabled is False:
                    findings.append(
                        self._finding(
                            snapshot=snapshot,
                            rule_id="STORAGE_ENCRYPTION_DISABLED",
                            category="STORAGE",
                            title="Snapshot reports storage encryption as disabled",
                            description=(
                                f"The supplied snapshot explicitly marks encryption disabled for "
                                f"bucket {bucket.name}."
                            ),
                            resource_type="storage_bucket",
                            resource_name=bucket.name,
                            principal=None,
                            evidence={
                                "encryption_enabled": False,
                                "default_kms_key_name": bucket.default_kms_key_name,
                            },
                            recommendation=(
                                "Verify the source data, restore encryption-at-rest controls, and "
                                "consider a customer-managed Cloud KMS key if policy requires it."
                            ),
                            identity="encryption-disabled",
                        )
                    )

            if self.rules.storage.require_cmek and not encryption_exempt:
                checks_evaluated += 1
                if not bucket.default_kms_key_name:
                    findings.append(
                        self._finding(
                            snapshot=snapshot,
                            rule_id="CMEK_NOT_CONFIGURED",
                            category="STORAGE",
                            title="Customer-managed encryption key not configured",
                            description=(
                                f"Bucket {bucket.name} uses Google-managed encryption rather than "
                                "the customer-managed key required by policy."
                            ),
                            resource_type="storage_bucket",
                            resource_name=bucket.name,
                            principal=None,
                            evidence={
                                "default_kms_key_name": None,
                                "require_cmek": True,
                                "gcs_default_encryption_still_applies": True,
                            },
                            recommendation=(
                                "Configure an approved Cloud KMS key as the bucket's default KMS "
                                "key, and grant the Storage service agent only the required key "
                                "role."
                            ),
                            identity="cmek-required",
                        )
                    )

            kms_key = bucket.default_kms_key_name
            approved_keys = self.rules.storage.approved_kms_keys
            approved_prefixes = self.rules.storage.approved_kms_key_prefixes
            if kms_key and not encryption_exempt and (approved_keys or approved_prefixes):
                checks_evaluated += 1
                approved = kms_key in approved_keys or any(
                    kms_key.startswith(prefix) for prefix in approved_prefixes
                )
                if not approved:
                    findings.append(
                        self._finding(
                            snapshot=snapshot,
                            rule_id="UNAPPROVED_KMS_KEY",
                            category="STORAGE",
                            title="Bucket uses an unapproved Cloud KMS key",
                            description=(
                                f"Bucket {bucket.name} is configured with KMS key {kms_key}, which "
                                "does not match the approved key policy."
                            ),
                            resource_type="storage_bucket",
                            resource_name=bucket.name,
                            principal=None,
                            evidence={
                                "default_kms_key_name": kms_key,
                                "approved_kms_keys": list(approved_keys),
                                "approved_kms_key_prefixes": list(approved_prefixes),
                        },
                        recommendation=(
                            "Use an approved Cloud KMS key, or document and approve a narrowly "
                            "scoped exception."
                            ),
                            identity=kms_key,
                        )
                    )

        findings.sort(
            key=lambda item: (
                item.severity.rank,
                item.rule_id,
                item.resource_type,
                item.resource_name,
                item.principal or "",
                item.finding_id,
            )
        )
        severity_counts = {
            severity.value: sum(1 for item in findings if item.severity is severity)
            for severity in Severity
        }
        key_count = sum(len(account.keys) for account in snapshot.service_accounts)
        iam_binding_count = len(snapshot.iam_policy.bindings) + sum(
            len(bucket.iam_policy.bindings) for bucket in snapshot.buckets
        )
        total_resources = 1 + len(snapshot.service_accounts) + key_count + len(snapshot.buckets)
        summary = AuditSummary(
            total_resources_scanned=total_resources,
            projects_scanned=1,
            iam_bindings_scanned=iam_binding_count,
            service_accounts_scanned=len(snapshot.service_accounts),
            service_account_keys_scanned=key_count,
            buckets_scanned=len(snapshot.buckets),
            checks_evaluated=checks_evaluated,
            violations=len(findings),
            severity_counts=severity_counts,
            compliant=not findings,
        )
        return AuditResult(
            schema_version="1.0",
            project_id=snapshot.project_id,
            generated_at=self.now,
            source=snapshot.source,
            ruleset_name=self.rules.name,
            ruleset_version=self.rules.version,
            summary=summary,
            findings=tuple(findings),
        )


def audit_snapshot(
    snapshot: AuditSnapshot | Mapping[str, Any],
    rules: AuditRules,
    now: datetime | None = None,
) -> AuditResult:
    """Normalize (if needed) and audit a GCP snapshot."""

    normalized = (
        snapshot
        if isinstance(snapshot, AuditSnapshot)
        else AuditSnapshot.from_dict(snapshot, source="offline")
    )
    return ComplianceAuditor(rules, now=now).audit(normalized)
