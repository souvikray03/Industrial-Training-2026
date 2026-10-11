"""Auditor rule crosswalks to CIS GCP and NIST SP 800-53 controls.

These mappings are an engineering crosswalk for triage and evidence routing;
they do not, by themselves, certify compliance with either framework.
"""

from __future__ import annotations

from collections.abc import Mapping

from .models import FrameworkControl

CIS_GCP = "CIS Google Cloud Platform Foundations Benchmark v3.0"
NIST_800_53 = "NIST SP 800-53 Rev. 5"


FRAMEWORK_MAPPINGS: Mapping[str, tuple[FrameworkControl, ...]] = {
    "IAM_PRIVILEGED_SERVICE_ACCOUNT": (
        FrameworkControl(
            CIS_GCP,
            "1.5",
            "Ensure service accounts do not have administrative privileges",
        ),
        FrameworkControl(NIST_800_53, "AC-6", "Least Privilege"),
        FrameworkControl(NIST_800_53, "AC-6(5)", "Privileged Accounts"),
    ),
    "IAM_STALE_SERVICE_ACCOUNT_KEY": (
        FrameworkControl(
            CIS_GCP,
            "1.7",
            "Rotate user-managed service account keys every 90 days or less",
        ),
        FrameworkControl(NIST_800_53, "IA-5", "Authenticator Management"),
    ),
    "IAM_ROLE_THRESHOLD_EXCEEDED": (
        FrameworkControl(
            CIS_GCP,
            "1 (IAM)",
            "Identity and Access Management least-privilege safeguards",
        ),
        FrameworkControl(NIST_800_53, "AC-2", "Account Management"),
        FrameworkControl(NIST_800_53, "AC-6", "Least Privilege"),
    ),
    "IAM_PERMISSION_THRESHOLD_EXCEEDED": (
        FrameworkControl(
            CIS_GCP,
            "1 (IAM)",
            "Identity and Access Management least-privilege safeguards",
        ),
        FrameworkControl(NIST_800_53, "AC-3", "Access Enforcement"),
        FrameworkControl(NIST_800_53, "AC-6", "Least Privilege"),
    ),
    "STORAGE_PUBLIC_ACCESS": (
        FrameworkControl(
            CIS_GCP,
            "5.1",
            "Ensure Cloud Storage buckets are not anonymously or publicly accessible",
        ),
        FrameworkControl(NIST_800_53, "AC-3", "Access Enforcement"),
        FrameworkControl(NIST_800_53, "AC-5", "Separation of Duties"),
        FrameworkControl(NIST_800_53, "AC-6", "Least Privilege"),
        FrameworkControl(NIST_800_53, "MP-2", "Media Access"),
    ),
    "STORAGE_UNIFORM_ACCESS_DISABLED": (
        FrameworkControl(
            CIS_GCP,
            "5.2",
            "Ensure uniform bucket-level access is enabled",
        ),
        FrameworkControl(NIST_800_53, "AC-3", "Access Enforcement"),
        FrameworkControl(NIST_800_53, "AC-5", "Separation of Duties"),
        FrameworkControl(NIST_800_53, "AC-6", "Least Privilege"),
        FrameworkControl(NIST_800_53, "MP-2", "Media Access"),
    ),
    "STORAGE_ENCRYPTION_DISABLED": (
        FrameworkControl(
            CIS_GCP,
            "5 (Cloud Storage)",
            "Cloud Storage data protection safeguards",
        ),
        FrameworkControl(NIST_800_53, "SC-28", "Protection of Information at Rest"),
        FrameworkControl(
            NIST_800_53,
            "SC-28(1)",
            "Cryptographic Protection of Information at Rest",
        ),
    ),
    "CMEK_NOT_CONFIGURED": (
        FrameworkControl(
            CIS_GCP,
            "5 (Cloud Storage)",
            "Cloud Storage data protection safeguards",
        ),
        FrameworkControl(NIST_800_53, "SC-12", "Cryptographic Key Management"),
        FrameworkControl(NIST_800_53, "SC-28", "Protection of Information at Rest"),
    ),
    "UNAPPROVED_KMS_KEY": (
        FrameworkControl(
            CIS_GCP,
            "1 (IAM) / 5 (Cloud Storage)",
            "KMS authorization and Cloud Storage data protection safeguards",
        ),
        FrameworkControl(NIST_800_53, "SC-12", "Cryptographic Key Management"),
        FrameworkControl(NIST_800_53, "SC-28", "Protection of Information at Rest"),
    ),
}


def frameworks_for(rule_id: str) -> tuple[FrameworkControl, ...]:
    """Return the immutable framework crosswalk for a known auditor rule."""

    try:
        return FRAMEWORK_MAPPINGS[rule_id]
    except KeyError as exc:
        raise KeyError(f"No framework mapping registered for rule {rule_id!r}") from exc


def framework_mappings_to_dict() -> dict[str, list[dict[str, str]]]:
    """Return a JSON-ready copy of every registered rule crosswalk."""

    return {
        rule_id: [control.to_dict() for control in controls]
        for rule_id, controls in sorted(FRAMEWORK_MAPPINGS.items())
    }
