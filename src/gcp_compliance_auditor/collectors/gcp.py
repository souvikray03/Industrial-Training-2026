"""Read-only collection of GCP IAM, service-account, and Storage metadata.

Google libraries are imported lazily so offline snapshot scans do not require the
``gcp`` optional dependency.  The collector deliberately exposes no mutation
methods. IAM's service-account key listing endpoint requires the ``cloud-platform``
OAuth scope; least privilege is enforced by granting the scanner only the documented
read permissions on the supplied principal.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

CLOUD_API_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)


class GCPCollectorError(RuntimeError):
    """Base class for safe, user-facing live collection failures."""


class GCPDependencyError(GCPCollectorError):
    """Raised when the optional Google client libraries are unavailable."""


class GCPAuthenticationError(GCPCollectorError):
    """Raised when Application Default Credentials cannot be loaded."""


class GCPAPIError(GCPCollectorError):
    """Raised when a required read-only Google API operation fails."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _status_code(error: BaseException) -> int | None:
    response = getattr(error, "resp", None)
    status = getattr(response, "status", None)
    if status is None:
        status = getattr(error, "status_code", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _safe_error_reason(error: BaseException) -> str:
    """Return a concise error reason without serializing credentials or headers."""

    response = getattr(error, "resp", None)
    reason = getattr(error, "reason", None) or getattr(response, "reason", None)
    if reason:
        cleaned = " ".join(str(reason).split())
        # Reasons originate with Google and should be short, but cap them so an
        # unexpected response cannot dump a large or sensitive value to stdout.
        return cleaned[:240]
    return error.__class__.__name__


def _normalise_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "role": str(binding.get("role", "")),
        "members": [str(member) for member in binding.get("members", [])],
    }
    condition = binding.get("condition")
    if isinstance(condition, Mapping):
        result["condition"] = {
            key: condition[key]
            for key in ("title", "description", "expression", "location")
            if key in condition
        }
    return result


def _normalise_policy(policy: Mapping[str, Any] | None) -> dict[str, Any]:
    policy = policy or {}
    result: dict[str, Any] = {
        "version": int(policy.get("version", 1) or 1),
        "bindings": [
            _normalise_binding(binding)
            for binding in policy.get("bindings", [])
            if isinstance(binding, Mapping)
        ],
    }
    return result


def _normalise_acl(entries: Any) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        return []
    controls: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        control = {key: entry[key] for key in ("entity", "role") if entry.get(key) is not None}
        project_team = entry.get("projectTeam")
        if isinstance(project_team, Mapping):
            control["project_team"] = {
                key: project_team[key] for key in ("projectNumber", "team") if key in project_team
            }
        if control:
            controls.append(control)
    return controls


class GCPCollector:
    """Collect the minimum GCP metadata needed by the compliance engine.

    Args:
        project_id: GCP project ID or project number to scan.
        credentials: Optional google-auth credentials.  When omitted, ADC is
            loaded (including ``GOOGLE_APPLICATION_CREDENTIALS`` when set).
        service_builder: Optional discovery ``build`` compatible callable,
            primarily useful for deterministic tests.
        service_clients: Optional prebuilt clients keyed by
            ``cloudresourcemanager``, ``iam``, and ``storage``.
        max_retries: Number of retry attempts delegated to google-api-python-client.
    """

    def __init__(
        self,
        project_id: str,
        *,
        credentials: Any | None = None,
        service_builder: Callable[..., Any] | None = None,
        service_clients: Mapping[str, Any] | None = None,
        max_retries: int = 2,
    ) -> None:
        project_id = str(project_id).strip()
        if not project_id or any(character.isspace() for character in project_id):
            raise ValueError("project_id must be a non-empty GCP project ID or number")
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")

        self.project_id = project_id
        self._credentials = credentials
        self._service_builder = service_builder
        self._service_clients = dict(service_clients or {})
        self._max_retries = max_retries

    def collect(self) -> dict[str, Any]:
        """Return an audit snapshot mapping without changing any cloud resource."""

        resource_manager, iam, storage = self._get_clients()
        project_policy = self._project_iam_policy(resource_manager)
        service_accounts = self._service_accounts(iam)
        buckets = self._buckets(storage)
        role_names = {
            str(binding.get("role"))
            for policy in [project_policy, *(bucket["iam_policy"] for bucket in buckets)]
            for binding in policy.get("bindings", [])
            if binding.get("role")
        }
        return {
            "project_id": self.project_id,
            "collected_at": _utc_now(),
            "iam_policy": project_policy,
            "service_accounts": service_accounts,
            "buckets": buckets,
            "role_permissions": self._role_permissions(iam, role_names),
        }

    def _get_clients(self) -> tuple[Any, Any, Any]:
        required = ("cloudresourcemanager", "iam", "storage")
        if all(name in self._service_clients for name in required):
            clients = tuple(self._service_clients[name] for name in required)
            return clients  # type: ignore[return-value]

        credentials = self._credentials
        builder = self._service_builder
        if credentials is None or builder is None:
            try:
                import google.auth  # type: ignore[import-not-found]
                from googleapiclient.discovery import build  # type: ignore[import-not-found]
            except ImportError as error:
                raise GCPDependencyError(
                    "Live scans require the optional Google dependencies. "
                    "Install the project with: pip install -e '.[gcp]'"
                ) from error

            if credentials is None:
                try:
                    credentials, _ = google.auth.default(scopes=CLOUD_API_SCOPES)
                except Exception as error:  # google-auth has several credential errors
                    raise GCPAuthenticationError(
                        "Application Default Credentials were not available. Run "
                        "'gcloud auth application-default login' or set "
                        "GOOGLE_APPLICATION_CREDENTIALS to an authorized credential file."
                    ) from error
            if builder is None:
                builder = build

        versions = {
            "cloudresourcemanager": "v1",
            "iam": "v1",
            "storage": "v1",
        }
        for api_name, version in versions.items():
            if api_name in self._service_clients:
                continue
            try:
                self._service_clients[api_name] = builder(
                    api_name,
                    version,
                    credentials=credentials,
                    cache_discovery=False,
                )
            except Exception as error:
                raise GCPAPIError(
                    f"Could not initialize the {api_name} API client: {_safe_error_reason(error)}."
                ) from error

        return tuple(self._service_clients[name] for name in required)  # type: ignore[return-value]

    def _execute(self, request: Any, operation: str) -> Mapping[str, Any]:
        try:
            response = request.execute(num_retries=self._max_retries)
        except Exception as error:
            status = _status_code(error)
            status_text = f" (HTTP {status})" if status is not None else ""
            raise GCPAPIError(
                f"{operation} failed{status_text}: {_safe_error_reason(error)}. "
                "Verify that the API is enabled and the scanning principal has "
                "the required read-only permission."
            ) from error
        if response is None:
            return {}
        if not isinstance(response, Mapping):
            raise GCPAPIError(f"{operation} returned an invalid API response")
        return response

    def _project_iam_policy(self, resource_manager: Any) -> dict[str, Any]:
        request = resource_manager.projects().getIamPolicy(
            resource=self.project_id,
            body={"options": {"requestedPolicyVersion": 3}},
        )
        response = self._execute(request, "Reading the project IAM policy")
        return _normalise_policy(response)

    def _service_accounts(self, iam: Any) -> list[dict[str, Any]]:
        accounts: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            parameters: dict[str, Any] = {
                "name": f"projects/{self.project_id}",
                "pageSize": 100,
            }
            if token:
                parameters["pageToken"] = token
            response = self._execute(
                iam.projects().serviceAccounts().list(**parameters),
                "Listing service accounts",
            )
            for raw_account in response.get("accounts", []):
                if not isinstance(raw_account, Mapping):
                    continue
                account_name = str(raw_account.get("name", ""))
                email = str(raw_account.get("email", ""))
                if not account_name and email:
                    account_name = f"projects/{self.project_id}/serviceAccounts/{email}"
                if not email:
                    raise GCPAPIError("A service account response did not contain an email address")
                account: dict[str, Any] = {
                    "email": email,
                    "display_name": str(raw_account.get("displayName", "")),
                    "disabled": bool(raw_account.get("disabled", False)),
                    "keys": self._service_account_keys(iam, account_name),
                }
                accounts.append(account)

            token = str(response.get("nextPageToken", "") or "") or None
            if not token:
                break
            if token in seen_tokens:
                raise GCPAPIError("Listing service accounts returned a repeated page token")
            seen_tokens.add(token)
        return accounts

    def _service_account_keys(self, iam: Any, account_name: str) -> list[dict[str, Any]]:
        if not account_name:
            raise GCPAPIError("A service account response did not contain a resource name")
        response = self._execute(
            iam.projects()
            .serviceAccounts()
            .keys()
            .list(name=account_name, keyTypes=["USER_MANAGED"]),
            f"Listing user-managed keys for {account_name}",
        )
        keys: list[dict[str, Any]] = []
        for raw_key in response.get("keys", []):
            if not isinstance(raw_key, Mapping):
                continue
            key_name = str(raw_key.get("name", ""))
            if not key_name:
                raise GCPAPIError(
                    f"A key response for {account_name} did not contain a resource name"
                )
            key = {
                "name": key_name,
                "key_type": str(raw_key.get("keyType", "USER_MANAGED")),
                "key_origin": str(raw_key.get("keyOrigin", "")),
                "valid_after_time": raw_key.get("validAfterTime"),
                "valid_before_time": raw_key.get("validBeforeTime"),
                "disabled": bool(raw_key.get("disabled", False)),
            }
            keys.append(key)
        return keys

    def _role_permissions(self, iam: Any, role_names: set[str]) -> dict[str, list[str]]:
        """Resolve assigned role definitions for permission-threshold checks."""

        definitions: dict[str, list[str]] = {}
        for role_name in sorted(role_names):
            if role_name.startswith("projects/") and "/roles/" in role_name:
                request = iam.projects().roles().get(name=role_name)
            elif role_name.startswith("organizations/") and "/roles/" in role_name:
                request = iam.organizations().roles().get(name=role_name)
            else:
                request = iam.roles().get(name=role_name)
            response = self._execute(
                request,
                f"Reading IAM role definition {role_name}",
            )
            permissions = response.get("includedPermissions", [])
            if not isinstance(permissions, list):
                raise GCPAPIError(f"IAM role definition {role_name} returned invalid permissions")
            definitions[role_name] = sorted(
                {str(permission) for permission in permissions if permission}
            )
        return definitions

    def _buckets(self, storage: Any) -> list[dict[str, Any]]:
        buckets: list[dict[str, Any]] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            parameters: dict[str, Any] = {
                "project": self.project_id,
                "projection": "noAcl",
                "maxResults": 1000,
            }
            if token:
                parameters["pageToken"] = token
            response = self._execute(
                storage.buckets().list(**parameters),
                "Listing Cloud Storage buckets",
            )
            for listed_bucket in response.get("items", []):
                if not isinstance(listed_bucket, Mapping):
                    continue
                bucket_name = str(listed_bucket.get("name", ""))
                if not bucket_name:
                    continue
                buckets.append(self._bucket(storage, bucket_name))

            token = str(response.get("nextPageToken", "") or "") or None
            if not token:
                break
            if token in seen_tokens:
                raise GCPAPIError("Listing Cloud Storage buckets returned a repeated page token")
            seen_tokens.add(token)
        return buckets

    def _bucket(self, storage: Any, bucket_name: str) -> dict[str, Any]:
        metadata = self._execute(
            storage.buckets().get(bucket=bucket_name, projection="noAcl"),
            f"Reading configuration for bucket {bucket_name}",
        )
        policy = self._execute(
            storage.buckets().getIamPolicy(
                bucket=bucket_name,
                optionsRequestedPolicyVersion=3,
            ),
            f"Reading IAM policy for bucket {bucket_name}",
        )

        raw_iam_configuration = metadata.get("iamConfiguration", {})
        if not isinstance(raw_iam_configuration, Mapping):
            raw_iam_configuration = {}
        raw_ubla = raw_iam_configuration.get("uniformBucketLevelAccess", {})
        if not isinstance(raw_ubla, Mapping):
            raw_ubla = {}
        ubla_enabled = bool(raw_ubla.get("enabled", False))

        acl: list[dict[str, Any]] = []
        default_object_acl: list[dict[str, Any]] = []
        if not ubla_enabled:
            acl = self._legacy_acl(
                storage.bucketAccessControls().list(bucket=bucket_name),
                f"Reading legacy bucket ACLs for {bucket_name}",
            )
            default_object_acl = self._legacy_acl(
                storage.defaultObjectAccessControls().list(bucket=bucket_name),
                f"Reading default object ACLs for {bucket_name}",
            )

        raw_encryption = metadata.get("encryption", {})
        if not isinstance(raw_encryption, Mapping):
            raw_encryption = {}
        kms_key = raw_encryption.get("defaultKmsKeyName")

        return {
            "name": bucket_name,
            "location": str(metadata.get("location", "")),
            "iam_policy": _normalise_policy(policy),
            "acl": acl,
            "default_object_acl": default_object_acl,
            "iam_configuration": {
                "uniform_bucket_level_access": {
                    "enabled": ubla_enabled,
                    "locked_time": raw_ubla.get("lockedTime"),
                },
                "public_access_prevention": str(
                    raw_iam_configuration.get("publicAccessPrevention", "inherited")
                ),
            },
            # Cloud Storage always encrypts data at rest.  An absent CMEK means
            # Google-managed encryption, not unencrypted storage.
            "encryption": {
                "enabled": True,
                "default_kms_key_name": str(kms_key) if kms_key else None,
                "key_management": "customer_managed" if kms_key else "google_managed",
            },
        }

    def _legacy_acl(self, request: Any, operation: str) -> list[dict[str, Any]]:
        """Read a legacy ACL, treating an UBLA-related HTTP 400 as no legacy ACL."""

        try:
            response = request.execute(num_retries=self._max_retries)
        except Exception as error:
            # A bucket can become UBLA-enabled between the metadata and ACL calls.
            # Google then returns 400 because legacy ACLs no longer apply.
            safe_reason = _safe_error_reason(error)
            reason = safe_reason.lower()
            is_ubla_rejection = (
                "uniform bucket" in reason or "uniformbucket" in reason or "ubla" in reason
            ) and ("acl" in reason or "access" in reason)
            if _status_code(error) == 400 and is_ubla_rejection:
                return []
            status = _status_code(error)
            status_text = f" (HTTP {status})" if status is not None else ""
            raise GCPAPIError(
                f"{operation} failed{status_text}: {safe_reason}. "
                "Verify storage.buckets.get access for the scanning principal."
            ) from error
        if not isinstance(response, Mapping):
            raise GCPAPIError(f"{operation} returned an invalid API response")
        return _normalise_acl(response.get("items", []))


def collect_gcp_snapshot(
    project_id: str,
    *,
    credentials: Any | None = None,
    service_builder: Callable[..., Any] | None = None,
    service_clients: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Convenience wrapper around :class:`GCPCollector`."""

    return GCPCollector(
        project_id,
        credentials=credentials,
        service_builder=service_builder,
        service_clients=service_clients,
    ).collect()
