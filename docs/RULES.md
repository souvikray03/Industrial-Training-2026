# Rules, Inputs, and Report Schema

## Rule document

Rules may be JSON or YAML. The canonical structure is:

```yaml
ruleset:
  name: GCP Least-Privilege Baseline
  version: 1.0.0

iam:
  disallowed_service_account_roles:
    - roles/owner
    - roles/editor
  privileged_service_account_allowlist: []
  threshold_exempt_principals: []
  key_max_age_days: 90
  user_managed_keys_only: true
  include_disabled_keys: false
  max_roles_per_member: 10
  max_permissions_per_member: 500
  max_permissions_per_role: 1000

storage:
  public_principals:
    - allUsers
    - allAuthenticatedUsers
  exempt_public_buckets: []
  exempt_uniform_access_buckets: []
  exempt_encryption_buckets: []
  require_uniform_bucket_level_access: true
  require_default_encryption: true
  require_cmek: false
  approved_kms_keys: []
  approved_kms_key_prefixes: []

severity_overrides: {}
```

`load_rules(path)` uses Python's JSON parser for `.json` and `yaml.safe_load` for YAML. Invalid types, non-positive key ages, negative thresholds, unknown rule IDs, and unsupported severities are rejected.

## IAM settings

### `disallowed_service_account_roles`

Roles a standard service account must not receive. The default includes the basic Owner and Editor roles. The check applies to members with the `serviceAccount:` prefix; a human user assigned Owner is outside this specific rule, although it may still be undesirable under your broader IAM program.

Finding: `IAM_PRIVILEGED_SERVICE_ACCOUNT`.

### `privileged_service_account_allowlist`

Explicit exceptions to the rule above. Values may be a bare service-account email or a full `serviceAccount:` principal. Shell-style `fnmatch` patterns are supported.

```yaml
privileged_service_account_allowlist:
  - serviceAccount:breakglass@example-prod.iam.gserviceaccount.com
  - serviceAccount:approved-migration-*@example-prod.iam.gserviceaccount.com
```

An entry suppresses only `IAM_PRIVILEGED_SERVICE_ACCOUNT`. It does not suppress stale-key or threshold findings. Avoid broad patterns such as `serviceAccount:*`.

### `threshold_exempt_principals`

Exact principals or `fnmatch` patterns excluded from the role and permission-count thresholds. These exemptions do not suppress privileged-role or stale-key findings.

### `key_max_age_days`

Maximum age for an included service-account key. A key is stale only when its age is strictly greater than the configured number of days; a key exactly 90 days old is within a 90-day limit.

Finding: `IAM_STALE_SERVICE_ACCOUNT_KEY`.

The key timestamp is `valid_after_time`, with `create_time` accepted as an input alias. Missing creation time cannot prove key age and should be treated as a coverage gap in upstream collection.

### `user_managed_keys_only`

When true, age checks apply only to `USER_MANAGED` keys. Google-managed keys are rotated by Google and should not be placed on the customer rotation schedule.

### `include_disabled_keys`

When false, disabled keys are excluded from key-age findings. Enable this if your policy requires deletion of stale disabled key material as well as deactivation.

### Role and permission thresholds

- `max_roles_per_member`: maximum distinct assigned roles per principal.
- `max_permissions_per_member`: maximum distinct permissions accumulated across known assigned roles.
- `max_permissions_per_role`: maximum permissions allowed in a single known role.

Set a threshold to `null` to disable it. A value of `0` permits no assignments/known permissions.

Findings:

- `IAM_ROLE_THRESHOLD_EXCEEDED`
- `IAM_PERMISSION_THRESHOLD_EXCEEDED`

Permission checks require a `role_permissions` catalog in the snapshot. The live collector populates this catalog by reading definitions for assigned roles with `iam.roles.get`. The auditor counts the union of known permission names so a permission present in two roles is counted once for the member total. Missing role definitions in offline evidence cannot be guessed and reduce threshold coverage.

## Storage settings

### `public_principals`

Principals considered public when found in direct bucket IAM, bucket ACL, or default-object ACL data. Keep both GCP convenience values unless your policy deliberately differs:

- `allUsers`: anyone on the internet;
- `allAuthenticatedUsers`: any authenticated Google account, including accounts outside your organization.

Finding: `STORAGE_PUBLIC_ACCESS`.

### Bucket exemptions

The following lists accept exact bucket names or `fnmatch` patterns:

- `exempt_public_buckets`
- `exempt_uniform_access_buckets`
- `exempt_encryption_buckets`

Exemptions are risk acceptances. They should be narrow, time-bounded in the surrounding governance process, and independently reviewed. An encryption exemption applies to encryption/CMEK/KMS-key findings; it does not make public access compliant.

### `require_uniform_bucket_level_access`

When true, a bucket with UBLA explicitly disabled produces `STORAGE_UNIFORM_ACCESS_DISABLED`. UBLA consolidates access in IAM and disables legacy ACL-based authorization after its lock-in behavior takes effect.

### `require_default_encryption`

This compatibility control reports `STORAGE_ENCRYPTION_DISABLED` only if an offline snapshot explicitly states `encryption.enabled: false`. A live Cloud Storage bucket does not normally produce that state: Cloud Storage encrypts data at rest with Google-managed encryption by default.

Do not use this flag as a synonym for CMEK.

### `require_cmek`

When true, a bucket without `default_kms_key_name` produces `CMEK_NOT_CONFIGURED`. When false, the same bucket is treated as using Google-managed encryption and does not produce an encryption finding.

### Approved KMS keys

When a bucket has a default KMS key and either allowlist below is non-empty, the key must match at least one entry:

- `approved_kms_keys`: full Cloud KMS key resource names;
- `approved_kms_key_prefixes`: approved project/location/key-ring prefixes.

Finding: `UNAPPROVED_KMS_KEY`.

Example:

```yaml
approved_kms_keys:
  - projects/security/locations/asia-south1/keyRings/storage/cryptoKeys/prod-data
approved_kms_key_prefixes:
  - projects/security/locations/asia-south1/keyRings/approved-storage/cryptoKeys/
```

An empty key list and empty prefix list impose no KMS allowlist. The check validates the resource name only; it does not validate the key's state, rotation schedule, IAM policy, location compatibility, or cryptographic version.

## Severity overrides

Default severities are:

| Rule ID | Default |
| --- | --- |
| `IAM_PRIVILEGED_SERVICE_ACCOUNT` | CRITICAL |
| `IAM_STALE_SERVICE_ACCOUNT_KEY` | MEDIUM |
| `IAM_ROLE_THRESHOLD_EXCEEDED` | MEDIUM |
| `IAM_PERMISSION_THRESHOLD_EXCEEDED` | HIGH |
| `STORAGE_PUBLIC_ACCESS` | CRITICAL |
| `STORAGE_UNIFORM_ACCESS_DISABLED` | HIGH |
| `STORAGE_ENCRYPTION_DISABLED` | HIGH |
| `CMEK_NOT_CONFIGURED` | HIGH |
| `UNAPPROVED_KMS_KEY` | HIGH |

Override only an exact known rule ID:

```yaml
severity_overrides:
  IAM_STALE_SERVICE_ACCOUNT_KEY: HIGH
```

Allowed values are `CRITICAL`, `HIGH`, and `MEDIUM`.

## Framework mappings

Each finding contains one or more framework references selected by rule ID. The baseline maps controls to concepts such as least privilege, authenticator management, access enforcement, public access, and protection of data at rest.

Framework references are traceability aids, not a claim of certification. Confirm benchmark versions and applicability with your assessor. In particular, CIS section numbers can change between GCP Foundation Benchmark releases; record the version in your compliance evidence.

Typical mappings include:

| Finding concept | Framework references |
| --- | --- |
| Privileged service account / excessive permissions | NIST SP 800-53 AC-6 (Least Privilege); CIS GCP Foundation IAM controls |
| Stale user-managed key | NIST SP 800-53 IA-5 (Authenticator Management); CIS GCP service-account key controls |
| Public bucket | NIST SP 800-53 AC-3/AC-6; CIS GCP Cloud Storage public-access controls |
| UBLA disabled | NIST SP 800-53 AC-3; CIS GCP uniform bucket-level access controls |
| CMEK/KMS policy | NIST SP 800-53 SC-12/SC-28; CIS GCP data-at-rest controls |

## Full snapshot input

Canonical top-level fields:

```json
{
  "project_id": "example-project",
  "collected_at": "2026-08-22T08:00:00Z",
  "iam_policy": {"bindings": []},
  "service_accounts": [],
  "buckets": [],
  "role_permissions": {}
}
```

### Project IAM

```json
{
  "iam_policy": {
    "version": 3,
    "bindings": [
      {
        "role": "roles/viewer",
        "members": ["group:auditors@example.com"],
        "condition": {
          "title": "Temporary access",
          "expression": "request.time < timestamp('2026-12-01T00:00:00Z')"
        }
      }
    ]
  }
}
```

Conditions are retained as evidence but are not executed or formally proven.

### Service accounts and keys

```json
{
  "service_accounts": [
    {
      "email": "worker@example-project.iam.gserviceaccount.com",
      "display_name": "Worker",
      "disabled": false,
      "keys": [
        {
          "name": "projects/example-project/serviceAccounts/worker@example-project.iam.gserviceaccount.com/keys/KEY_ID",
          "key_type": "USER_MANAGED",
          "valid_after_time": "2026-06-01T00:00:00Z",
          "valid_before_time": "9999-12-31T23:59:59Z",
          "disabled": false
        }
      ]
    }
  ]
}
```

Key names/IDs are metadata. Never put a private key or credential payload in a snapshot.

### Buckets

```json
{
  "buckets": [
    {
      "name": "private-data",
      "location": "ASIA-SOUTH1",
      "iam_policy": {"bindings": []},
      "acl": [],
      "default_object_acl": [],
      "iam_configuration": {
        "uniform_bucket_level_access": {"enabled": true},
        "public_access_prevention": "enforced"
      },
      "encryption": {
        "default_kms_key_name": "projects/security/locations/asia-south1/keyRings/storage/cryptoKeys/data"
      }
    }
  ]
}
```

Relevant GCP camelCase fields such as `iamConfiguration`, `uniformBucketLevelAccess`, `publicAccessPrevention`, `defaultKmsKeyName`, `validAfterTime`, and `keyType` are accepted.

### Permission catalog

Optional role definitions make permission thresholds evaluable:

```json
{
  "role_permissions": {
    "roles/custom.applicationReader": [
      "storage.objects.get",
      "storage.objects.list"
    ]
  }
}
```

The live collector fetches only role definitions referenced by the scanned project and bucket policies. Offline snapshots should include this catalog when permission thresholds must be evaluated.

## Raw IAM input

A direct `gcloud projects get-iam-policy PROJECT_ID --format=json` object, or an array of binding objects, is accepted. It is normalized to an IAM-only snapshot. Service-account key and bucket totals will be zero.

## Report JSON schema

The stable top-level structure is:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-08-22T08:00:00Z",
  "project_id": "example-project",
  "source": "offline",
  "ruleset": {"name": "...", "version": "..."},
  "summary": {
    "total_resources_scanned": 4,
    "projects_scanned": 1,
    "iam_bindings_scanned": 2,
    "service_accounts_scanned": 1,
    "service_account_keys_scanned": 1,
    "buckets_scanned": 1,
    "checks_evaluated": 12,
    "violations": 1,
    "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0},
    "compliant": false
  },
  "findings": []
}
```

Each finding contains:

```json
{
  "finding_id": "stable identifier",
  "rule_id": "STORAGE_PUBLIC_ACCESS",
  "category": "STORAGE",
  "severity": "CRITICAL",
  "title": "Publicly accessible Cloud Storage bucket",
  "description": "...",
  "project_id": "example-project",
  "resource": {"type": "storage_bucket", "name": "bucket-name"},
  "principal": "allUsers",
  "evidence": {},
  "recommendation": "...",
  "frameworks": [
    {"framework": "NIST SP 800-53", "control_id": "AC-3", "title": "Access Enforcement"}
  ]
}
```

Consumers should branch on `schema_version`, `rule_id`, `severity`, and `finding_id`, not on human-readable titles or descriptions.
