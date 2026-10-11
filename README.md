# GCP Compliance Auditor

A read-only command-line auditor for GCP project IAM, service-account keys, and Cloud Storage security posture. It supports deterministic offline scans from JSON and live scans through Google Cloud APIs, then writes a machine-readable JSON report and a human-readable PDF.

The scanner reports evidence; it never changes IAM policies, disables keys, or modifies buckets.

## What it checks

| Area | Check | Default severity |
| --- | --- | --- |
| IAM | `roles/owner` or `roles/editor` assigned to a non-allowlisted service account | CRITICAL |
| IAM | User-managed service-account key older than the configured maximum age | MEDIUM |
| IAM | Identity exceeds configured role or estimated-permission thresholds | HIGH |
| Storage | `allUsers` or `allAuthenticatedUsers` appears in bucket IAM/ACL data | CRITICAL |
| Storage | Uniform bucket-level access (UBLA) is disabled | HIGH |
| Storage | CMEK is required by local policy but no default KMS key is configured | HIGH |
| Storage | Configured default KMS key is outside the approved key list/prefixes | HIGH |

Cloud Storage encrypts data at rest by default with Google-managed encryption keys. A missing `defaultKmsKeyName` does **not** mean that a bucket is unencrypted. It is only a finding when your rules require customer-managed encryption keys (CMEK).

## Project layout

```text
gcp-compliance-auditor/
├── config/rules.yaml             Default policy
├── docs/                         Architecture, rules, and security guidance
├── examples/sample_snapshot.json Example offline input
├── src/gcp_compliance_auditor/   Scanner, collectors, reports, and CLI
├── tests/                        Unit and CLI regression tests
└── output/                       Generated reports (ignored by Git)
```

## Installation

Requirements: Python 3.10 or newer. Create an isolated environment from this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For live GCP collection, install the optional Google API dependencies:

```bash
python -m pip install -e ".[gcp,dev]"
```

## Quick start: offline mode

Offline mode does not require GCP credentials or network access:

```bash
python -m gcp_compliance_auditor scan \
  --snapshot examples/sample_snapshot.json \
  --rules config/rules.yaml \
  --output-dir output
```

The example intentionally contains violations, so a successful audit returns exit code `1`. This is useful for seeing the report format.

The accepted full snapshot shape is documented in [Rules and input schema](docs/RULES.md). A raw exported project IAM policy is also accepted:

```json
{
  "version": 1,
  "bindings": [
    {
      "role": "roles/viewer",
      "members": ["group:auditors@example.com"]
    }
  ]
}
```

An IAM-only export cannot evaluate service-account key or bucket checks. The summary and source metadata make that reduced coverage visible; absence of those findings must not be interpreted as proof that those resources are compliant.

## Quick start: live mode

Live mode uses Application Default Credentials (ADC). For local development:

```bash
gcloud auth application-default login
python -m gcp_compliance_auditor scan \
  --project YOUR_PROJECT_ID \
  --rules config/rules.yaml \
  --output-dir output
```

For CI, prefer Workload Identity Federation or a short-lived impersonated service account. If your environment already sets `GOOGLE_APPLICATION_CREDENTIALS`, the standard Google authentication library will honor it. Never commit credential JSON files.

Enable these APIs in the target project before a live scan:

- Cloud Resource Manager API (`cloudresourcemanager.googleapis.com`)
- Identity and Access Management API (`iam.googleapis.com`)
- Cloud Storage JSON API (`storage.googleapis.com`)

The preferred scanner identity is a custom read-only role containing only:

```text
resourcemanager.projects.getIamPolicy
iam.serviceAccounts.list
iam.serviceAccountKeys.list
iam.roles.get
storage.buckets.list
storage.buckets.get
storage.buckets.getIamPolicy
```

The same permission list is provided as an importable role definition in
`config/gcp_auditor_custom_role.yaml`. Review it before creating the role; the
scanner itself never creates or grants IAM roles.

If the project policy assigns organization-level custom roles, the scanner
identity also needs `iam.roles.get` at that organization (or you can use an
offline snapshot with a `role_permissions` catalog). Missing role-definition
access is treated as an incomplete scan and exits with code `2`.

See [Security and least privilege](docs/SECURITY.md) before granting access.

## Output and exit codes

Every completed scan prints project/source information, resource totals, counts by severity, and report paths. It writes:

- `OUTPUT_DIR/compliance_report.json` — stable, automation-friendly evidence
- `OUTPUT_DIR/report.pdf` — formatted review artifact

Exit codes are designed for CI:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and no violations were found |
| `1` | Scan completed and one or more violations were found |
| `2` | Invalid input/rules, authentication/API failure, or report-generation failure |

Example gate:

```bash
python -m gcp_compliance_auditor scan \
  --snapshot snapshot.json \
  --rules config/rules.yaml \
  --output-dir build/compliance
status=$?

if [ "$status" -eq 2 ]; then
  echo "Auditor failed to run; results are incomplete"
  exit 2
fi

exit "$status"
```

Do not convert exit code `2` to success: an incomplete scan is not a clean scan.

## Customize policy

Copy the default file and review every organization-specific value:

```bash
cp config/rules.yaml my-rules.yaml
```

At minimum, decide:

- which human or group principals are approved administrators;
- whether any service accounts are explicitly approved for privileged roles;
- the maximum age for user-managed keys;
- maximum roles/estimated permissions per identity;
- whether all buckets must use CMEK;
- approved Cloud KMS key resource names or prefixes;
- framework references used by your compliance program.

Rules are explained in [Rules and input schema](docs/RULES.md). An allowlist is an explicit risk acceptance, not a security control by itself. Keep it narrow, reviewed, and version-controlled.

## Test

```bash
pytest
```

The suite covers privileged service accounts, admin allowlists, stale user-managed keys, public buckets, UBLA, CMEK policy, KMS allowlists, thresholds, clean inputs, deterministic serialization, and CLI exit behavior.

## CI example

```yaml
- name: Install GCP compliance auditor
  run: python -m pip install -e ".[gcp]"

- name: Audit exported snapshot
  run: |
    python -m gcp_compliance_auditor scan \
      --snapshot artifacts/gcp-snapshot.json \
      --rules config/rules.yaml \
      --output-dir artifacts/compliance

- name: Upload compliance evidence
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: gcp-compliance-report
    path: artifacts/compliance/
```

Pin dependencies and protect rule changes with code review in production. Treat the JSON and PDF outputs as potentially sensitive security metadata.

## What you need to provide

Nothing sensitive is needed to run the included offline example. To audit your environment, provide locally—not in chat or source control—the following:

1. **Target:** a GCP project ID, or a sanitized IAM/full snapshot JSON file.
2. **Authentication for live mode:** ADC with the seven read-only permissions listed above. Prefer federation or impersonation; do not share private key material.
3. **Policy decisions:** approved admin principals, service-account exceptions, key-age and access thresholds, CMEK requirement, and approved KMS keys/prefixes.
4. **Governance context:** framework version(s) your organization uses and the team that owns remediation/risk acceptance.

If you provide only a raw IAM policy, the project can still audit IAM bindings, but key-age and bucket controls remain out of scope for that run.

## Scope and limitations

- This project currently scans one GCP project per invocation.
- Organization/folder inherited bindings, deny policies, IAM recommender data, workload identity pools, VPC Service Controls, object-level ACLs, and KMS key policy/rotation are outside the present scope unless they are represented in the supplied snapshot.
- Live bucket IAM retrieval returns the bucket policy; inherited project-level grants are evaluated from the project IAM policy, not duplicated in each bucket result.
- Conditional IAM bindings are reported from the supplied policy, but the scanner does not execute CEL conditions or prove whether a condition is currently reachable.
- Framework mappings are cross-references for triage, not a certification or substitute for an assessor.
- Offline permission thresholds have reduced coverage unless the snapshot includes a maintained role-to-permission catalog; live scans resolve assigned roles through the IAM API.

See [Architecture](docs/ARCHITECTURE.md), [Security](docs/SECURITY.md), and [Rules](docs/RULES.md) for the full operating model.
