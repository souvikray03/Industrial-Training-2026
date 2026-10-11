# Security and Least-Privilege Operation

## Security posture

The scanner is an evidence collector and policy evaluator. It has no remediation path and needs no `setIamPolicy`, object read, key creation, key download, or resource update/delete permission.

Its output can reveal principal email addresses, service-account names, bucket names, project structure, key identifiers, and security gaps. Store reports as restricted security artifacts.

## Preferred custom role

Grant the scanner principal a project-level custom role containing exactly these permissions:

| Permission | Why it is required |
| --- | --- |
| `resourcemanager.projects.getIamPolicy` | Read direct project IAM bindings |
| `iam.serviceAccounts.list` | Enumerate service accounts in the target project |
| `iam.serviceAccountKeys.list` | Read key metadata needed for age/type checks |
| `iam.roles.get` | Expand only assigned roles for permission-count thresholds |
| `storage.buckets.list` | Enumerate buckets and obtain bucket metadata |
| `storage.buckets.get` | Read bucket configuration/ACL metadata where needed |
| `storage.buckets.getIamPolicy` | Read direct bucket IAM bindings |

This list was checked against official Google Cloud permission documentation on 2026-08-22. Google can change predefined roles and API behavior; verify the custom role in your environment before rollout:

```bash
gcloud iam roles describe GcpComplianceAuditor \
  --project YOUR_SECURITY_PROJECT
```

Authoritative references:

- [Resource Manager project IAM permissions](https://cloud.google.com/resource-manager/docs/access-control-proj)
- [IAM roles and permissions](https://cloud.google.com/iam/docs/roles-permissions/iam)
- [Cloud Storage IAM permissions](https://cloud.google.com/storage/docs/access-control/iam-permissions)
- [Cloud Storage `buckets.getIamPolicy`](https://cloud.google.com/storage/docs/json_api/v1/buckets/getIamPolicy)

Some organizations may require the custom role to also contain paired project discovery permissions such as `resourcemanager.projects.get`/`list`. Add them only if a tested API call demonstrably requires them in your deployment.

The project-level grant covers predefined and project-level custom roles. If the target policy assigns an organization-level custom role, grant `iam.roles.get` at that organization or supply an offline `role_permissions` catalog. The live scanner fails closed with exit code `2` when it cannot expand an assigned role; it does not silently report reduced permission-threshold coverage.

## Predefined-role fallback

If custom roles are unavailable, a broader fallback is:

- Browser (`roles/browser`) for project policy visibility;
- Service Account Viewer (`roles/iam.serviceAccountViewer`) for service accounts and key metadata;
- Security Reviewer (`roles/iam.securityReviewer`) for read-only security/IAM visibility including storage policy metadata.

Predefined roles contain permissions beyond this scanner's seven required operations and evolve over time. Confirm effective permissions with IAM Policy Troubleshooter or `gcloud iam roles describe` before granting them. Prefer the custom role.

Do **not** grant Owner, Editor, Storage Admin, Project IAM Admin, Service Account Admin, Service Account Key Admin, or any role containing write, impersonation, signing, token-creation, or private-key creation permissions just to run this scanner.

## Authentication

Recommended order:

1. Workload Identity Federation for CI/CD.
2. Short-lived service-account impersonation.
3. User ADC for local, interactive evaluation.
4. A service-account key only when a legacy system makes the safer options impossible.

The scanner relies on standard ADC. A typical local flow is:

```bash
gcloud auth application-default login
python -m gcp_compliance_auditor scan \
  --project YOUR_PROJECT_ID \
  --rules config/rules.yaml \
  --output-dir output
```

Never paste tokens or private service-account keys into rules, snapshots, issue trackers, chat, or generated reports. `iam.serviceAccountKeys.list` returns public metadata; it does not return private key material.

If a legacy key file is unavoidable:

- store it outside the repository with owner-only filesystem permissions;
- set `GOOGLE_APPLICATION_CREDENTIALS` only in the process environment;
- scope the principal to the custom read-only role;
- rotate and revoke it on a short schedule;
- prevent it from entering CI logs, caches, or artifacts.

## Data minimization and privacy

Offline snapshots and reports may be classified as confidential. They can expose:

- user/group/service-account identifiers;
- bucket and project names;
- role assignments and exceptions;
- service-account key IDs and creation timestamps;
- the location of security weaknesses.

Controls:

- collect metadata only; do not collect object contents or private keys;
- use an access-restricted output directory;
- encrypt artifacts in transit and at rest;
- define a retention period and delete expired reports through your approved process;
- redact or replace principal/resource names before sharing outside the security team;
- do not commit snapshots or generated reports;
- review CI logs and artifact permissions.

## Trust boundaries

### Rules are trusted policy input

A malicious or accidental allowlist entry can hide a real privilege violation. Protect the rule file with mandatory review, branch protection, and CODEOWNERS. Treat threshold reductions and new exemptions like production access changes.

### Snapshots are untrusted data

The parser must reject malformed shapes and must not evaluate code from JSON/YAML. YAML must use a safe loader. Resource and principal text must be escaped before PDF rendering and terminal output.

### Cloud responses can be partial

API pagination, permission errors, disabled services, and transient failures can reduce visibility. These conditions must produce exit code `2`, never a compliant result. A raw IAM policy is explicitly labeled IAM-only.

### Reports are not authorization decisions

Framework mappings help route remediation, but they do not prove certification. Conditional IAM expressions, inherited organization/folder policy, group membership, deny policies, and access-context behavior require additional analysis.

## Cloud Storage encryption semantics

Cloud Storage always encrypts customer content at rest. With no default KMS key, Google-managed encryption keys are used. Therefore:

- missing `default_kms_key_name` is compliant when `require_cmek` is false;
- missing `default_kms_key_name` is `CMEK_NOT_CONFIGURED` when `require_cmek` is true;
- a configured key outside approved names/prefixes is `UNAPPROVED_KMS_KEY`;
- the scanner does not prove KMS key rotation, IAM policy, location compatibility, availability, or destruction state.

Avoid describing a bucket without CMEK as "unencrypted."

## Incident-safe operation

The scanner has no destructive actions. If a critical finding appears:

1. preserve the report and source metadata;
2. validate the finding against live state with an authorized operator;
3. determine whether exposure is active and whether logs require preservation;
4. remediate through an independently authorized workflow;
5. rerun the scanner and retain both before/after evidence.

Do not automatically remove IAM principals, disable keys, or change bucket access solely from this tool's output.
