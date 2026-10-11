# Architecture and Work Process

## Design goals

The auditor is intentionally read-only, deterministic, and usable without cloud access. Collection is separated from evaluation so the same policy engine can audit a live project, a captured snapshot, or a test fixture.

```text
rules.yaml ───────────────┐
                          v
GCP APIs -> live collector -> normalized AuditSnapshot -> audit engine
JSON file -> parser ──────┘                           |
                                                     v
                                        AuditResult + AuditSummary
                                              |             |
                                              v             v
                                      compliance_report.json report.pdf
                                              |
                                              v
                                        console + exit code
```

## Components

### CLI

`python -m gcp_compliance_auditor scan` validates the mutually exclusive input modes, loads rules, obtains an `AuditSnapshot`, runs the engine, writes both reports, prints the summary, and returns a CI-safe exit code.

The CLI owns orchestration only. It does not embed compliance decisions.

### Input normalization

`AuditSnapshot.from_dict(...)` converts external JSON into one canonical model. The parser accepts the project's documented snake_case form and the relevant camelCase names returned by Google APIs.

Supported sources:

- **Full offline snapshot:** project IAM, service accounts/keys, and bucket metadata/policies.
- **Raw IAM policy:** a top-level `bindings` object; coverage is IAM-only.
- **Live collector:** read-only calls to Resource Manager, IAM, and Storage APIs.

The source is recorded so consumers can distinguish a full live scan from partial offline evidence.

### Live collectors

Collectors request only metadata required by implemented checks:

1. Resource Manager `projects.getIamPolicy` obtains project role bindings.
2. IAM `projects.serviceAccounts.list` enumerates service accounts.
3. IAM `projects.serviceAccounts.keys.list` obtains key metadata; no private key material is returned.
4. IAM `roles.get` expands only assigned roles for permission-count thresholds.
5. Storage `buckets.list` obtains bucket metadata, including UBLA, public access prevention, and default KMS key configuration.
6. Storage `buckets.getIamPolicy` obtains direct bucket principals.
7. When ACL data is available for a bucket with UBLA disabled, it is normalized for the public-access check.

Pagination is exhausted before evaluation. An authentication/API failure is an operational error, not a clean result.

### Rules loader

`load_rules(path)` accepts JSON or YAML, validates types and ranges, normalizes principal and role values, and returns immutable audit policy. Invalid or unknown critical configuration is rejected rather than silently ignored.

### Audit engine

`audit_snapshot(snapshot, rules, now)` is a pure policy evaluation entry point. Supplying `now` makes key-age tests and replayed evidence deterministic.

Checks use explicit rule IDs. Each finding includes a stable finding ID derived from its rule and affected resource/principal, severity, evidence, remediation guidance, and framework references. Findings are sorted for reproducible JSON and PDF generation.

The engine does not call Google APIs and does not mutate the snapshot or rules.

### Reports

One `AuditResult` feeds both renderers:

- JSON preserves the complete structured result for automation and long-term evidence.
- PDF presents the same findings and summary for human review.

Report generation must not recalculate compliance. This prevents the JSON and PDF from disagreeing.

## Processing lifecycle

1. Parse CLI arguments.
2. Load and validate local rules.
3. Read the snapshot or acquire ADC and collect live metadata.
4. Normalize values and timestamps into `AuditSnapshot`.
5. Evaluate every enabled control.
6. Sort findings and compute summary counts.
7. Atomically write JSON and PDF to the selected output directory.
8. Print a terminal summary.
9. Exit `0` for compliant, `1` for findings, or `2` for operational failure.

## Data model

The central relationships are:

```text
AuditSnapshot
├── project IAM bindings -> role + principals + optional condition
├── service accounts
│   └── user-managed/system-managed key metadata
└── buckets
    ├── bucket IAM bindings
    ├── bucket/default object ACL entries when available
    ├── IAM configuration (UBLA and public access prevention)
    └── default KMS key name

AuditResult
├── immutable ordered findings
└── summary
    ├── resources/checks scanned
    ├── violations
    ├── counts by severity
    └── compliant boolean
```

## Finding identity and determinism

Finding IDs must remain stable for equivalent evidence. They should not contain generation timestamps or list positions. This lets a CI system compare runs, suppress an accepted finding by exact ID outside the scanner, and identify newly introduced risks.

Determinism requires:

- canonical principal, role, and resource strings;
- explicit UTC timestamps;
- sorted findings and framework identifiers;
- stable dictionary keys in serialization;
- a caller-supplied `now` in time-sensitive tests;
- no network calls in offline mode.

## Error boundaries

| Boundary | Expected behavior |
| --- | --- |
| Missing/malformed snapshot | Explain the invalid path or field; exit `2`; no clean report |
| Invalid rules | Explain the validation issue; exit `2` |
| Missing live dependency | Explain how to install the `gcp` extra; exit `2` |
| ADC/authentication failure | Explain the authentication class without exposing tokens; exit `2` |
| API permission/transport failure | Identify the service/operation; exit `2`; never label the scan compliant |
| Report write/render failure | Exit `2` and preserve no misleading partial success |
| Findings present | Reports are valid; exit `1` |

## Extension points

New collectors should normalize into existing models instead of adding cloud SDK objects to the engine. New checks should define one rule ID, severity, evidence contract, remediation text, and framework mapping, then add positive, negative, boundary, and serialization tests.

Likely future additions include organization/folder traversal, IAM deny policies, inherited bucket access resolution, Cloud KMS key rotation/policy checks, network controls, and SARIF output.
