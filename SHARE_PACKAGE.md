# Project Handover: GCP Compliance Auditor

## Purpose

This is a self-contained, read-only Python project for auditing Google Cloud IAM, service-account key age, and Cloud Storage security controls. It can analyze an offline JSON snapshot or collect metadata from one live GCP project through Google Cloud APIs. It never changes cloud resources.

## What is included

- `README.md` — installation, quick starts, output, exit codes, and limitations.
- `docs/ARCHITECTURE.md` — components, data flow, trust boundaries, and design decisions.
- `docs/RULES.md` — rules schema, input schema, exemptions, thresholds, and examples.
- `docs/SECURITY.md` — least-privilege permissions, authentication, and report handling.
- `config/rules.yaml` — editable default compliance policy.
- `config/gcp_auditor_custom_role.yaml` — seven-permission read-only GCP role template.
- `src/` — audit engine, live collector, CLI, framework mappings, and report generators.
- `tests/` — automated unit, integration, CLI, and reporting regression tests.
- `examples/sample_snapshot.json` — safe, synthetic offline input.
- `output/` — sample JSON and PDF reports generated from the synthetic example.
- `dist/` — installable wheel and source distribution for version `0.1.0`.

## Fast evaluation

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
python -m gcp_compliance_auditor scan \
  --snapshot examples/sample_snapshot.json \
  --rules config/rules.yaml \
  --output-dir output
```

The supplied sample is intentionally non-compliant, so the final command exits with code `1`. Exit `1` means the scan completed and found violations; exit `2` means the scan could not complete.

## Live GCP use

Install the live dependencies and configure Application Default Credentials locally:

```bash
python -m pip install -e ".[gcp,dev]"
gcloud auth application-default login
python -m gcp_compliance_auditor scan \
  --project YOUR_PROJECT_ID \
  --rules config/rules.yaml \
  --output-dir output
```

Review `docs/SECURITY.md` and the custom role template before granting access. Do not place credentials, tokens, or private service-account key files inside this project or archive.

## Before production adoption

1. Replace the sample allowlists and thresholds in `config/rules.yaml` with approved organizational policy.
2. Confirm the CIS and NIST control versions required by the organization.
3. Decide whether customer-managed encryption keys are mandatory and define approved key names or prefixes.
4. Run the scanner against a non-production project and review both JSON and PDF output.
5. Store reports as restricted security artifacts because they can contain principal, bucket, project, and key metadata.

## Verification status

Release `0.1.0` passed 60 automated tests, Ruff linting, Python bytecode compilation, clean/non-compliant CLI smoke tests, package builds, JSON validation, and a six-page PDF visual inspection on 2026-08-22.

