from __future__ import annotations

import json

import pytest

from gcp_compliance_auditor.cli import (
    EXIT_COMPLIANT,
    EXIT_OPERATIONAL_ERROR,
    EXIT_VIOLATIONS,
    _normalise_snapshot_payload,
    _safe_operational_message,
    main,
)


def _scan_args(snapshot, rules, output_dir):
    return [
        "scan",
        "--snapshot",
        str(snapshot),
        "--rules",
        str(rules),
        "--output-dir",
        str(output_dir),
    ]


def test_cli_clean_snapshot_returns_zero_and_prints_dashboard(
    tmp_path, fixture_dir, test_rules_path, capsys
):
    output = tmp_path / "clean-output"
    status = main(_scan_args(fixture_dir / "clean_snapshot.json", test_rules_path, output))

    captured = capsys.readouterr()
    assert status == EXIT_COMPLIANT
    assert "GCP COMPLIANCE AUDIT" in captured.out
    assert "Violations found: 0" in captured.out
    assert "Status: COMPLIANT" in captured.out
    assert (output / "compliance_report.json").is_file()
    assert (output / "report.pdf").is_file()


def test_cli_findings_return_one_and_report_severity_counts(
    tmp_path, fixture_dir, test_rules_path, capsys
):
    output = tmp_path / "violations-output"
    status = main(_scan_args(fixture_dir / "violations_snapshot.json", test_rules_path, output))

    captured = capsys.readouterr()
    assert status == EXIT_VIOLATIONS
    assert "Violations found:" in captured.out
    assert "CRITICAL:" in captured.out
    assert "HIGH:" in captured.out
    assert "MEDIUM:" in captured.out
    assert "Status: NON-COMPLIANT" in captured.out
    report = json.loads((output / "compliance_report.json").read_text(encoding="utf-8"))
    assert report["summary"]["violations"] > 0


def test_cli_malformed_snapshot_returns_operational_error_without_reports(
    tmp_path, test_rules_path, capsys
):
    snapshot = tmp_path / "bad.json"
    snapshot.write_text("{not-json", encoding="utf-8")
    output = tmp_path / "bad-output"

    status = main(_scan_args(snapshot, test_rules_path, output))

    captured = capsys.readouterr()
    assert status == EXIT_OPERATIONAL_ERROR
    assert "not valid JSON" in captured.err
    assert not (output / "compliance_report.json").exists()
    assert not (output / "report.pdf").exists()


def test_cli_raw_iam_export_is_explicitly_marked_partial(tmp_path, test_rules_path):
    snapshot = tmp_path / "iam-policy.json"
    snapshot.write_text(
        json.dumps(
            {
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["group:auditors@example.com"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "iam-output"

    status = main(_scan_args(snapshot, test_rules_path, output))

    assert status == EXIT_COMPLIANT
    report = json.loads((output / "compliance_report.json").read_text(encoding="utf-8"))
    assert report["source"] == "offline-iam-only"
    assert report["summary"]["service_accounts_scanned"] == 0
    assert report["summary"]["buckets_scanned"] == 0


def test_cli_requires_exactly_one_input_source(tmp_path, test_rules_path):
    common = [
        "scan",
        "--rules",
        str(test_rules_path),
        "--output-dir",
        str(tmp_path),
    ]
    with pytest.raises(SystemExit) as missing:
        main(common)
    assert missing.value.code == 2

    with pytest.raises(SystemExit) as both:
        main(common + ["--snapshot", "snapshot.json", "--project", "project-id"])
    assert both.value.code == 2


def test_operational_error_redacts_common_credential_fields():
    message = _safe_operational_message(
        RuntimeError(
            "private_key=super-secret access_token:also-secret authorization=Bearer-secret"
        )
    )

    assert "super-secret" not in message
    assert "also-secret" not in message
    assert "Bearer-secret" not in message
    assert message.count("[REDACTED]") == 3


def test_cli_normalizer_preserves_google_camel_case_snapshot_fields(tmp_path):
    payload = {
        "projectId": "example-project",
        "collectedAt": "2026-08-22T08:00:00Z",
        "iamPolicy": {"bindings": []},
        "serviceAccounts": [
            {"email": "worker@example-project.iam.gserviceaccount.com", "keys": []}
        ],
        "buckets": [],
        "rolePermissions": {"roles/example": ["example.resources.get"]},
    }

    normalized = _normalise_snapshot_payload(payload, tmp_path / "snapshot.json")

    assert normalized["iamPolicy"] == {"bindings": []}
    assert normalized["serviceAccounts"] == payload["serviceAccounts"]
    assert "service_accounts" not in normalized
    assert normalized["collectedAt"] == "2026-08-22T08:00:00Z"
