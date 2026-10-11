from __future__ import annotations

import json

from gcp_compliance_auditor.audit import audit_snapshot
from gcp_compliance_auditor.models import AuditSnapshot
from gcp_compliance_auditor.reporting import (
    write_json_report,
    write_pdf_report,
    write_reports,
)


def _result(snapshot_dict, rules):
    from datetime import datetime, timezone

    return audit_snapshot(
        AuditSnapshot.from_dict(snapshot_dict),
        rules,
        datetime(2026, 8, 22, 8, 0, tzinfo=timezone.utc),
    )


def test_json_report_round_trips_exact_audit_payload(
    tmp_path, violations_snapshot_dict, test_rules
):
    result = _result(violations_snapshot_dict, test_rules)
    path = write_json_report(result, tmp_path / "nested" / "report.json")

    assert path.is_absolute()
    assert json.loads(path.read_text(encoding="utf-8")) == result.to_dict()
    assert path.read_bytes().endswith(b"\n")


def test_pdf_report_has_valid_signature_and_eof(tmp_path, violations_snapshot_dict, test_rules):
    result = _result(violations_snapshot_dict, test_rules)
    path = write_pdf_report(result, tmp_path / "report.pdf")

    content = path.read_bytes()
    assert content.startswith(b"%PDF-")
    assert content.rstrip().endswith(b"%%EOF")
    assert len(content) > 5_000


def test_write_reports_creates_both_expected_artifacts(tmp_path, clean_snapshot_dict, test_rules):
    result = _result(clean_snapshot_dict, test_rules)
    artifacts = write_reports(result, tmp_path / "artifacts")

    assert artifacts.json_path.name == "compliance_report.json"
    assert artifacts.pdf_path.name == "report.pdf"
    assert artifacts.json_path.is_file()
    assert artifacts.pdf_path.is_file()
    assert (
        json.loads(artifacts.json_path.read_text(encoding="utf-8"))["summary"]["compliant"] is True
    )
