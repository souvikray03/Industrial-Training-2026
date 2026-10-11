"""Command-line interface for offline and live GCP compliance scans."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .collectors import GCPCollectorError, collect_gcp_snapshot

EXIT_COMPLIANT = 0
EXIT_VIOLATIONS = 1
EXIT_OPERATIONAL_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gcp-compliance-auditor",
        description=(
            "Audit a GCP IAM JSON snapshot or a live GCP project against a local "
            "least-privilege rule set. Live scans are read-only."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser(
        "scan",
        help="run a compliance scan and write JSON and PDF reports",
        description=(
            "Scan exactly one source. Offline scans need no Google libraries or "
            "credentials; live scans use Application Default Credentials."
        ),
    )
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--snapshot",
        type=Path,
        metavar="FILE",
        help="GCP policy or canonical audit snapshot JSON file",
    )
    source.add_argument(
        "--project",
        metavar="ID",
        help="live GCP project ID or project number",
    )
    scan.add_argument(
        "--rules",
        type=Path,
        required=True,
        metavar="FILE",
        help="local compliance rules in JSON or YAML format",
    )
    scan.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        metavar="DIR",
        help="directory for compliance_report.json and report.pdf",
    )
    scan.set_defaults(handler=_run_scan)
    return parser


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as source:
            return json.load(source)
    except FileNotFoundError as error:
        raise ValueError(f"Snapshot file does not exist: {path}") from error
    except IsADirectoryError as error:
        raise ValueError(f"Snapshot path is a directory, not a JSON file: {path}") from error
    except PermissionError as error:
        raise ValueError(f"Snapshot file is not readable: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Snapshot is not valid JSON at line {error.lineno}, column {error.colno}"
        ) from error
    except OSError as error:
        raise ValueError(f"Could not read snapshot file: {path}") from error


def _infer_project_id(payload: Mapping[str, Any], snapshot_path: Path) -> str:
    for field in ("project_id", "projectId", "project"):
        candidate = payload.get(field)
        if isinstance(candidate, str) and candidate.strip():
            value = candidate.strip()
            return value.rsplit("/", 1)[-1] if value.startswith("projects/") else value

    # Raw getIamPolicy exports contain member identities but no project field.
    # A service-account domain provides a useful non-secret project identifier.
    bindings = payload.get("bindings", [])
    if isinstance(bindings, list):
        pattern = re.compile(r"@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com$")
        for binding in bindings:
            if not isinstance(binding, Mapping):
                continue
            for member in binding.get("members", []):
                match = pattern.search(str(member))
                if match:
                    return match.group(1)
    return snapshot_path.stem or "offline-snapshot"


def _normalise_snapshot_payload(payload: Any, snapshot_path: Path) -> dict[str, Any]:
    """Accept canonical snapshots and raw ``getIamPolicy`` JSON exports."""

    if isinstance(payload, list):
        if not all(isinstance(binding, Mapping) for binding in payload):
            raise ValueError("A snapshot JSON array must contain IAM binding objects")
        payload = {"bindings": payload}
    if not isinstance(payload, Mapping):
        raise ValueError("Snapshot JSON must be an object or an array of IAM bindings")

    normalised = dict(payload)
    has_enveloped_policy = any(
        field in normalised for field in ("iam_policy", "iamPolicy", "project_iam_policy")
    )
    if not has_enveloped_policy:
        raw_policy: Mapping[str, Any] | None = None
        if isinstance(normalised.get("policy"), Mapping):
            raw_policy = normalised["policy"]
        elif "bindings" in normalised:
            raw_policy = normalised
        if raw_policy is None:
            raise ValueError("Snapshot must contain iam_policy, policy, or top-level bindings")
        normalised = {
            "project_id": _infer_project_id(normalised, snapshot_path),
            "collected_at": normalised.get("collected_at"),
            "source": "offline-iam-only",
            "iam_policy": {
                key: raw_policy[key] for key in ("version", "bindings", "etag") if key in raw_policy
            },
            "service_accounts": normalised.get(
                "service_accounts", normalised.get("serviceAccounts", [])
            ),
            "buckets": normalised.get("buckets", []),
            "role_permissions": normalised.get(
                "role_permissions", normalised.get("rolePermissions", {})
            ),
        }

    if not normalised.get("project_id"):
        normalised["project_id"] = _infer_project_id(normalised, snapshot_path)
    if not normalised.get("collected_at") and not normalised.get("collectedAt"):
        normalised["collected_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if "service_accounts" not in normalised and "serviceAccounts" not in normalised:
        normalised["service_accounts"] = []
    normalised.setdefault("buckets", [])
    return normalised


def _result_mapping(result: Any) -> Mapping[str, Any]:
    if isinstance(result, Mapping):
        return result
    to_dict = getattr(result, "to_dict", None)
    if not callable(to_dict):
        raise TypeError("The audit engine returned an unsupported result")
    value = to_dict()
    if not isinstance(value, Mapping):
        raise TypeError("The audit result did not serialize to an object")
    return value


def _severity_name(finding: Mapping[str, Any]) -> str:
    severity = finding.get("severity", "MEDIUM")
    value = getattr(severity, "value", severity)
    return str(value).upper()


def _finding_title(finding: Mapping[str, Any]) -> str:
    for field in ("title", "rule_name", "rule_id", "id", "message"):
        value = finding.get(field)
        if value:
            return " ".join(str(value).split())[:100]
    return "Compliance finding"


def _extract_report_paths(report_paths: Any, output_dir: Path) -> tuple[Path, Path]:
    default_json = output_dir / "compliance_report.json"
    default_pdf = output_dir / "report.pdf"
    if isinstance(report_paths, Mapping):
        json_value = (
            report_paths.get("json")
            or report_paths.get("json_path")
            or report_paths.get("compliance_report")
        )
        pdf_value = report_paths.get("pdf") or report_paths.get("pdf_path")
        return (
            Path(json_value) if json_value else default_json,
            Path(pdf_value) if pdf_value else default_pdf,
        )
    if isinstance(report_paths, (tuple, list)) and len(report_paths) >= 2:
        return Path(report_paths[0]), Path(report_paths[1])
    json_value = getattr(report_paths, "json_path", None)
    pdf_value = getattr(report_paths, "pdf_path", None)
    return (
        Path(json_value) if json_value else default_json,
        Path(pdf_value) if pdf_value else default_pdf,
    )


def _print_summary(
    *,
    snapshot: Any,
    result: Any,
    source_label: str,
    json_path: Path,
    pdf_path: Path,
) -> int:
    snapshot_data = snapshot.to_dict() if hasattr(snapshot, "to_dict") else snapshot
    if not isinstance(snapshot_data, Mapping):
        snapshot_data = {}
    result_data = _result_mapping(result)
    summary = result_data.get("summary", {})
    if not isinstance(summary, Mapping):
        summary = {}
    findings = [
        finding for finding in result_data.get("findings", []) if isinstance(finding, Mapping)
    ]

    policies: list[Mapping[str, Any]] = []
    project_policy = snapshot_data.get("iam_policy", {})
    if isinstance(project_policy, Mapping):
        policies.append(project_policy)
    service_accounts = snapshot_data.get("service_accounts", [])
    buckets = snapshot_data.get("buckets", [])
    if not isinstance(service_accounts, list):
        service_accounts = []
    if not isinstance(buckets, list):
        buckets = []
    for bucket in buckets:
        if isinstance(bucket, Mapping) and isinstance(bucket.get("iam_policy"), Mapping):
            policies.append(bucket["iam_policy"])

    binding_count = 0
    member_assignments = 0
    for policy in policies:
        for binding in policy.get("bindings", []):
            if isinstance(binding, Mapping):
                binding_count += 1
                if isinstance(binding.get("members"), list):
                    member_assignments += len(binding["members"])
    key_count = sum(
        len(account.get("keys", []))
        for account in service_accounts
        if isinstance(account, Mapping) and isinstance(account.get("keys", []), list)
    )
    resource_count = int(
        summary.get(
            "total_resources_scanned",
            1 + len(service_accounts) + key_count + len(buckets),
        )
    )
    severities = Counter(_severity_name(finding) for finding in findings)

    print("GCP COMPLIANCE AUDIT")
    print("=" * 52)
    print(f"Source: {source_label}")
    print(f"Project: {result_data.get('project_id') or snapshot_data.get('project_id', 'unknown')}")
    print(f"Resources scanned: {resource_count}")
    print(f"  IAM bindings: {summary.get('iam_bindings_scanned', binding_count)}")
    print(f"  IAM member assignments: {member_assignments}")
    print(f"  Service accounts: {len(service_accounts)}")
    print(f"  User-managed keys: {key_count}")
    print(f"  Storage buckets: {len(buckets)}")
    print(f"Violations found: {len(findings)}")
    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        print(f"  {severity}: {severities.get(severity, 0)}")

    if findings:
        print("Findings:")
        for severity in ("CRITICAL", "HIGH", "MEDIUM"):
            for finding in findings:
                if _severity_name(finding) == severity:
                    print(f"  [{severity}] {_finding_title(finding)}")
    print(f"Status: {'NON-COMPLIANT' if findings else 'COMPLIANT'}")
    print("Reports:")
    print(f"  JSON: {json_path}")
    print(f"  PDF: {pdf_path}")
    return EXIT_VIOLATIONS if findings else EXIT_COMPLIANT


def _run_scan(arguments: argparse.Namespace) -> int:
    # Imports stay local so `--help` and offline collection diagnostics remain
    # usable even when an optional report dependency is not installed.
    from .audit import audit_snapshot
    from .models import AuditSnapshot
    from .reporting import write_reports
    from .rules import load_rules

    rules = load_rules(arguments.rules)
    if arguments.snapshot is not None:
        raw_snapshot = _normalise_snapshot_payload(
            _read_json(arguments.snapshot), arguments.snapshot
        )
        snapshot = AuditSnapshot.from_dict(raw_snapshot, source="offline")
        source_label = f"snapshot ({arguments.snapshot})"
    else:
        raw_snapshot = collect_gcp_snapshot(arguments.project)
        snapshot = AuditSnapshot.from_dict(raw_snapshot, source="live")
        source_label = f"live GCP ({arguments.project})"

    output_dir = arguments.output_dir
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"Output path exists and is not a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    result = audit_snapshot(snapshot, rules)
    paths = write_reports(result, output_dir)
    json_path, pdf_path = _extract_report_paths(paths, output_dir)
    return _print_summary(
        snapshot=snapshot,
        result=result,
        source_label=source_label,
        json_path=json_path,
        pdf_path=pdf_path,
    )


def _safe_operational_message(error: BaseException) -> str:
    if isinstance(error, GCPCollectorError):
        return str(error)
    message = " ".join(str(error).split())
    # Never echo credential material that an unexpected dependency might place in
    # an exception. These substitutions preserve a useful field name while hiding
    # its value.
    message = re.sub(
        r"(?i)(private[_ -]?key|client[_ -]?secret|access[_ -]?token|authorization)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        message,
    )
    return message[:500] or error.__class__.__name__


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a stable process exit code."""

    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except KeyboardInterrupt:
        print("Error: scan cancelled by user", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {_safe_operational_message(error)}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR


if __name__ == "__main__":  # pragma: no cover - exercised through __main__.py
    raise SystemExit(main())
