"""Serialize compliance results to machine-readable JSON and polished PDF files.

The reporting layer intentionally accepts either an ``AuditResult`` instance or a
plain mapping.  Keeping that boundary loose makes reports useful in CI pipelines
and allows previously generated JSON results to be rendered without re-scanning
Google Cloud.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


@dataclass(frozen=True)
class ReportArtifacts:
    """Paths written by :func:`write_reports`."""

    json_path: Path
    pdf_path: Path

    def __iter__(self):  # type: ignore[no-untyped-def]
        """Allow convenient tuple unpacking while retaining named fields."""

        yield self.json_path
        yield self.pdf_path


def _json_default(value: Any) -> Any:
    """Convert supported domain and standard-library values to JSON values."""

    if hasattr(value, "value"):
        return value.value
    if isinstance(value, (datetime, Path)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _to_payload(result: Any) -> dict[str, Any]:
    """Return a detached JSON-compatible dictionary for an audit result."""

    if isinstance(result, Mapping):
        raw: Any = dict(result)
    elif hasattr(result, "to_dict"):
        raw = result.to_dict()
    elif is_dataclass(result):
        raw = asdict(result)
    else:
        raise TypeError("result must be a mapping, dataclass, or expose to_dict()")

    encoded = json.dumps(raw, default=_json_default, ensure_ascii=True)
    payload = json.loads(encoded)
    if not isinstance(payload, dict):
        raise TypeError("serialized audit result must be a JSON object")
    return payload


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes atomically so interrupted report generation leaves no partial file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
    temporary.replace(path)


def write_json_report(result: Any, output_path: str | Path) -> Path:
    """Write a stable, UTF-8 compliance report and return its absolute path."""

    path = Path(output_path).expanduser().resolve()
    payload = _to_payload(result)
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    _atomic_write(path, rendered.encode("utf-8"))
    return path


def _safe(value: Any, fallback: str = "Not available") -> str:
    """Escape arbitrary data for safe insertion into ReportLab paragraphs."""

    if value is None or value == "":
        value = fallback
    return escape(str(value))


def _severity_color(severity: str):  # type: ignore[no-untyped-def]
    """Return the visual color assigned to a normalized severity."""

    from reportlab.lib import colors

    return {
        "CRITICAL": colors.HexColor("#B42318"),
        "HIGH": colors.HexColor("#C2410C"),
        "MEDIUM": colors.HexColor("#A16207"),
    }.get(severity.upper(), colors.HexColor("#475467"))


def _pdf_bytes(payload: Mapping[str, Any]) -> bytes:
    """Render an audit payload to a complete in-memory PDF document."""

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - depends on installation extra
        raise RuntimeError(
            "PDF generation requires ReportLab. Install the project with its "
            "report dependencies before requesting a PDF."
        ) from exc

    from io import BytesIO

    navy = colors.HexColor("#122B39")
    ink = colors.HexColor("#172230")
    muted = colors.HexColor("#5D6B66")
    paper = colors.HexColor("#F7F5EF")
    pale_teal = colors.HexColor("#DCEFEB")
    line = colors.HexColor("#D7D8D2")
    white = colors.white

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title="GCP Infrastructure Compliance Report",
        author="Automated Infrastructure Compliance and Least-Privilege Auditor",
        subject="IAM and Cloud Storage compliance findings",
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=29,
            textColor=ink,
            spaceAfter=6 * mm,
            alignment=TA_LEFT,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=muted,
            spaceAfter=7 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=ink,
            spaceBefore=5 * mm,
            spaceAfter=3 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=ink,
            spaceAfter=2 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=13,
            textColor=ink,
            spaceAfter=2.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.4,
            leading=10.5,
            textColor=muted,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallWhite",
            parent=styles["Small"],
            textColor=white,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Metric",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=20,
            alignment=TA_CENTER,
            textColor=ink,
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetricLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=9,
            alignment=TA_CENTER,
            textColor=muted,
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetricLabelWhite",
            parent=styles["MetricLabel"],
            textColor=white,
        )
    )

    summary = dict(payload.get("summary") or {})
    findings = list(payload.get("findings") or [])
    ruleset = payload.get("ruleset")
    if not isinstance(ruleset, Mapping):
        ruleset = {}
    severity_counts = dict(summary.get("severity_counts") or {})
    normalized_counts = {
        str(key).upper(): int(value or 0) for key, value in severity_counts.items()
    }
    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        normalized_counts.setdefault(
            severity,
            sum(1 for finding in findings if str(finding.get("severity", "")).upper() == severity),
        )

    def summary_value(*keys: str, default: Any = 0) -> Any:
        for key in keys:
            if key in summary:
                return summary[key]
        return default

    def resource_values(finding: Mapping[str, Any]) -> tuple[Any, Any]:
        resource = finding.get("resource")
        if not isinstance(resource, Mapping):
            resource = {}
        return (
            finding.get("resource_type", resource.get("type")),
            finding.get("resource_name", resource.get("name")),
        )

    def framework_label(control: Any) -> str:
        if isinstance(control, Mapping):
            framework = str(control.get("framework", "Framework"))
            control_id = str(control.get("control_id", "")).strip()
            title = str(control.get("title", "")).strip()
            label = f"{framework} {control_id}".strip()
            return f"{label} - {title}" if title else label
        return str(control)

    def footer(canvas, doc):  # type: ignore[no-untyped-def]
        canvas.saveState()
        canvas.setStrokeColor(line)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18 * mm, 9 * mm, "GCP Compliance and Least-Privilege Auditor")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story: list[Any] = []
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("GCP INFRASTRUCTURE ASSURANCE", styles["Small"]))
    story.append(Paragraph("Compliance and Least-Privilege Report", styles["ReportTitle"]))
    status = "COMPLIANT" if not findings else "ACTION REQUIRED"
    story.append(
        Paragraph(
            "A deterministic, read-only assessment of project IAM, service-account "
            "credentials, and Cloud Storage security controls.",
            styles["ReportSubtitle"],
        )
    )

    status_table = Table(
        [
            [
                Paragraph("ASSESSMENT STATUS", styles["MetricLabelWhite"]),
                Paragraph(_safe(status), styles["Metric"]),
            ]
        ],
        colWidths=[48 * mm, 111 * mm],
        rowHeights=[19 * mm],
    )
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), navy),
                ("TEXTCOLOR", (0, 0), (0, 0), white),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, 0),
                    pale_teal if not findings else colors.HexColor("#FEE4E2"),
                ),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 0.6, navy),
            ]
        )
    )
    story.append(status_table)
    story.append(Spacer(1, 7 * mm))

    metric_values = [
        (summary.get("total_resources_scanned", 0), "RESOURCES"),
        (summary.get("violations", len(findings)), "VIOLATIONS"),
        (normalized_counts["CRITICAL"], "CRITICAL"),
        (normalized_counts["HIGH"], "HIGH"),
        (normalized_counts["MEDIUM"], "MEDIUM"),
    ]
    metric_cells = [
        [Paragraph(_safe(value, "0"), styles["Metric"]), Paragraph(label, styles["MetricLabel"])]
        for value, label in metric_values
    ]
    metrics = Table([metric_cells], colWidths=[31.8 * mm] * 5, rowHeights=[23 * mm])
    metrics.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), white),
                ("BOX", (0, 0), (-1, -1), 0.5, line),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, line),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    story.append(metrics)
    story.append(Spacer(1, 8 * mm))

    metadata_rows = [
        ("Project", payload.get("project_id")),
        ("Source", payload.get("source")),
        ("Generated", payload.get("generated_at") or datetime.now(timezone.utc).isoformat()),
        (
            "Ruleset",
            f"{payload.get('ruleset_name', ruleset.get('name', 'Local rules'))} "
            f"{payload.get('ruleset_version', ruleset.get('version', ''))}".strip(),
        ),
        ("Schema version", payload.get("schema_version")),
    ]
    metadata = Table(
        [
            [
                Paragraph(f"<b>{_safe(label)}</b>", styles["Small"]),
                Paragraph(_safe(value), styles["Small"]),
            ]
            for label, value in metadata_rows
        ],
        colWidths=[38 * mm, 121 * mm],
    )
    metadata.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), paper),
                ("BOX", (0, 0), (-1, -1), 0.5, line),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, line),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(metadata)
    story.append(Spacer(1, 6 * mm))
    story.append(
        Paragraph(
            "Important: this report is evidence from the supplied snapshot or the APIs "
            "successfully queried at scan time. It is not a certification, and framework "
            "mappings should be validated against the version adopted by your organization.",
            styles["ReportBody"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("Executive finding register", styles["Section"]))
    if not findings:
        story.append(
            Paragraph(
                "No configured rule produced a violation. Review scan scope and rule coverage "
                "before treating this result as complete assurance.",
                styles["ReportBody"],
            )
        )
    else:
        register_rows: list[list[Any]] = [
            [
                Paragraph("Severity", styles["SmallWhite"]),
                Paragraph("Finding", styles["SmallWhite"]),
                Paragraph("Resource", styles["SmallWhite"]),
                Paragraph("Rule", styles["SmallWhite"]),
            ]
        ]
        for finding in findings:
            severity = str(finding.get("severity", "UNKNOWN")).upper()
            _, resource_name = resource_values(finding)
            register_rows.append(
                [
                    Paragraph(f"<b>{_safe(severity)}</b>", styles["Small"]),
                    Paragraph(_safe(finding.get("title")), styles["Small"]),
                    Paragraph(_safe(resource_name), styles["Small"]),
                    Paragraph(_safe(finding.get("rule_id")), styles["Small"]),
                ]
            )
        register = Table(
            register_rows,
            colWidths=[22 * mm, 55 * mm, 52 * mm, 30 * mm],
            repeatRows=1,
        )
        table_commands: list[tuple[Any, ...]] = [
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("BOX", (0, 0), (-1, -1), 0.5, line),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, line),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        for row_index, finding in enumerate(findings, start=1):
            if row_index % 2 == 0:
                table_commands.append(("BACKGROUND", (0, row_index), (-1, row_index), paper))
            table_commands.append(
                (
                    "TEXTCOLOR",
                    (0, row_index),
                    (0, row_index),
                    _severity_color(str(finding.get("severity", ""))),
                )
            )
        register.setStyle(TableStyle(table_commands))
        story.append(register)

    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Scan coverage", styles["Section"]))
    coverage_rows = [
        ("Projects", summary_value("projects_scanned", "projects")),
        ("IAM bindings", summary_value("iam_bindings_scanned", "iam_bindings")),
        (
            "Service accounts",
            summary_value("service_accounts_scanned", "service_accounts"),
        ),
        (
            "Service-account keys",
            summary_value("service_account_keys_scanned", "service_account_keys"),
        ),
        ("Cloud Storage buckets", summary_value("buckets_scanned", "buckets")),
        ("Checks evaluated", summary_value("checks_evaluated")),
    ]
    coverage = Table(
        [
            [
                Paragraph(_safe(label), styles["Small"]),
                Paragraph(_safe(value, "0"), styles["Small"]),
            ]
            for label, value in coverage_rows
        ],
        colWidths=[80 * mm, 79 * mm],
    )
    coverage.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, line),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, line),
                ("BACKGROUND", (0, 0), (-1, -1), white),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(coverage)

    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Detailed findings", styles["Section"]))
        for index, finding in enumerate(findings, start=1):
            severity = str(finding.get("severity", "UNKNOWN")).upper()
            frameworks = finding.get("frameworks") or []
            if isinstance(frameworks, Mapping):
                frameworks = [f"{key}: {value}" for key, value in frameworks.items()]
            framework_text = (
                "; ".join(framework_label(item) for item in frameworks) or "No mapping configured"
            )
            evidence = finding.get("evidence") or {}
            evidence_text = json.dumps(evidence, sort_keys=True, ensure_ascii=True)
            if len(evidence_text) > 2200:
                evidence_text = evidence_text[:2197] + "..."

            title = f"{index}. {_safe(finding.get('title'))}"
            resource_type, resource_name = resource_values(finding)
            card = [
                Paragraph(title, styles["FindingTitle"]),
                Table(
                    [
                        [
                            Paragraph(f"<b>{_safe(severity)}</b>", styles["SmallWhite"]),
                            Paragraph(
                                f"<b>Rule:</b> {_safe(finding.get('rule_id'))}<br/>"
                                f"<b>Finding ID:</b> {_safe(finding.get('finding_id'))}",
                                styles["Small"],
                            ),
                        ]
                    ],
                    colWidths=[30 * mm, 125 * mm],
                    style=TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (0, 0), _severity_color(severity)),
                            ("TEXTCOLOR", (0, 0), (0, 0), white),
                            ("BACKGROUND", (1, 0), (1, 0), paper),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("BOX", (0, 0), (-1, -1), 0.45, line),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ]
                    ),
                ),
                Spacer(1, 2 * mm),
                Paragraph(
                    f"<b>Resource:</b> {_safe(resource_type)} / {_safe(resource_name)}",
                    styles["ReportBody"],
                ),
                Paragraph(
                    f"<b>Principal:</b> {_safe(finding.get('principal'), 'Not applicable')}",
                    styles["ReportBody"],
                ),
                Paragraph(_safe(finding.get("description")), styles["ReportBody"]),
                Paragraph(
                    f"<b>Evidence:</b> <font name='Courier'>{_safe(evidence_text)}</font>",
                    styles["Small"],
                ),
                Paragraph(
                    f"<b>Recommended action:</b> {_safe(finding.get('recommendation'))}",
                    styles["ReportBody"],
                ),
                Paragraph(
                    f"<b>Framework mapping:</b> {_safe(framework_text)}",
                    styles["Small"],
                ),
                Spacer(1, 5 * mm),
            ]
            story.append(KeepTogether(card))

    story.append(PageBreak())
    story.append(Paragraph("Methodology and interpretation", styles["Section"]))
    methodology = [
        (
            "IAM least privilege",
            "Project bindings are inverted into principal-to-role assignments. Configured "
            "basic roles and assignment thresholds are evaluated, with explicit exemptions "
            "limited to the approved administrator allowlist.",
        ),
        (
            "Service-account key age",
            "Only user-managed keys are subject to the rotation-age threshold. Google-managed "
            "keys are excluded because customers do not rotate them.",
        ),
        (
            "Public storage access",
            "Bucket IAM policies and available legacy ACL entries are checked for allUsers and "
            "allAuthenticatedUsers. Uniform bucket-level access and public access prevention "
            "are recorded as independent defense-in-depth controls.",
        ),
        (
            "Encryption policy",
            "Cloud Storage encrypts data at rest by default. A missing default KMS key is "
            "reported only when the local rules require customer-managed encryption keys; it "
            "must not be interpreted as plaintext storage.",
        ),
        (
            "Severity",
            "CRITICAL indicates immediately exploitable or broad privilege exposure; HIGH "
            "indicates a material control failure; MEDIUM indicates security hygiene or "
            "rotation debt requiring planned remediation.",
        ),
    ]
    for heading, body in methodology:
        story.append(Paragraph(_safe(heading), styles["FindingTitle"]))
        story.append(Paragraph(_safe(body), styles["ReportBody"]))

    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("Report limitations", styles["Section"]))
    story.append(
        Paragraph(
            "The scanner is read-only and does not remediate findings. Conditional IAM "
            "expressions are reported as evidence but are not formally proven for every "
            "possible request context. Organization, folder, inherited policies, object-level "
            "ACLs, KMS key state, VPC Service Controls, audit logging, and services outside the "
            "configured collectors are not implied to be compliant unless explicitly scanned.",
            styles["ReportBody"],
        )
    )

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def write_pdf_report(result: Any, output_path: str | Path) -> Path:
    """Write a visually structured PDF report and return its absolute path."""

    path = Path(output_path).expanduser().resolve()
    payload = _to_payload(result)
    _atomic_write(path, _pdf_bytes(payload))
    return path


def write_reports(result: Any, output_dir: str | Path) -> ReportArtifacts:
    """Write ``compliance_report.json`` and ``report.pdf`` to one directory."""

    directory = Path(output_dir).expanduser().resolve()
    payload = _to_payload(result)
    # Render both representations before publishing either one. A missing PDF
    # dependency or layout failure must not leave a newly generated JSON file
    # that could be mistaken for a complete successful run.
    json_bytes = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    pdf_bytes = _pdf_bytes(payload)
    pdf_path = (directory / "report.pdf").resolve()
    json_path = (directory / "compliance_report.json").resolve()
    _atomic_write(pdf_path, pdf_bytes)
    _atomic_write(json_path, json_bytes)
    return ReportArtifacts(json_path=json_path, pdf_path=pdf_path)
