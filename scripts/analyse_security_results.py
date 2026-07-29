from __future__ import annotations

import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEMGREP_REPORT = Path("semgrep-report.json")
GITLEAKS_REPORT = Path("gitleaks-report.json")

COMBINED_REPORT = Path("combined-security-report.json")
TEXT_REPORT = Path("security-report.txt")
HTML_REPORT = Path("security-report.html")


def load_json(
    path: Path,
    default: Any,
) -> Any:
    """Load a JSON report safely."""

    if not path.exists():
        print(f"Warning: {path} does not exist.")
        return default

    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"Warning: Unable to read {path}: {error}"
        )
        return default


def write_github_output(
    name: str,
    value: str | int,
) -> None:
    """Make an output available to later GitHub Actions steps."""

    output_path = os.environ.get("GITHUB_OUTPUT")

    if not output_path:
        return

    with open(
        output_path,
        "a",
        encoding="utf-8",
    ) as output_file:
        output_file.write(
            f"{name}={value}\n"
        )


def normalise_semgrep(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Convert Semgrep findings into a shared format."""

    findings: list[dict[str, Any]] = []

    severity_mapping = {
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "INVENTORY": "LOW",
        "EXPERIMENT": "LOW",
    }

    for result in report.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        start = result.get("start", {})
        end = result.get("end", {})

        original_severity = str(
            extra.get(
                "severity",
                "UNKNOWN",
            )
        ).upper()

        severity = severity_mapping.get(
            original_severity,
            "LOW",
        )

        cwe = metadata.get("cwe", [])

        if isinstance(cwe, str):
            cwe = [cwe]

        if not isinstance(cwe, list):
            cwe = []

        owasp = metadata.get("owasp", [])

        if isinstance(owasp, str):
            owasp = [owasp]

        if not isinstance(owasp, list):
            owasp = []

        references = metadata.get(
            "references",
            [],
        )

        if isinstance(references, str):
            references = [references]

        if not isinstance(references, list):
            references = []

        recommendation = (
            extra.get("fix")
            or metadata.get("fix")
            or (
                "Review the affected code and replace the insecure "
                "implementation with a validated secure coding "
                "approach. Apply the fix and rerun the automated "
                "security workflow."
            )
        )

        findings.append(
            {
                "tool": "Semgrep",
                "type": "Static Application Security Testing",
                "severity": severity,
                "original_severity": original_severity,
                "title": extra.get(
                    "message",
                    result.get(
                        "check_id",
                        "Semgrep security finding",
                    ),
                ),
                "rule_id": result.get(
                    "check_id",
                    "unknown-semgrep-rule",
                ),
                "file": result.get(
                    "path",
                    "Unknown file",
                ),
                "line": start.get("line"),
                "column": start.get("col"),
                "end_line": end.get("line"),
                "end_column": end.get("col"),
                "cwe": cwe,
                "owasp": owasp,
                "references": references,
                "recommendation": recommendation,
            }
        )

    return findings


def normalise_gitleaks(
    report: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert Gitleaks results into the shared format."""

    findings: list[dict[str, Any]] = []

    for result in report:
        rule_id = (
            result.get("RuleID")
            or result.get("RuleId")
            or result.get("rule_id")
            or "secret-detected"
        )

        description = (
            result.get("Description")
            or result.get("description")
            or "A potential exposed secret was detected."
        )

        file_path = (
            result.get("File")
            or result.get("file")
            or "Unknown file"
        )

        start_line = (
            result.get("StartLine")
            or result.get("start_line")
        )

        start_column = (
            result.get("StartColumn")
            or result.get("start_column")
        )

        end_line = (
            result.get("EndLine")
            or result.get("end_line")
        )

        commit = (
            result.get("Commit")
            or result.get("commit")
            or ""
        )

        findings.append(
            {
                "tool": "Gitleaks",
                "type": "Secret Scanning",
                "severity": "HIGH",
                "original_severity": "SECRET",
                "title": description,
                "rule_id": rule_id,
                "file": file_path,
                "line": start_line,
                "column": start_column,
                "end_line": end_line,
                "commit": commit,
                "cwe": [
                    "CWE-798: Use of Hard-coded Credentials"
                ],
                "owasp": [
                    "A07:2021 Identification and Authentication Failures"
                ],
                "references": [],
                "recommendation": (
                    "Remove the exposed secret from the source code "
                    "and Git history. Revoke or rotate the affected "
                    "credential immediately. Store the replacement "
                    "credential in GitHub Actions Secrets or another "
                    "approved secret-management system."
                ),
            }
        )

    return findings


def calculate_risk_score(
    severity_counts: Counter[str],
) -> tuple[int, str]:
    """Calculate a capped security risk score."""

    raw_score = (
        severity_counts.get("CRITICAL", 0) * 10
        + severity_counts.get("HIGH", 0) * 7
        + severity_counts.get("MEDIUM", 0) * 4
        + severity_counts.get("LOW", 0)
    )

    risk_score = min(
        raw_score,
        100,
    )

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return risk_score, risk_level


def generate_text_report(
    report: dict[str, Any],
) -> None:
    """Generate a plain-text report."""

    summary = report["summary"]
    scan = report["scan"]
    findings = report["findings"]

    lines = [
        "Courier Management System",
        "Automated Multi-Tool Security Assessment",
        "=" * 72,
        "",
        "SCAN INFORMATION",
        "-" * 72,
        f"Repository: {scan['repository']}",
        f"Branch: {scan['branch']}",
        f"Commit: {scan['commit']}",
        f"Workflow run ID: {scan['workflow_run_id']}",
        f"Generated: {scan['generated_at']}",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 72,
        f"Total findings: {summary['total']}",
        f"Semgrep findings: {summary['semgrep_total']}",
        f"Gitleaks findings: {summary['gitleaks_total']}",
        f"Critical findings: {summary['critical']}",
        f"High findings: {summary['high']}",
        f"Medium findings: {summary['medium']}",
        f"Low findings: {summary['low']}",
        f"Risk score: {summary['risk_score']}/100",
        f"Risk level: {summary['risk_level']}",
        f"Quality gate: {summary['quality_gate']}",
        "",
        "DETAILED FINDINGS",
        "-" * 72,
    ]

    if not findings:
        lines.extend(
            [
                "",
                "No Semgrep vulnerabilities or Gitleaks secrets "
                "were detected.",
            ]
        )

    for number, finding in enumerate(
        findings,
        start=1,
    ):
        cwe_text = (
            ", ".join(
                str(item)
                for item in finding.get("cwe", [])
            )
            or "Not provided"
        )

        owasp_text = (
            ", ".join(
                str(item)
                for item in finding.get("owasp", [])
            )
            or "Not provided"
        )

        lines.extend(
            [
                "",
                f"Finding {number}",
                "~" * 72,
                f"Scanner: {finding['tool']}",
                f"Category: {finding['type']}",
                f"Severity: {finding['severity']}",
                f"Original severity: "
                f"{finding['original_severity']}",
                f"Rule: {finding['rule_id']}",
                f"File: {finding['file']}",
                f"Line: "
                f"{finding.get('line') or 'Unknown'}",
                f"Description: {finding['title']}",
                f"CWE: {cwe_text}",
                f"OWASP: {owasp_text}",
                (
                    "Recommendation: "
                    f"{finding['recommendation']}"
                ),
            ]
        )

    lines.extend(
        [
            "",
            "SECURITY QUALITY GATE",
            "-" * 72,
        ]
    )

    if summary["quality_gate"] == "REVIEW REQUIRED":
        lines.extend(
            [
                "Status: REVIEW REQUIRED",
                "",
                (
                    "Critical, High, or exposed-secret findings "
                    "were detected. The findings should be reviewed "
                    "and remediated before deployment."
                ),
                "",
                (
                    "The GitHub Actions workflow remains successful "
                    "because the quality gate is operating in "
                    "reporting mode."
                ),
            ]
        )
    else:
        lines.extend(
            [
                "Status: PASSED",
                "",
                (
                    "No Critical, High, or exposed-secret findings "
                    "were detected."
                ),
            ]
        )

    lines.extend(
        [
            "",
            "ASSESSMENT LIMITATIONS",
            "-" * 72,
            (
                "Automated scanners may produce false positives and "
                "cannot detect every possible vulnerability. All "
                "findings should be validated through code review "
                "and authorised manual security testing."
            ),
            "",
        ]
    )

    TEXT_REPORT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def finding_html(
    number: int,
    finding: dict[str, Any],
) -> str:
    """Generate one detailed HTML finding card."""

    cwe_text = (
        ", ".join(
            str(item)
            for item in finding.get("cwe", [])
        )
        or "Not provided"
    )

    owasp_text = (
        ", ".join(
            str(item)
            for item in finding.get("owasp", [])
        )
        or "Not provided"
    )

    return f"""
    <section class="finding">
        <div class="finding-header">
            <h3>
                Finding {number}:
                {html.escape(str(finding["rule_id"]))}
            </h3>

            <span class="severity {html.escape(
                finding["severity"].lower()
            )}">
                {html.escape(finding["severity"])}
            </span>
        </div>

        <table>
            <tr>
                <th>Scanner</th>
                <td>{html.escape(finding["tool"])}</td>
            </tr>

            <tr>
                <th>Category</th>
                <td>{html.escape(finding["type"])}</td>
            </tr>

            <tr>
                <th>Affected file</th>
                <td>
                    <code>
                        {html.escape(str(finding["file"]))}
                    </code>
                </td>
            </tr>

            <tr>
                <th>Line</th>
                <td>
                    {html.escape(
                        str(finding.get("line") or "Unknown")
                    )}
                </td>
            </tr>

            <tr>
                <th>CWE</th>
                <td>{html.escape(cwe_text)}</td>
            </tr>

            <tr>
                <th>OWASP</th>
                <td>{html.escape(owasp_text)}</td>
            </tr>
        </table>

        <h4>Description</h4>

        <p>
            {html.escape(str(finding["title"]))}
        </p>

        <h4>Recommended Remediation</h4>

        <p>
            {html.escape(str(finding["recommendation"]))}
        </p>

        <h4>Verification</h4>

        <p>
            Apply the recommended remediation, review the modified
            source code and run the GitHub Actions security workflow
            again.
        </p>
    </section>
    """


def generate_html_report(
    report: dict[str, Any],
) -> None:
    """Generate a styled professional HTML report."""

    summary = report["summary"]
    scan = report["scan"]
    findings = report["findings"]

    finding_sections = "\n".join(
        finding_html(
            number,
            finding,
        )
        for number, finding in enumerate(
            findings,
            start=1,
        )
    )

    if not finding_sections:
        finding_sections = """
        <section class="clean-result">
            <h3>No Security Findings Detected</h3>

            <p>
                Semgrep and Gitleaks did not detect security findings
                during this scan.
            </p>
        </section>
        """

    if summary["quality_gate"] == "REVIEW REQUIRED":
        gate_class = "gate-review"
        gate_icon = "⚠️"
        gate_message = (
            "Critical, High, or exposed-secret findings were "
            "detected. Review the findings before deployment."
        )
    else:
        gate_class = "gate-pass"
        gate_icon = "✅"
        gate_message = (
            "No Critical, High, or exposed-secret findings "
            "were detected."
        )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        Courier Management System Security Report
    </title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: #f3f5f8;
            color: #1f2937;
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.6;
        }}

        .container {{
            width: min(1100px, 92%);
            margin: 30px auto;
        }}

        .cover {{
            padding: 45px;
            border-radius: 14px;
            background: #111827;
            color: white;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
        }}

        .cover h1 {{
            margin: 0 0 10px;
            font-size: 34px;
        }}

        .cover h2 {{
            margin: 0 0 25px;
            color: #d1d5db;
            font-size: 20px;
            font-weight: normal;
        }}

        .cover p {{
            margin: 5px 0;
            color: #d1d5db;
        }}

        .section {{
            margin-top: 24px;
            padding: 28px;
            border-radius: 14px;
            background: white;
            box-shadow: 0 5px 18px rgba(0, 0, 0, 0.07);
        }}

        .metrics {{
            display: grid;
            grid-template-columns:
                repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}

        .metric {{
            padding: 18px;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            background: #ffffff;
        }}

        .metric strong {{
            display: block;
            font-size: 28px;
        }}

        .metric span {{
            color: #6b7280;
        }}

        .finding {{
            margin-top: 20px;
            padding: 22px;
            border: 1px solid #e5e7eb;
            border-left: 6px solid #6b7280;
            border-radius: 10px;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            gap: 20px;
            align-items: center;
        }}

        .finding-header h3 {{
            margin: 0;
            overflow-wrap: anywhere;
        }}

        .severity {{
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            color: white;
            white-space: nowrap;
        }}

        .severity.critical {{
            background: #7f1d1d;
        }}

        .severity.high {{
            background: #dc2626;
        }}

        .severity.medium {{
            background: #d97706;
        }}

        .severity.low {{
            background: #2563eb;
        }}

        table {{
            width: 100%;
            margin-top: 15px;
            border-collapse: collapse;
        }}

        th,
        td {{
            padding: 10px;
            border: 1px solid #e5e7eb;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            width: 180px;
            background: #f9fafb;
        }}

        code {{
            overflow-wrap: anywhere;
        }}

        .clean-result {{
            padding: 24px;
            border-radius: 10px;
            background: #ecfdf5;
            border: 1px solid #10b981;
        }}

        .gate-pass {{
            padding: 20px;
            border-radius: 10px;
            color: #065f46;
            background: #ecfdf5;
            border: 1px solid #10b981;
        }}

        .gate-review {{
            padding: 20px;
            border-radius: 10px;
            color: #92400e;
            background: #fffbeb;
            border: 1px solid #f59e0b;
        }}

        footer {{
            padding: 30px 0;
            color: #6b7280;
            text-align: center;
        }}

        @media print {{
            body {{
                background: white;
            }}

            .container {{
                width: 100%;
                margin: 0;
            }}

            .section,
            .cover {{
                box-shadow: none;
            }}
        }}
    </style>
</head>

<body>
    <main class="container">
        <section class="cover">
            <h1>
                Automated Security Assessment Report
            </h1>

            <h2>
                Courier Management System
            </h2>

            <p>
                <strong>Repository:</strong>
                {html.escape(scan["repository"])}
            </p>

            <p>
                <strong>Branch:</strong>
                {html.escape(scan["branch"])}
            </p>

            <p>
                <strong>Commit:</strong>
                {html.escape(scan["commit"])}
            </p>

            <p>
                <strong>Generated:</strong>
                {html.escape(scan["generated_at"])}
            </p>
        </section>

        <section class="section">
            <h2>Executive Summary</h2>

            <div class="metrics">
                <div class="metric">
                    <strong>{summary["total"]}</strong>
                    <span>Total findings</span>
                </div>

                <div class="metric">
                    <strong>{summary["semgrep_total"]}</strong>
                    <span>Semgrep findings</span>
                </div>

                <div class="metric">
                    <strong>{summary["gitleaks_total"]}</strong>
                    <span>Gitleaks findings</span>
                </div>

                <div class="metric">
                    <strong>{summary["risk_score"]}/100</strong>
                    <span>Risk score</span>
                </div>

                <div class="metric">
                    <strong>{summary["risk_level"]}</strong>
                    <span>Risk level</span>
                </div>
            </div>
        </section>

        <section class="section">
            <h2>Severity Distribution</h2>

            <div class="metrics">
                <div class="metric">
                    <strong>{summary["critical"]}</strong>
                    <span>Critical</span>
                </div>

                <div class="metric">
                    <strong>{summary["high"]}</strong>
                    <span>High</span>
                </div>

                <div class="metric">
                    <strong>{summary["medium"]}</strong>
                    <span>Medium</span>
                </div>

                <div class="metric">
                    <strong>{summary["low"]}</strong>
                    <span>Low</span>
                </div>
            </div>
        </section>

        <section class="section">
            <h2>Security Quality Gate</h2>

            <div class="{gate_class}">
                <h3>
                    {gate_icon}
                    {html.escape(summary["quality_gate"])}
                </h3>

                <p>
                    {html.escape(gate_message)}
                </p>

                <p>
                    The GitHub Actions workflow remains successful
                    because the quality gate operates in reporting
                    mode.
                </p>
            </div>
        </section>

        <section class="section">
            <h2>Detailed Findings</h2>

            {finding_sections}
        </section>

        <section class="section">
            <h2>Assessment Limitations</h2>

            <p>
                Automated scanners may generate false positives and
                cannot identify every possible security weakness.
                Findings should be validated through secure code
                review and authorised manual security testing.
            </p>
        </section>

        <footer>
            Generated automatically by GitHub Actions,
            Semgrep and Gitleaks.
        </footer>
    </main>
</body>
</html>
"""

    HTML_REPORT.write_text(
        document,
        encoding="utf-8",
    )


def generate_github_summary(
    report: dict[str, Any],
) -> None:
    """Add security results to the GitHub Actions summary."""

    summary_path = os.environ.get(
        "GITHUB_STEP_SUMMARY"
    )

    if not summary_path:
        return

    summary = report["summary"]
    findings = report["findings"]

    lines = [
        "# Multi-Tool Security Scan",
        "",
        "## Scan Results",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Semgrep findings | "
        f"{summary['semgrep_total']} |",
        f"| Gitleaks findings | "
        f"{summary['gitleaks_total']} |",
        f"| Critical | {summary['critical']} |",
        f"| High | {summary['high']} |",
        f"| Medium | {summary['medium']} |",
        f"| Low | {summary['low']} |",
        f"| Total | {summary['total']} |",
        f"| Risk score | {summary['risk_score']}/100 |",
        f"| Risk level | {summary['risk_level']} |",
        f"| Quality gate | {summary['quality_gate']} |",
        "",
    ]

    if not findings:
        lines.append(
            "✅ No security findings were detected."
        )
    else:
        lines.extend(
            [
                "## First 20 Findings",
                "",
                "| Tool | Severity | Rule | File | Line |",
                "|---|---|---|---|---:|",
            ]
        )

        for finding in findings[:20]:
            rule = str(
                finding["rule_id"]
            ).replace(
                "|",
                "\\|",
            )

            file_path = str(
                finding["file"]
            ).replace(
                "|",
                "\\|",
            )

            lines.append(
                "| {tool} | {severity} | `{rule}` | "
                "`{file}` | {line} |".format(
                    tool=finding["tool"],
                    severity=finding["severity"],
                    rule=rule,
                    file=file_path,
                    line=(
                        finding.get("line")
                        or "Unknown"
                    ),
                )
            )

        if len(findings) > 20:
            lines.extend(
                [
                    "",
                    (
                        f"Only the first 20 of "
                        f"{len(findings)} findings are shown."
                    ),
                ]
            )

    with open(
        summary_path,
        "a",
        encoding="utf-8",
    ) as summary_file:
        summary_file.write(
            "\n".join(lines) + "\n"
        )


def main() -> int:
    """Run the combined security analysis."""

    semgrep_report = load_json(
        SEMGREP_REPORT,
        {
            "results": [],
            "errors": [],
        },
    )

    gitleaks_report = load_json(
        GITLEAKS_REPORT,
        [],
    )

    if not isinstance(
        semgrep_report,
        dict,
    ):
        print(
            "Semgrep report has an invalid format."
        )

        semgrep_report = {
            "results": [],
            "errors": [],
        }

    if not isinstance(
        gitleaks_report,
        list,
    ):
        print(
            "Gitleaks report has an invalid format."
        )

        gitleaks_report = []

    semgrep_findings = normalise_semgrep(
        semgrep_report
    )

    gitleaks_findings = normalise_gitleaks(
        gitleaks_report
    )

    findings = (
        semgrep_findings
        + gitleaks_findings
    )

    severity_counts: Counter[str] = Counter(
        finding["severity"]
        for finding in findings
    )

    risk_score, risk_level = calculate_risk_score(
        severity_counts
    )

    serious_findings_exist = (
        severity_counts.get(
            "CRITICAL",
            0,
        )
        > 0
        or severity_counts.get(
            "HIGH",
            0,
        )
        > 0
        or len(gitleaks_findings) > 0
    )

    quality_gate = (
        "REVIEW REQUIRED"
        if serious_findings_exist
        else "PASSED"
    )

    report = {
        "scan": {
            "repository": os.environ.get(
                "GITHUB_REPOSITORY",
                (
                    "Hashreena/"
                    "courier-management-system-security"
                ),
            ),
            "branch": os.environ.get(
                "GITHUB_REF_NAME",
                "Unknown",
            ),
            "commit": os.environ.get(
                "GITHUB_SHA",
                "Unknown",
            ),
            "workflow_run_id": os.environ.get(
                "GITHUB_RUN_ID",
                "Unknown",
            ),
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
        },
        "summary": {
            "semgrep_total": len(
                semgrep_findings
            ),
            "gitleaks_total": len(
                gitleaks_findings
            ),
            "critical": severity_counts.get(
                "CRITICAL",
                0,
            ),
            "high": severity_counts.get(
                "HIGH",
                0,
            ),
            "medium": severity_counts.get(
                "MEDIUM",
                0,
            ),
            "low": severity_counts.get(
                "LOW",
                0,
            ),
            "total": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "quality_gate": quality_gate,
            "workflow_status": "SUCCESS",
            "quality_gate_mode": "REPORTING",
        },
        "scanner_errors": {
            "semgrep": semgrep_report.get(
                "errors",
                [],
            ),
        },
        "findings": findings,
    }

    COMBINED_REPORT.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    generate_text_report(report)
    generate_html_report(report)
    generate_github_summary(report)

    write_github_output(
        "semgrep_total",
        len(semgrep_findings),
    )

    write_github_output(
        "gitleaks_total",
        len(gitleaks_findings),
    )

    write_github_output(
        "critical",
        severity_counts.get(
            "CRITICAL",
            0,
        ),
    )

    write_github_output(
        "high",
        severity_counts.get(
            "HIGH",
            0,
        ),
    )

    write_github_output(
        "medium",
        severity_counts.get(
            "MEDIUM",
            0,
        ),
    )

    write_github_output(
        "low",
        severity_counts.get(
            "LOW",
            0,
        ),
    )

    write_github_output(
        "total",
        len(findings),
    )

    write_github_output(
        "risk_score",
        risk_score,
    )

    write_github_output(
        "risk_level",
        risk_level,
    )

    write_github_output(
        "quality_gate",
        quality_gate,
    )

    write_github_output(
        "has_findings",
        str(
            bool(findings)
        ).lower(),
    )

    write_github_output(
        "should_fail",
        str(
            serious_findings_exist
        ).lower(),
    )

    print(
        "Combined security analysis completed."
    )

    print(
        f"Semgrep findings: "
        f"{len(semgrep_findings)}"
    )

    print(
        f"Gitleaks findings: "
        f"{len(gitleaks_findings)}"
    )

    print(
        f"Total findings: {len(findings)}"
    )

    print(
        f"Risk score: {risk_score}/100"
    )

    print(
        f"Risk level: {risk_level}"
    )

    print(
        f"Quality gate: {quality_gate}"
    )

    print(
        "Quality gate mode: REPORTING"
    )

    print(
        "Workflow status: SUCCESS"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
