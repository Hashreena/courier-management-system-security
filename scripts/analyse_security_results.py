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
    """Safely load a JSON file."""

    if not path.exists():
        print(f"Warning: {path} does not exist.")
        return default

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Warning: Unable to read {path}: {error}")
        return default


def write_github_output(
    name: str,
    value: str | int,
) -> None:
    """Write a value for later GitHub Actions steps."""

    output_path = os.environ.get("GITHUB_OUTPUT")

    if not output_path:
        return

    with open(output_path, "a", encoding="utf-8") as output_file:
        output_file.write(f"{name}={value}\n")


def normalise_semgrep(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Convert Semgrep findings into a common structure."""

    normalised: list[dict[str, Any]] = []

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
            extra.get("severity", "UNKNOWN")
        ).upper()

        severity = severity_mapping.get(
            original_severity,
            "LOW",
        )

        cwe = metadata.get("cwe", [])

        if isinstance(cwe, str):
            cwe = [cwe]

        owasp = metadata.get("owasp", [])

        if isinstance(owasp, str):
            owasp = [owasp]

        references = metadata.get("references", [])

        if isinstance(references, str):
            references = [references]

        normalised.append(
            {
                "tool": "Semgrep",
                "type": "SAST",
                "severity": severity,
                "original_severity": original_severity,
                "title": extra.get(
                    "message",
                    result.get("check_id", "Semgrep finding"),
                ),
                "rule_id": result.get(
                    "check_id",
                    "unknown-rule",
                ),
                "file": result.get(
                    "path",
                    "Unknown file",
                ),
                "line": start.get("line"),
                "column": start.get("col"),
                "end_line": end.get("line"),
                "cwe": cwe,
                "owasp": owasp,
                "references": references,
                "recommendation": (
                    extra.get("fix")
                    or metadata.get("fix")
                    or (
                        "Review the affected code and replace the "
                        "insecure implementation with a validated, "
                        "secure coding approach."
                    )
                ),
            }
        )

    return normalised


def normalise_gitleaks(
    report: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert Gitleaks findings into the common structure."""

    normalised: list[dict[str, Any]] = []

    for finding in report:
        rule_id = (
            finding.get("RuleID")
            or finding.get("RuleId")
            or finding.get("rule_id")
            or "secret-detected"
        )

        description = (
            finding.get("Description")
            or finding.get("description")
            or "Potential secret detected in the repository."
        )

        file_path = (
            finding.get("File")
            or finding.get("file")
            or "Unknown file"
        )

        line_number = (
            finding.get("StartLine")
            or finding.get("start_line")
        )

        commit = (
            finding.get("Commit")
            or finding.get("commit")
            or ""
        )

        normalised.append(
            {
                "tool": "Gitleaks",
                "type": "Secret Scanning",
                "severity": "HIGH",
                "original_severity": "SECRET",
                "title": description,
                "rule_id": rule_id,
                "file": file_path,
                "line": line_number,
                "column": finding.get("StartColumn"),
                "end_line": finding.get("EndLine"),
                "commit": commit,
                "cwe": ["CWE-798"],
                "owasp": ["A07:2021 Identification and Authentication Failures"],
                "references": [],
                "recommendation": (
                    "Remove the exposed secret from the source code "
                    "and Git history, revoke or rotate the affected "
                    "credential, and store the replacement in GitHub "
                    "Actions Secrets or another approved secret manager."
                ),
            }
        )

    return normalised


def calculate_risk_score(
    severity_counts: Counter[str],
) -> tuple[int, str]:
    """Calculate a capped project risk score."""

    raw_score = (
        severity_counts.get("CRITICAL", 0) * 10
        + severity_counts.get("HIGH", 0) * 7
        + severity_counts.get("MEDIUM", 0) * 4
        + severity_counts.get("LOW", 0)
    )

    risk_score = min(raw_score, 100)

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
    data: dict[str, Any],
) -> None:
    """Generate a readable plain-text security report."""

    summary = data["summary"]
    repository = data["scan"]["repository"]
    branch = data["scan"]["branch"]
    commit = data["scan"]["commit"]

    lines = [
        "Courier Management System",
        "Automated Multi-Tool Security Report",
        "=" * 68,
        "",
        "SCAN INFORMATION",
        "-" * 68,
        f"Repository: {repository}",
        f"Branch: {branch}",
        f"Commit: {commit}",
        f"Generated: {data['scan']['generated_at']}",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 68,
        f"Total findings: {summary['total']}",
        f"Semgrep findings: {summary['semgrep_total']}",
        f"Gitleaks findings: {summary['gitleaks_total']}",
        f"Critical: {summary['critical']}",
        f"High: {summary['high']}",
        f"Medium: {summary['medium']}",
        f"Low: {summary['low']}",
        f"Risk score: {summary['risk_score']}/100",
        f"Risk level: {summary['risk_level']}",
        "",
        "DETAILED FINDINGS",
        "-" * 68,
    ]

    findings = data["findings"]

    if not findings:
        lines.extend(
            [
                "",
                "No Semgrep vulnerabilities or Gitleaks secrets "
                "were detected.",
            ]
        )

    for number, finding in enumerate(findings, start=1):
        cwe_text = ", ".join(finding.get("cwe", [])) or "Not provided"
        owasp_text = (
            ", ".join(finding.get("owasp", []))
            or "Not provided"
        )

        lines.extend(
            [
                "",
                f"Finding {number}",
                f"Tool: {finding['tool']}",
                f"Category: {finding['type']}",
                f"Severity: {finding['severity']}",
                f"Rule: {finding['rule_id']}",
                f"File: {finding['file']}",
                f"Line: {finding.get('line') or 'Unknown'}",
                f"Description: {finding['title']}",
                f"CWE: {cwe_text}",
                f"OWASP: {owasp_text}",
                f"Recommendation: {finding['recommendation']}",
            ]
        )

    lines.extend(
        [
            "",
            "QUALITY GATE",
            "-" * 68,
            (
                "FAILED - Critical, High, or secret findings exist."
                if summary["quality_gate"] == "FAILED"
                else "PASSED - No Critical or High findings exist."
            ),
            "",
            "LIMITATIONS",
            "-" * 68,
            (
                "Automated tools may produce false positives and "
                "cannot identify every security weakness. Findings "
                "should be reviewed and validated by a security analyst."
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
    """Create an HTML card for one finding."""

    cwe_text = ", ".join(finding.get("cwe", [])) or "Not provided"
    owasp_text = ", ".join(
        finding.get("owasp", [])
    ) or "Not provided"

    return f"""
    <section class="finding">
        <div class="finding-header">
            <h3>Finding {number}: {html.escape(str(finding["rule_id"]))}</h3>
            <span class="severity {html.escape(finding["severity"].lower())}">
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
                <td><code>{html.escape(str(finding["file"]))}</code></td>
            </tr>
            <tr>
                <th>Line</th>
                <td>{html.escape(str(finding.get("line") or "Unknown"))}</td>
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
        <p>{html.escape(str(finding["title"]))}</p>

        <h4>Recommended remediation</h4>
        <p>{html.escape(str(finding["recommendation"]))}</p>

        <h4>Verification</h4>
        <p>
            Apply the recommended remediation, review the modified code,
            and run the GitHub Actions security workflow again.
        </p>
    </section>
    """


def generate_html_report(
    data: dict[str, Any],
) -> None:
    """Generate a styled HTML security report."""

    summary = data["summary"]
    findings = data["findings"]

    finding_sections = "\n".join(
        finding_html(number, finding)
        for number, finding in enumerate(findings, start=1)
    )

    if not finding_sections:
        finding_sections = """
        <section class="clean-result">
            <h3>No findings detected</h3>
            <p>
                Semgrep and Gitleaks did not detect security findings
                in this scan.
            </p>
        </section>
        """

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >
    <title>Automated Security Report</title>

    <style>
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

        .cover p {{
            margin: 4px 0;
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
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}

        .metric {{
            padding: 18px;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
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

        .severity {{
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            color: white;
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
            color: #047857;
        }}

        .gate-fail {{
            color: #b91c1c;
        }}

        footer {{
            padding: 30px 0;
            color: #6b7280;
            text-align: center;
        }}
    </style>
</head>

<body>
    <main class="container">
        <section class="cover">
            <h1>Automated Security Assessment Report</h1>
            <p>Courier Management System</p>
            <p>
                Repository:
                {html.escape(data["scan"]["repository"])}
            </p>
            <p>
                Branch:
                {html.escape(data["scan"]["branch"])}
            </p>
            <p>
                Commit:
                {html.escape(data["scan"]["commit"])}
            </p>
            <p>
                Generated:
                {html.escape(data["scan"]["generated_at"])}
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
                    <span>Exposed secrets</span>
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
            <h3 class="{
                "gate-fail"
                if summary["quality_gate"] == "FAILED"
                else "gate-pass"
            }">
                {summary["quality_gate"]}
            </h3>

            <p>
                The workflow fails when a Critical, High, or exposed
                secret finding is detected.
            </p>
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
                Findings should be validated through code review and
                authorised manual security testing.
            </p>
        </section>

        <footer>
            Generated automatically by GitHub Actions, Semgrep and
            Gitleaks.
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
    data: dict[str, Any],
) -> None:
    """Add the scan results to the GitHub Actions summary page."""

    output_path = os.environ.get("GITHUB_STEP_SUMMARY")

    if not output_path:
        return

    summary = data["summary"]

    lines = [
        "# Multi-Tool Security Scan",
        "",
        "## Scan Results",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Semgrep findings | {summary['semgrep_total']} |",
        f"| Gitleaks findings | {summary['gitleaks_total']} |",
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

    if not data["findings"]:
        lines.append("✅ No security findings were detected.")
    else:
        lines.extend(
            [
                "## First 20 Findings",
                "",
                "| Tool | Severity | Rule | File | Line |",
                "|---|---|---|---|---:|",
            ]
        )

        for finding in data["findings"][:20]:
            lines.append(
                "| {tool} | {severity} | `{rule}` | `{file}` | "
                "{line} |".format(
                    tool=finding["tool"],
                    severity=finding["severity"],
                    rule=str(finding["rule_id"]).replace("|", "\\|"),
                    file=str(finding["file"]).replace("|", "\\|"),
                    line=finding.get("line") or "Unknown",
                )
            )

    with open(output_path, "a", encoding="utf-8") as output_file:
        output_file.write("\n".join(lines) + "\n")


def main() -> int:
    semgrep_report = load_json(
        SEMGREP_REPORT,
        {"results": [], "errors": []},
    )

    gitleaks_report = load_json(
        GITLEAKS_REPORT,
        [],
    )

    if not isinstance(semgrep_report, dict):
        semgrep_report = {"results": [], "errors": []}

    if not isinstance(gitleaks_report, list):
        gitleaks_report = []

    semgrep_findings = normalise_semgrep(semgrep_report)
    gitleaks_findings = normalise_gitleaks(gitleaks_report)

    findings = semgrep_findings + gitleaks_findings

    severity_counts: Counter[str] = Counter(
        finding["severity"] for finding in findings
    )

    risk_score, risk_level = calculate_risk_score(
        severity_counts
    )

    should_fail = (
        severity_counts.get("CRITICAL", 0) > 0
        or severity_counts.get("HIGH", 0) > 0
    )

    quality_gate = "FAILED" if should_fail else "PASSED"

    data = {
        "scan": {
            "repository": os.environ.get(
                "GITHUB_REPOSITORY",
                "Hashreena/courier-management-system-security",
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
            "semgrep_total": len(semgrep_findings),
            "gitleaks_total": len(gitleaks_findings),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "total": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "quality_gate": quality_gate,
        },
        "scanner_errors": {
            "semgrep": semgrep_report.get("errors", []),
        },
        "findings": findings,
    }

    COMBINED_REPORT.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    generate_text_report(data)
    generate_html_report(data)
    generate_github_summary(data)

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
        severity_counts.get("CRITICAL", 0),
    )
    write_github_output(
        "high",
        severity_counts.get("HIGH", 0),
    )
    write_github_output(
        "medium",
        severity_counts.get("MEDIUM", 0),
    )
    write_github_output(
        "low",
        severity_counts.get("LOW", 0),
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
        "has_findings",
        str(bool(findings)).lower(),
    )
    write_github_output(
        "should_fail",
        str(should_fail).lower(),
    )

    print("Combined analysis completed.")
    print(f"Semgrep findings: {len(semgrep_findings)}")
    print(f"Gitleaks findings: {len(gitleaks_findings)}")
    print(f"Total findings: {len(findings)}")
    print(f"Risk score: {risk_score}/100")
    print(f"Quality gate: {quality_gate}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
