from __future__ import annotations

import json
import mimetypes
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path


REPORT_PATH = Path("combined-security-report.json")


def attach_file(
    message: EmailMessage,
    path: Path,
) -> None:
    """Attach a report file to the email."""

    if not path.exists():
        print(f"Attachment not found: {path}")
        return

    mime_type, _ = mimetypes.guess_type(path.name)

    if mime_type:
        main_type, sub_type = mime_type.split("/", 1)
    else:
        main_type = "application"
        sub_type = "octet-stream"

    message.add_attachment(
        path.read_bytes(),
        maintype=main_type,
        subtype=sub_type,
        filename=path.name,
    )


def main() -> int:
    if not REPORT_PATH.exists():
        print("Combined security report does not exist.")
        return 1

    required_variables = [
        "SMTP_SERVER",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "EMAIL_TO",
    ]

    missing_variables = [
        variable
        for variable in required_variables
        if not os.environ.get(variable)
    ]

    if missing_variables:
        print(
            "Missing email environment variables: "
            + ", ".join(missing_variables)
        )
        return 1

    try:
        report = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        print(f"Unable to read combined report: {error}")
        return 1

    summary = report.get("summary", {})
    scan = report.get("scan", {})

    smtp_server = os.environ["SMTP_SERVER"]
    smtp_port = int(os.environ["SMTP_PORT"])
    smtp_username = os.environ["SMTP_USERNAME"]
    smtp_password = os.environ["SMTP_PASSWORD"]
    email_to = os.environ["EMAIL_TO"]

    email_from = os.environ.get(
        "EMAIL_FROM",
        smtp_username,
    )

    jira_issue_key = os.environ.get(
        "JIRA_ISSUE_KEY",
        "",
    )
    jira_issue_url = os.environ.get(
        "JIRA_ISSUE_URL",
        "",
    )

    quality_gate = summary.get(
        "quality_gate",
        "UNKNOWN",
    )

    message = EmailMessage()
    message["From"] = email_from
    message["To"] = email_to
    message["Subject"] = (
        f"[{quality_gate}] Security Scan - "
        f"{scan.get('repository', 'Courier Management System')}"
    )

    jira_section = (
        f"Jira issue: {jira_issue_key}\n"
        f"Jira URL: {jira_issue_url}"
        if jira_issue_key
        else "Jira issue: No Jira issue was created."
    )

    body = f"""
Automated Security Scan Completed

Repository:
{scan.get("repository", "Unknown")}

Branch:
{scan.get("branch", "Unknown")}

Commit:
{scan.get("commit", "Unknown")}

Security Results
----------------
Semgrep findings: {summary.get("semgrep_total", 0)}
Gitleaks findings: {summary.get("gitleaks_total", 0)}
Critical: {summary.get("critical", 0)}
High: {summary.get("high", 0)}
Medium: {summary.get("medium", 0)}
Low: {summary.get("low", 0)}
Total findings: {summary.get("total", 0)}

Risk score:
{summary.get("risk_score", 0)}/100

Risk level:
{summary.get("risk_level", "UNKNOWN")}

Security quality gate:
{quality_gate}

{jira_section}

Recommended Action
------------------
Review the attached security reports and the corresponding Jira
issue. Critical, High and exposed-secret findings should be
remediated before the code is merged into the protected main branch.

This email was generated automatically by GitHub Actions.
""".strip()

    message.set_content(body)

    attach_file(
        message,
        Path("security-report.txt"),
    )
    attach_file(
        message,
        Path("security-report.html"),
    )
    attach_file(
        message,
        Path("combined-security-report.json"),
    )

    ssl_context = ssl.create_default_context()

    try:
        with smtplib.SMTP(
            smtp_server,
            smtp_port,
            timeout=30,
        ) as smtp:
            smtp.ehlo()
            smtp.starttls(
                context=ssl_context,
            )
            smtp.ehlo()
            smtp.login(
                smtp_username,
                smtp_password,
            )
            smtp.send_message(message)
    except (
        smtplib.SMTPException,
        OSError,
    ) as error:
        print(f"Unable to send notification email: {error}")
        return 1

    print(f"Security notification sent to {email_to}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
