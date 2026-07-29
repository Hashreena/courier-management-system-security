from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
from requests.auth import HTTPBasicAuth


REPORT_PATH = Path("combined-security-report.json")


def jira_request(
    method: str,
    url: str,
    auth: HTTPBasicAuth,
    **kwargs: Any,
) -> requests.Response:
    """Send a Jira API request with useful error output."""

    response = requests.request(
        method=method,
        url=url,
        auth=auth,
        timeout=30,
        **kwargs,
    )

    if not response.ok:
        print(f"Jira API request failed: {method} {url}")
        print(f"Status code: {response.status_code}")
        print(response.text)

    return response


def adf_paragraph(
    text: str,
) -> dict[str, Any]:
    """Create one Jira Atlassian Document Format paragraph."""

    return {
        "type": "paragraph",
        "content": [
            {
                "type": "text",
                "text": text[:30000],
            }
        ],
    }


def get_issue_type(
    base_url: str,
    project_id: str,
    auth: HTTPBasicAuth,
) -> dict[str, Any] | None:
    """Retrieve a valid Jira issue type for the project."""

    response = jira_request(
        "GET",
        (
            f"{base_url}/rest/api/3/issue/createmeta/"
            f"{project_id}/issuetypes"
        ),
        auth,
        headers={
            "Accept": "application/json",
        },
    )

    if not response.ok:
        return None

    issue_types = response.json().get("issueTypes", [])

    preferred_names = [
        "Task",
        "Bug",
        "Story",
    ]

    for preferred_name in preferred_names:
        for issue_type in issue_types:
            if (
                issue_type.get("name", "").lower()
                == preferred_name.lower()
            ):
                return issue_type

    return issue_types[0] if issue_types else None


def main() -> int:
    if not REPORT_PATH.exists():
        print("Combined security report was not found.")
        return 1

    try:
        report = json.loads(
            REPORT_PATH.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        print(f"Unable to read combined report: {error}")
        return 1

    summary = report.get("summary", {})
    findings = report.get("findings", [])

    if not findings:
        print(
            "No security findings detected. "
            "No Jira issue will be created."
        )
        return 0

    required_variables = [
        "JIRA_BASE_URL",
        "JIRA_EMAIL",
        "JIRA_API_TOKEN",
        "JIRA_PROJECT_KEY",
    ]

    missing_variables = [
        variable
        for variable in required_variables
        if not os.environ.get(variable)
    ]

    if missing_variables:
        print(
            "Missing Jira environment variables: "
            + ", ".join(missing_variables)
        )
        return 1

    base_url = os.environ["JIRA_BASE_URL"].rstrip("/")
    email = os.environ["JIRA_EMAIL"]
    token = os.environ["JIRA_API_TOKEN"]
    project_key = os.environ["JIRA_PROJECT_KEY"]

    auth = HTTPBasicAuth(
        email,
        token,
    )

    myself_response = jira_request(
        "GET",
        f"{base_url}/rest/api/3/myself",
        auth,
        headers={
            "Accept": "application/json",
        },
    )

    if not myself_response.ok:
        print(
            "Jira authentication failed. Check JIRA_EMAIL "
            "and JIRA_API_TOKEN."
        )
        return 1

    project_response = jira_request(
        "GET",
        f"{base_url}/rest/api/3/project/{project_key}",
        auth,
        headers={
            "Accept": "application/json",
        },
    )

    if not project_response.ok:
        print(
            f"Jira project {project_key} could not be accessed."
        )
        return 1

    project = project_response.json()
    project_id = project["id"]

    selected_issue_type = get_issue_type(
        base_url,
        project_id,
        auth,
    )

    if not selected_issue_type:
        print("No valid Jira issue type was found.")
        return 1

    description_content = [
        adf_paragraph(
            "An automated GitHub Actions security scan detected "
            f"{summary.get('total', 0)} security findings."
        ),
        adf_paragraph(
            "Scan summary:"
        ),
        adf_paragraph(
            f"Semgrep findings: "
            f"{summary.get('semgrep_total', 0)}"
        ),
        adf_paragraph(
            f"Gitleaks findings: "
            f"{summary.get('gitleaks_total', 0)}"
        ),
        adf_paragraph(
            f"Critical: {summary.get('critical', 0)}"
        ),
        adf_paragraph(
            f"High: {summary.get('high', 0)}"
        ),
        adf_paragraph(
            f"Medium: {summary.get('medium', 0)}"
        ),
        adf_paragraph(
            f"Low: {summary.get('low', 0)}"
        ),
        adf_paragraph(
            f"Risk score: {summary.get('risk_score', 0)}/100"
        ),
        adf_paragraph(
            f"Risk level: {summary.get('risk_level', 'UNKNOWN')}"
        ),
        adf_paragraph(
            f"Quality gate: "
            f"{summary.get('quality_gate', 'UNKNOWN')}"
        ),
        adf_paragraph(
            "Detected findings:"
        ),
    ]

    for number, finding in enumerate(
        findings[:20],
        start=1,
    ):
        description_content.append(
            adf_paragraph(
                f"{number}. [{finding.get('tool', 'Unknown')}] "
                f"[{finding.get('severity', 'UNKNOWN')}] "
                f"{finding.get('rule_id', 'Unknown rule')} in "
                f"{finding.get('file', 'Unknown file')}, line "
                f"{finding.get('line') or 'Unknown'}. "
                f"{finding.get('title', 'No description')}"
            )
        )

    if len(findings) > 20:
        description_content.append(
            adf_paragraph(
                f"Only the first 20 of {len(findings)} findings "
                "are displayed here. Review the attached reports "
                "for the complete results."
            )
        )

    github_server = os.environ.get(
        "GITHUB_SERVER_URL",
        "https://github.com",
    )
    github_repository = os.environ.get(
        "GITHUB_REPOSITORY",
        "",
    )
    github_run_id = os.environ.get(
        "GITHUB_RUN_ID",
        "",
    )

    workflow_url = (
        f"{github_server}/{github_repository}/actions/runs/"
        f"{github_run_id}"
    )

    description_content.append(
        adf_paragraph(
            f"GitHub Actions workflow: {workflow_url}"
        )
    )

    payload = {
        "fields": {
            "project": {
                "id": project_id,
            },
            "summary": (
                "[Automated Security] "
                f"{summary.get('total', 0)} findings detected - "
                f"Risk {summary.get('risk_level', 'UNKNOWN')}"
            )[:255],
            "description": {
                "type": "doc",
                "version": 1,
                "content": description_content,
            },
            "issuetype": {
                "id": selected_issue_type["id"],
            },
            "labels": [
                "security",
                "automation",
                "semgrep",
                "gitleaks",
                "github-actions",
                str(
                    summary.get(
                        "risk_level",
                        "unknown",
                    )
                ).lower(),
            ],
        }
    }

    create_response = jira_request(
        "POST",
        f"{base_url}/rest/api/3/issue",
        auth,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
    )

    if create_response.status_code not in {
        200,
        201,
    }:
        print("Failed to create Jira issue.")
        return 1

    issue = create_response.json()
    issue_key = issue["key"]
    issue_url = f"{base_url}/browse/{issue_key}"

    print(f"Jira issue created: {issue_key}")
    print(f"Jira issue URL: {issue_url}")

    github_output = os.environ.get("GITHUB_OUTPUT")

    if github_output:
        with open(
            github_output,
            "a",
            encoding="utf-8",
        ) as output_file:
            output_file.write(
                f"issue_key={issue_key}\n"
            )
            output_file.write(
                f"issue_url={issue_url}\n"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
