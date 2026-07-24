import json
import os
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth


def jira_request(
    method: str,
    url: str,
    auth: HTTPBasicAuth,
    **kwargs,
) -> requests.Response:
    """Send a Jira API request and print useful error information."""
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


def main() -> int:
    report_path = Path("semgrep-report.json")

    if not report_path.exists():
        print("Semgrep report was not found.")
        return 1

    try:
        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as error:
        print(f"Unable to read Semgrep report: {error}")
        return 1

    results = report.get("results", [])

    if not results:
        print("No findings detected. Jira issue will not be created.")
        return 0

    base_url = os.environ["JIRA_BASE_URL"].rstrip("/")
    email = os.environ["JIRA_EMAIL"]
    token = os.environ["JIRA_API_TOKEN"]
    project_key = os.environ["JIRA_PROJECT_KEY"]

    auth = HTTPBasicAuth(email, token)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # 1. Verify authentication
    myself_response = jira_request(
        "GET",
        f"{base_url}/rest/api/3/myself",
        auth,
        headers={"Accept": "application/json"},
    )

    if not myself_response.ok:
        print(
            "Authentication failed. Check JIRA_EMAIL and "
            "JIRA_API_TOKEN."
        )
        return 1

    account = myself_response.json()
    print(
        "Authenticated Jira account: "
        f"{account.get('displayName', 'Unknown')}"
    )

    # 2. Verify that the project is accessible
    project_response = jira_request(
        "GET",
        f"{base_url}/rest/api/3/project/{project_key}",
        auth,
        headers={"Accept": "application/json"},
    )

    if not project_response.ok:
        print(
            f"Project {project_key} is not accessible through the API."
        )
        print(
            "Confirm that the authenticated account can browse and "
            "create work items in this Jira space."
        )
        return 1

    project = project_response.json()
    project_id = project.get("id")
    project_name = project.get("name", project_key)

    print(
        f"Accessible Jira project: {project_name} "
        f"({project_key}, ID {project_id})"
    )

    # 3. Get valid issue/work-item types for this project
    issue_types_response = jira_request(
        "GET",
        (
            f"{base_url}/rest/api/3/issue/createmeta/"
            f"{project_id}/issuetypes"
        ),
        auth,
        headers={"Accept": "application/json"},
    )

    if not issue_types_response.ok:
        print("Unable to retrieve valid Jira work-item types.")
        return 1

    issue_type_data = issue_types_response.json()
    issue_types = issue_type_data.get("issueTypes", [])

    if not issue_types:
        print("No issue types are available for this project.")
        return 1

    print("Available Jira work-item types:")

    for issue_type in issue_types:
        print(
            f"- {issue_type.get('name')} "
            f"(ID: {issue_type.get('id')})"
        )

    # Prefer Task, then Bug, then Story, otherwise use the first type
    preferred_names = ["Task", "Bug", "Story"]

    selected_type = None

    for preferred_name in preferred_names:
        selected_type = next(
            (
                issue_type
                for issue_type in issue_types
                if issue_type.get("name", "").lower()
                == preferred_name.lower()
            ),
            None,
        )

        if selected_type:
            break

    if not selected_type:
        selected_type = issue_types[0]

    issue_type_id = selected_type["id"]
    issue_type_name = selected_type.get("name", "Unknown")

    print(
        f"Selected Jira work-item type: "
        f"{issue_type_name} ({issue_type_id})"
    )

    # 4. Prepare findings for Jira
    finding_lines = []

    for result in results[:10]:
        severity = (
            result.get("extra", {})
            .get("severity", "UNKNOWN")
        )
        rule = result.get("check_id", "Unknown rule")
        file_path = result.get("path", "Unknown file")
        line = result.get("start", {}).get("line", "Unknown")

        finding_lines.append(
            f"{severity}: {rule} in {file_path}, line {line}"
        )

    description_content = [
        {
            "type": "paragraph",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "The automated GitHub Actions Semgrep scan "
                        f"detected {len(results)} potential security "
                        "findings."
                    ),
                }
            ],
        }
    ]

    for finding in finding_lines:
        description_content.append(
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": finding[:1000],
                    }
                ],
            }
        )

    payload = {
        "fields": {
            "project": {
                "id": project_id,
            },
            "summary": (
                f"Automated Semgrep scan detected "
                f"{len(results)} findings"
            ),
            "description": {
                "type": "doc",
                "version": 1,
                "content": description_content,
            },
            "issuetype": {
                "id": issue_type_id,
            },
            "labels": [
                "security",
                "semgrep",
                "automation",
            ],
        }
    }

    # 5. Create Jira issue
    create_response = jira_request(
        "POST",
        f"{base_url}/rest/api/3/issue",
        auth,
        headers=headers,
        json=payload,
    )

    if create_response.status_code not in {200, 201}:
        print("Failed to create Jira issue.")
        return 1

    issue = create_response.json()
    issue_key = issue["key"]

    print(f"Jira issue created successfully: {issue_key}")
    print(f"Jira issue URL: {base_url}/browse/{issue_key}")

    github_output = os.environ.get("GITHUB_OUTPUT")

    if github_output:
        with open(
            github_output,
            "a",
            encoding="utf-8",
        ) as output:
            output.write(f"issue_key={issue_key}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
