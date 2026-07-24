import json
import os
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth


def main() -> int:
    report_path = Path("semgrep-report.json")

    if not report_path.exists():
        print("Semgrep report was not found.")
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    results = report.get("results", [])

    if not results:
        print("No findings detected. Jira issue will not be created.")
        return 0

    base_url = os.environ["JIRA_BASE_URL"].rstrip("/")
    email = os.environ["JIRA_EMAIL"]
    token = os.environ["JIRA_API_TOKEN"]
    project_key = os.environ["JIRA_PROJECT_KEY"]

    finding_lines = []

    for result in results[:10]:
        severity = result.get("extra", {}).get("severity", "UNKNOWN")
        rule = result.get("check_id", "Unknown rule")
        path = result.get("path", "Unknown file")
        line = result.get("start", {}).get("line", "Unknown")

        finding_lines.append(
            f"- {severity}: {rule} in {path}, line {line}"
        )

    description_text = "\n".join(finding_lines)

    payload = {
        "fields": {
            "project": {
                "key": project_key
            },
            "summary": (
                f"Automated Semgrep scan detected "
                f"{len(results)} findings"
            ),
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    "The GitHub Actions Semgrep scan "
                                    f"detected {len(results)} potential "
                                    "security findings."
                                )
                            }
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": description_text[:3000]
                            }
                        ]
                    }
                ]
            },
            "issuetype": {
                "name": "Task"
            },
            "labels": [
                "security",
                "semgrep",
                "automation"
            ]
        }
    }

    response = requests.post(
        f"{base_url}/rest/api/3/issue",
        auth=HTTPBasicAuth(email, token),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        json=payload,
        timeout=30
    )

    if response.status_code not in {200, 201}:
        print("Failed to create Jira issue.")
        print(response.status_code)
        print(response.text)
        return 1

    issue = response.json()
    issue_key = issue["key"]

    print(f"Jira issue created successfully: {issue_key}")

    with open(
        os.environ["GITHUB_OUTPUT"],
        "a",
        encoding="utf-8"
    ) as output:
        output.write(f"issue_key={issue_key}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
