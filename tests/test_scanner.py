from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_actions_guard.cli import main
from agentic_actions_guard.scanner import ScanError, scan


RISKY_WORKFLOW = """name: Review PR with Claude
on:
  pull_request_target:
jobs:
  review:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.REVIEW_KEY }}
    steps:
      - name: Run Claude agent
        uses: vendor/claude-agent-action@v1
        with:
          prompt: "Review this contribution: ${{ github.event.pull_request.body }}"
"""


def test_detects_untrusted_input_secrets_target_and_write_scope(tmp_path: Path):
    workflow = tmp_path / "review.yml"
    workflow.write_text(RISKY_WORKFLOW, encoding="utf-8")

    findings = scan(workflow)
    rules = {item["rule_id"] for item in findings}

    assert rules == {
        "AGENT_UNTRUSTED_EVENT_INPUT",
        "AGENT_SECRET_REFERENCE",
        "AGENT_ON_PULL_REQUEST_TARGET",
        "AGENT_WITH_WRITE_PERMISSION",
    }
    secret_finding = next(item for item in findings if item["rule_id"] == "AGENT_SECRET_REFERENCE")
    assert "REVIEW_KEY" not in secret_finding["evidence"]


def test_safe_read_only_agent_workflow_has_no_findings(tmp_path: Path):
    workflow = tmp_path / "safe.yaml"
    workflow.write_text("""name: Review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    steps:
      - name: Run Claude agent
        uses: vendor/claude-agent-action@v1
        with:
          prompt: Review the checked-out code for style issues.
""", encoding="utf-8")

    assert scan(workflow) == []


def test_detects_workflow_run_payload_as_untrusted_input(tmp_path: Path):
    workflow = tmp_path / "workflow-run.yml"
    expression = "${{ github.event.workflow_run.head_branch }}"
    workflow.write_text(
        f"""name: Review
on: workflow_run
permissions:
  contents: read
jobs:
  review:
    steps:
      - name: Run agent
        uses: vendor/claude-agent-action@v1
        with:
          prompt: "Review run: {expression}"
""",
        encoding="utf-8",
    )

    findings = scan(workflow)

    event_finding = next(item for item in findings if item["rule_id"] == "AGENT_UNTRUSTED_EVENT_INPUT")
    assert event_finding["evidence"] in expression


@pytest.mark.parametrize("env_scope", ["workflow", "job"])
def test_detects_untrusted_event_input_in_inherited_environment(tmp_path: Path, env_scope: str):
    workflow = tmp_path / f"{env_scope}-env.yml"
    expression = "${{ github.event.pull_request.body }}"
    workflow_env = f"env:\n  REVIEW_CONTEXT: {expression}\n" if env_scope == "workflow" else ""
    job_env = f"    env:\n      REVIEW_CONTEXT: {expression}\n" if env_scope == "job" else ""
    workflow.write_text(
        f"""name: Review
on: pull_request
{workflow_env}jobs:
  review:
{job_env}    permissions:
      contents: read
    steps:
      - name: Run agent
        run: echo review
""",
        encoding="utf-8",
    )

    findings = scan(workflow)

    event_finding = next(item for item in findings if item["rule_id"] == "AGENT_UNTRUSTED_EVENT_INPUT")
    assert event_finding["evidence"] in expression


def test_warns_when_agent_job_has_no_explicit_permissions(tmp_path: Path):
    workflow = tmp_path / "implicit.yml"
    workflow.write_text("""jobs:
  review:
    steps:
      - name: Run agent
        run: echo agent review
""", encoding="utf-8")

    findings = scan(workflow)
    assert [item["rule_id"] for item in findings] == ["AGENT_IMPLICIT_TOKEN_PERMISSIONS"]


def test_does_not_execute_workflow_run_commands(tmp_path: Path):
    marker = tmp_path / "should-not-exist"
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(f"""jobs:
  test:
    steps:
      - name: Run agent
        run: touch {marker}
""", encoding="utf-8")

    scan(workflow)
    assert not marker.exists()


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path):
    workflow = tmp_path / "duplicate.yml"
    workflow.write_text("""jobs:
  review:
    steps: []
    steps: []
""", encoding="utf-8")

    with pytest.raises(ScanError, match="invalid YAML"):
        scan(workflow)


def test_repository_root_discovers_github_workflows(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "review.yml").write_text(RISKY_WORKFLOW, encoding="utf-8")
    (tmp_path / "unrelated.yml").write_text("not: scanned\n", encoding="utf-8")

    assert scan(tmp_path)


def test_cli_json_and_fail_on_exit_code(tmp_path: Path, capsys):
    workflow = tmp_path / "risky.yml"
    workflow.write_text(RISKY_WORKFLOW, encoding="utf-8")

    status = main([str(workflow), "--json", "--fail-on", "high"])
    output = json.loads(capsys.readouterr().out)

    assert status == 1
    assert output["schema_version"] == "1"
    assert output["findings"]


def test_cli_returns_two_for_invalid_path(tmp_path: Path, capsys):
    status = main([str(tmp_path / "missing.yml")])
    assert status == 2
    assert "does not exist" in capsys.readouterr().err


def test_empty_directory_is_not_reported_as_clean(tmp_path: Path):
    with pytest.raises(ScanError, match="no workflow YAML files found"):
        scan(tmp_path)
