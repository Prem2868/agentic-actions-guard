"""Offline static checks for AI-agent GitHub Actions workflows."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver


class ScanError(ValueError):
    """Raised when a workflow cannot be read or parsed safely."""


class _UniqueKeyLoader(yaml.BaseLoader):
    pass


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError("while constructing a mapping", node.start_mark,
                                   "found an unhashable key", key_node.start_mark) from exc
        if duplicate:
            raise ConstructorError("while constructing a mapping", node.start_mark,
                                   f"found duplicate key {key!r}", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)

_AGENT_MARKER = re.compile(
    r"\b(?:agent|llm|copilot|claude|gemini|codex|openai|anthropic|openrouter|ai[-_ ](?:review|agent|inference))\b",
    re.IGNORECASE,
)
_UNTRUSTED_EVENT = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue|pull_request|pullrequest|comment|discussion|review|review_comment|head_commit|workflow_run)(?:\.[\w.-]+)?",
    re.IGNORECASE,
)
_UNTRUSTED_EVENT_JSON = re.compile(r"toJSON\s*\(\s*github\.event\s*\)", re.IGNORECASE)
_SECRET_REF = re.compile(r"\$\{\{\s*secrets\.[^}]+\}\}", re.IGNORECASE)
_WRITE_PERMISSION = re.compile(r"^write$", re.IGNORECASE)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        values: list[str] = []
        for key, item in value.items():
            if isinstance(key, str):
                values.append(key)
            values.extend(_strings(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_strings(item))
        return values
    return []


def _is_agent_step(step: dict[str, Any]) -> bool:
    # Keep classification evidence-based: inspect action metadata and command/input fields only.
    relevant = " ".join(_strings({key: step.get(key) for key in ("name", "uses", "run", "with")}))
    return bool(_AGENT_MARKER.search(relevant))


def _write_scopes(permissions: Any) -> list[str]:
    if isinstance(permissions, str):
        return ["write-all"] if permissions.lower() == "write-all" else []
    if not isinstance(permissions, dict):
        return []
    return [str(scope) for scope, value in permissions.items()
            if isinstance(value, str) and _WRITE_PERMISSION.fullmatch(value.strip())]


def _is_pull_request_target(trigger: Any) -> bool:
    if isinstance(trigger, str):
        return trigger == "pull_request_target"
    if isinstance(trigger, list):
        return "pull_request_target" in trigger
    if isinstance(trigger, dict):
        return "pull_request_target" in trigger
    return False


def _load_workflow(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ScanError(f"{path}: cannot read workflow: {exc}") from exc
    try:
        document = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ScanError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise ScanError(f"{path}: workflow document must be a YAML mapping")
    return document


def _findings_for_workflow(path: Path, workflow: dict[str, Any]) -> list[dict[str, str]]:
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        raise ScanError(f"{path}: 'jobs' must be a mapping")

    trigger = workflow.get("on", workflow.get(True))
    has_pr_target = _is_pull_request_target(trigger)
    workflow_env = workflow.get("env", {})
    if not isinstance(workflow_env, dict):
        workflow_env = {}

    findings: list[dict[str, str]] = []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        job_env = job.get("env", {})
        if not isinstance(job_env, dict):
            job_env = {}
        effective_permissions = job.get("permissions", workflow.get("permissions"))
        write_scopes = _write_scopes(effective_permissions)

        for index, step in enumerate(steps):
            if not isinstance(step, dict) or not _is_agent_step(step):
                continue
            step_id = str(step.get("name") or step.get("id") or f"step-{index + 1}")
            step_env = step.get("env", {})
            if not isinstance(step_env, dict):
                step_env = {}

            def add(rule_id: str, severity: str, message: str, evidence: str) -> None:
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "workflow": str(path),
                    "job": str(job_id),
                    "step": step_id,
                    "message": message,
                    "evidence": evidence,
                })

            merged_env = dict(workflow_env)
            merged_env.update(job_env)
            merged_env.update(step_env)
            agent_text = "\n".join(_strings({"step": step, "effective_env": merged_env}))
            event_match = _UNTRUSTED_EVENT.search(agent_text)
            event_json_match = _UNTRUSTED_EVENT_JSON.search(agent_text)
            if event_match or event_json_match:
                evidence = event_match.group(0) if event_match else event_json_match.group(0)
                add("AGENT_UNTRUSTED_EVENT_INPUT", "high",
                    "An agent step directly references GitHub event payload fields; treat them as untrusted input and isolate them from instructions.",
                    evidence)

            secret_match = _SECRET_REF.search("\n".join(_strings({"env": merged_env, "with": step.get("with", {}), "run": step.get("run", "")})))
            if secret_match:
                add("AGENT_SECRET_REFERENCE", "high",
                    "A secret reference is available to or passed directly into an agent step; separate credentials from agent-controlled execution.",
                    "a `${{ secrets.* }}` reference is present (value redacted)")

            if has_pr_target:
                add("AGENT_ON_PULL_REQUEST_TARGET", "high",
                    "An agent step runs in a workflow triggered by pull_request_target, where untrusted contribution content may coexist with elevated base-repository authority.",
                    "on.pull_request_target")

            if effective_permissions is None:
                add("AGENT_IMPLICIT_TOKEN_PERMISSIONS", "medium",
                    "The agent job has no explicit permissions block; the effective token permissions depend on repository or organization defaults.",
                    "workflow/job permissions are absent")

            if write_scopes:
                add("AGENT_WITH_WRITE_PERMISSION", "medium",
                    "The agent job has an explicit write permission; scope privileged access minimally and separate write operations from agent execution where possible.",
                    "write scopes: " + ", ".join(sorted(write_scopes)))

    return findings


def discover_workflows(target: Path) -> list[Path]:
    if not target.exists():
        raise ScanError(f"{target}: path does not exist")
    if target.is_file():
        if target.suffix.lower() not in {".yml", ".yaml"}:
            raise ScanError(f"{target}: expected a .yml or .yaml workflow file")
        return [target]
    workflow_dir = target / ".github" / "workflows"
    search_root = workflow_dir if workflow_dir.is_dir() else target
    return sorted(path for path in search_root.rglob("*")
                  if path.is_file() and path.suffix.lower() in {".yml", ".yaml"})


def scan(target: Path) -> list[dict[str, str]]:
    files = discover_workflows(target)
    if not files:
        raise ScanError(f"{target}: no workflow YAML files found")
    findings: list[dict[str, str]] = []
    for path in files:
        workflow = _load_workflow(path)
        findings.extend(_findings_for_workflow(path, workflow))
    return sorted(findings, key=lambda item: (item["workflow"], item["job"], item["step"], item["rule_id"]))
