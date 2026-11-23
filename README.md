# Agentic Actions Guard

A small, offline static checker for trust-boundary risks in AI-agent GitHub Actions workflows.

AI review and coding jobs can process attacker-controlled issue or pull-request text while also receiving secrets or repository write permissions. Agentic Actions Guard highlights a few high-signal combinations before a workflow is run. It parses workflow YAML only: it does **not** execute steps, start actions, contact MCP servers, or make network requests.

## Quick start

```bash
python -m pip install .
agentic-actions-guard .
```

Pass a repository root, the `.github/workflows` directory, or a single `.yml` / `.yaml` workflow. A repository root is scoped to `.github/workflows` when that directory exists.

```bash
# Machine-readable findings
agentic-actions-guard . --json

# Fail CI for medium or high findings (default is high)
agentic-actions-guard . --fail-on medium
```

To try the intentionally risky example:

```bash
agentic-actions-guard examples/.github/workflows/risky-agent-review.yml
```

Exit codes are `0` when the selected failure threshold is not met, `1` when it is met, and `2` for an unreadable or invalid workflow input.

## Current checks

The scanner heuristically identifies AI-agent steps from their names, action references, commands, and inputs. For those steps it reports:

- **High — `AGENT_UNTRUSTED_EVENT_INPUT`:** a direct expression references issue, pull-request, comment, discussion, or review event content (or serializes the whole GitHub event) in the agent step or its effective workflow/job/step environment.
- **High — `AGENT_SECRET_REFERENCE`:** a `${{ secrets.* }}` expression is present in the agent step or its effective workflow/job/step environment. Secret names and values are not included in the finding.
- **High — `AGENT_ON_PULL_REQUEST_TARGET`:** an agent step runs in a workflow triggered by `pull_request_target`.
- **Medium — `AGENT_WITH_WRITE_PERMISSION`:** the effective workflow/job permissions grant at least one explicit `write` scope to the agent job.
- **Medium — `AGENT_IMPLICIT_TOKEN_PERMISSIONS`:** neither the workflow nor the job declares permissions, so the effective token permissions depend on repository or organization defaults.

The YAML loader rejects duplicate mapping keys rather than silently choosing one. JSON output has a versioned top-level `schema_version` field; finding objects contain `rule_id`, `severity`, `workflow`, `job`, `step`, `message`, and `evidence`.

## Example output

```text
HIGH   AGENT_UNTRUSTED_EVENT_INPUT .github/workflows/review.yml :: review / Run Claude agent
       An agent step directly references issue/PR/comment event content; treat it as untrusted input and isolate it from instructions.
       Evidence: ${{ github.event.pull_request.body }}
```

## Scope and limits

This is an early heuristic scanner, not a complete taint analyzer, sandbox, or proof of safety. It only flags patterns it can see directly in workflow YAML. It does not follow values through environment files, outputs, reusable workflows, composite actions, shell expansion, or external action implementation. It can miss an agent step if its name and configuration do not contain recognizable AI/agent markers, and it can produce false positives. A clean scan is not a guarantee that a workflow is safe.

Use it alongside GitHub's Agentic Workflows guardrails when applicable and general-purpose workflow analyzers such as [zizmor](https://github.com/zizmorcore/zizmor). MCP configuration preflight tools such as [CallLint](https://github.com/calllint/calllint) address a neighboring surface. This project focuses on AI-agent steps and prompt/data trust boundaries inside GitHub Actions rather than replacing either category. Review every finding and retain human review for privileged workflows.

## Why this project

The [Cloud Security Alliance's research note on AI-enabled GitHub Actions](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-github-actions-security-20260503-csa-st/) describes the risk of untrusted pull-request content reaching agents that can use secrets or modify repositories. GitHub's [Agentic Workflows security FAQ](https://github.github.com/gh-aw/reference/faq/) documents read-only defaults and safe-output guardrails while also noting that authors can choose direct write permissions or custom jobs. Agentic Actions Guard is a small, local preflight check for repositories that author these workflows themselves.

## Development

```bash
python -m pip install -e '.[test]'
python -m pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
