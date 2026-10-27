"""CLI entry point for Agentic Actions Guard."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanError, scan

_SEVERITY = {"high": 2, "medium": 1, "low": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentic-actions-guard",
        description="Offline static checks for AI-agent trust boundaries in GitHub Actions workflows.",
    )
    parser.add_argument("path", nargs="?", default=".", help="workflow file, .github/workflows directory, or repository root")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="high",
                        help="exit 1 when findings meet this severity (default: high)")
    args = parser.parse_args(argv)

    try:
        findings = scan(Path(args.path))
    except ScanError as exc:
        print(f"agentic-actions-guard: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"schema_version": "1", "findings": findings}, ensure_ascii=False, indent=2))
    elif findings:
        for finding in findings:
            print(f"{finding['severity'].upper():6} {finding['rule_id']} {finding['workflow']} :: {finding['job']} / {finding['step']}")
            print(f"       {finding['message']}")
            print(f"       Evidence: {finding['evidence']}")
        print(f"\n{len(findings)} finding(s). Static checks only; review the workflow before relying on it.")
    else:
        print("No configured agent-workflow risk patterns found. This is not a safety guarantee.")

    threshold = _SEVERITY[args.fail_on]
    if threshold == 0:
        return 1 if findings else 0
    return 1 if any(_SEVERITY[item["severity"]] >= threshold for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
