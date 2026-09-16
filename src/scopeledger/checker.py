from __future__ import annotations

from pathlib import Path
from typing import Any

from .policy import matches


def evaluate(policy: dict[str, Any], evidence: dict[str, Any], root: Path | None = None) -> tuple[str, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    facts = evidence["execution"]
    scope = policy["scope"]
    checks = policy.get("checks", {})
    allowed = tuple(scope.get("allow_changes", []))
    denied = tuple(scope.get("deny_changes", []))

    if facts["timed_out"]:
        findings.append({"code": "EXECUTION_TIMEOUT", "message": "command exceeded the policy timeout"})
    required_exit = checks.get("require_exit_code", 0)
    if facts["exit_code"] != required_exit:
        findings.append({
            "code": "EXIT_CODE_MISMATCH",
            "message": f"expected exit code {required_exit}, got {facts['exit_code']}",
        })

    for change in evidence["changes"]:
        path = change["path"]
        if matches(path, denied):
            findings.append({"code": "DENIED_PATH_CHANGED", "message": path})
        elif not matches(path, allowed):
            findings.append({"code": "OUT_OF_SCOPE_CHANGE", "message": path})

    observed = evidence.get("required_files", {})
    for path in checks.get("required_files", []):
        if not observed.get(path, {}).get("exists", False):
            findings.append({"code": "REQUIRED_FILE_MISSING", "message": path})

    return ("PASS" if not findings else "HOLD", findings)

