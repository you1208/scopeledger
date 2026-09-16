from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checker import evaluate
from .ledger import ledger_paths, new_run_id, previous_receipt, write_pair
from .policy import Policy
from .snapshot import diff, snapshot
from .util import sha256_bytes, sha256_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _required_file_facts(policy: Policy) -> dict[str, dict[str, Any]]:
    facts: dict[str, dict[str, Any]] = {}
    for relative in policy.required_files:
        path = policy.root / relative
        resolved = path.resolve(strict=False)
        try:
            resolved.relative_to(policy.root)
        except ValueError:
            facts[relative] = {"exists": False, "reason": "outside root"}
            continue
        if path.is_file() and not path.is_symlink():
            content = path.read_bytes()
            facts[relative] = {"exists": True, "size": len(content), "sha256": sha256_bytes(content)}
        else:
            facts[relative] = {"exists": False}
    return facts


def _base_evidence(policy: Policy, run_id: str, command: list[str]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "policy": policy.raw,
        "policy_sha256": policy.sha256,
        "command": command,
    }


def _receipt(policy: Policy, evidence: dict[str, Any], status: str, findings: list[dict[str, str]]) -> dict[str, Any]:
    evidence_path, receipt_path = ledger_paths(policy.root, policy.ledger_directory, evidence["run_id"])
    previous_name, previous_sha = previous_receipt(receipt_path.parent)
    return {
        "schema_version": 1,
        "run_id": evidence["run_id"],
        "created_at": _now(),
        "status": status,
        "policy_sha256": policy.sha256,
        "subject_before_sha256": evidence.get("before", {}).get("digest"),
        "subject_after_sha256": evidence.get("after", {}).get("digest"),
        "evidence_file": evidence_path.relative_to(policy.root / policy.ledger_directory).as_posix(),
        "evidence_sha256": sha256_json(evidence),
        "previous_receipt_file": previous_name,
        "previous_receipt_sha256": previous_sha,
        "findings": findings,
    }


def stop(policy: Policy, command: list[str], code: str, message: str) -> tuple[dict[str, Any], Path]:
    run_id = new_run_id()
    evidence = _base_evidence(policy, run_id, command)
    evidence.update({
        "decision": "not_executed",
        "before": {}, "after": {}, "changes": [], "required_files": {},
        "execution": {"started_at": None, "finished_at": None, "exit_code": None, "timed_out": False, "stdout": {"size": 0, "sha256": sha256_bytes(b"")}, "stderr": {"size": 0, "sha256": sha256_bytes(b"")}},
    })
    receipt = _receipt(policy, evidence, "STOP", [{"code": code, "message": message}])
    _, receipt_path = write_pair(policy.root, policy.ledger_directory, run_id, evidence, receipt)
    return receipt, receipt_path


def run(policy: Policy, command: list[str]) -> tuple[dict[str, Any], Path]:
    executable = command[0] if command else ""
    if not command:
        return stop(policy, command, "EMPTY_COMMAND", "a command is required")
    if executable not in policy.executables:
        return stop(policy, command, "COMMAND_NOT_ALLOWED", executable)

    run_id = new_run_id()
    before = snapshot(policy.root, policy.ignored_paths, policy.ledger_directory)
    started = _now()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=policy.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=policy.timeout_seconds,
            check=False,
            env=os.environ.copy(),
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = None
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
    finished = _now()
    after = snapshot(policy.root, policy.ignored_paths, policy.ledger_directory)
    evidence = _base_evidence(policy, run_id, command)
    evidence.update({
        "decision": "executed",
        "before": before,
        "after": after,
        "changes": diff(before, after),
        "required_files": _required_file_facts(policy),
        "execution": {
            "started_at": started,
            "finished_at": finished,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": {"size": len(stdout), "sha256": sha256_bytes(stdout)},
            "stderr": {"size": len(stderr), "sha256": sha256_bytes(stderr)},
        },
    })
    status, findings = evaluate(policy.raw, evidence)
    receipt = _receipt(policy, evidence, status, findings)
    _, receipt_path = write_pair(policy.root, policy.ledger_directory, run_id, evidence, receipt)
    return receipt, receipt_path
