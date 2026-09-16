from __future__ import annotations

from pathlib import Path
from typing import Any

from .checker import evaluate
from .policy import Policy
from .util import read_json, sha256_bytes, sha256_json


def verify_ledger(policy: Policy) -> tuple[bool, list[dict[str, str]]]:
    ledger_root = policy.root / policy.ledger_directory
    receipts_dir = ledger_root / "receipts"
    problems: list[dict[str, str]] = []
    previous_name: str | None = None
    previous_sha: str | None = None
    receipt_paths = sorted(receipts_dir.glob("*.json")) if receipts_dir.exists() else []
    for receipt_path in receipt_paths:
        try:
            receipt = read_json(receipt_path)
            evidence_path = ledger_root / receipt["evidence_file"]
            evidence = read_json(evidence_path)
        except (OSError, ValueError, KeyError) as exc:
            problems.append({"file": receipt_path.name, "message": f"unreadable record: {exc}"})
            continue

        checks = [
            (receipt.get("run_id") == evidence.get("run_id"), "run id mismatch"),
            (receipt.get("policy_sha256") == evidence.get("policy_sha256"), "policy digest mismatch"),
            (receipt.get("evidence_sha256") == sha256_json(evidence), "evidence digest mismatch"),
            (receipt.get("previous_receipt_file") == previous_name, "previous receipt name mismatch"),
            (receipt.get("previous_receipt_sha256") == previous_sha, "receipt chain mismatch"),
        ]
        if evidence.get("decision") == "executed":
            expected_status, expected_findings = evaluate(evidence["policy"], evidence)
            checks.extend([
                (receipt.get("status") == expected_status, "status is not supported by evidence"),
                (receipt.get("findings") == expected_findings, "findings are not supported by evidence"),
            ])
        else:
            command = evidence.get("command", [])
            executable = command[0] if command else ""
            allowed = evidence.get("policy", {}).get("command", {}).get("executables", [])
            if not command:
                expected_stop = [{"code": "EMPTY_COMMAND", "message": "a command is required"}]
            elif executable not in allowed:
                expected_stop = [{"code": "COMMAND_NOT_ALLOWED", "message": executable}]
            else:
                expected_stop = None
            checks.extend([
                (receipt.get("status") == "STOP", "non-executed record must be STOP"),
                (expected_stop is not None, "evidence does not justify stopping execution"),
                (receipt.get("findings") == expected_stop, "STOP finding is not supported by evidence"),
            ])
        for passed, message in checks:
            if not passed:
                problems.append({"file": receipt_path.name, "message": message})
        previous_name = receipt_path.name
        previous_sha = sha256_bytes(receipt_path.read_bytes())
    return not problems, problems
