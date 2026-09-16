from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .util import read_json, sha256_bytes, write_json_exclusive


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{stamp}-{uuid4().hex[:10]}"


def ledger_paths(root: Path, directory: str, run_id: str) -> tuple[Path, Path]:
    ledger = root / directory
    return ledger / "evidence" / f"{run_id}.json", ledger / "receipts" / f"{run_id}.json"


def previous_receipt(receipts_dir: Path) -> tuple[str | None, str | None]:
    paths = sorted(receipts_dir.glob("*.json")) if receipts_dir.exists() else []
    if not paths:
        return None, None
    path = paths[-1]
    return path.name, sha256_bytes(path.read_bytes())


def write_pair(root: Path, directory: str, run_id: str, evidence: dict[str, Any], receipt: dict[str, Any]) -> tuple[Path, Path]:
    evidence_path, receipt_path = ledger_paths(root, directory, run_id)
    write_json_exclusive(evidence_path, evidence)
    write_json_exclusive(receipt_path, receipt)
    return evidence_path, receipt_path


def read_receipts(root: Path, directory: str) -> list[tuple[Path, dict[str, Any]]]:
    receipts_dir = root / directory / "receipts"
    return [(path, read_json(path)) for path in sorted(receipts_dir.glob("*.json"))]

