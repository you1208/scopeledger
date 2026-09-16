from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .util import sha256_bytes


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Policy:
    source: Path
    sha256: str
    raw: dict[str, Any]
    root: Path
    allowed_changes: tuple[str, ...]
    denied_changes: tuple[str, ...]
    ignored_paths: tuple[str, ...]
    executables: tuple[str, ...]
    timeout_seconds: int
    required_exit_code: int
    required_files: tuple[str, ...]
    ledger_directory: str


def _strings(value: Any, field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyError(f"{field} must be an array of strings")
    if not allow_empty and not value:
        raise PolicyError(f"{field} must not be empty")
    return tuple(value)


def _safe_relative(value: str, field: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value in {"", "."}:
        raise PolicyError(f"{field} must be a non-empty relative path")
    return value


def load_policy(path: Path) -> Policy:
    try:
        source_bytes = path.read_bytes()
        raw = tomllib.loads(source_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot read policy: {exc}") from exc

    if raw.get("version") != 1:
        raise PolicyError("policy version must be 1")
    scope = raw.get("scope")
    command = raw.get("command")
    checks = raw.get("checks", {})
    receipts = raw.get("receipts", {})
    if not isinstance(scope, dict) or not isinstance(command, dict):
        raise PolicyError("[scope] and [command] tables are required")
    if not isinstance(checks, dict) or not isinstance(receipts, dict):
        raise PolicyError("[checks] and [receipts] must be tables")

    root_value = scope.get("root", ".")
    if not isinstance(root_value, str):
        raise PolicyError("scope.root must be a string")
    root_path = PurePosixPath(root_value)
    if root_path.is_absolute() or ".." in root_path.parts:
        raise PolicyError("scope.root must stay within the policy directory")
    policy_directory = path.parent.resolve()
    root = (policy_directory / root_value).resolve()
    try:
        root.relative_to(policy_directory)
    except ValueError as exc:
        raise PolicyError("scope.root must stay within the policy directory") from exc
    if not root.is_dir():
        raise PolicyError(f"scope.root is not a directory: {root_value}")

    allowed = _strings(scope.get("allow_changes", []), "scope.allow_changes")
    denied = _strings(scope.get("deny_changes", []), "scope.deny_changes")
    ignored = _strings(scope.get("ignore", []), "scope.ignore")
    executables = _strings(command.get("executables"), "command.executables", allow_empty=False)

    timeout = command.get("timeout_seconds", 60)
    exit_code = checks.get("require_exit_code", 0)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 86400:
        raise PolicyError("command.timeout_seconds must be an integer from 1 to 86400")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise PolicyError("checks.require_exit_code must be an integer")

    required_files = _strings(checks.get("required_files", []), "checks.required_files")
    ledger = receipts.get("directory", ".scopeledger")
    if not isinstance(ledger, str):
        raise PolicyError("receipts.directory must be a string")
    ledger = _safe_relative(ledger, "receipts.directory")
    try:
        (root / ledger).resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise PolicyError("receipts.directory must stay within scope.root") from exc
    for index, item in enumerate(required_files):
        _safe_relative(item, f"checks.required_files[{index}]")

    return Policy(
        source=path.resolve(),
        sha256=sha256_bytes(source_bytes),
        raw=raw,
        root=root,
        allowed_changes=allowed,
        denied_changes=denied,
        ignored_paths=ignored,
        executables=executables,
        timeout_seconds=timeout,
        required_exit_code=exit_code,
        required_files=required_files,
        ledger_directory=ledger,
    )


def matches(path: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        normalized = pattern.rstrip("/")
        if fnmatch.fnmatchcase(path, pattern):
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return True
        if path == normalized:
            return True
    return False
