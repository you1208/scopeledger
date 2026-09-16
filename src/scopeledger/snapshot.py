from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .policy import matches
from .util import sha256_bytes, sha256_json


def snapshot(root: Path, ignored: tuple[str, ...], ledger_directory: str) -> dict[str, Any]:
    ignored_all = ignored + (ledger_directory, f"{ledger_directory}/**")
    files: dict[str, dict[str, Any]] = {}
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        traversable: list[str] = []
        for name in sorted(dirnames):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if matches(relative, ignored_all):
                continue
            if path.is_symlink():
                target = os.readlink(path)
                files[relative] = {
                    "kind": "symlink",
                    "target": target,
                    "sha256": sha256_bytes(target.encode("utf-8")),
                }
            else:
                traversable.append(name)
        dirnames[:] = traversable
        for name in sorted(filenames):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if matches(relative, ignored_all):
                continue
            if path.is_symlink():
                target = os.readlink(path)
                files[relative] = {
                    "kind": "symlink",
                    "target": target,
                    "sha256": sha256_bytes(target.encode("utf-8")),
                }
            elif path.is_file():
                content = path.read_bytes()
                files[relative] = {
                    "kind": "file",
                    "size": len(content),
                    "sha256": sha256_bytes(content),
                }
    return {"files": files, "digest": sha256_json(files)}


def diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    left = before["files"]
    right = after["files"]
    for path in sorted(set(left) | set(right)):
        if path not in left:
            result.append({"path": path, "effect": "created"})
        elif path not in right:
            result.append({"path": path, "effect": "deleted"})
        elif left[path] != right[path]:
            result.append({"path": path, "effect": "modified"})
    return result
