from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .policy import PolicyError, load_policy
from .runner import run
from .verify import verify_ledger


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeledger", description="Evidence-backed command scope gate")
    parser.add_argument("--version", action="version", version="scopeledger 0.1.0")
    sub = parser.add_subparsers(dest="action", required=True)
    run_parser = sub.add_parser("run", help="run a command under policy and write a receipt")
    run_parser.add_argument("--policy", default="scopeledger.toml")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    verify_parser = sub.add_parser("verify", help="verify the append-only receipt chain")
    verify_parser.add_argument("--policy", default="scopeledger.toml")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = load_policy(Path(args.policy))
    except PolicyError as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}, ensure_ascii=False))
        return 3

    if args.action == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        receipt, path = run(policy, command)
        print(json.dumps({"status": receipt["status"], "receipt": str(path), "findings": receipt["findings"]}, ensure_ascii=False))
        return {"PASS": 0, "HOLD": 2, "STOP": 3}[receipt["status"]]

    valid, problems = verify_ledger(policy)
    print(json.dumps({"valid": valid, "problems": problems}, ensure_ascii=False))
    return 0 if valid else 2


if __name__ == "__main__":
    sys.exit(main())

