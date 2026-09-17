"""Run a disposable PASS/HOLD/STOP demo with the installed ScopeLedger CLI."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    # No project files are changed. Temporary evidence is removed on exit.
    with tempfile.TemporaryDirectory(prefix="scopeledger-demo-") as directory:
        root = Path(directory)
        policy = root / "scopeledger.toml"
        policy.write_text(
            'version = 1\n[scope]\nroot = "."\n'
            'allow_changes = ["build/**"]\ndeny_changes = ["src/**"]\n'
            '[command]\nexecutables = [' + json.dumps(sys.executable) + ']\n'
            'timeout_seconds = 10\n[checks]\nrequire_exit_code = 0\n'
            'required_files = ["build/result.txt"]\n'
            '[receipts]\ndirectory = ".scopeledger"\n', encoding="utf-8"
        )
        (root / "src").mkdir()
        (root / "src/important.txt").write_text("original", encoding="utf-8")
        prefix = [sys.executable, "-m", "scopeledger.cli"]
        cases = [
            ("PASS", 0, [sys.executable, "-c",
                "from pathlib import Path; Path('build').mkdir(); Path('build/result.txt').write_text('ok')"]),
            ("HOLD", 2, [sys.executable, "-c",
                "from pathlib import Path; Path('src/important.txt').write_text('changed')"]),
            ("STOP", 3, ["scopeledger-unapproved-demo-command"]),
        ]
        for expected, exit_code, command in cases:
            result = subprocess.run(prefix + ["run", "--policy", str(policy), "--"] + command,
                                    capture_output=True, text=True, check=False)
            if result.returncode != exit_code:
                raise RuntimeError(result.stderr or result.stdout)
            output = json.loads(result.stdout)
            if output["status"] != expected:
                raise RuntimeError(output)
            # Only random receipt paths are normalized for readable documentation.
            output["receipt"] = "<temporary-workspace>/.scopeledger/receipts/<run-id>.json"
            print(json.dumps(output))
        verified = subprocess.run(prefix + ["verify", "--policy", str(policy)],
                                  capture_output=True, text=True, check=True)
        print(verified.stdout.strip())
        if not json.loads(verified.stdout)["valid"]:
            raise RuntimeError("Demo ledger did not verify")


if __name__ == "__main__":
    main()
