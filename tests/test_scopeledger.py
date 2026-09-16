from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from scopeledger.policy import PolicyError, load_policy
from scopeledger.runner import run
from scopeledger.verify import verify_ledger


POLICY = """\
version = 1
[scope]
root = "."
allow_changes = ["out/**"]
deny_changes = ["protected/**"]
ignore = []
[command]
executables = ["python", "python3"]
timeout_seconds = 5
[checks]
require_exit_code = 0
required_files = ["out/result.txt"]
[receipts]
directory = ".scopeledger"
"""


class ScopeLedgerTests(unittest.TestCase):
    def make_workspace(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "scopeledger.toml").write_text(POLICY, encoding="utf-8")
        return temporary, root

    def test_pass_and_verify(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        script = "from pathlib import Path; p=Path('out'); p.mkdir(); (p/'result.txt').write_text('ok')"
        receipt, _ = run(load_policy(root / "scopeledger.toml"), ["python", "-c", script])
        self.assertEqual("PASS", receipt["status"])
        valid, problems = verify_ledger(load_policy(root / "scopeledger.toml"))
        self.assertTrue(valid, problems)

    def test_out_of_scope_change_holds(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        script = "from pathlib import Path; Path('oops.txt').write_text('x')"
        receipt, _ = run(load_policy(root / "scopeledger.toml"), ["python", "-c", script])
        self.assertEqual("HOLD", receipt["status"])
        self.assertIn("OUT_OF_SCOPE_CHANGE", {item["code"] for item in receipt["findings"]})

    def test_denied_command_stops_without_execution(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        receipt, _ = run(load_policy(root / "scopeledger.toml"), ["sh", "-c", "touch pwned"])
        self.assertEqual("STOP", receipt["status"])
        self.assertFalse((root / "pwned").exists())
        valid, problems = verify_ledger(load_policy(root / "scopeledger.toml"))
        self.assertTrue(valid, problems)

    def test_executable_path_cannot_bypass_exact_allowlist(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        receipt, _ = run(load_policy(root / "scopeledger.toml"), ["/usr/bin/python", "-c", "pass"])
        self.assertEqual("STOP", receipt["status"])

    def test_nonzero_exit_holds(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        receipt, _ = run(load_policy(root / "scopeledger.toml"), ["python", "-c", "raise SystemExit(7)"])
        self.assertEqual("HOLD", receipt["status"])
        self.assertIn("EXIT_CODE_MISMATCH", {item["code"] for item in receipt["findings"]})

    def test_tampered_evidence_fails_verification(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        script = "from pathlib import Path; p=Path('out'); p.mkdir(); (p/'result.txt').write_text('ok')"
        _, receipt_path = run(load_policy(root / "scopeledger.toml"), ["python", "-c", script])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        evidence_path = root / ".scopeledger" / receipt["evidence_file"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence["execution"]["exit_code"] = 9
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        valid, problems = verify_ledger(load_policy(root / "scopeledger.toml"))
        self.assertFalse(valid)
        self.assertTrue(any("evidence digest" in item["message"] for item in problems))

    def test_tampered_stop_finding_fails_verification(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        _, receipt_path = run(load_policy(root / "scopeledger.toml"), ["sh", "-c", "true"])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["findings"] = [{"code": "EMPTY_COMMAND", "message": "a command is required"}]
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        valid, problems = verify_ledger(load_policy(root / "scopeledger.toml"))
        self.assertFalse(valid)
        self.assertTrue(any("STOP finding" in item["message"] for item in problems))

    def test_invalid_policy_rejected(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        (root / "scopeledger.toml").write_text("version = 2\n", encoding="utf-8")
        with self.assertRaises(PolicyError):
            load_policy(root / "scopeledger.toml")

    def test_policy_root_cannot_escape_policy_directory(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        escaped = POLICY.replace('root = "."', 'root = ".."')
        (root / "scopeledger.toml").write_text(escaped, encoding="utf-8")
        with self.assertRaises(PolicyError):
            load_policy(root / "scopeledger.toml")

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows developer mode")
    def test_directory_symlink_change_is_observed(self) -> None:
        temporary, root = self.make_workspace()
        self.addCleanup(temporary.cleanup)
        (root / "target").mkdir()
        script = "from pathlib import Path; Path('link').symlink_to('target', target_is_directory=True)"
        receipt, _ = run(load_policy(root / "scopeledger.toml"), ["python", "-c", script])
        self.assertEqual("HOLD", receipt["status"])
        self.assertTrue(any(item["message"] == "link" for item in receipt["findings"]))


if __name__ == "__main__":
    unittest.main()
