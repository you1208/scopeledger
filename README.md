# ScopeLedger

[![CI](https://github.com/you1208/scopeledger/actions/workflows/ci.yml/badge.svg)](https://github.com/you1208/scopeledger/actions/workflows/ci.yml)

**Run commands inside a declared scope. Keep receipts that can be checked without trusting the runner.**

ScopeLedger is a small, model-agnostic CLI for coding-agent and automation workflows. It does not run an AI agent. It wraps one command, records the exact before/after workspace state, checks effects against a policy, and writes an append-only `PASS`, `HOLD`, or `STOP` receipt.

The first release deliberately has no service, account, API key, model dependency, plugin system, or automatic retry.

## Why

An agent saying “tests passed” is a claim. ScopeLedger turns a narrow class of those claims into inspectable evidence:

- Was this command allowed to start?
- What files actually changed?
- Did anything outside the declared scope change?
- Were required outputs produced?
- Does the receipt still match its evidence?
- Has earlier history been removed or rewritten?

## Quick start

Requires Python 3.11 or newer.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
scopeledger run --policy scopeledger.toml -- python examples/write_result.py
scopeledger verify --policy scopeledger.toml
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

The included example permits changes only under `demo-output/`. A successful run writes evidence and a receipt beneath `.scopeledger/` and prints a compact result:

```json
{"status":"PASS","receipt":".../.scopeledger/receipts/<run-id>.json","findings":[]}
```

## Policy

```toml
version = 1

[scope]
root = "."
allow_changes = ["build/**"]
deny_changes = ["src/**", ".github/**"]
ignore = [".git/**", ".venv/**", "**/__pycache__/**"]

[command]
executables = ["python", "python3"]
timeout_seconds = 30

[checks]
require_exit_code = 0
required_files = ["build/result.json"]

[receipts]
directory = ".scopeledger"
```

Commands are executed directly, never through an implicit shell. `executables` matches the first command argument exactly; listing `python` does not allow `/some/path/python`. File patterns use case-sensitive glob matching with explicit `directory/**` subtree support.

## Decisions

| Status | Meaning |
| --- | --- |
| `PASS` | The command ran and every declared check passed. |
| `HOLD` | The command ran, but its result or effects did not satisfy policy. Human review is required. |
| `STOP` | Preflight refused execution, so the command did not run. |

ScopeLedger never changes a `HOLD` into a `PASS` by retrying. Recovery belongs to a new, separately receipted run.

## Evidence model

Each evidence document contains the policy, policy digest, command arguments, timestamps, exit result, stdout/stderr digests and sizes, before/after file manifests, the resulting change set, and required-output facts. Command output contents are not stored.

Each receipt binds to its evidence digest and the prior receipt file digest. `scopeledger verify` recomputes those bindings and independently derives the expected decision from recorded facts. Records use exclusive creation and are never updated by ScopeLedger.

This provides tamper evidence, not tamper prevention. Anyone who can replace the entire ledger and all external copies can create a new history. Signed checkpoints and external anchoring are possible future work, not v0.1 claims.

## Security boundary

ScopeLedger is a policy and evidence layer, **not a sandbox**. An allowed command runs with the current user's permissions and environment. Use an OS/container sandbox for untrusted code. A command may also access network resources unless your execution environment prevents it.

See [SECURITY.md](SECURITY.md) for reporting and the v0.1 threat boundary.

## Project status

v0.1 is intentionally narrow: one local command, one workspace, deterministic file-effect checks, local receipts. Feedback is welcome, especially from maintainers using coding agents in real repositories.

## License

MIT © Yohei Watanabe
