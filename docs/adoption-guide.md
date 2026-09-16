# Adoption guide

This guide adds one evidence-backed command to an existing repository without changing the command itself.

## 1. Install a pinned revision

Until the first PyPI release is available, install the reviewed commit directly:

```bash
python -m pip install "scopeledger @ git+https://github.com/you1208/scopeledger.git@0720530fd9d910ce8bd831901ff4aef0e588ddd3"
```

Pinning avoids silently changing the tool between runs. After PyPI publication, pin an exact package version instead.

## 2. Declare the smallest useful scope

Create `scopeledger.toml`:

```toml
version = 1

[scope]
root = "."
allow_changes = ["build/**"]
deny_changes = ["src/**", "tests/**", ".github/**"]
ignore = [".git/**", ".venv/**", "**/__pycache__/**"]

[command]
executables = ["python", "python3"]
timeout_seconds = 60

[checks]
require_exit_code = 0
required_files = ["build/result.json"]

[receipts]
directory = ".scopeledger"
```

Start with a disposable branch and a command whose expected output is already understood. ScopeLedger is not a sandbox; run untrusted code inside an appropriate isolated environment.

## 3. Run and verify

```bash
scopeledger run --policy scopeledger.toml -- python scripts/build_result.py
scopeledger verify --policy scopeledger.toml
```

Interpret the result as follows:

- `PASS`: recorded facts satisfy the declared policy.
- `HOLD`: the command ran, but its result or file effects require review.
- `STOP`: preflight refused to execute the command.

Do not delete a `HOLD` and rerun until it passes. Keep it as history and create a separate receipt for the corrected attempt.

## 4. Add CI without granting write access

The minimal GitHub Actions job can run with read-only repository permissions:

```yaml
name: ScopeLedger example

on: [pull_request]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install "scopeledger @ git+https://github.com/you1208/scopeledger.git@0720530fd9d910ce8bd831901ff4aef0e588ddd3"
      - run: scopeledger run --policy scopeledger.toml -- python scripts/build_result.py
      - run: scopeledger verify --policy scopeledger.toml
```

Treat uploaded ledgers as potentially sensitive metadata: evidence includes command arguments, file paths, timestamps, and digests. Review the contents before publishing an artifact.

## 5. Report the real workflow

If ScopeLedger helped—or stopped for a reason that should be clearer—open an issue with a minimal policy, expected behavior, actual status, platform, and Python version. Redact secrets and private paths.
