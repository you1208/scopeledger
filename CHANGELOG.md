# Changelog

## 0.1.0 - 2026-09-16

- Declare allowed commands and file effects in TOML.
- Emit `PASS`, `HOLD`, and pre-execution `STOP` receipts.
- Capture before/after file manifests and required-output facts.
- Chain receipts and independently recompute file changes from stored manifests during verification.
- Store only digests and sizes for stdout and stderr.
