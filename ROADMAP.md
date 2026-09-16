# Roadmap

ScopeLedger develops from observed maintainer workflows, not feature-count targets. Items move forward when a concrete use case and a testable trust boundary are clear.

## v0.1.x — adoption and hardening

- Publish reproducible Python packages and release notes.
- Test installation and the quick start on supported operating systems.
- Improve diagnostics from real policies and receipts.
- Add regression tests for confirmed path, policy, and verification defects.
- Document public integrations contributed by adopters.

## Candidate v0.2 work

- Export a stable machine-readable receipt schema.
- Support externally stored checkpoints without claiming full tamper prevention.
- Define safe composition for multiple sequential scoped commands.
- Evaluate additional Python versions from CI evidence.

## Non-goals

- Running or orchestrating AI agents.
- Automatically retrying failed work.
- Treating a receipt as proof of effects outside the observed workspace.
- Replacing operating-system or container isolation.

The order may change based on security findings and real adoption. Please open an issue describing the workflow and required trust claim before proposing a large implementation.
