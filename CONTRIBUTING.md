# Contributing

Small, reviewable changes are preferred. Before opening a pull request:

```bash
python -m unittest discover -s tests -v
```

Please include a regression test for behavior changes. Design discussions should preserve three invariants: a denied command does not execute; a completed run never rewrites an earlier receipt; and a `PASS` is derivable from stored evidence by the independent checker.

## Useful first contributions

- Try the [adoption guide](docs/adoption-guide.md) in a public repository and report unclear steps.
- Share a minimal policy for a real coding-agent or automation workflow.
- Report platform-specific behavior with the operating system, Python version, policy, command, and redacted receipt findings.

Please do not submit generated activity solely to increase project metrics. Reproducible reports and small fixes are more useful than volume.
