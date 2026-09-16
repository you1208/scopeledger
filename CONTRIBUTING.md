# Contributing

Small, reviewable changes are preferred. Before opening a pull request:

```bash
python -m unittest discover -s tests -v
```

Please include a regression test for behavior changes. Design discussions should preserve three invariants: a denied command does not execute; a completed run never rewrites an earlier receipt; and a `PASS` is derivable from stored evidence by the independent checker.

