# Three decisions in one disposable demo

Install `scopeledger==0.1.0` with Python 3.11 or newer, then run from a checkout of this repository:

```bash
python examples/three_decisions.py
```

The example creates a temporary workspace and a policy allowing changes only under
`build/`, denying changes under `src/`, and requiring `build/result.txt`.
It uses the current Python executable explicitly, including on Windows.
It removes its temporary files and demonstration receipts on exit; it does not edit
your project. Real workflow receipts should be retained according to your own policy.

## Observed output

The following output was captured by running the example against source matching
the public v0.1.0 commit `cdbfd8f17a19c771b6f15550f8ec79c1f5a8eb70` on Linux.
The example normalizes only the temporary receipt paths and random run IDs.
The same example is included in the cross-platform CI matrix.

```json
{"status": "PASS", "receipt": "<temporary-workspace>/.scopeledger/receipts/<run-id>.json", "findings": []}
{"status": "HOLD", "receipt": "<temporary-workspace>/.scopeledger/receipts/<run-id>.json", "findings": [{"code": "DENIED_PATH_CHANGED", "message": "src/important.txt"}]}
{"status": "STOP", "receipt": "<temporary-workspace>/.scopeledger/receipts/<run-id>.json", "findings": [{"code": "COMMAND_NOT_ALLOWED", "message": "scopeledger-unapproved-demo-command"}]}
{"valid": true, "problems": []}
```

| Step | Action | Result | CLI exit code |
| --- | --- | --- | --- |
| 1 | Python creates `build/result.txt` | PASS | 0 |
| 2 | Python changes `src/important.txt` | HOLD with `DENIED_PATH_CHANGED` | 2 |
| 3 | An unlisted executable is requested | STOP before execution | 3 |
| 4 | Verify the three recorded receipts | `valid: true` | 0 |

HOLD is detected **after the write occurred**. ScopeLedger does not block or roll back
that write; an OS/container sandbox is needed to constrain untrusted execution.
STOP refuses the unlisted command before trying to launch it.

`valid: true` means that the retained evidence and receipts pass the verifier's checks.
It does not turn HOLD or STOP into PASS, prove the recorded facts came from a trusted
machine, or detect deletion of the final receipts without an external expected head.
See the [trust model](design.md) for the full boundary.
