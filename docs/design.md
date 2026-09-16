# Design and trust model

ScopeLedger separates execution from qualification.

1. **Policy admission** checks whether the exact executable is allowed before starting it.
2. **Runner evidence** records the policy digest, command, before/after manifests, exit facts, and required-output facts.
3. **Independent checking** derives `PASS`, `HOLD`, or `STOP` from stored facts rather than trusting the runner's summary.
4. **Receipt chaining** binds every new receipt to its evidence and to the previous receipt file.

This is intentionally smaller than an agent framework. It can wrap a command launched by a person, CI job, or coding agent without depending on the model or orchestration system.

## Claims v0.1 makes

- A command denied at preflight was not launched by ScopeLedger.
- The recorded before/after regular-file and symbolic-link manifests produce the recorded change set.
- The decision can be independently derived from recorded evidence.
- Removing, editing, or reordering a record while retaining a later receipt that binds to it is detectable by verification.

## Claims v0.1 does not make

- The command was isolated from the host, network, credentials, or processes.
- Every intermediate or external effect was observed.
- Deleting the ledger or truncating its tail was detected without an externally retained expected head.
- An attacker able to replace the entire ledger cannot create a different history.
- A successful policy proves that the produced software is correct or safe.

The practical rule is simple: use ScopeLedger to qualify observed file effects, and use a sandbox and domain-specific tests for the stronger claims your workflow needs.
