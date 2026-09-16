# Security policy

## Supported versions

Only the latest released version receives security fixes during the v0.x period.

## Reporting

Please do not open a public issue for a vulnerability that could enable command-policy bypass, path escape, receipt forgery, or unintended disclosure. Use GitHub private vulnerability reporting when it is enabled for the repository.

## v0.1 boundary

ScopeLedger is not a sandbox, privilege boundary, secret scanner, process monitor, or network monitor. It observes regular files and symbolic links beneath one workspace before and after a command. It does not prove intermediate effects, external effects, child-process lifetime after exit, or actions hidden by an attacker with equivalent filesystem access. v0.1 also expects a single ScopeLedger writer per workspace; concurrent writers are not serialized.
