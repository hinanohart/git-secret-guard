---
name: Bug report
about: A rule fires when it shouldn't, or doesn't fire when it should.
title: "[bug] "
labels: bug
---

## What happened

<!-- Paste the minimal staged file content (scrub real secrets) and what the guard returned. -->

```
$ git-secret-guard scan
<output>
```

## What you expected

<!-- Should it have fired? Should it not have fired? Why? -->

## Rule ID (if a rule fired)

<!-- e.g. aws-access-key-id. Run `git-secret-guard list-rules` to see the catalog. -->

## Environment

- `git-secret-guard version`:
- Python version:
- OS:
- pre-commit.com or direct hook?:

## Additional context

<!-- Config excerpt (redact secrets), allowlist contents, anything else relevant. -->
