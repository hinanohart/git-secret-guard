# Security policy

## Reporting a vulnerability

Please report security issues privately by email to
**`hinanohart@gmail.com`** with the subject prefix
`[git-secret-guard security]`.

I aim to acknowledge within 72 hours and to ship a fix (or publish an
advisory explaining the trade-off) within 14 days for high-severity
issues.

## What counts as security-relevant

* A **bypass**: a credential shape that a rule clearly intends to block
  but that escapes the current regex (unusual whitespace, encoding,
  prefix drift, chunked across lines of the diff, etc.). Please scrub
  the real value — use a dummy with the right prefix and random chars.
* A **crash-on-untrusted-input** in the hook: any staged diff content
  that causes `git-secret-guard scan` to exit non-zero without a
  finding, hang, or consume unbounded memory. The hook is designed to
  fail open; a crash that turns this into a denial-of-service against
  the developer's `git commit` workflow is in scope.
* **Supply-chain concerns** with the packaging (signed releases,
  Trusted Publishing configuration, CI token scope, etc.).

## What is not in scope

* Rules you disagree with. Allowlist them and, if you have a case study
  for why the shape is sometimes safe, open a regular issue.
* Root-level compromise of the developer's machine. If the attacker can
  edit `.git/hooks/pre-commit` or install a malicious package, they can
  disable the guard entirely; this guard is a safety net against
  accidental commits, not privileged adversaries.
* The fundamental regex-not-entropy design trade-off (see the "Threat
  model & non-goals" section in the README).
* Secrets already pushed to a remote before the hook was installed.
  Rotate them; this tool can't reach back in time.

## Disclosure

Coordinated disclosure preferred. Once a fix is released, a short
advisory is added to [CHANGELOG.md](CHANGELOG.md) crediting the reporter
(unless they prefer to remain anonymous).
