# Contributing to git-secret-guard

Thanks for helping make committed secrets a rarer event. The scope of this
project is deliberately narrow — prevent credentials from entering git
history — and every change should reinforce that scope.

## Principles

1. **Rules ship with tests, both ways.** A new rule needs at least one
   positive example (must match) and at least one nearby negative example
   (must not match). Silent rules and noisy rules are equally bad.
2. **Tight regexes over fuzzy ones.** A weekly false positive gets the
   hook disabled across the team. It's better to miss an exotic
   credential shape than to block legitimate commits.
3. **Stable rule IDs.** Pinning an ID in a user's allowlist must keep
   working. Fix bugs in place; never rename. New coverage is a new ID.
4. **No ML, no network, no telemetry.** This tool runs in tight local
   loops where contributors notice if it's slow or suspicious.
5. **No "just-in-case" rules.** Every rule must have a concrete, named
   service it protects. "Might be a credential" isn't good enough.

## Adding a rule

1. Open an issue using the **New pattern proposal** template.
2. In the issue, include:
   - Proposed ID: `<category>-<short-name>`, kebab-case.
   - Severity: BLOCK or WARN, with a sentence on why.
   - Shape: 1–3 examples of the real credential format (scrub any real
     value — use dummies with the right prefix + random chars).
   - Negative examples: 1–3 legitimate strings the regex must not match.
   - Source: link to the service's docs describing the token shape.
3. After discussion, open a PR with:
   - The rule in `src/git_secret_guard/rules.py`, in the right category
     block, with a docstring comment explaining any non-obvious regex
     choice.
   - Positive and negative tests in `tests/test_rules.py`.
   - A row in `docs/PATTERNS.md` and an entry in `CHANGELOG.md`.

## Running the test suite

```bash
pip install -e '.[dev]'
pytest
ruff check src tests
ruff format --check src tests
mypy --strict src
```

All four must pass. CI runs the same matrix across Python 3.10/3.11/3.12/3.13
on Linux/macOS/Windows.

## Reporting false positives

Open an issue with the minimal file content that trips the rule, and the
exact rule ID (see `git-secret-guard list-rules`). Tightening a regex is
usually cheaper than silencing the whole rule.

## Reporting missed secrets

Please **do not** paste the real credential shape in a public issue if
there's any chance it's been used by a real service. Email
<hinanohart@gmail.com> with a scrubbed example instead — see
[`SECURITY.md`](SECURITY.md).

## Code of conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Contact: hinanohart@gmail.com.
