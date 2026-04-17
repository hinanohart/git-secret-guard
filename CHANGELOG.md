# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule IDs are part of the public API. They never change meaning across
minor releases. Removals only happen in major releases.

## [Unreleased]

## [0.1.1] — 2026-04-18

### Changed

- `pyproject.toml` now declares `license = "Apache-2.0"` (SPDX
  expression) plus `license-files = ["LICENSE", "NOTICE"]`, replacing
  the older `{ file = "LICENSE" }` form that caused PyPI to render the
  full license text in the project's "License" field. No runtime
  behaviour change.
- Fix Windows CI: skip the POSIX executable-bit assertion in
  `test_install_hook_writes_executable` on `os.name == "nt"` because
  NTFS doesn't track an execute bit and git for Windows ignores it
  anyway.
- `release.yml` now auto-creates a GitHub Release (with the built
  wheel + sdist attached) after the PyPI publish succeeds.

## [0.1.0] — 2026-04-18

### Added

- Initial public release.
- 28 rules across 7 categories: filename, cloud (AWS/GCP/Azure), VCS
  (GitHub/GitLab), chat (Slack/Discord/Telegram), SaaS (Stripe, SendGrid,
  Mailgun, OpenAI, Anthropic, Google), cryptographic material (PEM/PGP/JWT),
  and a generic keyword-assignment heuristic.
- `git-secret-guard scan` — reads `git diff --cached`, returns exit 1 on
  BLOCK.
- `git-secret-guard install-hook` — writes a basic
  `.git/hooks/pre-commit` wrapper.
- `git-secret-guard list-rules` — prints the catalog.
- `.pre-commit-hooks.yaml` for [pre-commit.com](https://pre-commit.com)
  compatibility.
- Config via `~/.config/git-secret-guard/config.toml` (XDG) or
  `.git-secret-guard.toml` at the repo root.
- Inline `# git-secret-guard: allow <rule-id>` pragma for per-line opt-outs.
- `--dry-run` (never block) and `--warn-as-block` (zero tolerance).
- `--json` machine-readable output.
- Typed Python library API (`py.typed`): `Scanner`, `Decision`, `Finding`,
  `Outcome`, `Severity`, `Rule`, `default_rules`, `scan_staged`.
- CI matrix: Python 3.10/3.11/3.12/3.13 × Linux/macOS/Windows.
- CodeQL analysis, Dependabot updates, Trusted Publishing to PyPI.

[Unreleased]: https://github.com/hinanohart/git-secret-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hinanohart/git-secret-guard/releases/tag/v0.1.0
