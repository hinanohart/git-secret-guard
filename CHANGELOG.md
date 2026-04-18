# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule IDs are part of the public API. They never change meaning across
minor releases. Removals only happen in major releases.

## [Unreleased]

## [0.1.2] — 2026-04-18

### Security

- **Matched-text preview is now redacted, not truncated.** `_truncate`
  previously returned the first 80 chars of the match — which printed
  an entire AWS access key, Stripe secret, short bearer token, etc.
  directly to stderr, IDE output panels, shell history, and alerting
  webhook payloads. Replaced with `<prefix4>…<redacted len=N>` (or
  fully redacted for matches ≤8 chars). The tool no longer leaks the
  credentials it finds.
- **NFKC + Cf stripping before scan.** Attackers (or careless
  Notion/Slack paste) could embed U+200B / U+200D / U+FEFF inside a
  credential to defeat every content rule while still working when the
  consumer stripped Cf characters. Scanner now normalises both the
  path and each added line before regex match. Inline allow-pragma
  check runs against the original line so attackers cannot hide a
  pragma in Cf characters.
- **ReDoS fix in `generic-keyword-assignment`.** Prior lookahead
  `(?!.*(...))` caused O(N²) backtracking on long inputs (a 100 KB
  line with repeated `password:` anchors took ~48 s). Placeholder
  exclusions moved inside the quoted value; same regression now
  completes in ~17 ms.
- **Strict bool config parsing**: `dry_run = "false"` is no longer
  silently truthy (non-empty strings are truthy in Python's `bool()`),
  which would otherwise disable the scanner repo-wide with no log
  line.
- **Diff size cap (50 MB)**: a committer staging a multi-GB text blob
  no longer hangs the pre-commit hook.

### Added

- New detectors: `huggingface-token` (`hf_…`), `dockerhub-pat`
  (`dckr_pat_…`), `google-oauth-refresh` (`1//0…`),
  `db-url-with-password` (postgres / mysql / mongodb / redis / amqp /
  mssql / clickhouse URIs with embedded user:pass@host).

### Changed

- **`filename-dotenv`**: add `re.IGNORECASE` (case-insensitive
  filesystem bypass like `.ENV` / `.Env.Production` no longer
  slips through) and restructure the carve-out so template suffixes
  only short-circuit for `.env` exactly, not when there's an
  arbitrary prefix. `secrets.env.example` / `config.env.production`
  now match the rule.
- **`filename-ssh-private-key`**: add `re.IGNORECASE` (catches
  `id_RSA` / `id_ED25519`) and accept rotation suffixes (`.old`,
  `.bak`, `.backup`, `.orig`, `.save`).
- **`filename-netrc`**: add `_netrc` (Windows variant).
- **`slack-token`**: extend to `xoxe-` (refresh), `xoxe.xoxp-`
  (rotated), `xapp-` (app-level). Length cap raised to 100 for modern
  tokens.
- **`openai-api-key`**: require explicit prefix (`sk-proj-` /
  `sk-svcacct-` / `sk-admin-` / `sk-None-`) with body length ≥40, OR
  legacy `sk-` + 48 strict-alnum. Eliminates false positives like
  `sk-learn-pipeline-classifier-utils-v2`.

### Governance

- `.github/CODEOWNERS` added.
- `release.yml` gains identity-leak grep gate.

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
