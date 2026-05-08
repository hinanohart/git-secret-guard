# git-secret-guard

> ## ℹ️ Notice (2026-05-09) — gitleaks covers most cases, but filename-only rules here are unique
>
> A 2026-05-09 R17 audit found that this repo ships **36 rules**: roughly
> **26 content-based rules** are concept-equivalent to entries in
> [gitleaks](https://github.com/gitleaks/gitleaks)' 222-rule default config
> (`aws-access-token`, `github-pat`, `github-fine-grained-pat`, `gitlab-pat`,
> `slack-token`, `gcp-service-account`, `azure-storage-connection-string`, etc.).
>
> The remaining **10 filename-only rules are unique to this scanner**:
>
> - `filename-dotenv` / `filename-dotenv-example-allowed`
> - `filename-private-key` / `filename-ssh-private-key`
> - `filename-aws-credentials` / `filename-gcp-service-account`
> - `filename-kube-config` / `filename-netrc` / `filename-pypirc`
> - `filename-credentials-json`
>
> These block **even empty files with sensitive names** — e.g., committing
> an empty `.env`, an empty `id_rsa`, or an empty `.kube/config`. gitleaks
> scans content together with filename, so it does **not** block such empty
> sensitive-named files. If "the path itself is the secret signal" matters
> in your threat model (precedent guard, prevent placeholder commits that
> later get filled in), the filename-only layer here is genuinely
> complementary.
>
> ### Recommendation
>
> - **Most projects**: use [gitleaks](https://github.com/gitleaks/gitleaks)
>   alone (Go, 17k★, 222 content rules, faster, more battle-tested).
>
>   ```yaml
>   # .pre-commit-config.yaml
>   repos:
>     - repo: https://github.com/gitleaks/gitleaks
>       rev: v8.28.0
>       hooks:
>         - id: gitleaks
>   ```
>
> - **If empty-sensitive-filename block matters**: keep `git-secret-guard`
>   as a thin precedent layer running before gitleaks, or open an upstream
>   issue at https://github.com/gitleaks/gitleaks/issues proposing
>   path-only patterns (the contribution would benefit the whole ecosystem).
>
> This repo stays in maintenance mode for security fixes and existing users
> with an empty-file precedent need; new development should target gitleaks
> instead.

---

A zero-dependency pre-commit hook that blocks secrets before they enter git
history.

Designed to be **loud, fast, and boring**:

* **Loud.** When a secret matches, the commit stops. No silent partial scans.
* **Fast.** Pure regex over `git diff --cached`; finishes in milliseconds on
  normal diffs.
* **Boring.** No network calls, no ML, no hidden state. One regex per rule,
  each with positive and negative tests. Catalog is append-only; rule IDs
  never change meaning.

Why another secret scanner? Most existing tools run as a repo-wide scan on
a schedule or in CI. By then the secret is already committed, already pushed,
and already indexed. `git-secret-guard` runs **before the commit lands**, so
the credential never enters history at all.

## Install

```bash
pip install git-secret-guard
```

Or use [pipx](https://pipx.pypa.io/) so the CLI lands on your PATH without
polluting the project's environment:

```bash
pipx install git-secret-guard
```

## Use it with pre-commit.com

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/hinanohart/git-secret-guard
    rev: v0.1.0
    hooks:
      - id: git-secret-guard
```

Then:

```bash
pre-commit install
```

## Use it without pre-commit.com

```bash
pip install git-secret-guard
git-secret-guard install-hook
```

This drops a 3-line `.git/hooks/pre-commit` wrapper that calls
`git-secret-guard scan`. Use `--force` to overwrite an existing hook.

## What it catches

| Category      | Example rule                       | Default severity |
| ------------- | ---------------------------------- | ---------------- |
| Filenames     | `.env`, `id_rsa`, `.aws/credentials`, `.netrc`, `.pypirc` | BLOCK |
| Cloud         | AWS access/secret keys, Azure storage connection strings, GCP service-account JSON | BLOCK |
| VCS           | GitHub PATs (classic + fine-grained), GitHub OAuth tokens, GitLab PATs | BLOCK |
| Chat          | Slack tokens, Slack/Discord webhooks, Telegram bot tokens | BLOCK |
| SaaS          | Stripe, SendGrid, Mailgun, OpenAI, Anthropic, Google API keys | BLOCK |
| Cryptographic | PEM private-key headers, PGP private-key blocks, JWTs | BLOCK (WARN for JWT) |
| Generic       | `api_key = "..."` style literal assignments | WARN |

See [`docs/PATTERNS.md`](docs/PATTERNS.md) for every rule, its ID, regex, and
rationale.

## Configure

Config lives at `~/.config/git-secret-guard/config.toml`, or
`.git-secret-guard.toml` at the repo root, or wherever
`$GIT_SECRET_GUARD_CONFIG` points.

```toml
# Silence specific rules by their stable ID. Everything else keeps working.
allowlist = [
  "filename-credentials-json",
]

# Never block — just print findings. Good for onboarding.
dry_run = false

# Treat WARN as BLOCK. Good for teams that want zero tolerance.
warn_as_block = false
```

### Inline allow pragma

For one-off false positives (e.g. a test fixture with a dummy JWT), put the
pragma on the **same line** as the match:

```python
TOKEN = "eyJhbGci..."  # git-secret-guard: allow jwt-token
```

Multiple rule IDs can be comma-separated: `# git-secret-guard: allow r1, r2`.
The pragma only silences the line it's on — it cannot be used at the top of
a file to disable scanning wholesale.

## CLI

```text
git-secret-guard scan           # scan staged files (exit 1 on BLOCK)
git-secret-guard scan --dry-run # never exit non-zero
git-secret-guard scan --json    # machine-readable output
git-secret-guard scan --all-files PATH...  # scan working tree instead of diff
git-secret-guard install-hook   # write .git/hooks/pre-commit wrapper
git-secret-guard list-rules     # print the catalog
git-secret-guard version
```

## Library API

```python
from git_secret_guard import scan_staged, Outcome

decision = scan_staged()
if decision.outcome is Outcome.BLOCK:
    for f in decision.findings:
        print(f.rule_id, f.path, f.line, f.reason)
```

Every dataclass is frozen and JSON-safe via `.to_dict()`.

## Design commitments

* **Tight regexes over fuzzy ones.** A rule that fires weekly on legitimate
  code gets ignored; an ignored rule is worse than no rule. We prefer to
  miss an exotic-looking secret rather than block a valid commit.
* **Stable rule IDs.** Pinning an ID in your allowlist must keep working
  across minor versions. New coverage is added as new IDs.
* **No network, no telemetry.** The scanner doesn't call home. Your diffs
  stay on your machine.
* **Fail open on git errors.** If `git` itself is broken, the hook exits 0
  and logs a warning. A broken guard must not become a second outage.

## Threat model

`git-secret-guard` is a **speed bump**, not a vault.

* **In scope:** hard-coded credentials typed or pasted into source files
  that get committed — the single most common source of real-world
  credential leaks.
* **Out of scope:** deliberately obfuscated secrets (base64 encoding, string
  slicing), secrets in binary blobs, secrets that the rule catalog hasn't
  learned about yet, and attackers with push access who can `--no-verify`.
  For those, combine this with server-side scanning, short-lived credentials,
  and least-privilege IAM.

If a secret ever does land in a commit, **rotate it immediately** — even if
you delete the commit. Assume anything ever pushed to a public host is
compromised.

## Contributing

New rule? See [`CONTRIBUTING.md`](CONTRIBUTING.md). Every rule must ship
with positive and negative tests and a one-sentence rationale.

Found a real-world secret shape we miss? Open an issue — please scrub the
value first.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
