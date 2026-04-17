# Installing git-secret-guard

## With pre-commit.com (recommended)

[pre-commit](https://pre-commit.com) manages hooks across your team, pins
exact versions, and runs in CI. If you use it already, this is the shortest
path.

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/hinanohart/git-secret-guard
    rev: v0.1.0
    hooks:
      - id: git-secret-guard
```

Activate the hook in this clone:

```bash
pre-commit install
```

Run it once over the staged diff:

```bash
pre-commit run git-secret-guard --all-files
```

`pre-commit autoupdate` picks up new releases automatically.

## Without pre-commit.com

### Via pipx

```bash
pipx install git-secret-guard
git-secret-guard install-hook
```

`install-hook` writes `.git/hooks/pre-commit` with a 3-line wrapper. Pass
`--force` to overwrite a pre-existing hook.

### Via pip in a venv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install git-secret-guard
git-secret-guard install-hook
```

The hook invokes the `git-secret-guard` binary from `PATH`, so the venv
must be active (or symlinked) when committing. If you commit outside the
venv, prefer `pipx`.

## Verifying the install

```bash
# Should print the version:
git-secret-guard version

# Should list ~30 rules:
git-secret-guard list-rules
```

Create a test file and confirm the hook blocks:

```bash
echo 'KEY="AKIAIOSFODNN7EXAMPLE"' > /tmp/fake.py
git -C /tmp init -q -b main  # throwaway repo
cp /tmp/fake.py /tmp/.git-secret-guard-demo/
# ...then try committing. You should see a BLOCK.
```

## Troubleshooting

### `git: command not found`

The hook fails open — it prints a warning and exits 0. Install git and
try again.

### Hook isn't running

Check `.git/hooks/pre-commit` exists and is executable:

```bash
ls -la .git/hooks/pre-commit
```

For pre-commit.com, confirm `pre-commit install` was run in this clone.

### False positive on a test fixture

Inline pragma is the cleanest path:

```python
TOKEN = "eyJhbGci..."  # git-secret-guard: allow jwt-token
```

For a repeated pattern, silence the rule in config:

```toml
# .git-secret-guard.toml
allowlist = ["generic-keyword-assignment"]
```

### I committed a secret before installing this

Rotate it now. Deleting the commit is not sufficient — assume anything
that touched a public host is compromised. `git filter-repo` or
`git filter-branch` can rewrite history, but the old SHA remains
accessible via forks and caches.
