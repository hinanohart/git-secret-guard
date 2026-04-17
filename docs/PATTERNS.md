# Rule Catalog

Every rule has a stable `id` — pin it in your `allowlist` to opt out of a
specific check without losing coverage of the rest. **IDs never change
meaning.** Bugs are fixed in place; deprecated rules are removed only in
major versions.

Generate this list at runtime with:

```bash
git-secret-guard list-rules
```

## Filename rules

Fire on the path alone. The reasoning: even an empty file named `.env` is a
bad precedent that almost certainly should have been `.gitignore`d.

| ID | Severity | What it catches |
| -- | -------- | --------------- |
| `filename-dotenv` | BLOCK | `.env`, `.env.local`, `.env.production`, `prod.env`, etc. **Allows** `.env.example`, `.env.sample`, `.env.template`. |
| `filename-private-key` | BLOCK | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.asc`. |
| `filename-ssh-private-key` | BLOCK | `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, custom `*_rsa` names. |
| `filename-aws-credentials` | BLOCK | `.aws/credentials` anywhere in the tree. |
| `filename-netrc` | BLOCK | `.netrc` (plaintext HTTP/FTP credentials). |
| `filename-pypirc` | BLOCK | `.pypirc` (PyPI upload tokens). |
| `filename-gcp-service-account` | WARN | `*service-account*.json`, `*-sa.json`. Verify content. |
| `filename-kube-config` | WARN | `kubeconfig`, `.kube/config`. May embed cluster creds. |
| `filename-credentials-json` | WARN | Files literally named `credentials.json` or `secrets.yml`. |

## Cloud content rules

| ID | Severity | Shape |
| -- | -------- | ----- |
| `aws-access-key-id` | BLOCK | `AKIA…`, `ASIA…`, `AGPA…`, `AIDA…`, `AROA…`, `ANPA…`, `ACCA…` (20-char AWS key IDs). |
| `aws-secret-access-key` | BLOCK | Literal 40-char secret key assigned to a secret-like name. |
| `gcp-service-account-private-key` | BLOCK | `"type": "service_account"` — GCP service-account JSON shape. |
| `azure-storage-connection-string` | BLOCK | `DefaultEndpointsProtocol=…;AccountKey=…` literal. |

## VCS tokens

| ID | Severity | Shape |
| -- | -------- | ----- |
| `github-pat-classic` | BLOCK | `ghp_` + 36+ chars. |
| `github-pat-fine-grained` | BLOCK | `github_pat_` + 50+ chars. |
| `github-oauth-token` | BLOCK | `gho_`, `ghu_`, `ghs_`, `ghr_` + 36+ chars. |
| `gitlab-pat` | BLOCK | `glpat-` + 20+ chars. |

## Chat / notification

| ID | Severity | Shape |
| -- | -------- | ----- |
| `slack-token` | BLOCK | `xoxa-`, `xoxb-`, `xoxp-`, `xoxs-`, `xoxr-` bot/user tokens. |
| `slack-webhook` | BLOCK | `https://hooks.slack.com/services/T…/B…/…` URL. |
| `discord-webhook` | BLOCK | `https://(discord|discordapp).com/api/webhooks/…` URL. |
| `telegram-bot-token` | BLOCK | `<digits>:<35-char token>` shape. |

## SaaS API keys

| ID | Severity | Shape |
| -- | -------- | ----- |
| `stripe-secret-key` | BLOCK | `sk_live_…`, `sk_test_…`, `rk_live_…`, `rk_test_…`. |
| `sendgrid-key` | BLOCK | `SG.<22 chars>.<43 chars>`. |
| `mailgun-key` | BLOCK | `key-<32 hex chars>`. |
| `openai-api-key` | BLOCK | `sk-…` / `sk-proj-…` + 32+ chars. |
| `anthropic-api-key` | BLOCK | `sk-ant-` + 80+ chars. |
| `google-api-key` | BLOCK | `AIza` + 35 chars. |

## Cryptographic material

| ID | Severity | Shape |
| -- | -------- | ----- |
| `pem-private-key-block` | BLOCK | `-----BEGIN (RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY-----` header. |
| `pgp-private-key-block` | BLOCK | `-----BEGIN PGP PRIVATE KEY BLOCK-----`. |
| `jwt-token` | WARN | JWT-shaped `eyJ…` three-segment base64url strings. (WARN because test fixtures legitimately include dummy JWTs.) |

## Generic

| ID | Severity | Shape |
| -- | -------- | ----- |
| `generic-keyword-assignment` | WARN | `api_key = "…"`, `password: "…"`, `token = "…"` with a 16+ char literal. Skips obvious non-secrets (`os.environ`, `process.env`, `${...}`, `<...>`, `xxx…`, `***…`). |

## Why WARN vs BLOCK?

* **BLOCK** — the match is overwhelmingly likely to be a real credential.
  False positives should be rare enough to justify using the inline pragma
  or the allowlist.
* **WARN** — the shape is suspicious but legitimately appears in test
  fixtures, docs, or placeholder code. Teams that want zero tolerance can
  set `warn_as_block = true` in config.

## Proposing new rules

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md). Every new rule needs:

1. A stable kebab-case ID (`<category>-<short-name>`).
2. Positive tests (strings that must match).
3. Negative tests (nearby strings that must not match).
4. A one-sentence `reason` shown to users on fire.
5. A row in this document.
