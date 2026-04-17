"""Catalog of secret-detection rules.

Each :class:`Rule` has a stable ``id``, a ``category`` for reporting, a
``severity``, a ``kind`` (``"filename"`` for path-level checks or
``"content"`` for line-level checks), a compiled regex, and a
human-readable ``reason``.

Versioning commitments
----------------------

* **IDs never change meaning.** New rules get new IDs; bugs are fixed in
  place; deprecated rules are removed only in major versions. This lets
  teams pin individual allowlists in their config without losing coverage
  of newer rules.
* **Additive by default.** Minor releases add new rules. Allowlists that
  disable a given ID keep working; everyone else picks up the new coverage
  for free.
* **Minimal false positives.** Each new rule ships with positive and
  negative tests. A rule that cries wolf weekly gets ignored, which is
  worse than not having it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

from git_secret_guard.scanner import Severity

RuleKind = Literal["filename", "content"]


@dataclass(frozen=True, slots=True)
class Rule:
    """A single secret-detection rule.

    Parameters
    ----------
    id:
        Stable kebab-case identifier (``<category>-<short-name>``).
    category:
        Grouping label shown in reports.
    severity:
        ``BLOCK`` denies the commit; ``WARN`` surfaces without blocking.
    kind:
        ``"filename"`` to match ``path``; ``"content"`` to match each added
        line.
    regex:
        Compiled pattern. Rules are designed to be tight — we prefer to
        miss an exotic-looking key rather than block a legitimate commit.
    reason:
        One-sentence human-readable explanation.
    """

    id: str
    category: str
    severity: Severity
    kind: RuleKind
    regex: re.Pattern[str]
    reason: str


def _re(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# The catalog is intentionally additive and versioned — see module docstring.
_CATALOG: Final[tuple[Rule, ...]] = (
    # --- Filename rules ---------------------------------------------------
    # These fire purely on path. The reasoning: even if the file is empty
    # today, its *presence* in the repo is a bad precedent and signals that
    # the developer probably meant to .gitignore it.
    Rule(
        id="filename-dotenv",
        category="filename",
        severity=Severity.BLOCK,
        kind="filename",
        # Matches .env, .env.local, .env.production, production.env, etc.
        # but NOT .env.example / .env.sample / .env.template / .env.dist
        # which are the established convention for committing a *schema* of
        # env vars. The negative lookahead only bites when the suffix stands
        # alone (e.g. ``.env.example.bak`` still matches).
        regex=_re(
            r"(?:^|/)"
            r"(?:"
            r"\.env(?:\.(?!(?:example|sample|template|dist)$)[^/]*)?"
            r"|[^/]*\.env"
            r")$",
        ),
        reason=(
            "Dotenv files almost always contain secrets. Use .env.example "
            "for schema, and commit the schema only."
        ),
    ),
    Rule(
        id="filename-dotenv-example-allowed",
        category="filename",
        severity=Severity.WARN,
        kind="filename",
        # This rule never fires; it exists so allowlists can opt out of the
        # auto-exception below. Kept as a catch if we later tighten things.
        regex=_re(r"\A\Z"),
        reason="Reserved.",
    ),
    Rule(
        id="filename-private-key",
        category="filename",
        severity=Severity.BLOCK,
        kind="filename",
        regex=_re(r"\.(?:pem|key|p12|pfx|asc)$", re.IGNORECASE),
        reason="Private-key file extensions (.pem/.key/.p12/.pfx/.asc). Treat as secret unless proven public.",
    ),
    Rule(
        id="filename-ssh-private-key",
        category="filename",
        severity=Severity.BLOCK,
        kind="filename",
        # Matches ~/.ssh/id_rsa, id_ed25519, id_ecdsa, id_dsa, plus *_rsa
        # style custom names.
        regex=_re(r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+_(?:rsa|ed25519|ecdsa))$"),
        reason="SSH private-key file. Committing this hands your identity to anyone with repo access.",
    ),
    Rule(
        id="filename-aws-credentials",
        category="filename",
        severity=Severity.BLOCK,
        kind="filename",
        regex=_re(r"(?:^|/)\.aws/credentials$"),
        reason="AWS shared credentials file. Always contains long-lived access keys.",
    ),
    Rule(
        id="filename-gcp-service-account",
        category="filename",
        severity=Severity.WARN,
        kind="filename",
        # Heuristic: most teams name service-account JSON keys like
        # "prod-sa.json" or "service-account.json". We WARN because the
        # filename alone isn't a proof — user code might also store public
        # metadata JSON. The content rule below upgrades to BLOCK on match.
        regex=_re(
            r"(?:^|/)(?:[^/]*service[-_]?account[^/]*\.json|[^/]*-sa\.json)$",
            re.IGNORECASE,
        ),
        reason="Filename suggests a GCP service-account key. Verify contents before committing.",
    ),
    Rule(
        id="filename-kube-config",
        category="filename",
        severity=Severity.WARN,
        kind="filename",
        regex=_re(r"(?:^|/)(?:kubeconfig|\.kube/config)$"),
        reason="Kubernetes config often embeds cluster credentials. Scrub before committing.",
    ),
    Rule(
        id="filename-netrc",
        category="filename",
        severity=Severity.BLOCK,
        kind="filename",
        regex=_re(r"(?:^|/)\.netrc$"),
        reason=".netrc stores plaintext HTTP/FTP credentials. Never commit.",
    ),
    Rule(
        id="filename-pypirc",
        category="filename",
        severity=Severity.BLOCK,
        kind="filename",
        regex=_re(r"(?:^|/)\.pypirc$"),
        reason=".pypirc stores PyPI upload tokens. Never commit.",
    ),
    Rule(
        id="filename-credentials-json",
        category="filename",
        severity=Severity.WARN,
        kind="filename",
        regex=_re(r"(?:^|/)(?:credentials?|secrets?)\.(?:json|ya?ml)$", re.IGNORECASE),
        reason="File literally named 'credentials' or 'secrets'. Check contents before committing.",
    ),
    # --- Content: cloud provider credentials ------------------------------
    Rule(
        id="aws-access-key-id",
        category="cloud",
        severity=Severity.BLOCK,
        kind="content",
        # AKIA (long-lived), ASIA (STS session), AGPA (user groups), AIDA
        # (users), AROA (roles), ANPA (managed policies). All 20 chars.
        regex=_re(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|ACCA)[0-9A-Z]{16}\b"),
        reason="AWS Access Key ID. Revoke immediately if committed — scanners find these within minutes.",
    ),
    Rule(
        id="aws-secret-access-key",
        category="cloud",
        severity=Severity.BLOCK,
        kind="content",
        # AWS secret keys are 40 chars of base64-ish. The keyword anchor
        # keeps false positives low; a raw 40-char base64 string is far too
        # common to block on its own.
        regex=_re(
            r"(?i)aws[_-]?(?:secret[_-]?access[_-]?key|secret)[^\n]{0,20}[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        ),
        reason="AWS Secret Access Key literal. Move to an env var or secrets manager.",
    ),
    Rule(
        id="gcp-service-account-private-key",
        category="cloud",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r'"type"\s*:\s*"service_account"'),
        reason="GCP service-account JSON key contents detected. This grants full project access.",
    ),
    Rule(
        id="azure-storage-connection-string",
        category="cloud",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(
            r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
        ),
        reason="Azure Storage connection string with embedded AccountKey. Use a SAS token or Managed Identity.",
    ),
    # --- Content: VCS / CI platforms --------------------------------------
    Rule(
        id="github-pat-classic",
        category="vcs",
        severity=Severity.BLOCK,
        kind="content",
        # Classic PATs: "ghp_" + 36+ of [A-Za-z0-9]. Newer fine-grained
        # tokens start with "github_pat_".
        regex=_re(r"\bghp_[A-Za-z0-9]{36,}\b"),
        reason="GitHub personal access token (classic). Revoke via Settings > Developer settings.",
    ),
    Rule(
        id="github-pat-fine-grained",
        category="vcs",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
        reason="GitHub fine-grained personal access token. Revoke immediately.",
    ),
    Rule(
        id="github-oauth-token",
        category="vcs",
        severity=Severity.BLOCK,
        kind="content",
        # gho_ = OAuth user-to-server, ghu_ = user-to-server, ghs_ = server-
        # to-server, ghr_ = refresh.
        regex=_re(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
        reason="GitHub OAuth/app token. Revoke via the relevant App or Action settings.",
    ),
    Rule(
        id="gitlab-pat",
        category="vcs",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        reason="GitLab personal access token. Revoke via User Settings > Access Tokens.",
    ),
    # --- Content: communication platforms --------------------------------
    Rule(
        id="slack-token",
        category="chat",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b"),
        reason="Slack API token. Revoke via the Slack app dashboard.",
    ),
    Rule(
        id="slack-webhook",
        category="chat",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        ),
        reason="Slack incoming webhook URL. Treat as a credential — anyone with the URL can post as the bot.",
    ),
    Rule(
        id="discord-webhook",
        category="chat",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(
            r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        ),
        reason="Discord webhook URL. Anyone with this can post to the channel — rotate via server settings.",
    ),
    Rule(
        id="telegram-bot-token",
        category="chat",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
        reason="Telegram bot token. Revoke via BotFather /revoke.",
    ),
    # --- Content: payment / SaaS ----------------------------------------
    Rule(
        id="stripe-secret-key",
        category="saas",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        reason="Stripe secret or restricted key. Roll immediately via the Stripe dashboard.",
    ),
    Rule(
        id="sendgrid-key",
        category="saas",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        reason="SendGrid API key. Revoke via the SendGrid dashboard.",
    ),
    Rule(
        id="mailgun-key",
        category="saas",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bkey-[0-9a-f]{32}\b"),
        reason="Mailgun API key. Rotate via the Mailgun dashboard.",
    ),
    Rule(
        id="openai-api-key",
        category="saas",
        severity=Severity.BLOCK,
        kind="content",
        # Both legacy (sk-...) and project-scoped (sk-proj-...) keys.
        regex=_re(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
        reason="OpenAI API key. Revoke via platform.openai.com/api-keys.",
    ),
    Rule(
        id="anthropic-api-key",
        category="saas",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bsk-ant-[A-Za-z0-9_-]{80,}\b"),
        reason="Anthropic API key. Revoke via console.anthropic.com.",
    ),
    Rule(
        id="google-api-key",
        category="saas",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        reason="Google API key. Revoke via console.cloud.google.com > Credentials.",
    ),
    # --- Content: cryptographic material ---------------------------------
    Rule(
        id="pem-private-key-block",
        category="crypto",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        ),
        reason="PEM private-key header in diff. Private keys must never enter version control.",
    ),
    Rule(
        id="pgp-private-key-block",
        category="crypto",
        severity=Severity.BLOCK,
        kind="content",
        regex=_re(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        reason="PGP private key block. Treat as compromised if committed.",
    ),
    Rule(
        id="jwt-token",
        category="crypto",
        severity=Severity.WARN,
        kind="content",
        # Three base64url segments joined by dots. We WARN rather than BLOCK
        # because test fixtures legitimately include dummy JWTs — the
        # assumption is that real tokens will also trip a more specific rule
        # (GitHub/Slack/etc).
        regex=_re(
            r"\beyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_.=-]{10,}\b",
        ),
        reason="JWT-shaped string. Verify it isn't a real user token — if so, rotate the signing key.",
    ),
    # --- Content: generic high-signal keyword+value ----------------------
    Rule(
        id="generic-keyword-assignment",
        category="generic",
        severity=Severity.WARN,
        kind="content",
        # Keyword followed by ``=`` or ``:`` then a 16+ char literal. Carve
        # out the obvious non-secret shapes so noise stays manageable:
        #   * references to env vars: os.environ, process.env, $VAR, getenv
        #   * template placeholders: ${...}, {{...}}, <...>, xxx..., ****
        regex=_re(
            r"""(?ix)
            (?:api[_-]?key|secret|password|passwd|token|access[_-]?key)
            \s*[:=]\s*
            ['"]
            (?!.*(?:os\.environ|process\.env|getenv|\$\{|\{\{|<|xxx+|\*\*\*+))
            ([A-Za-z0-9/_+=.-]{16,})
            ['"]
            """,
        ),
        reason=(
            "Hard-coded literal assigned to a secret-like name. Move to an env "
            "var or secrets manager. If this is a test fixture, add the inline "
            "pragma 'git-secret-guard: allow generic-keyword-assignment'."
        ),
    ),
)


def default_rules() -> tuple[Rule, ...]:
    """Return the bundled rule catalog."""
    return _CATALOG


def all_rule_ids() -> frozenset[str]:
    """Return every default rule ID — useful for config validation."""
    return frozenset(r.id for r in _CATALOG)
