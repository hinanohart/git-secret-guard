"""Positive and negative tests for every bundled rule.

Each rule ships with:
* at least one string that MUST match (otherwise the rule is asleep at
  the wheel)
* at least one nearby string that MUST NOT match (otherwise the rule
  fires on legitimate code)

Bugs in the catalog are the product's single biggest risk — a noisy
tool gets disabled; a silent one gets exploited. Keep these tests loud.
"""

from __future__ import annotations

import re

import pytest

from git_secret_guard.rules import Rule, all_rule_ids, default_rules
from git_secret_guard.scanner import Severity


def _by_id(rid: str) -> Rule:
    for r in default_rules():
        if r.id == rid:
            return r
    raise AssertionError(f"no rule {rid!r}")


def test_ids_are_unique() -> None:
    ids = [r.id for r in default_rules()]
    assert len(ids) == len(set(ids))


def test_ids_are_kebab_case() -> None:
    pattern = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
    for r in default_rules():
        assert pattern.match(r.id), f"bad ID: {r.id}"


def test_all_rule_ids_matches_default_catalog() -> None:
    assert all_rule_ids() == frozenset(r.id for r in default_rules())


def test_every_rule_has_reason_and_category() -> None:
    for r in default_rules():
        assert r.reason, r.id
        assert r.category, r.id


def test_severity_is_known_value() -> None:
    for r in default_rules():
        assert r.severity in (Severity.BLOCK, Severity.WARN)


# -------- Filename rules ---------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".env", True),
        (".env.local", True),
        (".env.production", True),
        ("config/.env", True),
        ("prod.env", True),
        (".env.example", False),  # schema, OK to commit
        (".env.sample", False),
        (".env.template", False),
        ("env.py", False),
        ("README.md", False),
    ],
)
def test_filename_dotenv(path: str, expected: bool) -> None:
    rule = _by_id("filename-dotenv")
    # We allow .env.example/.env.sample/.env.template as non-matches; the
    # regex matches any .env.* suffix, so the "allowed" suffixes are
    # carved out by negative look-ahead. Let's just assert expected match
    # behaviour — implementation may use a separate list.
    got = bool(rule.regex.search(path))
    if path.endswith((".example", ".sample", ".template")):
        # These MUST be allowed. If the current regex incorrectly matches,
        # fail loudly so the carve-out can be added.
        assert got is False, f"dotenv rule incorrectly flagged {path}"
    else:
        assert got is expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("certs/id_rsa", True),
        ("deploy/id_ed25519", True),
        ("~/.ssh/id_ecdsa", True),
        ("backup/jenkins_rsa", True),
        ("README_rsa.md", False),  # not the real key
        ("something.py", False),
    ],
)
def test_filename_ssh_private_key(path: str, expected: bool) -> None:
    rule = _by_id("filename-ssh-private-key")
    assert bool(rule.regex.search(path)) is expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("keys/server.pem", True),
        ("prod.key", True),
        ("cert.p12", True),
        ("cert.pfx", True),
        ("encryption.asc", True),
        ("README.md", False),
        ("config.yaml", False),
    ],
)
def test_filename_private_key_ext(path: str, expected: bool) -> None:
    rule = _by_id("filename-private-key")
    assert bool(rule.regex.search(path)) is expected


def test_filename_aws_credentials() -> None:
    rule = _by_id("filename-aws-credentials")
    assert rule.regex.search(".aws/credentials")
    assert rule.regex.search("dist/.aws/credentials")
    assert not rule.regex.search("aws/credentials.txt")


def test_filename_netrc() -> None:
    rule = _by_id("filename-netrc")
    assert rule.regex.search(".netrc")
    assert rule.regex.search("home/.netrc")
    assert not rule.regex.search("netrc.py")


def test_filename_pypirc() -> None:
    rule = _by_id("filename-pypirc")
    assert rule.regex.search(".pypirc")
    assert not rule.regex.search("pypirc_template.py")


# -------- Cloud content rules ---------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        "ASIAZPWUNYTHTOZYX6HN",
        "AROAJI4AVVEXAMPLE123",
    ],
)
def test_aws_access_key_id_positive(line: str) -> None:
    assert _by_id("aws-access-key-id").regex.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "let s = 'AKIAshort'",  # too short
        "const id = 'AKIALOWERcaseok12345'",  # contains lowercase — fails [0-9A-Z]
        "const k = 'key-ABCDEFGH1234567890'",  # wrong prefix
    ],
)
def test_aws_access_key_id_negative(line: str) -> None:
    assert not _by_id("aws-access-key-id").regex.search(line)


def test_aws_secret_access_key() -> None:
    rule = _by_id("aws-secret-access-key")
    assert rule.regex.search('aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    assert not rule.regex.search('aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"]')


def test_gcp_service_account_json() -> None:
    rule = _by_id("gcp-service-account-private-key")
    assert rule.regex.search('"type": "service_account"')
    assert rule.regex.search('{"type":"service_account","project_id":"x"}')
    assert not rule.regex.search('"type": "user"')


def test_azure_storage_connection_string() -> None:
    rule = _by_id("azure-storage-connection-string")
    cs = "DefaultEndpointsProtocol=https;AccountName=prod;AccountKey=abcDEFghij+/=="
    assert rule.regex.search(cs)
    assert not rule.regex.search("DefaultEndpointsProtocol=https;AccountName=prod")


# -------- VCS ---------------------------------------------------------------


def test_github_pat_classic() -> None:
    rule = _by_id("github-pat-classic")
    assert rule.regex.search("ghp_" + "A" * 36)
    assert not rule.regex.search("ghp_tooshort")


def test_github_pat_fine_grained() -> None:
    rule = _by_id("github-pat-fine-grained")
    assert rule.regex.search("github_pat_" + "A" * 60)
    assert not rule.regex.search("github_pat_short")


def test_github_oauth_token() -> None:
    rule = _by_id("github-oauth-token")
    for prefix in ("gho_", "ghu_", "ghs_", "ghr_"):
        assert rule.regex.search(prefix + "A" * 36)


def test_gitlab_pat() -> None:
    rule = _by_id("gitlab-pat")
    assert rule.regex.search("glpat-" + "x" * 20)
    assert not rule.regex.search("glpat-short")


# -------- Chat --------------------------------------------------------------


def test_slack_token() -> None:
    rule = _by_id("slack-token")
    for prefix in ("xoxa-", "xoxb-", "xoxp-", "xoxs-", "xoxr-"):
        assert rule.regex.search(prefix + "A" * 20)


def test_slack_webhook() -> None:
    rule = _by_id("slack-webhook")
    # Construct via concatenation so the literal shape doesn't appear in
    # source and trip third-party secret scanners (GitHub push protection,
    # etc.) that don't know this is an obviously-fake placeholder.
    url = "https://hooks.slack.com/services/" + "T" + "0" * 8 + "/" + "B" + "0" * 8 + "/" + "X" * 24
    assert rule.regex.search(url)


def test_discord_webhook() -> None:
    rule = _by_id("discord-webhook")
    assert rule.regex.search("https://discord.com/api/webhooks/123456/abcXYZ_0123-456")
    assert rule.regex.search("https://discordapp.com/api/webhooks/123456/abcXYZ_0123-456")


def test_telegram_bot_token() -> None:
    rule = _by_id("telegram-bot-token")
    assert rule.regex.search("1234567890:" + "A" * 35)
    assert not rule.regex.search("1234:shortshortshortshort")


# -------- SaaS --------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "sk_live_" + "A" * 24,
        "sk_test_" + "B" * 24,
        "rk_live_" + "C" * 24,
    ],
)
def test_stripe_secret_key(line: str) -> None:
    assert _by_id("stripe-secret-key").regex.search(line)


def test_sendgrid_key() -> None:
    rule = _by_id("sendgrid-key")
    assert rule.regex.search("SG." + "A" * 22 + "." + "B" * 43)


def test_mailgun_key() -> None:
    rule = _by_id("mailgun-key")
    assert rule.regex.search("key-" + "a" * 32)


def test_openai_api_key() -> None:
    rule = _by_id("openai-api-key")
    assert rule.regex.search("sk-" + "A" * 32)
    assert rule.regex.search("sk-proj-" + "A" * 48)


def test_anthropic_api_key() -> None:
    rule = _by_id("anthropic-api-key")
    assert rule.regex.search("sk-ant-" + "A" * 80)


def test_google_api_key() -> None:
    rule = _by_id("google-api-key")
    assert rule.regex.search("AIza" + "A" * 35)


# -------- Crypto ------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ],
)
def test_pem_private_key_block(line: str) -> None:
    assert _by_id("pem-private-key-block").regex.search(line)


def test_pgp_private_key_block() -> None:
    rule = _by_id("pgp-private-key-block")
    assert rule.regex.search("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert not rule.regex.search("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_jwt_token() -> None:
    rule = _by_id("jwt-token")
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert rule.regex.search(jwt)


# -------- Generic -----------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'api_key = "abcdefghijklmnop1234"',
        'password: "NotAReal1234PasswordRand"',
        'const token = "sk_abcdefghij1234567890"',
    ],
)
def test_generic_keyword_assignment_positive(line: str) -> None:
    assert _by_id("generic-keyword-assignment").regex.search(line)


@pytest.mark.parametrize(
    "line",
    [
        'api_key = os.environ["API_KEY"]',
        "password = process.env.PASSWORD",
        'token = "${TOKEN}"',
        'secret = "{{ .Secret }}"',
        'api_key = "<your-key-here>"',
        'password = "xxxxxxxxxxxxxxxxx"',
        'token = "***redacted***"',
    ],
)
def test_generic_keyword_assignment_negative(line: str) -> None:
    assert not _by_id("generic-keyword-assignment").regex.search(line)
