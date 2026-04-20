"""Evaluation engine — pure, deterministic, side-effect-free.

The scanner takes a bundle of inputs to inspect (file paths and, optionally,
their diff/content) and a list of :class:`~git_secret_guard.rules.Rule`
objects, and returns an immutable :class:`Decision`.

Design constraints
------------------

* **No I/O.** The engine never touches the filesystem or invokes git. Anyone
  who wants to scan must materialize the inputs themselves (see
  :mod:`git_secret_guard.staged` for the git integration). This keeps the
  engine trivial to unit-test.
* **Immutability.** Every public dataclass is frozen. ``Decision`` is a value
  type that round-trips through JSON cleanly so downstream tools (e.g. CI
  reporters) can consume it without reimplementing it.
* **Explicit ordering.** Findings are returned in the order rules are
  evaluated, which is stable — consumers can rely on it for diff-friendly
  output.

Inline allowlist pragma
-----------------------

A contributor can silence a specific rule on a specific added line by placing
``git-secret-guard: allow <rule-id>`` in a comment on that line. This is
verified by :class:`Scanner` when checking content rules — see
:func:`_line_is_allowlisted`. We deliberately only honor the pragma when it
appears on the *same line* as the match, so a blanket "allow everything"
comment at the top of a file cannot silently disable scanning.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from git_secret_guard.rules import Rule


_INLINE_ALLOW_RE = re.compile(
    r"git-secret-guard\s*:\s*allow\s+([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)",
    re.IGNORECASE,
)


def _normalise_for_scan(text: str) -> str:
    """Fold compatibility forms and drop invisible format chars.

    Parallel to ``claude_safety_guard.guard._normalise_for_scan``. Without
    this step, an attacker (or a careless paste from Notion/Slack) can
    embed U+200B/U+200D/U+FEFF inside an otherwise-matching credential
    literal and defeat every content rule — the scanned bytes are still
    a valid secret after the shell / editor strips the Cf character, but
    the regex never fires because the character class doesn't include Cf.

    NFKC additionally folds full-width forms so fullwidth variants of
    ``password`` / ``secret`` in ``generic-keyword-assignment`` are
    caught.
    """
    return "".join(
        ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf"
    )


class Severity(str, Enum):
    """Severity of a finding.

    ``BLOCK`` causes a non-zero exit in the CLI. ``WARN`` is surfaced but
    allowed by default; users can opt in to blocking on WARN via config.
    """

    BLOCK = "BLOCK"
    WARN = "WARN"


class Outcome(str, Enum):
    """Overall disposition of a scan."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single rule hit.

    Parameters
    ----------
    rule_id:
        Stable kebab-case ID from the rule catalog (e.g. ``"aws-access-key-id"``).
    category:
        Short grouping label (``"filename"``, ``"cloud"``, ``"generic"``...).
    severity:
        Whether this hit should block the commit or just warn.
    reason:
        One-sentence explanation shown to the user.
    path:
        Repository-relative path where the match was found.
    line:
        1-based line number within the file's *added lines* diff. ``None`` for
        filename-level findings (which have no line number).
    matched_text:
        The raw text that matched the rule. Trimmed to 80 chars so we never
        accidentally echo a full credential back into logs.
    """

    rule_id: str
    category: str
    severity: Severity
    reason: str
    path: str
    line: int | None = None
    matched_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "reason": self.reason,
            "path": self.path,
            "line": self.line,
            "matched_text": self.matched_text,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of a scan over one or more inputs."""

    outcome: Outcome
    findings: tuple[Finding, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.outcome is Outcome.BLOCK

    @property
    def has_warnings(self) -> bool:
        return any(f.severity is Severity.WARN for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Knobs that influence scanning without changing the rule set itself.

    Attributes
    ----------
    allowlist:
        Rule IDs to silence unconditionally.
    dry_run:
        Downgrade BLOCK findings to WARN at the outcome level. Findings keep
        their original severity so reporters can still distinguish "would
        have blocked" from "real WARN."
    warn_as_block:
        Promote WARN findings to BLOCK outcome. Useful for teams that want
        every finding to gate.
    """

    allowlist: frozenset[str] = field(default_factory=frozenset)
    dry_run: bool = False
    warn_as_block: bool = False


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """A single file to be scanned.

    ``added_lines`` is the list of lines *added* in the diff, in order. For
    an ``--all-files`` scan this is simply every line in the file.
    """

    path: str
    added_lines: tuple[str, ...] = ()


_MATCH_PREVIEW_LIMIT = 80


def _truncate(text: str) -> str:
    """Redact a matched string so we never echo a full credential.

    A scanner that prints the credential it found — even once, even to
    stderr — is a leak vector. The matched text ends up in CI logs, IDE
    output panels, shell history, and (via alerting) Discord / Slack
    webhooks. Short secrets (AWS access keys at 20 chars, Stripe sk_live_…
    at ~40) fit well under the old 80-char cap, so the raw value was being
    printed in full.

    The output retains enough information for the user to locate the
    finding (first 4 chars + length) without reproducing the secret.
    """
    s = text.strip()
    n = len(s)
    if n == 0:
        return ""
    if n <= 8:
        return f"<redacted len={n}>"
    return f"{s[:4]}…<redacted len={n}>"


def _line_is_allowlisted(line: str, rule_id: str) -> bool:
    """Return True iff the line contains an inline allow pragma for this rule."""
    m = _INLINE_ALLOW_RE.search(line)
    if not m:
        return False
    ids = {part.strip().lower() for part in m.group(1).split(",")}
    return rule_id.lower() in ids


class Scanner:
    """Apply a set of rules to a sequence of :class:`ScanTarget` inputs."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = tuple(rules)

    def scan(
        self,
        targets: Iterable[ScanTarget],
        options: ScanOptions | None = None,
    ) -> Decision:
        opts = options or ScanOptions()
        findings: list[Finding] = []
        for target in targets:
            findings.extend(self._scan_target(target, opts))
        return self._decide(findings, opts)

    def _scan_target(self, target: ScanTarget, opts: ScanOptions) -> list[Finding]:
        hits: list[Finding] = []
        normalised_path = _normalise_for_scan(target.path)
        for rule in self._rules:
            if rule.id in opts.allowlist:
                continue
            if rule.kind == "filename":
                m = rule.regex.search(normalised_path)
                if m:
                    hits.append(
                        Finding(
                            rule_id=rule.id,
                            category=rule.category,
                            severity=rule.severity,
                            reason=rule.reason,
                            path=target.path,
                            line=None,
                            matched_text=_truncate(m.group(0)),
                        )
                    )
            elif rule.kind == "content":
                for i, line in enumerate(target.added_lines, start=1):
                    scan_line = _normalise_for_scan(line)
                    m = rule.regex.search(scan_line)
                    if not m:
                        continue
                    # Allow-pragma check runs against the ORIGINAL line —
                    # otherwise an attacker could use Cf chars to hide an
                    # unwanted pragma. Both views must agree.
                    if _line_is_allowlisted(line, rule.id):
                        continue
                    hits.append(
                        Finding(
                            rule_id=rule.id,
                            category=rule.category,
                            severity=rule.severity,
                            reason=rule.reason,
                            path=target.path,
                            line=i,
                            matched_text=_truncate(m.group(0)),
                        )
                    )
        return hits

    @staticmethod
    def _decide(findings: list[Finding], opts: ScanOptions) -> Decision:
        if not findings:
            return Decision(outcome=Outcome.ALLOW, findings=())
        severities = {f.severity for f in findings}
        has_block = Severity.BLOCK in severities
        has_warn = Severity.WARN in severities

        if opts.dry_run:
            # Dry-run: never block. If any finding fired, emit WARN.
            return Decision(outcome=Outcome.WARN, findings=tuple(findings))

        if has_block or (opts.warn_as_block and has_warn):
            return Decision(outcome=Outcome.BLOCK, findings=tuple(findings))
        return Decision(outcome=Outcome.WARN, findings=tuple(findings))
