"""Tests for the scanner engine, independent of the rule catalog."""

from __future__ import annotations

import dataclasses
import json
import re

import pytest

from git_secret_guard.rules import Rule
from git_secret_guard.scanner import (
    Decision,
    Finding,
    Outcome,
    Scanner,
    ScanOptions,
    ScanTarget,
    Severity,
)


def _rule(
    rid: str = "test-rule",
    severity: Severity = Severity.BLOCK,
    kind: str = "content",
    regex: str = r"DANGER",
    category: str = "test",
) -> Rule:
    return Rule(
        id=rid,
        category=category,
        severity=severity,
        kind=kind,  # type: ignore[arg-type]
        regex=re.compile(regex),
        reason="test reason",
    )


def test_empty_targets_returns_allow() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan([])
    assert decision.outcome is Outcome.ALLOW
    assert decision.findings == ()


def test_content_rule_blocks_on_match() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("x = DANGER",))],
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.blocked is True
    assert len(decision.findings) == 1
    f = decision.findings[0]
    assert f.rule_id == "test-rule"
    assert f.line == 1
    assert f.path == "a.py"


def test_content_rule_reports_line_numbers_correctly() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("ok", "ok", "DANGER", "DANGER again"))],
    )
    lines = sorted(f.line for f in decision.findings if f.line is not None)
    assert lines == [3, 4]


def test_filename_rule_has_no_line_number() -> None:
    scanner = Scanner([_rule(kind="filename", regex=r"\.pem$")])
    decision = scanner.scan([ScanTarget(path="secrets/id_rsa.pem", added_lines=())])
    assert decision.outcome is Outcome.BLOCK
    assert decision.findings[0].line is None


def test_warn_alone_produces_warn_outcome() -> None:
    scanner = Scanner([_rule(severity=Severity.WARN)])
    decision = scanner.scan([ScanTarget(path="a.py", added_lines=("DANGER",))])
    assert decision.outcome is Outcome.WARN
    assert decision.has_warnings is True
    assert decision.blocked is False


def test_block_plus_warn_is_block() -> None:
    rules = [
        _rule("b", Severity.BLOCK, regex=r"KILL"),
        _rule("w", Severity.WARN, regex=r"DANGER"),
    ]
    scanner = Scanner(rules)
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("KILL", "DANGER"))],
    )
    assert decision.outcome is Outcome.BLOCK
    assert {f.rule_id for f in decision.findings} == {"b", "w"}


def test_allowlist_silences_specific_rule() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("DANGER",))],
        options=ScanOptions(allowlist=frozenset({"test-rule"})),
    )
    assert decision.outcome is Outcome.ALLOW
    assert decision.findings == ()


def test_allowlist_does_not_silence_other_rules() -> None:
    rules = [
        _rule("r1", regex=r"DANGER"),
        _rule("r2", regex=r"KILL"),
    ]
    scanner = Scanner(rules)
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("DANGER KILL",))],
        options=ScanOptions(allowlist=frozenset({"r1"})),
    )
    assert decision.outcome is Outcome.BLOCK
    assert {f.rule_id for f in decision.findings} == {"r2"}


def test_dry_run_downgrades_block_outcome_to_warn() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("DANGER",))],
        options=ScanOptions(dry_run=True),
    )
    assert decision.outcome is Outcome.WARN
    assert decision.findings[0].severity is Severity.BLOCK


def test_warn_as_block_promotes_outcome() -> None:
    scanner = Scanner([_rule(severity=Severity.WARN)])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("DANGER",))],
        options=ScanOptions(warn_as_block=True),
    )
    assert decision.outcome is Outcome.BLOCK


def test_inline_allow_pragma_silences_matching_line() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan(
        [
            ScanTarget(
                path="a.py",
                added_lines=("foo = DANGER  # git-secret-guard: allow test-rule",),
            )
        ],
    )
    assert decision.outcome is Outcome.ALLOW


def test_inline_allow_pragma_does_not_silence_other_rules() -> None:
    rules = [_rule("test-rule"), _rule("other", regex=r"DANGER")]
    scanner = Scanner(rules)
    decision = scanner.scan(
        [
            ScanTarget(
                path="a.py",
                added_lines=("DANGER  # git-secret-guard: allow test-rule",),
            )
        ],
    )
    # Only "other" should remain.
    assert {f.rule_id for f in decision.findings} == {"other"}


def test_inline_allow_pragma_multiple_ids() -> None:
    rules = [_rule("r1"), _rule("r2", regex=r"DANGER")]
    scanner = Scanner(rules)
    decision = scanner.scan(
        [
            ScanTarget(
                path="a.py",
                added_lines=("DANGER  # git-secret-guard: allow r1, r2",),
            )
        ],
    )
    assert decision.outcome is Outcome.ALLOW


def test_matched_text_is_truncated() -> None:
    scanner = Scanner([_rule(regex=r"A{1,500}")])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("A" * 400,))],
    )
    assert len(decision.findings[0].matched_text) <= 83  # 80 + "..."
    assert decision.findings[0].matched_text.endswith("...")


def test_finding_to_dict_json_roundtrip() -> None:
    f = Finding(
        rule_id="r",
        category="c",
        severity=Severity.BLOCK,
        reason="why",
        path="p",
        line=3,
        matched_text="x",
    )
    data = f.to_dict()
    assert json.loads(json.dumps(data)) == data


def test_decision_to_dict_json_roundtrip() -> None:
    scanner = Scanner([_rule()])
    decision = scanner.scan([ScanTarget(path="a", added_lines=("DANGER",))])
    data = decision.to_dict()
    assert json.loads(json.dumps(data)) == data


def test_decision_is_immutable() -> None:
    d = Decision(outcome=Outcome.ALLOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.outcome = Outcome.BLOCK  # type: ignore[misc]


def test_empty_rule_list_never_blocks() -> None:
    scanner = Scanner([])
    decision = scanner.scan(
        [ScanTarget(path="a.py", added_lines=("DANGER",))],
    )
    assert decision.outcome is Outcome.ALLOW
