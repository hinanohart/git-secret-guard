"""Tests for git integration.

Use a real ephemeral git repo rather than mocking subprocess. Mocks of
subprocess drift; a real repo either works or it doesn't.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from git_secret_guard.scanner import Outcome
from git_secret_guard.staged import (
    GitNotAvailableError,
    scan_files,
    scan_staged,
    staged_added_lines,
    staged_paths,
)

GIT_AVAILABLE = shutil.which("git") is not None

pytestmark = pytest.mark.skipif(not GIT_AVAILABLE, reason="git not on PATH")


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """An initialized, identity-configured ephemeral git repo."""
    _run(["init", "-q", "-b", "main"], tmp_path)
    _run(["config", "user.email", "test@example.com"], tmp_path)
    _run(["config", "user.name", "Test"], tmp_path)
    _run(["config", "commit.gpgsign", "false"], tmp_path)
    return tmp_path


def test_staged_paths_empty_repo(repo: Path) -> None:
    assert staged_paths(cwd=repo) == []


def test_staged_paths_returns_added_files(repo: Path) -> None:
    (repo / "a.txt").write_text("hello\n")
    (repo / "b.txt").write_text("world\n")
    _run(["add", "a.txt"], repo)
    assert staged_paths(cwd=repo) == ["a.txt"]


def test_staged_added_lines_returns_new_content(repo: Path) -> None:
    (repo / "a.txt").write_text("line1\nline2\n")
    _run(["add", "a.txt"], repo)
    assert staged_added_lines("a.txt", cwd=repo) == ("line1", "line2")


def test_staged_added_lines_skips_hunk_markers(repo: Path) -> None:
    (repo / "a.txt").write_text("a\nb\nc\nd\n")
    _run(["add", "a.txt"], repo)
    _run(["commit", "-m", "init", "--no-verify"], repo)
    (repo / "a.txt").write_text("a\nb\nNEW\nd\n")
    _run(["add", "a.txt"], repo)
    added = staged_added_lines("a.txt", cwd=repo)
    assert "NEW" in added
    assert not any(line.startswith("@@") for line in added)
    assert not any(line.startswith("+++") for line in added)


def test_scan_staged_blocks_on_aws_key(repo: Path) -> None:
    (repo / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _run(["add", "config.py"], repo)
    decision = scan_staged(cwd=repo)
    assert decision.outcome is Outcome.BLOCK
    assert any(f.rule_id == "aws-access-key-id" for f in decision.findings)


def test_scan_staged_allows_clean_commit(repo: Path) -> None:
    (repo / "a.py").write_text("print('hello')\n")
    _run(["add", "a.py"], repo)
    decision = scan_staged(cwd=repo)
    assert decision.outcome is Outcome.ALLOW


def test_scan_staged_blocks_dotenv_filename(repo: Path) -> None:
    (repo / ".env").write_text("FOO=bar\n")
    _run(["add", "-f", ".env"], repo)
    decision = scan_staged(cwd=repo)
    assert decision.outcome is Outcome.BLOCK
    assert any(f.rule_id == "filename-dotenv" for f in decision.findings)


def test_scan_staged_allows_dotenv_example(repo: Path) -> None:
    (repo / ".env.example").write_text("FOO=bar\n")
    _run(["add", ".env.example"], repo)
    decision = scan_staged(cwd=repo)
    # Content has no secrets, and filename is in the carve-out.
    assert decision.outcome is Outcome.ALLOW


def test_scan_files_reads_working_tree(repo: Path) -> None:
    # Not staged — should still fire because we're reading the WT.
    (repo / "leaked.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    decision = scan_files(["leaked.py"], cwd=repo)
    assert decision.outcome is Outcome.BLOCK


def test_scan_files_ignores_binary_gracefully(repo: Path) -> None:
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02\x03\xff")
    decision = scan_files(["blob.bin"], cwd=repo)
    assert decision.outcome is Outcome.ALLOW


def test_git_missing_raises_helpful_error(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    # Point PATH away from git. The helper should raise a typed error
    # instead of bubbling a raw FileNotFoundError.
    monkeypatch.setenv("PATH", "/no/such/path")  # type: ignore[attr-defined]
    with pytest.raises(GitNotAvailableError):
        staged_paths(cwd=tmp_path)
