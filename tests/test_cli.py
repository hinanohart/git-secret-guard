"""Tests for the command-line interface."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from git_secret_guard._version import __version__
from git_secret_guard.cli import main

GIT_AVAILABLE = shutil.which("git") is not None


def _run_git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: object) -> Path:
    if not GIT_AVAILABLE:
        pytest.skip("git not on PATH")
    _run_git(["init", "-q", "-b", "main"], tmp_path)
    _run_git(["config", "user.email", "t@example.com"], tmp_path)
    _run_git(["config", "user.name", "T"], tmp_path)
    _run_git(["config", "commit.gpgsign", "false"], tmp_path)
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    return tmp_path


def test_version_prints_version(capsys: object) -> None:
    rc = main(["version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()  # type: ignore[attr-defined]
    assert out == __version__


def test_list_rules_prints_header(capsys: object) -> None:
    rc = main(["list-rules"])
    assert rc == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "ID" in out.splitlines()[0]
    assert "aws-access-key-id" in out


def test_scan_clean_repo_returns_zero(repo: Path, capsys: object) -> None:
    (repo / "a.py").write_text("print('hi')\n")
    _run_git(["add", "a.py"], repo)
    rc = main(["scan"])
    assert rc == 0
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "ALLOW" in out


def test_scan_with_secret_blocks(repo: Path, capsys: object) -> None:
    (repo / "leaked.py").write_text('K="AKIAIOSFODNN7EXAMPLE"\n')
    _run_git(["add", "leaked.py"], repo)
    rc = main(["scan"])
    assert rc == 1
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "BLOCK" in out
    assert "aws-access-key-id" in out


def test_scan_json_output_is_valid(repo: Path, capsys: object) -> None:
    (repo / "leaked.py").write_text('K="AKIAIOSFODNN7EXAMPLE"\n')
    _run_git(["add", "leaked.py"], repo)
    rc = main(["scan", "--json"])
    assert rc == 1
    out = capsys.readouterr().out  # type: ignore[attr-defined]
    payload = json.loads(out)
    assert payload["outcome"] == "BLOCK"
    assert payload["findings"]


def test_scan_dry_run_never_blocks(repo: Path) -> None:
    (repo / "leaked.py").write_text('K="AKIAIOSFODNN7EXAMPLE"\n')
    _run_git(["add", "leaked.py"], repo)
    rc = main(["scan", "--dry-run"])
    assert rc == 0


def test_scan_warn_as_block_promotes_warn(repo: Path) -> None:
    # JWT tokens are WARN severity; with --warn-as-block, a clean
    # otherwise-WARN diff should now block.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    (repo / "fixture.py").write_text(f'TOKEN = "{jwt}"\n')
    _run_git(["add", "fixture.py"], repo)

    rc_default = main(["scan"])
    assert rc_default == 0  # just WARN, exit 0

    rc_strict = main(["scan", "--warn-as-block"])
    assert rc_strict == 1


def test_scan_positional_files_argument(repo: Path) -> None:
    # Simulates pre-commit.com passing file paths.
    (repo / "leaked.py").write_text('K="AKIAIOSFODNN7EXAMPLE"\n')
    _run_git(["add", "leaked.py"], repo)
    rc = main(["scan", "leaked.py"])
    assert rc == 1


def test_scan_all_files_uses_working_tree(repo: Path) -> None:
    # File is NOT staged, but --all-files reads the working tree anyway.
    (repo / "leaked.py").write_text('K="AKIAIOSFODNN7EXAMPLE"\n')
    rc = main(["scan", "--all-files", "leaked.py"])
    assert rc == 1


def test_install_hook_writes_executable(repo: Path) -> None:
    rc = main(["install-hook"])
    assert rc == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.is_file()
    # chmod bits
    mode = hook.stat().st_mode
    assert mode & 0o111, "hook should be executable"


def test_install_hook_refuses_without_force(repo: Path) -> None:
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\necho existing\n")
    rc = main(["install-hook"])
    assert rc == 2


def test_install_hook_force_overwrites(repo: Path) -> None:
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\necho existing\n")
    rc = main(["install-hook", "--force"])
    assert rc == 0
    assert "git-secret-guard scan" in hook.read_text()


def test_install_hook_outside_repo(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    rc = main(["install-hook"])
    assert rc == 2
