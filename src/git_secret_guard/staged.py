"""Git integration: materialize a list of :class:`ScanTarget` from git state.

This module is the *only* place the package touches git. Keeping it small
and isolated means every other module (rules, scanner, CLI formatter) can
be exercised from pytest without a real repo.

The integration uses ``git diff --cached`` rather than walking the working
tree so we scan exactly what's about to land in the commit — no more, no
less. That means:

* Untracked files that haven't been ``git add``'d are ignored (correctly).
* Partial stages (``git add -p``) are respected.
* Deletions produce no scan targets (there's nothing to leak in a diff
  that only removes lines).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from git_secret_guard.rules import default_rules
from git_secret_guard.scanner import Decision, Scanner, ScanOptions, ScanTarget

if TYPE_CHECKING:
    from collections.abc import Iterable

    from git_secret_guard.rules import Rule


class GitNotAvailableError(RuntimeError):
    """Raised when git is missing or the cwd isn't a repository."""


def _run_git(args: list[str], *, cwd: Path | None = None) -> str:
    """Invoke ``git`` safely.

    ``subprocess.run`` is used with ``shell=False`` so there's no risk of
    filename-based command injection. ``check=True`` is deliberately not
    set — caller interprets the return code so we can distinguish "not a
    repo" from "real failure."
    """
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell.
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitNotAvailableError("git executable not found on PATH.") from exc
    if proc.returncode != 0:
        raise GitNotAvailableError(
            f"git {' '.join(args)} failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def staged_paths(cwd: Path | None = None) -> list[str]:
    """Return repo-relative paths of files staged for commit (A, C, M)."""
    out = _run_git(
        ["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
        cwd=cwd,
    )
    return [p for p in out.split("\0") if p]


def staged_added_lines(path: str, cwd: Path | None = None) -> tuple[str, ...]:
    """Return the *added* lines of a staged file's diff.

    We read from ``git diff --cached`` with ``-U0`` (no context) so every
    ``+``-prefixed line is real new content, not a context repeat. Binary
    files produce no added lines — git returns a ``Binary files ... differ``
    marker we deliberately skip.
    """
    out = _run_git(
        ["diff", "--cached", "-U0", "--no-color", "--", path],
        cwd=cwd,
    )
    added: list[str] = []
    for line in out.splitlines():
        # Skip diff headers: +++ b/path, and hunk markers @@
        if line.startswith(("+++", "@@")) or not line.startswith("+"):
            continue
        added.append(line[1:])
    return tuple(added)


def all_file_lines(path: str, cwd: Path | None = None) -> tuple[str, ...]:
    """Read every line of ``path`` in the working tree.

    Used for ``--all-files`` scans. Binary files and anything we can't
    decode as UTF-8 (with replacement) yield an empty tuple — better than
    a crash when the scanner would not produce findings anyway.
    """
    file_path = (cwd or Path.cwd()) / path
    try:
        data = file_path.read_bytes()
    except (OSError, ValueError):
        return ()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    return tuple(text.splitlines())


def scan_staged(
    options: ScanOptions | None = None,
    rules: Iterable[Rule] | None = None,
    cwd: Path | None = None,
) -> Decision:
    """Scan everything currently staged for commit.

    Returns an immutable :class:`Decision`. Raises
    :class:`GitNotAvailableError` if git itself is unusable — callers who
    want to "fail open" should catch that exception explicitly.
    """
    rs = tuple(rules) if rules is not None else default_rules()
    scanner = Scanner(rs)
    paths = staged_paths(cwd=cwd)
    targets = [ScanTarget(path=p, added_lines=staged_added_lines(p, cwd=cwd)) for p in paths]
    return scanner.scan(targets, options=options)


def scan_files(
    paths: Iterable[str],
    options: ScanOptions | None = None,
    rules: Iterable[Rule] | None = None,
    cwd: Path | None = None,
) -> Decision:
    """Scan an explicit list of paths from the working tree (full contents)."""
    rs = tuple(rules) if rules is not None else default_rules()
    scanner = Scanner(rs)
    targets = [ScanTarget(path=p, added_lines=all_file_lines(p, cwd=cwd)) for p in paths]
    return scanner.scan(targets, options=options)
