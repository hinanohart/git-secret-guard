"""Command-line interface.

Subcommands
-----------

``scan``
    The workhorse. Defaults to scanning staged files; ``--all-files`` walks
    everything pre-commit hands us. Exit 0 = ALLOW/WARN; exit 1 = BLOCK.

``install-hook``
    Installs a simple ``.git/hooks/pre-commit`` wrapper that invokes
    ``git-secret-guard scan``. A fallback for users who don't use
    pre-commit.com.

``list-rules``
    Prints the catalog.

``version``
    Prints the version.
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path
from typing import Any

from git_secret_guard._version import __version__
from git_secret_guard.config import Config, load_config
from git_secret_guard.rules import default_rules
from git_secret_guard.scanner import Outcome, Scanner, ScanOptions, ScanTarget
from git_secret_guard.staged import (
    GitNotAvailableError,
    scan_files,
    scan_staged,
    staged_added_lines,
    staged_paths,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="git-secret-guard",
        description="Block commits that contain secrets.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "Path to a TOML config file "
            "(default: $XDG_CONFIG_HOME/git-secret-guard/config.toml, "
            "then ./.git-secret-guard.toml)."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser(
        "scan",
        help="Scan staged (or specified) files for secrets.",
    )
    p_scan.add_argument(
        "--all-files",
        action="store_true",
        help="Ignore staging; scan full contents of the given paths.",
    )
    p_scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Never exit non-zero; downgrade BLOCK outcomes to WARN.",
    )
    p_scan.add_argument(
        "--warn-as-block",
        action="store_true",
        help="Promote WARN findings to BLOCK outcome.",
    )
    p_scan.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a human summary.",
    )
    # When invoked as a pre-commit.com hook, the files to scan are passed
    # positionally. With no paths, we default to git's staged set.
    p_scan.add_argument(
        "files",
        nargs="*",
        help="Explicit paths to scan. Defaults to git staged files.",
    )

    p_install = sub.add_parser(
        "install-hook",
        help="Install a basic .git/hooks/pre-commit wrapper.",
    )
    p_install.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing .git/hooks/pre-commit.",
    )

    sub.add_parser("list-rules", help="Print the catalog of rules.")
    sub.add_parser("version", help="Print the version.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)

    if args.cmd == "scan":
        return _cmd_scan(args, config)
    if args.cmd == "install-hook":
        return _cmd_install_hook(args)
    if args.cmd == "list-rules":
        return _cmd_list_rules()
    if args.cmd == "version":
        print(__version__)
        return 0
    parser.error(f"unknown command: {args.cmd}")
    return 2  # pragma: no cover — argparse exits first.


def _cmd_scan(args: argparse.Namespace, config: Config) -> int:
    options = ScanOptions(
        allowlist=frozenset(config.allowlist),
        dry_run=args.dry_run or config.dry_run,
        warn_as_block=args.warn_as_block or config.warn_as_block,
    )

    try:
        if args.files:
            if args.all_files:
                decision = scan_files(args.files, options=options)
            else:
                # pre-commit.com mode: it passes staged paths positionally,
                # but we still want to scan only *added* content, not the
                # whole file. Fall back to the staged scanner and let it
                # filter to these paths.
                decision = _scan_staged_paths(args.files, options)
        else:
            decision = scan_staged(options=options)
    except GitNotAvailableError as exc:
        sys.stderr.write(f"git-secret-guard: {exc}\n")
        # Fail open when git itself is broken. This matches the design
        # principle: a broken tool must not become a second outage.
        return 0

    if args.json:
        sys.stdout.write(json.dumps(decision.to_dict(), indent=2) + "\n")
    else:
        _render_human(decision)

    if decision.outcome is Outcome.BLOCK:
        return 1
    return 0


def _scan_staged_paths(paths: list[str], options: ScanOptions) -> Any:
    """Scan only the intersection of git-staged files and the given paths."""
    wanted = set(paths)
    staged = [p for p in staged_paths() if p in wanted]
    targets = [ScanTarget(path=p, added_lines=staged_added_lines(p)) for p in staged]
    scanner = Scanner(default_rules())
    return scanner.scan(targets, options=options)


def _render_human(decision: Any) -> None:
    banner = {
        Outcome.ALLOW: "ALLOW",
        Outcome.WARN: "WARN ",
        Outcome.BLOCK: "BLOCK",
    }[decision.outcome]
    sys.stdout.write(f"[{banner}] git-secret-guard: {len(decision.findings)} finding(s)\n")
    for f in decision.findings:
        loc = f.path if f.line is None else f"{f.path}:{f.line}"
        sys.stdout.write(
            f"  - [{f.severity.value:<5}] {f.rule_id:<32} {loc}\n      reason : {f.reason}\n"
        )
        if f.matched_text:
            sys.stdout.write(f"      match  : {f.matched_text!r}\n")


def _cmd_install_hook(args: argparse.Namespace) -> int:
    # Find the .git directory. We walk up from cwd so the command works
    # from any subdirectory of the repo.
    cur = Path.cwd()
    git_dir: Path | None = None
    for candidate in [cur, *cur.parents]:
        if (candidate / ".git").is_dir():
            git_dir = candidate / ".git"
            break
    if git_dir is None:
        sys.stderr.write("git-secret-guard: not a git repository.\n")
        return 2

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists() and not args.force:
        sys.stderr.write(
            f"git-secret-guard: {hook_path} already exists. Use --force to overwrite.\n"
        )
        return 2

    hook_path.write_text(
        "#!/bin/sh\n# Installed by git-secret-guard install-hook.\nexec git-secret-guard scan\n"
    )
    # chmod +x without clobbering other bits.
    current = hook_path.stat().st_mode
    hook_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    sys.stdout.write(f"Installed pre-commit hook at {hook_path}\n")
    return 0


def _cmd_list_rules() -> int:
    sys.stdout.write(f"{'ID':<36} {'CATEGORY':<10} {'KIND':<8} {'SEV':<5} REASON\n")
    sys.stdout.write("-" * 100 + "\n")
    for r in default_rules():
        sys.stdout.write(
            f"{r.id:<36} {r.category:<10} {r.kind:<8} {r.severity.value:<5} {r.reason}\n"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
