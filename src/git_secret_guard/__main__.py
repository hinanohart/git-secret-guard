"""Allows ``python -m git_secret_guard`` to dispatch to the CLI entrypoint."""

from __future__ import annotations

from git_secret_guard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
