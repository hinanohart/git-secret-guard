"""git-secret-guard: block commits that contain secrets.

Public surface
--------------

The library exposes a small, deliberately flat API:

* :class:`Scanner` — the evaluation engine.
* :class:`Decision`, :class:`Finding`, :class:`Outcome`, :class:`Severity` —
  the result objects.
* :class:`Rule` — a single filename- or content-level detection rule.
* :func:`default_rules` — the bundled rule catalog.
* :func:`scan_staged` — convenience entry point that reads ``git diff --cached``
  and returns a :class:`Decision`.

The pre-commit integration (``git-secret-guard scan``) is implemented in
:mod:`git_secret_guard.cli`; users who just want to block bad commits do not
need to import anything from this module.
"""

from __future__ import annotations

from git_secret_guard._version import __version__
from git_secret_guard.rules import Rule, default_rules
from git_secret_guard.scanner import (
    Decision,
    Finding,
    Outcome,
    Scanner,
    ScanOptions,
    Severity,
)
from git_secret_guard.staged import scan_staged

__all__ = [
    "Decision",
    "Finding",
    "Outcome",
    "Rule",
    "ScanOptions",
    "Scanner",
    "Severity",
    "__version__",
    "default_rules",
    "scan_staged",
]
