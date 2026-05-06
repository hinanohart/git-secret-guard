"""User configuration loader.

Default config path, in order of precedence:

1. ``$GIT_SECRET_GUARD_CONFIG``
2. ``$XDG_CONFIG_HOME/git-secret-guard/config.toml``
   (``~/.config/git-secret-guard/config.toml``)
3. Repository-local ``.git-secret-guard.toml`` in cwd.
4. Empty defaults.

The schema is intentionally small. A security tool with many knobs is a
security tool whose knobs get misconfigured.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from git_secret_guard.rules import all_rule_ids

if sys.version_info >= (3, 11):
    import tomllib  # pragma: no cover — stdlib since 3.11
else:  # pragma: no cover — only exercised on 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef, import-not-found, unused-ignore]


@dataclass(frozen=True, slots=True)
class Config:
    """Parsed user configuration.

    Attributes
    ----------
    allowlist:
        Rule IDs the user has explicitly chosen to ignore.
    dry_run:
        If True, BLOCK findings become WARN at the outcome level. Useful
        for onboarding without breaking existing flows.
    warn_as_block:
        If True, WARN findings also block. For teams that want zero
        tolerance.
    """

    allowlist: frozenset[str] = field(default_factory=frozenset)
    dry_run: bool = False
    warn_as_block: bool = False


def default_config_path() -> Path:
    override = os.environ.get("GIT_SECRET_GUARD_CONFIG")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "git-secret-guard" / "config.toml"


def repo_local_config_path(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / ".git-secret-guard.toml"


def load_config(path: Path | None = None, *, cwd: Path | None = None) -> Config:
    """Load the config from ``path``, or try defaults.

    Resolution order when ``path`` is None: XDG path, then repo-local.
    Missing files return the default :class:`Config`. Malformed files log
    to stderr and return defaults — a broken config must never brick the
    hook.
    """
    candidates: list[Path]
    if path is not None:
        candidates = [path]
    else:
        candidates = [default_config_path(), repo_local_config_path(cwd=cwd)]

    for candidate in candidates:
        if candidate.is_file():
            try:
                with candidate.open("rb") as f:
                    data = tomllib.load(f)
            except (tomllib.TOMLDecodeError, OSError) as exc:
                # Avoid embedding the raw exception payload in the error
                # message — for TOMLDecodeError that payload includes a
                # snippet of the offending source line, which can leak the
                # very secrets the user is trying to hide (e.g. a malformed
                # ``api_key = "sk-..."``). Surface the exception type only;
                # the user can ``cat`` the file themselves to debug.
                print(
                    f"git-secret-guard: failed to parse {candidate}: "
                    f"{type(exc).__name__}; using defaults.",
                    file=sys.stderr,
                )
                return Config()
            return _from_dict(data)

    return Config()


def _strict_bool(value: Any, *, key: str, default: bool) -> bool:
    """Interpret ``value`` strictly as True/False.

    ``bool("false")`` is ``True`` in Python because any non-empty string
    is truthy. A user who types ``dry_run = "false"`` in TOML would
    silently enable dry-run, stopping every BLOCK from firing. Reject
    non-bool values and use the default.
    """
    if value is None:
        return default
    if not isinstance(value, bool):
        print(
            f"git-secret-guard: config key {key!r} must be a bool, "
            f"got {type(value).__name__}={value!r}; using default={default}.",
            file=sys.stderr,
        )
        return default
    return value


def _from_dict(data: dict[str, Any]) -> Config:
    raw_allow = data.get("allowlist", [])
    allowlist: frozenset[str]
    if isinstance(raw_allow, list):
        known = all_rule_ids()
        items = [str(x) for x in raw_allow if isinstance(x, str)]
        unknown = [i for i in items if i not in known]
        if unknown:
            print(
                f"git-secret-guard: ignoring unknown rule IDs in allowlist: {unknown}",
                file=sys.stderr,
            )
        allowlist = frozenset(i for i in items if i in known)
    else:
        allowlist = frozenset()

    return Config(
        allowlist=allowlist,
        dry_run=_strict_bool(data.get("dry_run"), key="dry_run", default=False),
        warn_as_block=_strict_bool(data.get("warn_as_block"), key="warn_as_block", default=False),
    )
