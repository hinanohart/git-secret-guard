"""Tests for config loading."""

from __future__ import annotations

from pathlib import Path

from git_secret_guard.config import (
    Config,
    default_config_path,
    load_config,
    repo_local_config_path,
)


def test_default_config_path_honors_env_override(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    override = tmp_path / "custom.toml"
    monkeypatch.setenv("GIT_SECRET_GUARD_CONFIG", str(override))  # type: ignore[attr-defined]
    assert default_config_path() == override


def test_default_config_path_uses_xdg(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.delenv("GIT_SECRET_GUARD_CONFIG", raising=False)  # type: ignore[attr-defined]
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))  # type: ignore[attr-defined]
    path = default_config_path()
    assert path == tmp_path / "git-secret-guard" / "config.toml"


def test_repo_local_path_uses_cwd(tmp_path: Path) -> None:
    p = repo_local_config_path(cwd=tmp_path)
    assert p == tmp_path / ".git-secret-guard.toml"


def test_load_returns_defaults_when_missing(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    cfg = load_config(missing)
    assert cfg == Config()


def test_load_parses_all_fields(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("allowlist = ['filename-dotenv']\ndry_run = true\nwarn_as_block = true\n")
    cfg = load_config(cfg_file)
    assert cfg.allowlist == frozenset({"filename-dotenv"})
    assert cfg.dry_run is True
    assert cfg.warn_as_block is True


def test_load_ignores_unknown_rule_ids(
    tmp_path: Path,
    capsys: object,
) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("allowlist = ['filename-dotenv', 'nonsense-rule']\n")
    cfg = load_config(cfg_file)
    assert cfg.allowlist == frozenset({"filename-dotenv"})
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "nonsense-rule" in captured.err


def test_malformed_toml_falls_back_to_defaults(
    tmp_path: Path,
    capsys: object,
) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("this is = not valid toml [[[")
    cfg = load_config(cfg_file)
    assert cfg == Config()
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "failed to parse" in captured.err


def test_non_list_allowlist_falls_back_to_empty(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('allowlist = "not-a-list"\n')
    cfg = load_config(cfg_file)
    assert cfg.allowlist == frozenset()


def test_load_walks_default_candidates_when_path_is_none(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    # Neither XDG path nor repo-local path exists → defaults.
    monkeypatch.delenv("GIT_SECRET_GUARD_CONFIG", raising=False)  # type: ignore[attr-defined]
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty-xdg"))  # type: ignore[attr-defined]
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
    cfg = load_config(None, cwd=tmp_path)
    assert cfg == Config()

    # Now drop a repo-local config and re-check.
    (tmp_path / ".git-secret-guard.toml").write_text("dry_run = true\n")
    cfg = load_config(None, cwd=tmp_path)
    assert cfg.dry_run is True
