"""``.github/scripts/alembic_heads.py`` counts Alembic heads without a DB.

release-forward-merge.yml uses it to refuse a forward merge whose merged tree
has two heads, so it must agree with alembic on the real tree and see a fork.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / ".github" / "scripts" / "alembic_heads.py"

# The dev container copies only ``backend/``; this runs for real in CI.
pytestmark = pytest.mark.skipif(not _SCRIPT.exists(), reason="script not present here")


def _load():
    spec = importlib.util.spec_from_file_location("alembic_heads", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mig(d: pathlib.Path, rev: str, down: str) -> None:
    down_src = "None" if down == "None" else f'"{down}"'
    (d / f"{rev}.py").write_text(
        f'revision: str = "{rev}"\ndown_revision: str | None = {down_src}\n'
    )


def test_linear_chain_has_one_head(tmp_path):
    _mig(tmp_path, "aaa111", "None")
    _mig(tmp_path, "bbb222", "aaa111")
    _mig(tmp_path, "ccc333", "bbb222")
    assert _load().heads(tmp_path) == ["ccc333"]


def test_fork_has_two_heads(tmp_path):
    _mig(tmp_path, "aaa111", "None")
    _mig(tmp_path, "bbb222", "aaa111")
    _mig(tmp_path, "ccc333", "aaa111")
    assert _load().heads(tmp_path) == ["bbb222", "ccc333"]


def test_merge_migration_with_tuple_down_revision_closes_fork(tmp_path):
    _mig(tmp_path, "aaa111", "None")
    _mig(tmp_path, "bbb222", "aaa111")
    _mig(tmp_path, "ccc333", "aaa111")
    (tmp_path / "ddd444.py").write_text(
        'revision = "ddd444"\ndown_revision = ("bbb222", "ccc333")\n'
    )
    assert _load().heads(tmp_path) == ["ddd444"]


def test_real_tree_has_exactly_one_head():
    assert len(_load().heads(_REPO_ROOT / "backend" / "alembic" / "versions")) == 1
