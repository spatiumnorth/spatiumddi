"""Migration safety (#1253): safe-DDL lint rule, statement_timeout knob, and
the audit_log.seq unique index living on the model as well as the migration."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

from app.core import migrate_guard
from app.models.audit import AuditLog

_SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "lint_migrations.py"

# The dev container copies only ``backend/``; CI tests from a full checkout.
_needs_script = pytest.mark.skipif(not _SCRIPT.exists(), reason="scripts/ not in this checkout")


def _linter():
    spec = importlib.util.spec_from_file_location("lint_migrations_1253", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # @dataclass resolves its module through here
    spec.loader.exec_module(mod)
    return mod


def _rules(tmp_path, body: str) -> list[str]:
    lint = _linter()
    f = tmp_path / "x.py"
    f.write_text(body)
    lint.REPO_ROOT = tmp_path
    return [x.rule for x in lint._scan_unsafe_ddl(body, f)]


@_needs_script
def test_plain_index_on_large_table_is_flagged(tmp_path):
    body = 'def upgrade():\n    op.create_index("ix_a", "audit_log", ["x"])\n'
    assert _rules(tmp_path, body) == ["create_index_blocking"]


@_needs_script
def test_concurrent_index_and_small_table_are_clean(tmp_path):
    body = (
        "def upgrade():\n"
        '    op.create_index("ix_a", "audit_log", ["x"], postgresql_concurrently=True)\n'
        '    op.create_index("ix_b", "dns_zone", ["x"])\n'
    )
    assert _rules(tmp_path, body) == []


@_needs_script
def test_constraint_needs_not_valid_on_large_table(tmp_path):
    body = (
        "def upgrade():\n"
        '    op.create_foreign_key("fk_a", "ip_address", "subnet", ["s"], ["id"])\n'
        '    op.create_check_constraint("ck_a", "dns_record", "x > 0", postgresql_not_valid=True)\n'
    )
    assert _rules(tmp_path, body) == ["add_constraint_validating"]


@_needs_script
def test_table_created_in_same_file_is_exempt(tmp_path):
    body = (
        'def upgrade():\n    op.create_table("dhcp_log_entry")\n'
        '    op.create_index("ix_a", "dhcp_log_entry", ["x"])\n'
    )
    assert _rules(tmp_path, body) == []


class _Conn:
    def __init__(self):
        self.sql: list[str] = []

    def execute(self, stmt):
        self.sql.append(str(stmt))

    def commit(self):
        pass


def test_statement_timeout_is_off_by_default(monkeypatch):
    monkeypatch.delenv(migrate_guard.STATEMENT_TIMEOUT_ENV, raising=False)
    conn = _Conn()
    assert migrate_guard.apply_statement_timeout(conn) == 0
    assert conn.sql == []


def test_statement_timeout_env_override(monkeypatch):
    monkeypatch.setenv(migrate_guard.STATEMENT_TIMEOUT_ENV, "3600")
    conn = _Conn()
    assert migrate_guard.apply_statement_timeout(conn) == 3600
    assert conn.sql == ["SET statement_timeout = '3600s'"]


def test_audit_log_seq_unique_index_is_on_the_model():
    idx = {i.name: i for i in AuditLog.__table__.indexes}
    assert idx["ix_audit_log_seq"].unique is True
    assert [c.name for c in idx["ix_audit_log_seq"].columns] == ["seq"]
