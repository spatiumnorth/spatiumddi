"""Operator Copilot maintenance-mode tool tests (issues #57, #3415).

Covers:

* ``maintenance_status`` returns the current state.
* ``propose_set_maintenance_mode`` is registered read-only and default-disabled:
  it only stages a proposal, and the operator's Apply runs the
  ``set_maintenance_mode`` operation (#3415). No tool flips the switch directly.
* The operation's preview writes nothing; its apply toggles state, stamps
  started_at and audits the way ``PUT /settings`` does, a reworded banner
  included.
* A non-superadmin is refused at preview and at apply (no mutation).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import maintenance_mode
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.ai.operations import Operation, get_operation
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.maintenance import (
    MaintenanceStatusArgs,
    maintenance_status,
)


async def _make_user(db: AsyncSession, *, superadmin: bool, username: str) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    maintenance_mode.invalidate_cache()


def _op() -> Operation:
    op = get_operation("set_maintenance_mode")
    assert op is not None, "the set_maintenance_mode operation is not registered"
    return op


async def _audit(db: AsyncSession, action: str) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.action == action)
    return list((await db.execute(stmt)).scalars().all())


async def _enabled(db: AsyncSession) -> bool:
    maintenance_mode.invalidate_cache()
    enabled, _, _ = await maintenance_mode.get_maintenance_state(db)
    return enabled


def test_tools_registered_with_expected_flags() -> None:
    status_tool = REGISTRY.get("maintenance_status")
    propose_tool = REGISTRY.get("propose_set_maintenance_mode")
    assert status_tool is not None
    assert propose_tool is not None
    # Read tool: default-enabled, no writes.
    assert status_tool.writes is False
    assert status_tool.default_enabled is True
    # The write is a proposal the operator applies (#3415): the tool only
    # stages it, so it is read-only, and it ships off (broad blast radius,
    # non-negotiable #13), for the operator to opt in from the Tool Catalog.
    assert propose_tool.writes is False
    assert propose_tool.default_enabled is False
    assert propose_tool.module is None
    assert propose_tool.permission == "superadmin"
    # No tool flips maintenance mode directly, and the operation the Apply
    # runs is superadmin-only, as PUT /settings is for these fields.
    assert REGISTRY.get("set_maintenance_mode") is None
    assert _op().requires_superadmin is True


async def test_maintenance_status_reflects_state(db_session: AsyncSession) -> None:
    user = await _make_user(db_session, superadmin=True, username="aistatus")
    out = await maintenance_status(db_session, user, MaintenanceStatusArgs())
    assert out["enabled"] is False

    # Flip on through the operation the operator's Apply runs, then re-read.
    op = _op()
    await op.apply(db_session, user, op.args_model(enabled=True, message="ai window"))
    maintenance_mode.invalidate_cache()
    out = await maintenance_status(db_session, user, MaintenanceStatusArgs())
    assert out["enabled"] is True
    assert out["message"] == "ai window"
    assert out["started_at"] is not None


async def test_set_maintenance_mode_preview_writes_nothing(db_session: AsyncSession) -> None:
    user = await _make_user(db_session, superadmin=True, username="aipreview")
    op = _op()

    preview = await op.preview(db_session, user, op.args_model(enabled=True, message="x"))

    assert preview.ok is True
    assert "read-only" in preview.preview_text
    assert await _enabled(db_session) is False
    assert await _audit(db_session, "maintenance_mode.enabled") == []


async def test_set_maintenance_mode_audits(db_session: AsyncSession) -> None:
    user = await _make_user(db_session, superadmin=True, username="aiset")
    op = _op()
    res = await op.apply(db_session, user, op.args_model(enabled=True, message="x"))
    assert res["enabled"] is True
    assert res["changed"] is True
    assert res["started_at"] is not None

    audit = await _audit(db_session, "maintenance_mode.enabled")
    assert len(audit) == 1
    assert audit[0].resource_id == "maintenance"
    assert audit[0].new_value == {"enabled": True, "message": "x", "via": "ai_proposal"}

    res = await op.apply(db_session, user, op.args_model(enabled=False))
    assert res["enabled"] is False
    assert res["changed"] is True
    assert res["started_at"] is None
    assert len(await _audit(db_session, "maintenance_mode.disabled")) == 1


async def test_set_maintenance_mode_apply_refreshes_the_middleware_cache(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As ``PUT /settings`` does: the apply drops this process's cached state,
    so the middleware enforces the new state at once, not at the TTL."""
    # A TTL no test outlives, so only the apply's own drop can refresh it.
    monkeypatch.setattr(maintenance_mode, "_CACHE_TTL_S", 3600.0)
    user = await _make_user(db_session, superadmin=True, username="aicache")
    op = _op()
    enabled, _, _ = await maintenance_mode.get_maintenance_state(db_session)
    assert enabled is False  # the middleware's cached "off"

    await op.apply(db_session, user, op.args_model(enabled=True, message="now"))

    enabled, message, _ = await maintenance_mode.get_maintenance_state(db_session)
    assert (enabled, message) == (True, "now")


async def test_set_maintenance_mode_rewording_the_banner_is_audited(
    db_session: AsyncSession,
) -> None:
    """As ``PUT /settings`` does: a message-only change is still an
    operator-visible maintenance change (non-negotiable #4)."""
    user = await _make_user(db_session, superadmin=True, username="aireword")
    op = _op()
    await op.apply(db_session, user, op.args_model(enabled=True, message="first"))

    res = await op.apply(db_session, user, op.args_model(enabled=True, message="second"))

    assert res["changed"] is False
    assert res["message"] == "second"
    (row,) = await _audit(db_session, "maintenance_mode.message_changed")
    assert row.new_value == {"enabled": True, "message": "second", "via": "ai_proposal"}


def test_set_maintenance_mode_message_is_capped() -> None:
    """The column is VARCHAR(500); PUT /settings refuses a longer banner too."""
    op = _op()
    with pytest.raises(ValidationError):
        op.args_model(enabled=True, message="x" * 501)
    op.args_model(enabled=True, message="x" * 500)


async def test_set_maintenance_mode_non_superadmin_rejected(
    db_session: AsyncSession,
) -> None:
    user = await _make_user(db_session, superadmin=False, username="aiplain")
    op = _op()
    args = op.args_model(enabled=True)

    preview = await op.preview(db_session, user, args)
    assert preview.ok is False
    with pytest.raises(ValueError, match="superadmin"):
        await op.apply(db_session, user, args)

    # No audit row, no state change.
    assert await _audit(db_session, "maintenance_mode.enabled") == []
    assert await _enabled(db_session) is False
