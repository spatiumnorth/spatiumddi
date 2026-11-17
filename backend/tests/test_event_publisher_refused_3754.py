"""A refused request publishes no typed webhook event (#3754).

Route permission gates and ``refuse_and_audit`` write an audit row with
``result="denied"``; the action behind it never happened, so no event may be
queued for it. A row recording an action that did happen still publishes.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import refuse_and_audit
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import event_publisher


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Event snapshots handed to the outbox writer after a commit."""
    seen: list[dict[str, Any]] = []
    pending: list[Any] = []

    async def fake_publish(snapshots: list[dict[str, Any]]) -> None:
        seen.extend(snapshots)

    def fake_dispatch(name: str, fn: Any, count: int = 0) -> None:  # noqa: ARG001
        pending.append(asyncio.ensure_future(fn()))

    monkeypatch.setattr(event_publisher, "_publish_outbox_rows", fake_publish)
    monkeypatch.setattr(event_publisher, "dispatch", fake_dispatch)
    published_holder_pending[id(seen)] = pending
    return seen


published_holder_pending: dict[int, list[Any]] = {}


async def _settle(seen: list[dict[str, Any]]) -> list[str]:
    await asyncio.gather(*published_holder_pending[id(seen)])
    return [s["event_type"] for s in seen]


async def _user(db: AsyncSession, permissions: list[dict]) -> User:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"u-{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user


async def test_refused_route_gate_publishes_no_event(
    client: AsyncClient, db_session: AsyncSession, published: list[dict[str, Any]]
) -> None:
    user = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="s")
    db_session.add(subnet)
    await db_session.commit()
    token = create_access_token(str(user.id))

    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403
    denied = (
        await db_session.execute(
            AuditLog.__table__.select().where(AuditLog.__table__.c.result == "denied")
        )
    ).all()
    assert denied, "the refusal must still be audited"
    assert await _settle(published) == []


async def test_refuse_and_audit_publishes_no_event(
    db_session: AsyncSession, published: list[dict[str, Any]]
) -> None:
    user = await _user(db_session, [])
    with pytest.raises(HTTPException):
        await refuse_and_audit(
            db_session,
            user,
            None,
            action="update",
            resource_type="group",
            resource_id=str(uuid.uuid4()),
            resource_display="g",
            reason="test",
            detail="no",
        )
    assert await _settle(published) == []


async def test_successful_action_still_publishes(
    db_session: AsyncSession, published: list[dict[str, Any]]
) -> None:
    db_session.add(
        AuditLog(
            user_display_name="u",
            action="delete",
            resource_type="subnet",
            resource_id=str(uuid.uuid4()),
            resource_display="10.0.5.0/24",
            result="success",
        )
    )
    await db_session.commit()
    assert await _settle(published) == ["subnet.deleted"]
