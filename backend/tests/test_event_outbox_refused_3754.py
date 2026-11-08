"""A refused request queues no webhook delivery — asserted on ``event_outbox``.

Companion to ``test_event_publisher_refused_3754.py``, which stubs the outbox
writer. Here nothing in the publish path is stubbed: an enabled
subscribe-to-everything subscription exists, a real route refuses the
request, the real after-commit dispatch runs, and the test reads the
``event_outbox`` table. Each test ends with a request that DOES happen and
asserts its row appears, so an empty outbox cannot pass for the wrong reason.
"""

from __future__ import annotations

import asyncio
import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.event_subscription import EventOutbox, EventSubscription
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import after_commit_dispatch


async def _drain() -> None:
    pending = [t for t in after_commit_dispatch._tasks if not t.done()]  # noqa: SLF001
    if pending:
        await asyncio.wait(pending, timeout=10)


async def _outbox_types(db: AsyncSession) -> list[str]:
    await _drain()
    db.expire_all()
    rows = (await db.execute(select(EventOutbox.event_type))).scalars().all()
    return sorted(rows)


async def _subscribe_to_everything(db: AsyncSession) -> None:
    db.add(
        EventSubscription(
            name=f"all-{uuid.uuid4().hex[:6]}",
            url="https://receiver.invalid/hook",
            enabled=True,
            event_types=None,
        )
    )
    await db.commit()


async def _user(db: AsyncSession, permissions: list[dict], password: str = "password123") -> User:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"u-{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password(password),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.commit()
    return user


async def test_refused_subnet_delete_writes_no_outbox_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _subscribe_to_everything(db_session)
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
    subnet_id, token = str(subnet.id), create_access_token(str(user.id))
    baseline = await _outbox_types(db_session)

    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 403
    denied = (
        (await db_session.execute(select(AuditLog).where(AuditLog.result == "denied")))
        .scalars()
        .all()
    )
    assert denied, "the refusal must still be audited"
    assert await _outbox_types(db_session) == baseline

    # Control: an action that happened reaches the same outbox.
    db_session.add(
        AuditLog(
            user_display_name="u",
            action="delete",
            resource_type="subnet",
            resource_id=subnet_id,
            resource_display="10.0.5.0/24",
            result="success",
        )
    )
    await db_session.commit()
    assert await _outbox_types(db_session) == sorted([*baseline, "subnet.deleted"])


async def test_failed_sign_in_writes_no_outbox_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _subscribe_to_everything(db_session)
    user = await _user(db_session, [], password="correct-horse-1")
    username = user.username
    baseline = await _outbox_types(db_session)

    r = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": "wrong-password"}
    )
    assert r.status_code == 401
    failed = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "login", AuditLog.result == "failure")
            )
        )
        .scalars()
        .all()
    )
    assert failed, "the failed sign-in must still be audited"
    assert await _outbox_types(db_session) == baseline

    # Control: a sign-in that succeeds still publishes.
    r = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": "correct-horse-1"}
    )
    assert r.status_code == 200, r.text
    assert await _outbox_types(db_session) == sorted([*baseline, "auth.user.login"])
