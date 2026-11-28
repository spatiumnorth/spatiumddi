"""The Copilot's session prompt includes only what the signed-in user can read.

The prompt's context block carries resource counts and the newest audit
events. A user without ``read`` on ``audit_log`` gets no events, and a count
appears only for a resource type the user can read. ``GET /ai/sessions/{id}``
returns the stored prompt, so it is held to the same rule.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.ai import AIChatSession, AIProvider
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPSpace
from app.services.ai.chat import build_system_prompt

MARKER = "marker-subnet-7f3a"
OTHER_USER = "Other Tenant Admin"


async def _user(db: AsyncSession, perms: list[dict]) -> User:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"ctx-{tag}",
        email=f"ctx-{tag}@example.test",
        display_name="Ctx probe",
        hashed_password=hash_password("x"),
    )
    user.groups = []
    if perms:
        role = Role(name=f"r-{tag}", permissions=perms)
        group = Group(name=f"g-{tag}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.commit()
    await db.refresh(user, ["groups"])
    return user


async def _seed(db: AsyncSession) -> None:
    db.add(IPSpace(name="tenant-space"))
    db.add(
        AuditLog(
            timestamp=datetime.now(UTC),
            user_display_name=OTHER_USER,
            action="create",
            resource_type="subnet",
            resource_id=str(uuid.uuid4()),
            resource_display=MARKER,
            result="success",
        )
    )
    await db.commit()


async def _prompt(db: AsyncSession, user: User) -> str:
    return await build_system_prompt(db, user, [], None)


async def test_no_roles_prompt_has_no_events_or_counts(db_session: AsyncSession) -> None:
    await _seed(db_session)
    user = await _user(db_session, [])
    prompt = await _prompt(db_session, user)
    assert MARKER not in prompt
    assert OTHER_USER not in prompt
    assert "Recent activity" not in prompt
    assert "Topology" not in prompt
    assert "1 space" not in prompt


async def test_counts_follow_the_types_the_user_reads(db_session: AsyncSession) -> None:
    await _seed(db_session)
    user = await _user(db_session, [{"action": "read", "resource_type": "ip_space"}])
    prompt = await _prompt(db_session, user)
    assert "1 space" in prompt
    assert MARKER not in prompt
    assert "Recent activity" not in prompt


async def test_audit_reader_sees_events(db_session: AsyncSession) -> None:
    await _seed(db_session)
    user = await _user(db_session, [{"action": "read", "resource_type": "audit_log"}])
    prompt = await _prompt(db_session, user)
    assert MARKER in prompt
    assert "1 space" not in prompt


async def test_admin_sees_both(db_session: AsyncSession) -> None:
    await _seed(db_session)
    user = await _user(db_session, [{"action": "*", "resource_type": "*"}])
    prompt = await _prompt(db_session, user)
    assert MARKER in prompt
    assert "1 space" in prompt


async def test_session_detail_returns_the_filtered_prompt(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed(db_session)
    user = await _user(db_session, [])
    provider = AIProvider(
        name=f"llm-{uuid.uuid4().hex[:8]}",
        kind="openai_compat",
        base_url="http://llm.example.test/v1",
        default_model="test-model",
        is_enabled=True,
    )
    db_session.add(provider)
    await db_session.flush()
    row = AIChatSession(
        user_id=user.id,
        provider_id=provider.id,
        model="test-model",
        name="t",
        system_prompt=await _prompt(db_session, user),
    )
    db_session.add(row)
    await db_session.commit()
    resp = await client.get(
        f"/api/v1/ai/sessions/{row.id}",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert MARKER not in body
    assert OTHER_USER not in body
