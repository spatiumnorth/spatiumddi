"""Any signed-in user can ask whether the Operator Copilot is available (#1345).

The console asks on every page, to decide whether to offer "Ask AI". It used
to read ``GET /ai/providers`` for that, a superadmin-only route (#90 Wave 1),
so every page a non-superadmin opened raised a 403, and the console read the
refusal as "available": a read-only Viewer was offered Ask AI on an install
with no provider configured, where the admin was offered none.

Any signed-in user may chat (``POST /ai/chat`` takes ``CurrentUser``), so any
signed-in user may ask whether a chat would have a provider behind it. The
answer is a bare yes or no and names no provider; the provider list itself
stays superadmin-only.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.ai import AIProvider
from app.models.auth import Group, Role, User

AVAILABLE = "/api/v1/ai/available"


async def _user(db: AsyncSession, *, superadmin: bool = False) -> User:
    """A superadmin, or a user whose only grant is the built-in Viewer's
    ``read`` on ``*``."""
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"copilot-{tag}",
        email=f"copilot-{tag}@example.test",
        display_name="Copilot probe",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    user.groups = []
    if not superadmin:
        role = Role(name=f"viewer-{tag}", permissions=[{"action": "read", "resource_type": "*"}])
        group = Group(name=f"viewers-{tag}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.commit()
    return user


def _auth(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _provider(db: AsyncSession, *, enabled: bool) -> AIProvider:
    provider = AIProvider(
        name=f"llm-{uuid.uuid4().hex[:8]}",
        kind="openai_compat",
        base_url="http://llm.example.test/v1",
        default_model="test-model",
        is_enabled=enabled,
    )
    db.add(provider)
    await db.commit()
    return provider


async def test_a_viewer_is_answered_not_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    viewer = await _user(db_session)
    resp = await client.get(AVAILABLE, headers=_auth(viewer))
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"available": False}


async def test_an_enabled_provider_makes_it_available_to_every_user(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _provider(db_session, enabled=True)
    for user in (await _user(db_session), await _user(db_session, superadmin=True)):
        resp = await client.get(AVAILABLE, headers=_auth(user))
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"available": True}


async def test_a_disabled_provider_is_not_available(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _provider(db_session, enabled=False)
    viewer = await _user(db_session)
    resp = await client.get(AVAILABLE, headers=_auth(viewer))
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"available": False}


async def test_the_provider_list_stays_superadmin_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The probe moved; the guard on the list did not."""
    await _provider(db_session, enabled=True)
    viewer = await _user(db_session)
    resp = await client.get("/api/v1/ai/providers", headers=_auth(viewer))
    assert resp.status_code == 403


async def test_signed_out_is_refused(client: AsyncClient) -> None:
    resp = await client.get(AVAILABLE)
    assert resp.status_code == 401
