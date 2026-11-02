"""#3302: the ``agent`` API-token scope reached nothing and is retired.

The agent push routes authenticate with the agent's own JWT / PSK and never
resolve an ``sddi_*`` token, so the scope was a promise nothing kept. Create
and update refuse it; a stored ``["agent"]`` row stays a token that can do
nothing (a non-empty list matching nothing is refused, not unrestricted).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.settings import PlatformSettings
from app.services.api_token_scopes import (
    TOKEN_SCOPE_VOCABULARY,
    scope_matches_request,
    validate_scopes,
)


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
    u = User(
        username=f"ag-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Agent scope admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def test_agent_is_not_in_the_vocabulary() -> None:
    assert "agent" not in TOKEN_SCOPE_VOCABULARY
    with pytest.raises(ValueError, match="retired"):
        validate_scopes(["read", "agent"])


@pytest.mark.parametrize(
    "path",
    ["/api/v1/dns/agents/heartbeat", "/api/v1/dhcp/agents/lease-events", "/api/v1/ipam/subnets"],
)
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_a_stored_agent_scope_matches_nothing(method: str, path: str) -> None:
    assert scope_matches_request(["agent"], method, path) is False


@pytest.mark.asyncio
async def test_create_with_agent_scope_is_422_and_explains(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _u, h = await _admin(db_session)
    r = await client.post(
        "/api/v1/api-tokens",
        json={"name": "agentish", "scopes": ["agent"], "stepup_password": "x"},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "retired" in r.text and "pre-shared key" in r.text
    # Positive control: the same request with a real scope is accepted.
    ok = await client.post(
        "/api/v1/api-tokens",
        json={"name": "fine", "scopes": ["read"], "stepup_password": "x"},
        headers=h,
    )
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_stored_agent_only_token_is_refused_everywhere_not_unrestricted(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    u, _h = await _admin(db_session)
    raw, _p, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name="legacy-agent",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=["agent"],
            user_id=u.id,
            created_by_user_id=u.id,
            is_active=True,
        )
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {raw}"}
    for method, path in [
        ("GET", "/api/v1/ipam/spaces"),
        ("POST", "/api/v1/ipam/spaces"),
        ("GET", "/api/v1/dns/groups"),
        ("GET", "/api/v1/dhcp/servers"),
    ]:
        r = await client.request(method, path, headers=hdr, json={} if method == "POST" else None)
        assert r.status_code == 403, (method, path, r.status_code, r.text)
        assert "scope" in r.text.lower()
