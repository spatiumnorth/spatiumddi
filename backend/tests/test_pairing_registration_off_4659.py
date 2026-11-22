"""#4659 — minting a pairing code while appliance registration is off warns,
and ``INITIAL_SUPERVISOR_REGISTRATION`` sets the state a fresh row starts in
without ever overriding a row that already exists."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.settings import PlatformSettings
from tests.test_appliance_pairing import _make_user

_URL = "/api/v1/appliance/pairing-codes"


async def _set_registration(db: AsyncSession, enabled: bool) -> None:
    await db.execute(delete(PlatformSettings))
    db.add(PlatformSettings(id=1, supervisor_registration_enabled=enabled))
    await db.commit()


@pytest.mark.asyncio
async def test_mint_while_registration_off_carries_warning(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pcwarnoff")
    await _set_registration(db_session, False)
    resp = await client.post(_URL, headers={"Authorization": f"Bearer {token}"}, json={})
    assert resp.status_code == 201, resp.text
    warning = resp.json()["warning"]
    assert warning and "supervisor_registration_enabled" in warning


@pytest.mark.asyncio
async def test_mint_while_registration_on_has_no_warning(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_user(db_session, username="pcwarnon")
    await _set_registration(db_session, True)
    resp = await client.post(_URL, headers={"Authorization": f"Bearer {token}"}, json={})
    assert resp.status_code == 201, resp.text
    assert resp.json()["warning"] is None


@pytest.mark.asyncio
async def test_initial_env_sets_a_fresh_row_only(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "initial_supervisor_registration", True)
    await db_session.execute(delete(PlatformSettings))
    await db_session.commit()
    db_session.add(PlatformSettings(id=1))
    await db_session.commit()
    row = await db_session.get(PlatformSettings, 1)
    assert row is not None and row.supervisor_registration_enabled is True

    # The operator turns it off; a later restart (same env) must not undo it.
    row.supervisor_registration_enabled = False
    await db_session.commit()
    db_session.expire_all()
    row = await db_session.get(PlatformSettings, 1)
    assert row is not None and row.supervisor_registration_enabled is False


@pytest.mark.asyncio
async def test_default_stays_off(db_session: AsyncSession) -> None:
    assert settings.initial_supervisor_registration is False
    await db_session.execute(delete(PlatformSettings))
    await db_session.commit()
    db_session.add(PlatformSettings(id=1))
    await db_session.commit()
    row = await db_session.get(PlatformSettings, 1)
    assert row is not None and row.supervisor_registration_enabled is False
