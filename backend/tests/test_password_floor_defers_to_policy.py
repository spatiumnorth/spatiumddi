"""The hardcoded 8-character floor no longer contradicts the policy (#1004).

Three request models carried ``if len(v) < 8: raise`` — a SECOND password
minimum, independent of ``platform_settings.password_min_length`` (12 by
default) and unconfigurable. It was also the only source of the number 8
anywhere in the flow.

Two things went wrong with it, and the second is the reason this matters:

* under 8 characters the request never reached the handler, so the operator
  was told "at least 8" while the policy wanted 12; and
* it fired as a **pydantic 422**, whose ``detail`` is an error ARRAY rather
  than the ``{reason, errors}`` object the policy path returns. The
  change-password screen parsed neither shape and fell back to "Check your
  current password and try again" — a wrong answer, pointing at the wrong
  field, on the one screen a fresh install cannot navigate away from.

The floor is now non-emptiness only. It cannot collide with a policy minimum
(the settings validator clamps that to 6..72), so every length verdict comes
from one place and arrives in one shape.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings

pytestmark = pytest.mark.asyncio


async def _settings(db: AsyncSession, **over) -> PlatformSettings:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
    for k, v in over.items():
        setattr(row, k, v)
    await db.flush()
    return row


async def _user(db: AsyncSession, *, superadmin: bool = False) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("OldPass123!"),
        auth_source="local",
        is_active=True,
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    return u


def _bearer(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# ── change-password ─────────────────────────────────────────────────────────
async def test_a_short_password_is_refused_by_the_policy_not_the_floor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's reproduction, from the server side.

    ``Abcde1f`` is 7 characters: under the old floor it 422'd with a pydantic
    array saying "at least 8". It must now reach the handler and be refused by
    the configured policy, in the shape the UI knows how to render.
    """
    await _settings(db_session, password_min_length=12)
    user = await _user(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123!", "new_password": "Abcde1f"},
        headers=_bearer(user),
    )
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail["reason"] == "password_policy"
    assert any("12" in e for e in detail["errors"]), detail
    assert not any("8 characters" in e for e in detail["errors"]), detail


async def test_the_floor_still_refuses_an_empty_password(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Kept deliberately: a legacy client sending nothing still 422s rather
    than reaching the handler, which is what the floor was for."""
    await _settings(db_session)
    user = await _user(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123!", "new_password": ""},
        headers=_bearer(user),
    )
    assert r.status_code == 422, r.text
    assert "cannot be empty" in r.text


async def test_a_relaxed_policy_is_honoured_below_eight(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The operator's setting is the only length authority now.

    Six is the lowest the settings validator allows, and the old floor made
    that configuration unreachable through this endpoint — the UI offered a
    number the API refused.
    """
    await _settings(
        db_session,
        password_min_length=6,
        password_require_uppercase=False,
        password_require_lowercase=False,
        password_require_digit=False,
        password_require_symbol=False,
        password_history_count=0,
    )
    user = await _user(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123!", "new_password": "abcdef"},
        headers=_bearer(user),
    )
    assert r.status_code == 204, r.text


async def test_a_wrong_current_password_still_wins(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The generic message the UI used to show wrongly is still shown rightly.

    Order matters: the current-password check runs before the policy check, so
    this is the one case where "check your current password" is the truth.
    """
    await _settings(db_session, password_min_length=12)
    user = await _user(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "WRONG", "new_password": "Abcdefghij12"},
        headers=_bearer(user),
    )
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == "Current password is incorrect"


# ── the admin-facing twins ──────────────────────────────────────────────────
async def test_admin_create_user_defers_to_the_policy(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session, password_min_length=12)
    admin = await _user(db_session, superadmin=True)
    await db_session.commit()

    r = await client.post(
        "/api/v1/users",
        json={
            "username": f"n-{uuid.uuid4().hex[:8]}",
            "email": "n@x.com",
            "display_name": "N",
            "password": "Abcde1f",
        },
        headers=_bearer(admin),
    )
    assert r.status_code == 400, r.text
    assert any("12" in e for e in r.json()["detail"]["errors"])


async def test_admin_reset_password_defers_to_the_policy(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _settings(db_session, password_min_length=12)
    admin = await _user(db_session, superadmin=True)
    target = await _user(db_session)
    target_id = str(target.id)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/users/{target_id}/reset-password",
        json={"new_password": "Abcde1f"},
        headers=_bearer(admin),
    )
    assert r.status_code == 400, r.text
    assert any("12" in e for e in r.json()["detail"]["errors"])
