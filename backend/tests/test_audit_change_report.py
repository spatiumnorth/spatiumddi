"""Compliance / change report PDF (#48)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User


async def _admin_token(db: AsyncSession) -> str:
    user = User(
        username=f"aud-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Audit Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


def _audit(action: str, rtype: str, who: str) -> AuditLog:
    return AuditLog(
        action=action,
        resource_type=rtype,
        resource_id=str(uuid.uuid4()),
        resource_display="10.0.0.0/24",
        user_display_name=who,
        auth_source="local",
        result="success",
    )


async def test_change_report_pdf_renders(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _admin_token(db_session)
    db_session.add_all(
        [
            _audit("subnet.create", "subnet", "alice"),
            _audit("subnet.update", "subnet", "alice"),
            _audit("dns.zone.delete", "dns_zone", "bob"),
        ]
    )
    await db_session.commit()

    r = await client.get("/api/v1/audit/export.pdf", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")  # a real PDF, with content


async def test_change_report_pdf_empty_range_is_valid(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _admin_token(db_session)
    await db_session.commit()
    # A future window with no events still renders a valid (empty-state) PDF.
    r = await client.get(
        "/api/v1/audit/export.pdf?since=2999-01-01T00:00:00&until=2999-02-01T00:00:00",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF")


@pytest.mark.parametrize(
    "until",
    ["0001-01-01T00:00:00Z", "0001-01-20T00:00:00Z", "0001-01-30T23:59:59"],
    ids=["day-one", "inside-the-window", "naive-last-day"],
)
async def test_an_until_near_year_one_does_not_underflow_the_default_since(
    client: AsyncClient, db_session: AsyncSession, until: str
) -> None:
    """#1201: with no ``since`` the route defaulted it to ``until - 30 days``,
    which steps before ``datetime.min`` for any ``until`` in the first 30
    days of year 1 and raised OverflowError: a 500. The window now starts at
    the earliest representable instant instead."""
    token = await _admin_token(db_session)
    db_session.add(_audit("subnet.create", "subnet", "alice"))
    await db_session.commit()
    r = await client.get(
        "/api/v1/audit/export.pdf",
        params={"until": until},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF")


async def test_an_until_before_year_one_in_utc_is_a_client_error(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``0001-01-01T00:00:00+05:00`` is 19:00 on the last day of year 0 in
    UTC, which no datetime can hold. The default ``since`` no longer raises
    on it, and binding the value itself is the client's error: a 422 from
    the unstorable-value handler, not a 500."""
    token = await _admin_token(db_session)
    await db_session.commit()
    r = await client.get(
        "/api/v1/audit/export.pdf",
        params={"until": "0001-01-01T00:00:00+05:00"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422, r.text
