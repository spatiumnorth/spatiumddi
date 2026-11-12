"""#3931 — the Test button says why a delivery failed, without leaking secrets."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import audit_forward as svc

from .test_forward_target_secrets_at_rest import _AUTH, _GENERIC, _TARGETS, _admin, _webhook_body

pytestmark = pytest.mark.asyncio


async def _detail(client: AsyncClient, db: AsyncSession, body: dict, exc: Exception | None) -> str:
    h = await _admin(db)
    created = (await client.post(_TARGETS, headers=h, json=body)).json()
    with patch.object(svc, "_send_webhook", new=AsyncMock(side_effect=exc)):
        resp = await client.post(f"{_TARGETS}/{created['id']}/test", headers=h)
    assert resp.status_code == 502, resp.text
    return resp.json()["detail"]


async def test_refused_connection_is_named(client: AsyncClient, db_session: AsyncSession) -> None:
    d = await _detail(
        client, db_session, _webhook_body(), httpx.ConnectError("All connection attempts failed")
    )
    assert "ConnectError" in d and "All connection attempts failed" in d
    assert d != "delivery failed: failed"


async def test_timeout_without_message_is_named_by_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    d = await _detail(client, db_session, _webhook_body(), httpx.ConnectTimeout(""))
    assert d == "delivery failed: ConnectTimeout"


async def test_secrets_are_redacted_from_the_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    exc = httpx.ConnectError(f"cannot reach {_GENERIC} with {_AUTH}")
    d = await _detail(client, db_session, _webhook_body(), exc)
    assert "t0kenInPath" not in d and "hdr-fixture-9f8e7d" not in d
    assert "[redacted]" in d


async def test_smtp_missing_setting_is_named(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    created = (
        await client.post(
            _TARGETS,
            headers=h,
            json={
                "name": "mail",
                "enabled": True,
                "kind": "smtp",
                "smtp_host": "smtp.example.test",
                "smtp_from_address": "a@example.test",
                "smtp_to_addresses": ["b@example.test"],
            },
        )
    ).json()
    # Blank the host in the stored row so the delivery code sees it missing.
    from app.models.audit_forward import AuditForwardTarget

    row = await db_session.get(AuditForwardTarget, created["id"])
    row.smtp_host = ""
    await db_session.commit()
    resp = await client.post(f"{_TARGETS}/{created['id']}/test", headers=h)
    assert resp.status_code == 502
    assert "SMTP host" in resp.json()["detail"]
