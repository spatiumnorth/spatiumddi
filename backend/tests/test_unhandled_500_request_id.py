"""A 500 carries the request id the rest of the request logged under (#1201).

``RequestContextMiddleware`` generates an id when the client sends none,
binds it to every log line and returns it as ``X-Request-ID``. The
unhandled-exception handler runs in Starlette's ServerErrorMiddleware,
outside that middleware, so the response it builds never passes back through
it: it has to set the header itself. It used to read the id from the request
headers alone, so a client that sent none got a 500 with no ``X-Request-ID``,
and the ``unhandled_exception`` log line and the Diagnostics row carried
``request_id: null``: the one failure a client most needs to report was the
one it could not correlate.
"""

from __future__ import annotations

import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.audit import router as audit_router
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.auth import User

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


async def _admin_token(db: AsyncSession) -> str:
    user = User(
        username=f"rid-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Request Id",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return create_access_token(str(user.id))


async def _raise(*_args: object, **_kwargs: object) -> bytes:
    raise ValueError("a real bug")


@pytest.fixture
def broken_route(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make one real route raise an unhandled error, so the request runs the
    whole middleware stack rather than calling the handler directly."""
    monkeypatch.setattr(audit_router, "generate_change_report_pdf", _raise)


@pytest.mark.usefixtures("broken_route")
async def test_a_500_returns_the_request_id_the_middleware_generated(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _admin_token(db_session)
    # ``client`` installs the DB override; this one lets the 500 through as a
    # response instead of re-raising the error into the test.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/v1/audit/export.pdf", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal Server Error"}
    assert _UUID.match(r.headers.get("x-request-id", "")), r.headers


@pytest.mark.usefixtures("broken_route")
async def test_a_500_echoes_the_request_id_the_client_sent(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _admin_token(db_session)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get(
            "/api/v1/audit/export.pdf",
            headers={"Authorization": f"Bearer {token}", "X-Request-ID": "client-chosen-id"},
        )
    assert r.status_code == 500
    assert r.headers.get("x-request-id") == "client-chosen-id"
