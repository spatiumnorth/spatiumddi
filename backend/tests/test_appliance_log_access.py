"""Reading appliance log text takes ``admin`` on ``appliance`` and is redacted.

Host log files and pod logs carry whatever a process printed, including
connection strings, keys and tokens. A role holding only ``read`` on
``appliance`` (the builtin Viewer shape) can see the appliance's state but
not its raw log lines; a role holding ``admin`` can, and every line it
receives has been passed through the support bundle's secret redaction.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import containers as containers_route
from app.api.v1.appliance import diagnostics as diagnostics_route
from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User

DSN_LINE = "connecting to postgresql+asyncpg://spatium:hunter2-db-pass@db:5432/spatiumddi"
PEM_BLOCK = (
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
)
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"
RAW_LOG = f"starting up\n{DSN_LINE}\n{PEM_BLOCK}\nbearer {JWT}\nready"

SECRETS = ("hunter2-db-pass", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", JWT)

LOG_ROUTES = (
    "/api/v1/appliance/diagnostics/logs",
    "/api/v1/appliance/diagnostics/logs/syslog",
    "/api/v1/appliance/containers/api-0/logs",
    "/api/v1/appliance/containers/api-0/logs/stream",
    "/api/v1/appliance/containers/workloads/api/logs/stream",
)


async def _headers(db: AsyncSession, action: str) -> dict[str, str]:
    """A non-superadmin holding ``action`` on ``appliance`` and nothing else."""
    user = User(
        username=f"u{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="n",
        hashed_password=hash_password("x"),
        is_superadmin=False,
        force_password_change=False,
    )
    db.add(user)
    await db.flush()
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": action, "resource_type": "appliance"}],
    )
    db.add(role)
    await db.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [user]
    db.add(group)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.fixture
def stub_log_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every log source returns the same secret-bearing text."""

    async def _finite_stream(
        _name: str, tail: int = 100, container: str | None = None
    ) -> AsyncIterator[str]:
        yield RAW_LOG

    monkeypatch.setattr(diagnostics_route, "list_log_sources", lambda: ["syslog"])
    monkeypatch.setattr(diagnostics_route, "read_log_tail", lambda _n, lines=500: RAW_LOG)
    monkeypatch.setattr(containers_route, "get_container_logs", lambda _n, tail=200: RAW_LOG)
    monkeypatch.setattr(containers_route, "stream_container_logs", _finite_stream)
    monkeypatch.setattr(containers_route, "resolve_workload_pod", lambda _c: ("api-0", "api"))


@pytest.mark.usefixtures("stub_log_sources")
@pytest.mark.parametrize("path", LOG_ROUTES)
async def test_read_only_role_cannot_read_appliance_logs(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, "read")
    r = await client.get(path, headers=headers)
    assert r.status_code == 403, r.text


@pytest.mark.usefixtures("stub_log_sources")
@pytest.mark.parametrize("path", LOG_ROUTES)
async def test_admin_role_can_read_appliance_logs(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, "admin")
    r = await client.get(path, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.usefixtures("stub_log_sources")
@pytest.mark.parametrize("path", LOG_ROUTES[1:])
async def test_appliance_log_text_is_redacted(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, "admin")
    r = await client.get(path, headers=headers)
    assert r.status_code == 200, r.text
    body = r.text
    for secret in SECRETS:
        assert secret not in body, f"{secret!r} reached the response for {path}"
    # The rest of the log survives: redaction replaces the secret, not the line.
    assert "starting up" in body
    assert "ready" in body
    assert "db:5432" in body


async def test_read_only_role_still_sees_the_container_list(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the log text moves to ``admin``; the pod list stays ``read``."""
    monkeypatch.setattr(containers_route, "svc_list_containers", lambda: [])
    headers = await _headers(db_session, "read")
    r = await client.get("/api/v1/appliance/containers", headers=headers)
    assert r.status_code == 200, r.text
