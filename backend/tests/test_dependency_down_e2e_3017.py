"""#3017 end to end: each failover path in the issue answers 503 through the real app.

``test_dependency_down_3017.py`` pins the classifier and the handlers called
directly. These drive the whole ASGI stack (every middleware, the exception
handlers, FastAPI's dependency exit) so a path that only works when a handler
is called by hand cannot pass. The database failure is injected where the
driver raises it: a ``async_creator`` that refuses, so the error carries
SQLAlchemy's pool frames exactly as it does live, or a ``before_cursor_execute``
fault on the test engine.
"""

from __future__ import annotations

import errno
import socket
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.exc import InterfaceError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.db as dbmod
from app.api.v1.dhcp.agents import _auth_agent
from app.core import maintenance_mode
from app.core.security import create_access_token
from app.main import app
from app.models.dhcp import DHCPServer
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.agent_token import mint_agent_token as mint_dhcp_agent_token
from tests.conftest import _test_engine


@pytest.fixture(autouse=True)
def _no_diagnostics_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dependency-down request must never try the diagnostics capture."""
    import app.services.diagnostics as diag

    async def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("diagnostics capture attempted for a dependency-down error")

    monkeypatch.setattr(diag, "record_unhandled_exception_async", boom)
    maintenance_mode.invalidate_cache()


def _dead_sessionmaker(exc_factory: Any) -> Any:
    """Sessions whose first connect raises ``exc_factory()`` from inside the pool."""

    async def creator() -> Any:
        raise exc_factory()

    engine = create_async_engine(
        "postgresql+asyncpg://nobody:x@db.invalid:5432/none", async_creator=creator
    )
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
async def raw_client() -> AsyncIterator[AsyncClient]:
    """The real app, no ``get_db`` override, app exceptions answered not raised."""
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _assert_503(r: Any) -> None:
    assert r.status_code == 503, r.text
    assert r.headers.get("Retry-After") == "2"
    assert "retry" in r.json()["detail"].lower()


# ── row 1: the maintenance-mode middleware's settings read ────────────────


@pytest.mark.parametrize(
    "exc_factory",
    [
        lambda: ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"),
        TimeoutError,
        lambda: ExceptionGroup("tg", [ConnectionRefusedError(111, "Connection refused")]),
        lambda: ExceptionGroup("tg", [TimeoutError()]),
    ],
    ids=["refused", "timeout", "group-refused", "group-timeout"],
)
@pytest.mark.parametrize(
    "path",
    ["/api/v1/dhcp/agents/heartbeat", "/api/v1/ipam/spaces"],
    ids=["agent-exempt", "operator-route"],
)
async def test_a_mutating_request_with_the_database_refusing_answers_503(
    raw_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    exc_factory: Any,
    path: str,
) -> None:
    """REGRESSION (#3017 row 1): 24 of the 35 500s, agent POSTs among them."""
    monkeypatch.setattr(dbmod, "AsyncSessionLocal", _dead_sessionmaker(exc_factory))
    if "/agents/" in path:
        # A real agent's credential, so the route's own auth reaches the
        # database rather than 401ing on the token's shape.
        token, _ = mint_dhcp_agent_token(str(uuid.uuid4()), "agent-1", "fp")
    else:
        token = create_access_token(str(uuid.uuid4()), jti=str(uuid.uuid4()))
    r = await raw_client.post(path, json={}, headers={"Authorization": f"Bearer {token}"})
    _assert_503(r)


async def test_an_exempt_path_does_not_read_the_maintenance_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent and supervisor POSTs pass a maintenance window whatever the flag
    says, so the middleware has no reason to read it for them, and a failed
    read must not stand between an agent and its route (whose own switchover
    handling, #2845, is better than a blanket 503)."""
    calls: list[str] = []

    async def spy(db: Any) -> Any:
        calls.append("read")
        return False, "", None

    monkeypatch.setattr(maintenance_mode, "get_maintenance_state", spy)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        await ac.post("/api/v1/appliance/supervisor/heartbeat", json={})
        await ac.post("/api/v1/dhcp/agents/heartbeat", json={})
        assert calls == []
        await ac.post("/api/v1/ipam/spaces", json={})
        assert calls == ["read"]


async def test_maintenance_on_still_blocks_a_non_exempt_post(
    raw_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control: the reorder did not open the window."""

    async def on(db: Any) -> Any:
        return True, "window", None

    monkeypatch.setattr(maintenance_mode, "get_maintenance_state", on)
    r = await raw_client.post("/api/v1/ipam/spaces", json={})
    assert r.status_code == 503
    assert r.json().get("maintenance") is True
    assert r.headers.get("Retry-After") == "120"


# ── row 3: the bearer check's session read, OSError 113 in a group ────────


@pytest.mark.parametrize(
    "exc_factory",
    [
        lambda: ExceptionGroup("unhandled errors in a TaskGroup", [OSError(113, "No route")]),
        lambda: OSError(errno.EHOSTUNREACH, "No route to host"),
        lambda: OSError(errno.ENETUNREACH, "Network is unreachable"),
        lambda: OSError("Multiple exceptions: [Errno 113] x, [Errno 111] y"),
    ],
    ids=["group-113", "bare-113", "bare-101", "multiple-exceptions"],
)
async def test_cluster_health_with_the_primary_unreachable_answers_503(
    raw_client: AsyncClient, monkeypatch: pytest.MonkeyPatch, exc_factory: Any
) -> None:
    """REGRESSION (#3017 row 3): the seed's ``cluster/health`` 500 that
    ``ha/partition_health_contract`` grades."""
    monkeypatch.setattr(dbmod, "AsyncSessionLocal", _dead_sessionmaker(exc_factory))
    token = create_access_token(str(uuid.uuid4()), jti=str(uuid.uuid4()))
    r = await raw_client.get(
        "/api/v1/appliance/cluster/health", headers={"Authorization": f"Bearer {token}"}
    )
    _assert_503(r)


async def test_an_unreachable_host_from_outside_the_driver_is_not_a_database_503(
    raw_client: AsyncClient,
) -> None:
    """Over-classification guard: an ``OSError`` 113 a route raises itself (a
    WinRM or DNS target that is down) is not the database failing over. It
    keeps the 500 path it had before #3017."""
    from fastapi import APIRouter

    router = APIRouter()

    @router.get("/__t3017/outbound")
    async def outbound() -> None:
        raise OSError(errno.EHOSTUNREACH, "No route to host")

    app.include_router(router)
    try:
        r = await raw_client.get("/__t3017/outbound")
    finally:
        app.router.routes[:] = [
            rt for rt in app.router.routes if getattr(rt, "path", "") != "/__t3017/outbound"
        ]
    assert r.status_code == 500


# ── row 2: get_db's cleanup after the response started ────────────────────


class _ClosingFails(AsyncSession):
    close_exc: BaseException | None = None

    async def close(self) -> None:
        await super().close()
        if self.close_exc is not None:
            raise self.close_exc


@pytest.mark.parametrize(
    "close_exc",
    [
        InterfaceError(
            "ROLLBACK",
            {},
            Exception("cannot call Transaction.rollback(): the underlying connection is closed"),
        ),
        TimeoutError(),
    ],
    ids=["closed-connection", "timeout"],
)
async def test_get_db_cleanup_failing_after_the_response_is_not_an_error(
    monkeypatch: pytest.MonkeyPatch, close_exc: BaseException
) -> None:
    """REGRESSION (#3017 row 2): the supervisor's nettool / storage polls
    logged ``RuntimeError: Caught handled exception, but response already
    started`` when the rollback on close hit the closed connection.
    ``raise_app_exceptions=True``: anything the ASGI app raises fails here."""
    _ClosingFails.close_exc = close_exc
    monkeypatch.setattr(
        dbmod,
        "AsyncSessionLocal",
        async_sessionmaker(_test_engine, class_=_ClosingFails, expire_on_commit=False),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get("/api/v1/settings/public")
    assert r.status_code == 200, r.text


async def test_get_db_cleanup_real_bug_still_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: a cleanup failure that is not the connection going away is
    still raised, not swallowed."""
    _ClosingFails.close_exc = ValueError("bug in close")
    monkeypatch.setattr(
        dbmod,
        "AsyncSessionLocal",
        async_sessionmaker(_test_engine, class_=_ClosingFails, expire_on_commit=False),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        with pytest.raises(Exception):  # noqa: B017,PT011 — wrapped differently by version
            await ac.get("/api/v1/settings/public")


# ── row 4: DHCP lease events after the connection is lost mid-batch ───────


class _Fault:
    """Once armed, every statement fails: the connection is gone for good,
    as it is when the primary has moved."""

    def __init__(self) -> None:
        self.exc: BaseException | None = None
        self.armed = False

    def __call__(self, *_a: Any, **_k: Any) -> None:
        if self.armed and self.exc is not None:
            raise self.exc


@pytest.fixture
def fault() -> Iterator[_Fault]:
    f = _Fault()
    event.listen(_test_engine.sync_engine, "before_cursor_execute", f)
    try:
        yield f
    finally:
        event.remove(_test_engine.sync_engine, "before_cursor_execute", f)


async def _seed_dhcp(db: AsyncSession) -> DHCPServer:
    space = IPSpace(name=f"s3017-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.71.0.0/16", name="b3017")
    db.add(block)
    await db.flush()
    db.add(Subnet(space_id=space.id, block_id=block.id, network="10.71.1.0/24", name="n3017"))
    server = DHCPServer(
        name=f"k3017-{uuid.uuid4().hex[:6]}", driver="kea", host="127.0.0.1", port=67
    )
    db.add(server)
    await db.commit()
    return server


def _lease_batch() -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "leases": [
            {
                "ip_address": "10.71.1.50",
                "mac_address": "aa:bb:cc:dd:ee:01",
                "hostname": "h1",
                "state": "active",
                "starts_at": datetime.now(UTC).isoformat(),
                "ends_at": end,
                "expires_at": end,
            }
        ]
    }


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(
            asyncpg.exceptions.ConnectionDoesNotExistError(
                "connection was closed in the middle of operation"
            ),
            id="connection-gone",
        ),
        pytest.param(
            asyncpg.exceptions.AdminShutdownError(
                "terminating connection due to administrator command"
            ),
            id="admin-shutdown",
        ),
    ],
)
async def test_lease_events_losing_the_connection_in_ddns_answers_503(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    fault: _Fault,
    exc: BaseException,
) -> None:
    """REGRESSION (#3017 row 4): the DDNS step's ``except Exception`` swallowed
    the lost connection, and the next touch of the session raised
    ``PendingRollbackError`` as a 500. The batch is not committed either way;
    the agent's spool (#1077) resends it on a 503."""
    server = await _seed_dhcp(db_session)

    async def ddns_hits_failover(db: AsyncSession, *, ipam_row: Any, **_k: Any) -> None:
        # The connection drops under the DDNS step's flush, which leaves the
        # session needing a rollback; the route's next statement then meets
        # PendingRollbackError, which is what the drill logged.
        fault.exc = exc
        fault.armed = True
        ipam_row.description = "ddns"
        await db.flush()

    import app.services.dns.ddns as ddns

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", ddns_hits_failover)
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post("/api/v1/dhcp/agents/lease-events", json=_lease_batch())
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert r.status_code == 503, r.text
    assert r.headers.get("Retry-After")


async def test_lease_events_ddns_bug_is_still_swallowed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: a DDNS failure that is not the database going away is still
    logged and skipped, as before; the lease is upserted."""
    server = await _seed_dhcp(db_session)

    async def ddns_bug(db: AsyncSession, **_k: Any) -> None:
        raise ValueError("ddns bug")

    import app.services.dns.ddns as ddns

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", ddns_bug)
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        r = await client.post("/api/v1/dhcp/agents/lease-events", json=_lease_batch())
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert r.status_code == 200, r.text
    assert r.json()["upserted"] == 1


async def test_lease_events_ddns_target_refusing_is_still_a_logged_skip(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: a DNS server refusing the DDNS update (a ConnectionError that
    is not the database) must not turn the lease batch into a 503 the agent
    would resend forever."""
    server = await _seed_dhcp(db_session)

    async def ddns_refused(db: AsyncSession, **_k: Any) -> None:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "dns server refused")

    import app.services.dns.ddns as ddns

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", ddns_refused)
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        r = await client.post("/api/v1/dhcp/agents/lease-events", json=_lease_batch())
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert r.status_code == 200, r.text
    assert r.json()["upserted"] == 1


# ── a resolver that did not answer for the database host ─────────────────


@pytest.mark.parametrize(
    ("exc_factory", "status"),
    [
        (lambda: socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"), 503),
        (lambda: socket.gaierror(socket.EAI_NONAME, "Name or service not known"), 500),
    ],
    ids=["eai-again-503", "eai-noname-500"],
)
async def test_database_host_name_resolution(
    raw_client: AsyncClient, monkeypatch: pytest.MonkeyPatch, exc_factory: Any, status: int
) -> None:
    """A node loss can take the CoreDNS replica a node resolves through with
    it (#1718): resolving the database host then fails with EAI_AGAIN, which
    is the same failover. A name that does not exist (EAI_NONAME) is a
    configuration error and stays on the 500 path, diagnostics and all."""
    if status == 500:
        # The 500 path tries the capture; let it (it fails harmlessly here).
        import app.services.diagnostics as diag

        async def quiet(*_a: Any, **_k: Any) -> None:
            return None

        monkeypatch.setattr(diag, "record_unhandled_exception_async", quiet)
    monkeypatch.setattr(dbmod, "AsyncSessionLocal", _dead_sessionmaker(exc_factory))
    token = create_access_token(str(uuid.uuid4()), jti=str(uuid.uuid4()))
    r = await raw_client.get(
        "/api/v1/appliance/cluster/health", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == status, r.text
