"""Long-lived streaming responses re-validate their caller while they run.

The auth dependency runs once, when a request arrives. A server-sent-event
stream (cluster health, pod logs, nmap progress, AI chat) then keeps sending
for as long as the connection is open, so signing the session out, disabling
the account, removing the permission or revoking the API token has to end a
stream that is already flowing — within the re-check interval, not whenever
the client happens to disconnect.

The tests drive the ASGI app directly rather than through httpx's
``ASGITransport``, which collects the whole body before returning and so
cannot observe a stream that never ends.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import AsyncGenerator, AsyncIterator, MutableMapping
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import app.api.deps as deps_module
import app.api.stream_auth as stream_auth
from app.api.v1.ai import chat as chat_module
from app.api.v1.appliance import cluster as cluster_module
from app.api.v1.appliance import containers as containers_module
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_api_token,
    hash_password,
)
from app.db import get_db
from app.main import app
from app.models.auth import APIToken, Group, Role, User, UserSession
from app.models.nmap import NmapScan

RECHECK = 0.3
# Generous: the stream must end within one re-check interval plus a tick.
ENDS_WITHIN = 5.0


@pytest.fixture
async def stream_env(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[None]:
    """Fast cadences, a loop-safe session factory, and stubbed data sources."""
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as s:
            yield s

    monkeypatch.setattr(stream_auth, "STREAM_AUTH_RECHECK_SECONDS", RECHECK, raising=False)
    monkeypatch.setattr(stream_auth, "AsyncSessionLocal", factory, raising=False)
    monkeypatch.setattr(deps_module, "AsyncSessionLocal", factory)
    monkeypatch.setattr(cluster_module, "_STREAM_INTERVAL_S", 0.05)
    monkeypatch.setattr(cluster_module, "get_cluster_health", lambda: {"available": True})

    async def _no_merge(_db: Any, _snap: Any) -> None:
        return None

    monkeypatch.setattr(cluster_module, "_merge_host_state_best_effort", _no_merge)
    monkeypatch.setattr(cluster_module, "AsyncSessionLocal", factory)

    async def _endless_logs(
        _name: str, tail: int = 100, container: str | None = None
    ) -> AsyncIterator[str]:
        while True:
            yield "log line"
            await asyncio.sleep(0.05)

    monkeypatch.setattr(containers_module, "stream_container_logs", _endless_logs)

    async def _endless_scan(_scan_id: uuid.UUID, **_kw: Any) -> AsyncIterator[str]:
        while True:
            yield "scanning"
            await asyncio.sleep(0.05)

    class _EndlessChat:
        def __init__(self, _db: Any, _user: Any) -> None:
            pass

        async def get_or_create_session(self, **_kw: Any) -> Any:
            return SimpleNamespace(id=uuid.uuid4())

        async def stream_turn(self, **_kw: Any) -> AsyncIterator[Any]:
            while True:
                yield SimpleNamespace(kind="content", data={"delta": "x"})
                await asyncio.sleep(0.05)

    async def _provider(_db: Any) -> Any:
        return SimpleNamespace(is_enabled=True, default_model="m")

    async def _no_caps(_db: Any, _user: Any) -> None:
        return None

    monkeypatch.setattr(chat_module, "ChatOrchestrator", _EndlessChat)
    monkeypatch.setattr(chat_module, "_get_default_provider", _provider)
    monkeypatch.setattr(chat_module, "check_user_caps", _no_caps)

    import app.services.nmap.runner as runner_module

    monkeypatch.setattr(runner_module, "stream_scan_lines", _endless_scan)

    app.dependency_overrides[get_db] = _get_db
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()


class _Stream:
    """One in-flight ASGI request, with its response messages queued."""

    def __init__(
        self, path: str, headers: dict[str, str], *, method: str = "GET", body: bytes = b""
    ) -> None:
        self.messages: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._disconnect = asyncio.Event()
        self._requested = False
        self._body = body
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"host", b"test")]
            + [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": ("127.0.0.1", 40000),
            "server": ("test", 80),
        }
        self.task = asyncio.create_task(app(scope, self._receive, self._send))

    async def _receive(self) -> dict[str, Any]:
        if not self._requested:
            self._requested = True
            return {"type": "http.request", "body": self._body, "more_body": False}
        await self._disconnect.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message: MutableMapping[str, Any]) -> None:
        await self.messages.put(dict(message))

    async def status(self) -> int:
        msg = await asyncio.wait_for(self.messages.get(), ENDS_WITHIN)
        assert msg["type"] == "http.response.start", msg
        return int(msg["status"])

    async def frame(self) -> bytes:
        """Next non-empty body chunk; fails if the stream ended instead."""
        while True:
            msg = await asyncio.wait_for(self.messages.get(), ENDS_WITHIN)
            assert msg["type"] == "http.response.body", msg
            assert msg.get("more_body", False), "stream ended"
            if msg.get("body"):
                return bytes(msg["body"])

    async def ended_within(self, seconds: float) -> bool:
        """True when the response body completes within ``seconds``."""
        deadline = asyncio.get_running_loop().time() + seconds
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False
            try:
                msg = await asyncio.wait_for(self.messages.get(), remaining)
            except TimeoutError:
                return False
            if msg["type"] == "http.response.body" and not msg.get("more_body", False):
                return True

    async def close(self) -> None:
        self._disconnect.set()
        try:
            await asyncio.wait_for(self.task, 5)
        except (TimeoutError, Exception):  # noqa: BLE001 — teardown only
            self.task.cancel()


async def _viewer(db: AsyncSession) -> tuple[User, Role, UserSession, str]:
    """A non-superadmin with read on appliance + the nmap permission, a live
    session, and an access token bound to it."""
    user = User(
        username=f"s-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="S",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_active=True,
        is_superadmin=False,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(user)
    await db.flush()
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[
            {"action": "read", "resource_type": "appliance"},
            {"action": "read", "resource_type": "manage_nmap_scans"},
        ],
    )
    db.add(role)
    await db.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [user]
    db.add(group)
    _raw, refresh_hash = create_refresh_token(str(user.id))
    now = datetime.now(UTC)
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_hash,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=1),
        revoked=False,
    )
    db.add(session)
    await db.commit()
    token = create_access_token(str(user.id), jti=str(session.id))
    return user, role, session, token


async def _api_token(db: AsyncSession, user: User) -> tuple[APIToken, str]:
    raw, _prefix, token_hash = generate_api_token()
    token = APIToken(
        name=f"t-{uuid.uuid4().hex[:6]}",
        token_hash=token_hash,
        prefix=raw[:10],
        scope="user",
        scopes=[],
        user_id=user.id,
        created_by_user_id=user.id,
        is_active=True,
    )
    db.add(token)
    await db.commit()
    return token, raw


CLUSTER = "/api/v1/appliance/cluster/health/stream"
LOGS = "/api/v1/appliance/containers/api-0/logs/stream"


async def _open(path: str, bearer: str) -> _Stream:
    stream = _Stream(path, {"Authorization": f"Bearer {bearer}"})
    assert await stream.status() == 200
    await stream.frame()
    return stream


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_keeps_flowing_for_a_valid_caller(db_session: AsyncSession) -> None:
    _user, _role, _session, token = await _viewer(db_session)
    stream = await _open(CLUSTER, token)
    try:
        # Several re-check intervals pass and frames keep arriving.
        loop = asyncio.get_running_loop()
        until = loop.time() + RECHECK * 4
        while loop.time() < until:
            await stream.frame()
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_ends_when_the_session_is_revoked(db_session: AsyncSession) -> None:
    _user, _role, session, token = await _viewer(db_session)
    stream = await _open(CLUSTER, token)
    try:
        await db_session.execute(
            update(UserSession).where(UserSession.id == session.id).values(revoked=True)
        )
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_ends_when_the_session_expires(db_session: AsyncSession) -> None:
    _user, _role, session, token = await _viewer(db_session)
    stream = await _open(CLUSTER, token)
    try:
        await db_session.execute(
            update(UserSession)
            .where(UserSession.id == session.id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_ends_when_the_account_is_disabled(db_session: AsyncSession) -> None:
    user, _role, _session, token = await _viewer(db_session)
    stream = await _open(CLUSTER, token)
    try:
        await db_session.execute(update(User).where(User.id == user.id).values(is_active=False))
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_ends_when_the_permission_is_removed(
    db_session: AsyncSession,
) -> None:
    _user, role, _session, token = await _viewer(db_session)
    stream = await _open(CLUSTER, token)
    try:
        await db_session.execute(update(Role).where(Role.id == role.id).values(permissions=[]))
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_ends_when_the_api_token_is_revoked(db_session: AsyncSession) -> None:
    user, _role, _session, _token = await _viewer(db_session)
    api_token, raw = await _api_token(db_session, user)
    stream = await _open(CLUSTER, raw)
    try:
        await db_session.execute(
            update(APIToken).where(APIToken.id == api_token.id).values(is_active=False)
        )
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_cluster_stream_ends_when_the_api_token_expires(db_session: AsyncSession) -> None:
    user, _role, _session, _token = await _viewer(db_session)
    api_token, raw = await _api_token(db_session, user)
    stream = await _open(CLUSTER, raw)
    try:
        await db_session.execute(
            update(APIToken)
            .where(APIToken.id == api_token.id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_log_stream_ends_when_the_session_is_revoked(db_session: AsyncSession) -> None:
    _user, _role, session, token = await _viewer(db_session)
    stream = await _open(LOGS, token)
    try:
        await db_session.execute(
            update(UserSession).where(UserSession.id == session.id).values(revoked=True)
        )
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_log_stream_ends_when_the_permission_is_removed(db_session: AsyncSession) -> None:
    _user, role, _session, token = await _viewer(db_session)
    stream = await _open(LOGS, token)
    try:
        await db_session.execute(update(Role).where(Role.id == role.id).values(permissions=[]))
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_nmap_stream_ends_when_the_account_is_disabled(db_session: AsyncSession) -> None:
    user, _role, _session, token = await _viewer(db_session)
    scan = NmapScan(target_ip="192.0.2.1", preset="quick", status="running")
    db_session.add(scan)
    await db_session.commit()
    stream = await _open(f"/api/v1/nmap/scans/{scan.id}/stream", token)
    try:
        await db_session.execute(update(User).where(User.id == user.id).values(is_active=False))
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()


@pytest.mark.usefixtures("stream_env")
async def test_ai_chat_stream_ends_when_the_session_is_revoked(db_session: AsyncSession) -> None:
    _user, _role, session, token = await _viewer(db_session)
    stream = _Stream(
        "/api/v1/ai/chat",
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
        body=json.dumps({"message": "hi"}).encode(),
    )
    try:
        assert await stream.status() == 200
        await stream.frame()
        await db_session.execute(
            update(UserSession).where(UserSession.id == session.id).values(revoked=True)
        )
        await db_session.commit()
        assert await stream.ended_within(ENDS_WITHIN)
    finally:
        await stream.close()
