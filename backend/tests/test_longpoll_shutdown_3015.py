"""#3015 — a stopping api pod ends its parked long-polls with the ordinary
"nothing new" answer instead of cancelling them into a 500 + traceback.

uvicorn cancels in-flight requests at ``--timeout-graceful-shutdown`` (20 s) and
the agents' / supervisors' long-polls hold up to 30 s. The shutdown flag in
``app.core.shutdown`` is set when SIGTERM lands; each wait races it.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import uuid
from collections.abc import AsyncGenerator, Callable
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_api
from app.api.v1.dns import agents as dns_agents
from app.config import settings
from app.core import agent_wake, shutdown
from app.core.agent_wake import WakeResult
from app.db import get_db
from app.main import app
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance import agent_cmd, k8s_proxy
from app.services.appliance.ca import generate_session_token
from tests.conftest import _TestSessionLocal
from tests.test_dhcp_longpoll_wake_2040 import _estate as _dhcp_estate
from tests.test_dns_agents_config_serve_newest import CONFIG_URL as DNS_CONFIG_URL
from tests.test_dns_agents_config_serve_newest import _agent as _dns_agent
from tests.test_dns_agents_config_serve_newest import _render as _dns_render
from tests.test_lg_longpoll_wake_2040 import _estate as _lg_estate

PROMPT_S = 5.0  # "promptly" — far below any hold (30 s) or the 20 s cut


@pytest.fixture(autouse=True)
def _clean_flag() -> Any:
    shutdown.reset()
    yield
    shutdown.reset()


@pytest.fixture
def fresh_session_per_request() -> Any:
    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


# ── the flag, the waits, the signal hook ────────────────────────────────────


async def test_sleep_or_shutdown_ends_early_and_returns_true() -> None:
    task = asyncio.create_task(shutdown.sleep_or_shutdown(30))
    await asyncio.sleep(0.1)
    assert not task.done()
    shutdown.request_shutdown()
    assert await asyncio.wait_for(task, 2) is True


async def test_sleep_or_shutdown_before_the_call_does_not_wait() -> None:
    shutdown.request_shutdown()
    assert await asyncio.wait_for(shutdown.sleep_or_shutdown(30), 1) is True


async def test_sleep_or_shutdown_times_out_normally() -> None:
    assert await shutdown.sleep_or_shutdown(0.05) is False


async def test_get_or_shutdown_returns_an_item_and_never_drops_one() -> None:
    q: asyncio.Queue[str] = asyncio.Queue()
    q.put_nowait("job")
    shutdown.request_shutdown()
    # Shutdown already begun but work is queued: it is still handed out.
    assert await shutdown.get_or_shutdown(q, 30) == ("job", False)
    assert await shutdown.get_or_shutdown(q, 30) == (None, True)


async def test_waiter_registry_does_not_leak() -> None:
    await shutdown.sleep_or_shutdown(0.01)
    await shutdown.get_or_shutdown(asyncio.Queue(), 0.01)
    assert shutdown._waiters == set()


def test_signal_hook_sets_the_flag_and_chains_to_the_previous_handler() -> None:
    seen: list[int] = []

    def previous(signum: int, frame: Any) -> None:
        seen.append(signum)

    old = signal.signal(signal.SIGTERM, previous)
    old_int = signal.getsignal(signal.SIGINT)
    try:
        assert shutdown.install_signal_hook() is True
        handler = signal.getsignal(signal.SIGTERM)
        assert handler is not previous
        assert not shutdown.shutdown_requested()
        handler(signal.SIGTERM, None)  # type: ignore[operator]
        assert shutdown.shutdown_requested()
        assert seen == [signal.SIGTERM], "uvicorn's own handler must still run"
        # idempotent: a second install does not stack another wrapper
        assert (
            shutdown.install_signal_hook() is False or signal.getsignal(signal.SIGTERM) is handler
        )
    finally:
        signal.signal(signal.SIGTERM, old)
        signal.signal(signal.SIGINT, old_int)


def test_signal_hook_never_wraps_a_default_disposition() -> None:
    old = signal.signal(signal.SIGTERM, signal.SIG_DFL)
    old_int = signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        assert shutdown.install_signal_hook() is False
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
    finally:
        signal.signal(signal.SIGTERM, old)
        signal.signal(signal.SIGINT, old_int)


def test_lifespan_installs_the_hook() -> None:
    import inspect

    from app.main import lifespan

    src = inspect.getsource(lifespan)
    assert "install_signal_hook()" in src and "request_shutdown()" in src


# ── WakeSubscription / queues ───────────────────────────────────────────────


class _PubSub:
    async def get_message(self, ignore_subscribe_messages: bool = True, timeout: float = 0) -> Any:
        await asyncio.sleep(timeout)
        return None


@pytest.mark.parametrize("degraded", [False, True])
async def test_wake_wait_returns_shutdown_mid_wait(degraded: bool) -> None:
    sub = agent_wake.WakeSubscription(None if degraded else _PubSub(), None, degraded)
    task = asyncio.create_task(sub.wait(12))
    await asyncio.sleep(0.2)
    shutdown.request_shutdown()
    assert await asyncio.wait_for(task, 2) == WakeResult.SHUTDOWN


@pytest.mark.parametrize("degraded", [False, True])
async def test_wake_wait_returns_shutdown_when_already_shutting_down(degraded: bool) -> None:
    shutdown.request_shutdown()
    sub = agent_wake.WakeSubscription(None if degraded else _PubSub(), None, degraded)
    assert await asyncio.wait_for(sub.wait(12), 1) == WakeResult.SHUTDOWN


@pytest.mark.parametrize(
    "pop",
    [
        lambda aid: agent_cmd.pop_command(aid, timeout=30.0),
        lambda aid: agent_cmd.pop_command(aid, timeout=30.0, channel=agent_cmd.CHANNEL_STORAGE),
        lambda aid: k8s_proxy.pop_request(aid, timeout=30.0),
    ],
    ids=["nettool", "storage", "k8s-proxy"],
)
@pytest.mark.parametrize("before", [False, True])
async def test_queue_polls_return_none_promptly(pop: Callable[..., Any], before: bool) -> None:
    aid = uuid.uuid4()
    if before:
        shutdown.request_shutdown()
    task = asyncio.create_task(pop(aid))
    if not before:
        await asyncio.sleep(0.2)
        assert not task.done()
        shutdown.request_shutdown()
    assert await asyncio.wait_for(task, 2) is None


# ── the endpoints, over HTTP ────────────────────────────────────────────────


async def _timed_get_or_post(call: Callable[[], Any], before: bool) -> Any:
    if before:
        shutdown.request_shutdown()
    task = asyncio.create_task(call())
    if not before:
        await asyncio.sleep(1.0)
        assert not task.done(), "the poll should be parked"
        shutdown.request_shutdown()
    return await asyncio.wait_for(task, PROMPT_S)


@pytest.mark.parametrize("before", [False, True], ids=["mid-wait", "before-request"])
async def test_dhcp_config_poll_answers_304(
    db_session: AsyncSession, fresh_session_per_request: None, before: bool
) -> None:
    ids = await _dhcp_estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get("/api/v1/dhcp/agents/config", headers=headers)
        etag = first.json()["etag"]
        resp = await _timed_get_or_post(
            lambda: ac.get(
                "/api/v1/dhcp/agents/config", headers={**headers, "If-None-Match": f'"{etag}"'}
            ),
            before,
        )
    assert resp.status_code == 304


@pytest.mark.parametrize("before", [False, True], ids=["mid-wait", "before-request"])
async def test_lg_config_poll_answers_304(
    db_session: AsyncSession, fresh_session_per_request: None, before: bool
) -> None:
    ids = await _lg_estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get("/api/v1/looking-glass/agents/config", headers=headers)
        etag = first.json()["etag"]
        resp = await _timed_get_or_post(
            lambda: ac.get(
                "/api/v1/looking-glass/agents/config",
                headers={**headers, "If-None-Match": f'"{etag}"'},
            ),
            before,
        )
    assert resp.status_code == 304


@pytest.mark.parametrize("before", [False, True], ids=["mid-wait", "before-request"])
async def test_dns_config_poll_answers_304(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
    before: bool,
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)

    async def _no_enqueue(_ids: Any) -> None:
        return None

    monkeypatch.setattr(dns_agents, "enqueue_renders", _no_enqueue)
    server, _zone, headers = await _dns_agent(db_session)
    await db_session.commit()
    bundle = await _dns_render(db_session, server)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await _timed_get_or_post(
            lambda: ac.get(
                DNS_CONFIG_URL, headers={**headers, "If-None-Match": f'"{bundle.etag}"'}
            ),
            before,
        )
    assert resp.status_code == 304


async def _supervisor(db: AsyncSession) -> tuple[Appliance, str]:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="shutdown-3015",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.commit()
    return row, token


@pytest.mark.parametrize("before", [False, True], ids=["mid-wait", "before-request"])
async def test_supervisor_heartbeat_hold_returns_a_normal_response(
    client: AsyncClient, db_session: AsyncSession, before: bool
) -> None:
    row, token = await _supervisor(db_session)
    resp = await _timed_get_or_post(
        lambda: client.post(
            "/api/v1/appliance/supervisor/heartbeat",
            json={"appliance_id": str(row.id), "session_token": token, "wait_seconds": 25},
        ),
        before,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["long_poll"] is True


@pytest.mark.parametrize(
    ("path", "empty_key"),
    [
        ("/supervisor/nettool/poll", "request_id"),
        ("/supervisor/storage/poll", "request_id"),
        ("/supervisor/k8s-proxy/poll", "request_id"),
    ],
)
@pytest.mark.parametrize("before", [False, True], ids=["mid-wait", "before-request"])
async def test_supervisor_command_polls_answer_the_empty_shape(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    empty_key: str,
    before: bool,
) -> None:
    row, _token = await _supervisor(db_session)

    async def _auth(_request: Any, _db: Any) -> Appliance:
        return row

    monkeypatch.setattr(supervisor_api, "_require_cert_auth", _auth)
    resp = await _timed_get_or_post(lambda: client.post(f"/api/v1/appliance{path}"), before)
    assert resp.status_code == 200, resp.text
    assert resp.json()[empty_key] == ""
