"""The long-poll's inline fallback at scale (#1111, review item C).

With ``dns_agent_bundle_inline_fallback`` on, every poll that finds its
bundle stale renders it in the api. At 1.09 M records that render cannot fit
the api's 30 s ``command_timeout``, so each attempt fails the poll. These pin
what such a failure must not do to the worker path that would have served
the agent anyway.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.agent_token import mint_agent_token
from app.tasks import agent_bundles

CONFIG_URL = "/api/v1/dns/agents/config"


async def _agent(db: AsyncSession) -> tuple[DNSServer, dict[str, str]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=zone.id, name="h", fqdn=f"h.{zone.name}", record_type="A", value="10.0.0.9"
        )
    )
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_a_failed_inline_render_does_not_hold_the_sweep_off_the_worker_render(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The api's inline attempt timed out; the worker must still be asked.

    The sweep leaves a server whose last render FAILED within the last 5
    minutes to the explicit enqueue, so that it does not spin on a render
    the worker keeps failing. Recording the api's timed-out inline attempt as
    that failure stamps the row on every poll, and the sweep never re-enqueues
    the worker's render of the server for as long as its agent keeps
    polling: a lost or crashed worker render is then never retried.
    """
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    server, headers = await _agent(db_session)
    await db_session.commit()
    server_id = str(server.id)  # the handler's rollback expires the instance

    async def _timed_out(db, server, *, rendered_by):  # noqa: ANN001
        # What asyncpg's 30 s command_timeout raises out of the records query.
        raise TimeoutError()

    monkeypatch.setattr(agents_api, "render_and_store", _timed_out)
    # No bundle is served either way; whether the poll then fails or holds on
    # the worker is not what this pins.
    polled = await client.get(CONFIG_URL, headers=headers)
    assert polled.status_code != 200, polled.text

    captured: list[str] = []
    monkeypatch.setattr(
        agent_bundles, "enqueue_render", lambda sid: (captured.append(sid), True)[1]
    )
    await agent_bundles._sweep()
    assert server_id in captured, (
        "the api's timed-out inline attempt was recorded as the server's render "
        "failure, and the sweep backs off failed servers for 5 minutes: the "
        "worker's render of a stale bundle is not re-enqueued while the agent "
        "keeps polling"
    )
