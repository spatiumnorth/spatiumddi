"""A lease renewal whose DDNS writes nothing locks no DNS zone (#3773).

Under Kea HA both peers' agents report every renewal. Each lease-events batch
locked every zone its leases' DDNS might write, ``FOR NO KEY UPDATE`` to its
commit, even when the name was already published and unchanged, so the two
peers' batches ran one after the other on the zone row: at 10 renewals a
second each stayed open 9 to 18 s, past the agent's 15 s request timeout, and
both agents resent from their spools. A grant whose DDNS would write nothing
now takes no zone lock and skips its DDNS.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import event, select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents
from app.models.dhcp import DHCPServer
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import Subnet
from tests.test_lease_events_insert_order_3480 import _ddns_subnet, _two_agents
from tests.test_lease_events_trashed_scope_3733 import (
    concurrent_client,  # noqa: F401 — the fixture, shared
)

_IPS = ["10.31.1.20", "10.31.1.21", "10.31.1.22"]


def _ev(ip: str, hostname: str | None = None) -> dict[str, Any]:
    """An active lease for ``ip``, with a name and MAC fixed by the address."""
    last = int(ip.rsplit(".", 1)[1])
    now = datetime.now(UTC)
    end = (now + timedelta(hours=1)).isoformat()
    return {
        "ip_address": ip,
        "mac_address": f"aa:bb:cc:37:73:{last:02x}",
        "hostname": hostname or f"renew-{last}",
        "state": "active",
        "starts_at": now.isoformat(),
        "ends_at": end,
        "expires_at": end,
    }


async def _post(client: AsyncClient, server: DHCPServer, events: list[dict[str, Any]]) -> Response:
    return await client.post(
        "/api/v1/dhcp/agents/lease-events",
        headers={"x-test-server": str(server.id)},
        json={"leases": events},
    )


@contextlib.contextmanager
def _zone_locks() -> Iterator[list[str]]:
    seen: list[str] = []

    def _record(conn: Any, cursor: Any, statement: str, *a: Any) -> None:
        if "FROM dns_zone" in statement and " FOR " in statement:
            seen.append(statement)

    event.listen(Engine, "before_cursor_execute", _record)
    try:
        yield seen
    finally:
        event.remove(Engine, "before_cursor_execute", _record)


async def _pair(
    client: AsyncClient, db: AsyncSession
) -> tuple[DHCPServer, DHCPServer, Subnet, uuid.UUID]:
    """Two Kea peers on a DDNS subnet, whose leases peer A has published."""
    subnet, _block = await _ddns_subnet(db)
    peer_a, peer_b = await _two_agents(db, [subnet])
    first = await _post(client, peer_a, [_ev(ip) for ip in _IPS])
    assert first.status_code == 200, first.text
    return peer_a, peer_b, subnet, uuid.UUID(str(subnet.dns_zone_id))


async def _forward(db: AsyncSession, zone_id: uuid.UUID) -> tuple[list[tuple[str, str]], Any]:
    records = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.value)
            .where(
                DNSRecord.zone_id == zone_id,
                DNSRecord.auto_generated.is_(True),
                DNSRecord.record_type == "A",
            )
            .execution_options(populate_existing=True)
        )
    ).all()
    serial = (
        await db.execute(
            select(DNSZone.last_serial)
            .where(DNSZone.id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return sorted((n, v) for n, v in records), serial


@pytest.mark.asyncio
async def test_a_peers_unchanged_renewal_locks_no_zone_and_writes_nothing(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    peer_a, peer_b, _subnet, zone_id = await _pair(concurrent_client, db_session)
    before = await _forward(db_session, zone_id)
    assert len(before[0]) == len(_IPS), before

    with _zone_locks() as seen:
        for peer in (peer_b, peer_a):
            r = await _post(concurrent_client, peer, [_ev(ip) for ip in _IPS])
            assert r.status_code == 200, r.text
    assert seen == [], seen
    assert await _forward(db_session, zone_id) == before


@pytest.mark.asyncio
async def test_a_renamed_lease_still_publishes_its_new_name(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """The quiet path is for a write that would not happen: a new name does."""
    _peer_a, peer_b, _subnet, zone_id = await _pair(concurrent_client, db_session)
    r = await _post(
        concurrent_client, peer_b, [_ev(_IPS[0], "moved"), *(_ev(ip) for ip in _IPS[1:])]
    )
    assert r.status_code == 200, r.text
    names = [n for n, _v in (await _forward(db_session, zone_id))[0]]
    assert "moved" in names and "renew-20" not in names, names


@pytest.mark.asyncio
async def test_peer_batches_of_different_renewals_do_not_wait_on_each_other(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The issue's contention: peer A's batch is still open (held before its
    commit) when peer B's batch of other renewals arrives. B must answer
    without waiting for A to commit; before, it waited on the zone row."""
    peer_a, peer_b, _subnet, _zone_id = await _pair(concurrent_client, db_session)

    real = agents.recount_subnets_and_blocks
    held, release = asyncio.Event(), asyncio.Event()

    async def _hold_first(*args: Any, **kwargs: Any) -> Any:
        if not held.is_set():
            held.set()
            await asyncio.wait_for(release.wait(), timeout=30)
        return await real(*args, **kwargs)

    monkeypatch.setattr(agents, "recount_subnets_and_blocks", _hold_first)
    batch_a = asyncio.create_task(_post(concurrent_client, peer_a, [_ev(_IPS[0])]))
    try:
        await asyncio.wait_for(held.wait(), timeout=30)
        resp_b = await asyncio.wait_for(
            _post(concurrent_client, peer_b, [_ev(ip) for ip in _IPS[1:]]), timeout=5
        )
        assert resp_b.status_code == 200, resp_b.text
    finally:
        release.set()
        resp_a = await asyncio.wait_for(batch_a, timeout=30)
    assert resp_a.status_code == 200, resp_a.text
