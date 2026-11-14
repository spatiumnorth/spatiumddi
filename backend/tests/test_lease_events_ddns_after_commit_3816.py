"""A lease-events batch no longer holds the DNS zone rows to its commit (#3816).

A publish bumps its zone's serial, which holds the zone row until the
transaction commits. A first-acquisition batch spent most of its time in
DDNS, so under Kea HA the other member's batch of new leases queued on the
zone row for the whole batch. The grants' DDNS now runs after the batch's own
transaction committed, in short transactions of a few names each.

Each test holds peer A's batch open just before its commit; B's batch of
OTHER new leases in the same zone must answer while A is still held (before
the fix it waited for A's zone row), and every name ends up published once.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress
from tests.test_lease_events_ha_renewal_3773 import _ev, _post
from tests.test_lease_events_ha_row_locks_3789 import (
    _a_records,
    _b_while_a_held,
    _held_open,
)
from tests.test_lease_events_insert_order_3480 import _ddns_subnet, _two_agents
from tests.test_lease_events_trashed_scope_3733 import (
    concurrent_client,  # noqa: F401 — the fixture, shared
)


async def _post_with_id(
    client: AsyncClient, server: DHCPServer, events: list[dict[str, Any]], batch_id: str
) -> Response:
    return await client.post(
        "/api/v1/dhcp/agents/lease-events",
        headers={"x-test-server": str(server.id)},
        json={"leases": events, "batch_id": batch_id},
    )


_A_IPS = [f"10.31.1.{n}" for n in range(60, 80)]
_B_IPS = [f"10.31.1.{n}" for n in range(100, 120)]


@pytest.mark.asyncio
async def test_a_batch_of_new_leases_does_not_hold_the_zone_for_the_other_members_batch(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))

    async with _held_open(monkeypatch) as held:
        batch_a = asyncio.create_task(_post(concurrent_client, peer_a, [_ev(i) for i in _A_IPS]))
        await asyncio.wait_for(held.wait(), timeout=30)
        batch_b = asyncio.create_task(_post(concurrent_client, peer_b, [_ev(i) for i in _B_IPS]))
        await asyncio.wait({batch_b}, timeout=30)
        answered_while_held = batch_b.done() and not batch_a.done()
    resp_b = await asyncio.wait_for(batch_b, timeout=60)
    resp_a = await asyncio.wait_for(batch_a, timeout=60)
    assert resp_a.status_code == 200, resp_a.text
    assert resp_b.status_code == 200, resp_b.text
    assert answered_while_held, "peer B waited on the zone row peer A's batch held"

    records = await _a_records(db_session, zone_id)
    assert len(records) == len(_A_IPS) + len(_B_IPS), records
    assert len({v for _n, v in records}) == len(records)


@pytest.mark.asyncio
async def test_both_members_reporting_the_same_new_leases_publish_each_name_once(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    events = [_ev(i) for i in _A_IPS]
    resp_a, resp_b, _ = await _b_while_a_held(
        concurrent_client, monkeypatch, peer_a, peer_b, events
    )
    assert resp_a.status_code == 200 and resp_b.status_code == 200
    assert len(await _a_records(db_session, zone_id)) == len(_A_IPS)
    # Every mirror points at its published record, forward and reverse.
    mirrors = (
        (
            await db_session.execute(
                select(IPAddress)
                .where(IPAddress.address.in_(_A_IPS))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert len(mirrors) == len(_A_IPS)
    assert all(m.dns_record_id is not None for m in mirrors)
    ptr = (
        await db_session.execute(
            select(func.count())
            .select_from(DNSRecord)
            .where(DNSRecord.record_type == "PTR", DNSRecord.deleted_at.is_(None))
        )
    ).scalar_one()
    assert ptr == len(_A_IPS)


@pytest.mark.asyncio
async def test_a_replayed_batch_is_a_duplicate_and_publishes_nothing_twice(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    events = [_ev(i) for i in _A_IPS[:5]]
    batch_id = uuid.uuid4().hex
    first = await _post_with_id(concurrent_client, peer_a, events, batch_id)
    assert first.status_code == 200, first.text
    before = await _a_records(db_session, zone_id)
    assert len(before) == 5
    again = await _post_with_id(concurrent_client, peer_a, events, batch_id)
    assert again.status_code == 200, again.text
    assert await _a_records(db_session, zone_id) == before


@pytest.mark.asyncio
async def test_a_grant_released_in_the_same_batch_leaves_no_record(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    ip = _A_IPS[0]
    resp = await _post(
        concurrent_client, peer_a, [_ev(ip), {**_ev(ip), "state": "released"}, _ev(_A_IPS[1])]
    )
    assert resp.status_code == 200, resp.text
    names = await _a_records(db_session, zone_id)
    assert [v for _n, v in names] == [_A_IPS[1]]


@pytest.mark.asyncio
async def test_a_hundred_new_names_publish_in_a_few_transactions(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each commit wakes the DNS agents to rebuild their bundle, so a box must
    not pay it every few names: 100 names went through 13 transactions after
    the batch's own and a first-acquisition batch took three times as long as
    before the change, then 7 to 10 when the chunk halved past a 2 s hold. The
    first chunk is 40 names and the next is sized from what those cost."""
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    ips = [f"10.31.1.{n}" for n in range(100, 200)]
    commits = 0
    real = AsyncSession.commit

    async def _count(self: AsyncSession) -> None:
        nonlocal commits
        commits += 1
        await real(self)

    monkeypatch.setattr(AsyncSession, "commit", _count)
    resp = await _post(concurrent_client, peer_a, [_ev(i) for i in ips])
    assert resp.status_code == 200, resp.text
    assert len(await _a_records(db_session, zone_id)) == len(ips)
    # The batch's own commit, then the chunks: 40 names, then the rest.
    assert commits <= 3, commits


@pytest.mark.asyncio
async def test_a_replay_after_a_mid_ddns_outage_publishes_each_name_once(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The batch commits before its DDNS, so a connection lost in the DDNS
    answers 503 with the receipt already committed (#3017: the agent must
    spool and resend). The resend is a duplicate by that receipt and must
    still publish what the first attempt did not."""
    import asyncpg
    from sqlalchemy.exc import InterfaceError

    import app.services.dns.ddns as ddns

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    ips = _A_IPS[:6]
    events = [_ev(i) for i in ips]
    batch_id = uuid.uuid4().hex
    real = ddns.apply_ddns_for_lease
    calls = 0

    async def _outage(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise InterfaceError("stmt", {}, asyncpg.exceptions.ConnectionDoesNotExistError("x"))
        return await real(*args, **kwargs)

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _outage)
    first = await _post_with_id(concurrent_client, peer_a, events, batch_id)
    assert first.status_code == 503, first.text
    assert len(await _a_records(db_session, zone_id)) < len(ips)

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", real)
    again = await _post_with_id(concurrent_client, peer_a, events, batch_id)
    assert again.status_code == 200, again.text
    assert again.json()["duplicate"] is True
    names = await _a_records(db_session, zone_id)
    assert sorted(v for _n, v in names) == sorted(ips)
    third = await _post_with_id(concurrent_client, peer_a, events, batch_id)
    assert third.status_code == 200
    assert await _a_records(db_session, zone_id) == names


@pytest.mark.asyncio
async def test_a_replay_does_not_republish_a_name_a_later_batch_renamed(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncpg
    from sqlalchemy.exc import InterfaceError

    import app.services.dns.ddns as ddns

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    ip = _A_IPS[0]
    first_batch = uuid.uuid4().hex
    real = ddns.apply_ddns_for_lease

    async def _outage(*args: Any, **kwargs: Any) -> Any:
        raise InterfaceError("stmt", {}, asyncpg.exceptions.ConnectionDoesNotExistError("x"))

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _outage)
    r1 = await _post_with_id(concurrent_client, peer_a, [_ev(ip, "host-a")], first_batch)
    assert r1.status_code == 503, r1.text
    monkeypatch.setattr(ddns, "apply_ddns_for_lease", real)
    r2 = await _post_with_id(concurrent_client, peer_a, [_ev(ip, "host-b")], uuid.uuid4().hex)
    assert r2.status_code == 200, r2.text
    assert [n for n, _v in await _a_records(db_session, zone_id)] == ["host-b"]

    replay = await _post_with_id(concurrent_client, peer_a, [_ev(ip, "host-a")], first_batch)
    assert replay.status_code == 200 and replay.json()["duplicate"] is True
    assert [n for n, _v in await _a_records(db_session, zone_id)] == ["host-b"]


def _count_wakes(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    import app.core.agent_wake as agent_wake

    published: list[tuple[str, ...]] = []

    async def _publish(*channels: str) -> None:
        published.append(channels)

    monkeypatch.setattr(agent_wake, "publish_wake", _publish)
    return published


@pytest.mark.asyncio
async def test_a_hundred_new_names_wake_the_dns_agents_once(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chunks commit separately but the DNS agents are woken once for the
    POST, after the last of them, so they rebuild once per batch."""
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    ips = [f"10.31.1.{n}" for n in range(100, 200)]
    published = _count_wakes(monkeypatch)
    resp = await _post(concurrent_client, peer_a, [_ev(i) for i in ips])
    assert resp.status_code == 200, resp.text
    assert len(await _a_records(db_session, zone_id)) == len(ips)
    dns_wakes = [c for c in published if any(":dns:" in ch for ch in c)]
    assert len(dns_wakes) == 1, published


@pytest.mark.asyncio
async def test_a_batch_that_lost_the_database_mid_ddns_still_wakes_for_what_committed(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 503 drops the request's collected wakes, so the names the earlier
    chunks committed would wait for the safety tick."""
    import asyncpg
    from sqlalchemy.exc import InterfaceError

    import app.api.v1.dhcp.agents as agents
    import app.services.dns.ddns as ddns

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    monkeypatch.setattr(agents, "_DDNS_CHUNK_START", 3)
    real = ddns.apply_ddns_for_lease
    calls = 0

    async def _outage(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 5:  # the second chunk
            raise InterfaceError("stmt", {}, asyncpg.exceptions.ConnectionDoesNotExistError("x"))
        return await real(*args, **kwargs)

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _outage)
    published = _count_wakes(monkeypatch)
    resp = await _post(concurrent_client, peer_a, [_ev(i) for i in _A_IPS[:8]])
    assert resp.status_code == 503, resp.text
    assert len(await _a_records(db_session, zone_id)) == 3
    dns_wakes = [c for c in published if any(":dns:" in ch for ch in c)]
    assert len(dns_wakes) == 1, published


async def _chunk_serials(db_session: AsyncSession, zone_id: uuid.UUID) -> tuple[int, list[int]]:
    """The zone's stored serial and the distinct target serials its ops carry."""
    from app.models.dns import DNSRecordOp, DNSZone

    zone = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone_id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    targets = (
        (
            await db_session.execute(
                select(DNSRecordOp.target_serial).where(DNSRecordOp.zone_id == zone_id).distinct()
            )
        )
        .scalars()
        .all()
    )
    return int(zone.last_serial), sorted(t for t in targets if t is not None)


@pytest.mark.asyncio
async def test_a_chunk_bumps_each_zone_serial_once_not_once_per_name(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bumped per name, 100 names moved the zone's serial 100 times and flushed
    an UPDATE of the row they hold locked for each. A chunk is one transaction
    and moves it once; the zone still ends on the serial its last op names."""
    import app.api.v1.dhcp.agents as agents

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    before, _ = await _chunk_serials(db_session, zone_id)
    monkeypatch.setattr(agents, "_DDNS_CHUNK_START", 30)
    ips = [f"10.31.1.{n}" for n in range(100, 200)]
    resp = await _post(concurrent_client, peer_a, [_ev(i) for i in ips])
    assert resp.status_code == 200, resp.text
    assert len(await _a_records(db_session, zone_id)) == len(ips)
    after, targets = await _chunk_serials(db_session, zone_id)
    # 30 names, then the other 70 in one chunk: two chunks, two bumps.
    assert len(targets) == 2, targets
    assert after == targets[-1]
    assert after - before <= 2, (before, after)


@pytest.mark.asyncio
async def test_a_chunk_that_runs_out_of_hold_leaves_the_rest_for_the_next(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hold is measured as the chunk runs: with none left after its first
    name each chunk publishes one name and the rest follow, every name once,
    and the zone's serial rises for every chunk that changed it."""
    import app.api.v1.dhcp.agents as agents

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    before, _ = await _chunk_serials(db_session, zone_id)
    monkeypatch.setattr(agents, "_DDNS_HOLD_S", 0.0)
    ips = _A_IPS[:12]
    resp = await _post(concurrent_client, peer_a, [_ev(i) for i in ips])
    assert resp.status_code == 200, resp.text
    records = await _a_records(db_session, zone_id)
    assert sorted(v for _n, v in records) == sorted(ips)
    after, targets = await _chunk_serials(db_session, zone_id)
    assert len(targets) == len(ips), targets  # one chunk per name, each its own serial
    assert targets == sorted(set(targets)) and after == targets[-1] > before
