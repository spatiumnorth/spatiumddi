"""Kea HA members' batches of the same leases stop queuing on the address rows (#3789).

Under Kea HA both members report every lease. Each lease-events batch locked
all its addresses' ``ip_address`` rows ``FOR UPDATE`` and held them to its
commit, so the second member's batch of the same renewals waited out the first
member's whole batch: at 10 renewals a second ddi-pg measured 15 to 16 s per
batch, 39 to 53% of it waiting on the other member's rows. On a first
acquisition the second batch's INSERT of a mirror waited on the first's
uncommitted insert of the same row until the 30 s command timeout.

A renewal whose mirror row already carries what it would write, and whose
DDNS writes nothing, now takes its row ``SKIP LOCKED`` and leaves a held one
to its holder; a new mirror row another batch is inserting is left to that
batch. Each test holds peer A's batch open before its commit and times peer
B's batch of the same addresses; before the fix B waited for A's commit.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents
from app.models.dhcp import DHCPLease, DHCPServer
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress
from tests.test_lease_events_ha_renewal_3773 import _ev, _post
from tests.test_lease_events_insert_order_3480 import _ddns_subnet, _two_agents
from tests.test_lease_events_trashed_scope_3733 import (
    concurrent_client,  # noqa: F401 — the fixture, shared
)

# Twenty leases, so a batch that waits for the other member's rows waits for
# all of them, and the pass threshold below is far from both outcomes.
_IPS = [f"10.31.1.{n}" for n in range(30, 50)]
#: How long peer A's batch is held open before its commit.
_HOLD_S = 8.0
#: Peer B must answer within this while A is held (it took _HOLD_S before).
_MAX_B_S = 3.0


@asynccontextmanager
async def _held_open(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[asyncio.Event]:
    """Hold the first batch to reach its recount (just before its commit)
    for ``_HOLD_S``, or until the test lets it go. Yields the event set once
    the batch is held."""
    real = agents.recount_subnets_and_blocks
    held, release = asyncio.Event(), asyncio.Event()

    async def _hold_first(*args: Any, **kwargs: Any) -> Any:
        if not held.is_set():
            held.set()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(release.wait(), timeout=_HOLD_S)
        return await real(*args, **kwargs)

    monkeypatch.setattr(agents, "recount_subnets_and_blocks", _hold_first)
    try:
        yield held
    finally:
        release.set()


async def _b_while_a_held(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    peer_a: DHCPServer,
    peer_b: DHCPServer,
    events: list[dict[str, Any]],
) -> tuple[Response, Response, float]:
    """Post A's batch, hold it open, post B's batch of the same events, and
    return both responses and how long B took."""
    async with _held_open(monkeypatch) as held:
        batch_a = asyncio.create_task(_post(client, peer_a, events))
        await asyncio.wait_for(held.wait(), timeout=30)
        started = time.monotonic()
        resp_b = await asyncio.wait_for(_post(client, peer_b, events), timeout=_HOLD_S + 20)
        elapsed = time.monotonic() - started
    resp_a = await asyncio.wait_for(batch_a, timeout=30)
    return resp_a, resp_b, elapsed


async def _mirrors(db: AsyncSession) -> dict[str, IPAddress]:
    rows = (
        (
            await db.execute(
                select(IPAddress)
                .where(IPAddress.address.in_(_IPS))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return {str(r.address): r for r in rows}


async def _a_records(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.value).where(
                DNSRecord.zone_id == zone_id,
                DNSRecord.record_type == "A",
                DNSRecord.deleted_at.is_(None),
            )
        )
    ).all()
    return sorted((n, v) for n, v in rows)


@pytest.mark.asyncio
async def test_a_peers_unchanged_renewals_do_not_wait_for_the_other_members_batch(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    first = await _post(concurrent_client, peer_a, [_ev(ip) for ip in _IPS])
    assert first.status_code == 200, first.text
    zone_id = uuid.UUID(str(subnet.dns_zone_id))
    published = await _a_records(db_session, zone_id)
    assert len(published) == len(_IPS), published

    resp_a, resp_b, elapsed = await _b_while_a_held(
        concurrent_client, monkeypatch, peer_a, peer_b, [_ev(ip) for ip in _IPS]
    )
    assert resp_b.status_code == 200, resp_b.text
    assert resp_a.status_code == 200, resp_a.text
    assert resp_b.json()["upserted"] == len(_IPS)
    assert elapsed < _MAX_B_S, f"peer B waited {elapsed:.1f} s for peer A's address rows"

    # Nothing changed but A's sighting stamp: one row each, same names, same
    # records, and B's own leases recorded.
    mirrors = await _mirrors(db_session)
    assert sorted(mirrors) == sorted(_IPS)
    assert all(m.status == "dhcp" and m.auto_from_lease for m in mirrors.values())
    assert await _a_records(db_session, zone_id) == published
    b_leases = (
        await db_session.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == peer_b.id)
        )
    ).scalar_one()
    assert b_leases == len(_IPS)


@pytest.mark.asyncio
async def test_a_peers_first_acquisition_does_not_wait_on_the_other_members_inserts(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both members report the same NEW leases. B's batch must not wait on A's
    uncommitted mirror inserts, and the pair still ends with one mirror and
    one published record per address."""
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    zone_id = uuid.UUID(str(subnet.dns_zone_id))

    resp_a, resp_b, elapsed = await _b_while_a_held(
        concurrent_client, monkeypatch, peer_a, peer_b, [_ev(ip) for ip in _IPS]
    )
    assert resp_b.status_code == 200, resp_b.text
    assert resp_a.status_code == 200, resp_a.text
    assert elapsed < _MAX_B_S, f"peer B waited {elapsed:.1f} s on peer A's inserts"

    mirrors = await _mirrors(db_session)
    assert sorted(mirrors) == sorted(_IPS)
    assert all(m.status == "dhcp" and m.auto_from_lease for m in mirrors.values())
    assert len(await _a_records(db_session, zone_id)) == len(_IPS)
    b_leases = (
        await db_session.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == peer_b.id)
        )
    ).scalar_one()
    assert b_leases == len(_IPS)


@pytest.mark.asyncio
async def test_a_renewal_nobody_holds_still_stamps_the_sighting(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """The skip is for a row someone else is writing. An uncontended renewal
    takes its row and stamps it as before (#1141's ``last_seen_at``)."""
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, _peer_b = await _two_agents(db_session, [subnet])
    first = await _post(concurrent_client, peer_a, [_ev(_IPS[0])])
    assert first.status_code == 200, first.text
    old = datetime.now(UTC) - timedelta(days=3)
    row = (await _mirrors(db_session))[_IPS[0]]
    row.last_seen_at = old
    await db_session.commit()

    again = await _post(concurrent_client, peer_a, [_ev(_IPS[0])])
    assert again.status_code == 200, again.text
    row = (await _mirrors(db_session))[_IPS[0]]
    assert row.last_seen_at is not None and row.last_seen_at > old + timedelta(days=2)


@pytest.mark.asyncio
async def test_a_renewal_that_changes_the_row_still_waits_and_applies(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only an unchanged renewal is left to the holder: B's rename of a row A
    holds waits for A and is applied after it."""
    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    first = await _post(concurrent_client, peer_a, [_ev(ip) for ip in _IPS[:2]])
    assert first.status_code == 200, first.text

    async with _held_open(monkeypatch) as held:
        batch_a = asyncio.create_task(
            _post(concurrent_client, peer_a, [_ev(ip) for ip in _IPS[:2]])
        )
        await asyncio.wait_for(held.wait(), timeout=30)
        batch_b = asyncio.create_task(
            _post(concurrent_client, peer_b, [_ev(_IPS[0], "moved"), _ev(_IPS[1])])
        )
        await asyncio.sleep(1.0)
        assert not batch_b.done(), "B's rename did not wait for A's row"
    resp_a = await asyncio.wait_for(batch_a, timeout=30)
    resp_b = await asyncio.wait_for(batch_b, timeout=30)
    assert resp_a.status_code == 200, resp_a.text
    assert resp_b.status_code == 200, resp_b.text
    assert (await _mirrors(db_session))[_IPS[0]].hostname == "moved"
