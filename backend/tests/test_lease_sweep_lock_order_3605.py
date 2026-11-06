"""#3605: the lease expiry sweep locks in the lease-events order.

The sweep used to interleave, per expired lease, the DDNS revoke (which bumps
the zone's serial row and holds it to commit) with that lease's IPAM mirror
delete. A lease-events batch holds the mirror rows first (``FOR UPDATE``, #2580)
and then wants the zone rows for its own DDNS publish. The sweep held a zone
and waited for a mirror row, the batch held the mirror row and waited for the
zone: Postgres broke the cycle with 40P01 and one side failed (#3601 fixed the
batch's own order; this is the sweep's half).

Forced rather than hoped for: the lease-events batch is held at its first DDNS
publish (after it holds every mirror row) until the sweep has revoked its first
address's DDNS. The hold times out when the sweep is parked on the mirror lock,
which is what the fixed sweep does before any DDNS work.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease
from tests.test_lease_events_insert_order_3480 import (  # noqa: F401
    _ddns_subnet,
    _lease,
    _two_agents,
    concurrent_client,
)

_HOLD_S = 3.0


@pytest.mark.asyncio
async def test_sweep_and_lease_events_on_the_same_addresses_do_not_deadlock(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.dns import ddns
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    ips = ["10.31.1.10", "10.31.1.20"]

    async def _post(server: Any, events: list[dict[str, Any]]) -> Any:
        return await concurrent_client.post(
            "/api/v1/dhcp/agents/lease-events",
            headers={"x-test-server": str(server.id)},
            json={"leases": events},
        )

    # A's leases create the mirrors and their DDNS records; then they lapse.
    first = await _post(peer_a, [_lease(ip, n) for n, ip in enumerate(ips)])
    assert first.status_code == 200, first.text
    await db_session.execute(
        update(DHCPLease)
        .where(DHCPLease.server_id == peer_a.id)
        .values(expires_at=datetime.now(UTC) - timedelta(hours=1))
    )
    await db_session.commit()

    batch_locked = asyncio.Event()
    revoked = asyncio.Event()
    log: list[str] = []
    real_apply, real_revoke = ddns.apply_ddns_for_lease, ddns.revoke_ddns_for_lease

    async def _apply(db: AsyncSession, **kw: Any) -> Any:
        if not batch_locked.is_set():
            batch_locked.set()  # every mirror row of the batch is locked by now
            try:
                await asyncio.wait_for(revoked.wait(), timeout=_HOLD_S)
                log.append("batch: met the sweep's revoke")
            except TimeoutError:
                log.append("batch: went on alone")
        return await real_apply(db, **kw)

    async def _revoke(db: AsyncSession, **kw: Any) -> Any:
        result = await real_revoke(db, **kw)
        revoked.set()
        return result

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _apply)
    monkeypatch.setattr(ddns, "revoke_ddns_for_lease", _revoke)

    renamed = [{**_lease(ip, n), "hostname": f"renamed-{n}"} for n, ip in enumerate(ips)]
    batch = asyncio.create_task(_post(peer_b, renamed))
    await asyncio.wait_for(batch_locked.wait(), timeout=30)
    results = await asyncio.wait_for(
        asyncio.gather(_sweep(), batch, return_exceptions=True), timeout=60
    )
    assert not any(isinstance(r, BaseException) for r in results), f"{results!r}; {log}"
    assert results[1].status_code == 200, f"{results[1].text}; {log}"

    # The sweep expired A's leases; B's batch is committed and active.
    states = (
        await db_session.execute(
            select(DHCPLease.server_id, DHCPLease.state).execution_options(populate_existing=True)
        )
    ).all()
    assert {(s, st) for s, st in states if s == peer_a.id} == {(peer_a.id, "expired")}
    assert {st for s, st in states if s == peer_b.id} == {"active"}
    # The sweep is idempotent: a second run finds nothing to do.
    assert await _sweep() == (0, 0)
