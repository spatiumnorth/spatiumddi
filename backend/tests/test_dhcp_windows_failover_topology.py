"""#1110 — the topology poll on a group with more than one Windows member.

Two things the poll now does that it did not:

* **Records what it reads** — each server's failover relationships and
  which scopes it holds — so the group and scope views, and the next poll,
  can tell a failover pair from two servers serving a scope on their own.
* **Imports each shared scope from ONE member.** Every member's pass used
  to merge its own view of the group's scope. Failover partners do not sync
  configuration, so two partners routinely disagree about a reservation —
  and then each pass undid the other: the first created the reservation
  (and its IPAM mirror and DNS records), the second absence-deleted it, on
  every poll, forever.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import (
    DHCPFailoverRelationship,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPServerScopeState,
    DHCPStaticAssignment,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp import pull_leases as pl
from app.services.dhcp.windows_failover import (
    OBSERVATION_FRESH_FOR,
    record_failover_observation,
    record_scope_observation,
)

CIDR = "10.50.0.0/24"
SID = "10.50.0.0"
MAC_A = "aa:bb:cc:00:50:01"
MAC_B = "aa:bb:cc:00:50:02"


def wire_scope(statics: list[tuple[str, str]], **kw: Any) -> dict[str, Any]:
    out = {
        "scope_id": SID,
        "subnet_cidr": CIDR,
        "name": "office",
        "description": "",
        "lease_time": 86400,
        "is_active": True,
        "options": {},
        "pools": [{"start_ip": "10.50.0.100", "end_ip": "10.50.0.200", "pool_type": "dynamic"}],
        "statics": [
            {"ip_address": ip, "mac_address": mac, "hostname": "h", "client_id": None}
            for mac, ip in statics
        ],
        "pools_ok": True,
        "statics_ok": True,
    }
    out.update(kw)
    return out


def rel(partner: str) -> dict[str, Any]:
    return {
        "name": "dhcp1-dhcp2",
        "partner_server": partner,
        "mode": "LoadBalance",
        "server_role": None,
        "state": "Normal",
        "load_balance_percent": 50,
        "reserve_percent": None,
        "max_client_lead_time_seconds": 3600,
        "state_switch_interval_seconds": None,
        "auto_state_transition": False,
        "enable_auth": False,
        "scope_ids": [SID],
    }


@dataclass
class _Server:
    scopes: list[dict[str, Any]] = field(default_factory=list)
    failover: dict[str, Any] | Exception = field(
        default_factory=lambda: {"ok": True, "error": None, "relationships": []}
    )
    scopes_error: Exception | None = None
    failover_calls: int = 0


class _Driver:
    def __init__(self, by_name: dict[str, _Server]) -> None:
        self.by_name = by_name

    async def get_scopes(self, server: DHCPServer) -> list[dict[str, Any]]:
        st = self.by_name[server.name]
        if st.scopes_error:
            raise st.scopes_error
        return st.scopes

    async def get_failover_relationships(self, server: DHCPServer) -> dict[str, Any]:
        st = self.by_name[server.name]
        st.failover_calls += 1
        if isinstance(st.failover, Exception):
            raise st.failover
        return st.failover

    async def get_leases(self, server: DHCPServer) -> list[dict[str, Any]]:
        return []


@dataclass
class _DNSSpy:
    calls: list[str] = field(default_factory=list)


def _install(monkeypatch: pytest.MonkeyPatch, by_name: dict[str, _Server]) -> _DNSSpy:
    monkeypatch.setattr(pl, "get_driver", lambda _d: _Driver(by_name))
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)
    spy = _DNSSpy()
    import app.api.v1.ipam.router as ipam_router

    async def _sync(_db: Any, row: Any, _subnet: Any, action: str = "create", **_kw: Any) -> None:
        spy.calls.append(f"{action}:{row.address}")

    monkeypatch.setattr(ipam_router, "_sync_dns_record", _sync)
    return spy


async def _setup(
    db: AsyncSession, names: tuple[str, ...] = ("dhcp1", "dhcp2")
) -> tuple[DHCPServerGroup, list[DHCPServer], DHCPScope]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.50.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="office")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([subnet, group])
    await db.flush()
    servers = [
        DHCPServer(
            name=n,
            driver="windows_dhcp",
            host=f"{n}.corp.example",
            port=67,
            server_group_id=group.id,
        )
        for n in names
    ]
    db.add_all(servers)
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, is_active=True, name="office")
    db.add(scope)
    await db.flush()
    return group, servers, scope


async def _reservations(db: AsyncSession, scope: DHCPScope) -> set[str]:
    rows = (
        (
            await db.execute(
                select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
            )
        )
        .scalars()
        .all()
    )
    return {str(r.mac_address) for r in rows}


# ── the flip-flop ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_drifted_partners_do_not_undo_each_other(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dhcp1 has reservation A, dhcp2 has reservation B (an unreplicated
    console edit on each). Polling both, in one run, twice, must converge on
    ONE view with no create/delete churn — and say the partners drifted."""
    (s1, s2), scope = (await _setup(db_session))[1:]
    by_name = {
        "dhcp1": _Server(
            scopes=[wire_scope([(MAC_A, "10.50.0.10")])],
            failover={"ok": True, "error": None, "relationships": [rel("dhcp2")]},
        ),
        "dhcp2": _Server(
            scopes=[wire_scope([(MAC_B, "10.50.0.11")])],
            failover={"ok": True, "error": None, "relationships": [rel("dhcp1")]},
        ),
    }
    spy = _install(monkeypatch, by_name)

    # Run 1 — the scheduled task polls every server in one transaction.
    r1 = await pl.pull_leases_from_server(db_session, s1)
    r2 = await pl.pull_leases_from_server(db_session, s2)
    await db_session.commit()
    first = await _reservations(db_session, scope)

    # dhcp1 imports (lowest name); dhcp2 defers and does not absence-delete.
    assert first == {MAC_A}
    assert r1.scopes_deferred == 0
    assert r2.scopes_deferred == 1
    assert r2.statics_removed == 0

    # Run 2 — steady state: nothing moves, no DNS churn.
    spy.calls.clear()
    r1b = await pl.pull_leases_from_server(db_session, s1)
    r2b = await pl.pull_leases_from_server(db_session, s2)
    await db_session.commit()
    assert await _reservations(db_session, scope) == {MAC_A}
    assert spy.calls == [], f"steady state must not touch DNS, got {spy.calls}"
    assert r1b.statics_synced == r1b.statics_removed == 0
    assert r2b.statics_synced == r2b.statics_removed == 0

    # And the drift is reported, once, by the owner's pass.
    assert any("differs" in w for w in r1b.warnings), r1b.warnings
    assert not r2b.warnings


@pytest.mark.asyncio
async def test_an_unreachable_owner_hands_the_scope_to_the_partner(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An owner whose view has gone stale must not freeze the import."""
    (s1, s2), scope = (await _setup(db_session))[1:]
    by_name = {
        "dhcp1": _Server(scopes=[wire_scope([(MAC_A, "10.50.0.10")])]),
        "dhcp2": _Server(scopes=[wire_scope([(MAC_B, "10.50.0.11")])]),
    }
    _install(monkeypatch, by_name)
    await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()
    # dhcp1's last good read ages out of the freshness window.
    s1.scopes_observed_at = datetime.now(UTC) - OBSERVATION_FRESH_FOR - timedelta(minutes=1)
    await db_session.commit()

    r2 = await pl.pull_leases_from_server(db_session, s2)
    await db_session.commit()
    assert r2.scopes_deferred == 0
    assert await _reservations(db_session, scope) == {MAC_B}


@pytest.mark.asyncio
async def test_single_member_group_reconciles_exactly_as_before(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    (s1,), scope = (await _setup(db_session, ("dhcp1",)))[1:]
    _install(monkeypatch, {"dhcp1": _Server(scopes=[wire_scope([(MAC_A, "10.50.0.10")])])})
    result = await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()
    assert result.scopes_deferred == 0
    assert await _reservations(db_session, scope) == {MAC_A}


@pytest.mark.asyncio
async def test_uncoordinated_shared_scope_is_reported(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    s1, s2 = (await _setup(db_session))[1]
    same = wire_scope([(MAC_A, "10.50.0.10")])
    _install(monkeypatch, {"dhcp1": _Server(scopes=[same]), "dhcp2": _Server(scopes=[same])})
    await pl.pull_leases_from_server(db_session, s2)  # dhcp2 first: records its view
    r1 = await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()
    assert any("same address" in w for w in r1.warnings), r1.warnings


# ── what gets recorded ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_poll_records_relationships_and_scope_presence(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    (s1,) = (await _setup(db_session, ("dhcp1",)))[1]
    st = _Server(
        scopes=[wire_scope([(MAC_A, "10.50.0.10")])],
        failover={"ok": True, "error": None, "relationships": [rel("dhcp9.elsewhere")]},
    )
    _install(monkeypatch, {"dhcp1": st})
    await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()

    rels = (await db_session.execute(select(DHCPFailoverRelationship))).scalars().all()
    assert [(r.name, r.partner_server, r.scope_ids) for r in rels] == [
        ("dhcp1-dhcp2", "dhcp9.elsewhere", [SID])
    ]
    state = (await db_session.execute(select(DHCPServerScopeState))).scalar_one()
    assert str(state.scope_cidr) == CIDR
    assert state.is_active is True
    assert str(state.start_ip) == "10.50.0.100"
    assert s1.failover_observed_at is not None
    assert s1.scopes_observed_at is not None
    assert s1.failover_error is None


@pytest.mark.asyncio
async def test_a_denied_failover_read_keeps_the_last_relationships(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """'The read was denied' must not become 'there is no failover'."""
    (s1,) = (await _setup(db_session, ("dhcp1",)))[1]
    st = _Server(
        scopes=[wire_scope([])],
        failover={"ok": True, "error": None, "relationships": [rel("dhcp2")]},
    )
    _install(monkeypatch, {"dhcp1": st})
    await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()
    first_seen = s1.failover_observed_at

    st.failover = {"ok": False, "error": "Access is denied.", "relationships": []}
    result = await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()

    rels = (await db_session.execute(select(DHCPFailoverRelationship))).scalars().all()
    assert [r.name for r in rels] == ["dhcp1-dhcp2"]
    assert s1.failover_error == "Access is denied."
    assert s1.failover_observed_at == first_seen
    assert any("Access is denied." in w for w in result.warnings)
    assert not result.errors, "a denied failover read is a standing condition, not a poll failure"


@pytest.mark.asyncio
async def test_a_failover_read_that_raises_is_recorded_not_fatal(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    (s1,), scope = (await _setup(db_session, ("dhcp1",)))[1:]
    st = _Server(scopes=[wire_scope([(MAC_A, "10.50.0.10")])], failover=RuntimeError("boom"))
    _install(monkeypatch, {"dhcp1": st})
    await pl.pull_leases_from_server(db_session, s1)
    await db_session.commit()
    assert s1.failover_error == "boom"
    assert await _reservations(db_session, scope) == {MAC_A}


@pytest.mark.asyncio
async def test_failover_read_is_skipped_when_the_scope_read_failed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server is almost certainly unreachable; a third WinRM call would
    only add another full timeout to the poll."""
    (s1,) = (await _setup(db_session, ("dhcp1",)))[1]
    st = _Server(scopes_error=RuntimeError("WinRM down"))
    _install(monkeypatch, {"dhcp1": st})
    await pl.pull_leases_from_server(db_session, s1)
    assert st.failover_calls == 0
    assert s1.scopes_observed_at is None


@pytest.mark.asyncio
async def test_an_empty_scope_read_records_nothing(db_session: AsyncSession) -> None:
    """Empty is indistinguishable from a quiet enumeration failure (#482):
    let the view go stale instead of claiming the server holds nothing."""
    (s1,) = (await _setup(db_session, ("dhcp1",)))[1]
    db_session.add(DHCPServerScopeState(server_id=s1.id, scope_cidr=CIDR, is_active=True))
    await db_session.flush()
    await record_scope_observation(db_session, s1, [], now=datetime.now(UTC))
    await db_session.flush()
    assert s1.scopes_observed_at is None
    assert len((await db_session.execute(select(DHCPServerScopeState))).scalars().all()) == 1


@pytest.mark.asyncio
async def test_scope_observation_writes_only_what_changed(db_session: AsyncSession) -> None:
    (s1,) = (await _setup(db_session, ("dhcp1",)))[1]
    now = datetime.now(UTC)
    other = wire_scope([], subnet_cidr="10.50.1.0/24", scope_id="10.50.1.0")
    await record_scope_observation(db_session, s1, [wire_scope([]), other], now=now)
    await db_session.commit()
    rows = {
        str(r.scope_cidr): r
        for r in (await db_session.execute(select(DHCPServerScopeState))).scalars().all()
    }
    assert set(rows) == {CIDR, "10.50.1.0/24"}
    stamp = rows[CIDR].modified_at

    # Same content → the row is not rewritten; a vanished scope is removed.
    await record_scope_observation(db_session, s1, [wire_scope([])], now=now)
    await db_session.commit()
    after = (await db_session.execute(select(DHCPServerScopeState))).scalars().all()
    assert [str(r.scope_cidr) for r in after] == [CIDR]
    assert after[0].modified_at == stamp


@pytest.mark.asyncio
async def test_failover_observation_updates_in_place_and_drops_the_gone(
    db_session: AsyncSession,
) -> None:
    (s1,) = (await _setup(db_session, ("dhcp1",)))[1]
    now = datetime.now(UTC)
    two = [rel("dhcp2"), {**rel("dhcp3"), "name": "other"}]
    await record_failover_observation(
        db_session, s1, {"ok": True, "error": None, "relationships": two}, now=now
    )
    await db_session.commit()
    keep_id = (
        await db_session.execute(
            select(DHCPFailoverRelationship.id).where(
                DHCPFailoverRelationship.name == "dhcp1-dhcp2"
            )
        )
    ).scalar_one()

    changed = {**rel("dhcp2"), "state": "CommunicationInterrupted"}
    await record_failover_observation(
        db_session, s1, {"ok": True, "error": None, "relationships": [changed]}, now=now
    )
    await db_session.commit()
    rows = (await db_session.execute(select(DHCPFailoverRelationship))).scalars().all()
    assert [(r.id, r.name, r.state) for r in rows] == [
        (keep_id, "dhcp1-dhcp2", "CommunicationInterrupted")
    ]
