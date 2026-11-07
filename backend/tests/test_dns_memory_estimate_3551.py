"""A BIND9 group's named memory is estimated and warned about (#3551).

Under split-horizon each view that applies a blocklist loads its own copy of
it (BIND refuses a response-policy zone defined by ``in-view``), so adding a
view to a group subscribed to a large list can push named over the agents'
memory limit and OOM-loop the whole group. The estimate compares what named
will hold against the limit the agents report, and warns at 80 %.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSView,
    DNSZone,
    dns_blocklist_group_assoc,
    dns_blocklist_view_assoc,
)
from app.services.alerts import _matching_dns_memory_pressure_subjects
from app.services.dns.memory_estimate import (
    BASELINE_BYTES,
    BYTES_PER_RECORD,
    BYTES_PER_RPZ_ENTRY,
    DEFAULT_LIMIT_BYTES,
    MIB,
    RpzLoad,
    assess,
    estimate_bytes,
    group_memory_estimate,
    zone_copies,
)

# ── the pure estimator ──────────────────────────────────────────────────────


def test_an_rpz_costs_once_per_view_that_loads_it() -> None:
    one = RpzLoad("spatium-blocklist.rpz.", ("default",), 1000)
    two = RpzLoad("spatium-blocklist.rpz.", ("restricted", "default"), 1000)
    flat = RpzLoad("spatium-blocklist.rpz.", (), 1000)
    assert one.bytes == flat.bytes == 1000 * BYTES_PER_RPZ_ENTRY
    assert two.bytes == 2 * one.bytes
    assert estimate_bytes(0, []) == BASELINE_BYTES
    assert estimate_bytes(10, [two]) == BASELINE_BYTES + 10 * BYTES_PER_RECORD + two.bytes


def test_the_reported_group_warns_with_two_views_and_not_with_one() -> None:
    """The reported install: one ~187,500-entry list, 1 GiB agent limit. One
    view fits; adding the second loads the list twice and OOM-looped it."""
    limit = 1024 * MIB
    entries = 187_544
    one = assess(estimate_bytes(0, [RpzLoad("r.", ("default",), entries)]), limit)
    two = assess(estimate_bytes(0, [RpzLoad("r.", ("restricted", "default"), entries)]), limit)
    assert not one.warn
    assert two.warn
    assert two.limit_source == "agent"


def test_the_threshold_is_eighty_percent_of_the_limit() -> None:
    limit = 1000 * MIB
    assert not assess(int(0.8 * limit) - 1, limit).warn
    assert assess(int(0.8 * limit), limit).warn
    assert assess(int(0.8 * limit), limit).percent == 80.0


def test_without_a_reported_limit_the_documented_default_is_assumed() -> None:
    a = assess(BASELINE_BYTES, None)
    assert a.limit_bytes == DEFAULT_LIMIT_BYTES
    assert a.limit_source == "default"


def test_identical_view_copies_count_once() -> None:
    # restricted and default render the same copy; lab its own.
    copies = zone_copies([("lab", "k1", 30), ("restricted", "k0", 10), ("default", "k0", 10)])
    assert copies == [(("lab",), 30), (("restricted", "default"), 10)]


# ── gathered from the database ──────────────────────────────────────────────


async def _group(
    db: AsyncSession, views: list[str], limits: list[int | None], driver: str = "bind9"
) -> tuple[DNSServerGroup, list[DNSView]]:
    group = DNSServerGroup(name=f"mem-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    for i, lim in enumerate(limits):
        db.add(
            DNSServer(
                group_id=group.id,
                name=f"ns{i}-{uuid.uuid4().hex[:4]}",
                driver=driver,
                host=f"192.0.2.{10 + i}",
                port=53,
                memory_limit_bytes=lim,
            )
        )
    vs = []
    for i, name in enumerate(views):
        v = DNSView(group_id=group.id, name=name, order=i, match_clients=["any"])
        db.add(v)
        vs.append(v)
    await db.flush()
    return group, vs


async def _list(db: AsyncSession, domains: list[str]) -> DNSBlockList:
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:8]}")
    db.add(bl)
    await db.flush()
    if domains:
        await db.execute(
            insert(DNSBlockListEntry),
            [
                {"list_id": bl.id, "domain": d, "entry_type": "block", "source": "manual"}
                for d in domains
            ],
        )
    return bl


async def _on_group(db: AsyncSession, bl: DNSBlockList, group: DNSServerGroup) -> None:
    await db.execute(
        insert(dns_blocklist_group_assoc).values(blocklist_id=bl.id, group_id=group.id)
    )


async def _on_view(db: AsyncSession, bl: DNSBlockList, view: DNSView) -> None:
    await db.execute(insert(dns_blocklist_view_assoc).values(blocklist_id=bl.id, view_id=view.id))


def _domains(n: int, prefix: str = "d") -> list[str]:
    return [f"{prefix}{i}.example.net" for i in range(n)]


@pytest.mark.asyncio
async def test_a_group_list_is_loaded_once_per_view(
    db_session: AsyncSession,
) -> None:
    """The reported shape: one group-level list, two views. The bundle folds
    the group's lists into each view's own zone, so named loads it twice."""
    group, _views = await _group(db_session, ["restricted", "default"], [1024 * MIB])
    bl = await _list(db_session, _domains(50))
    await _on_group(db_session, bl, group)
    await db_session.flush()

    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    assert [(r.zone, r.views, r.entries) for r in est.rpz] == [
        ("spatium-blocklist-restricted.rpz.", ("restricted",), 50),
        ("spatium-blocklist-default.rpz.", ("default",), 50),
    ]
    assert est.rpz_bytes == 2 * 50 * BYTES_PER_RPZ_ENTRY


@pytest.mark.asyncio
async def test_without_views_the_group_list_loads_once(db_session: AsyncSession) -> None:
    group, _ = await _group(db_session, [], [None])
    bl = await _list(db_session, _domains(50))
    await _on_group(db_session, bl, group)
    await db_session.flush()
    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    assert [(r.zone, r.views, r.entries) for r in est.rpz] == [("spatium-blocklist.rpz.", (), 50)]


@pytest.mark.asyncio
async def test_entries_are_counted_after_dedup_and_exceptions(db_session: AsyncSession) -> None:
    """Each owner name once across the lists a zone draws on (#878), and an
    exception the lists do not carry is a passthru owner of its own."""
    group, _ = await _group(db_session, [], [None])
    a = await _list(db_session, ["dup.example.net", "a.example.net"])
    b = await _list(db_session, ["DUP.example.net", "b.example.net"])
    db_session.add(DNSBlockListException(list_id=b.id, domain="allowed.example.net"))
    db_session.add(DNSBlockListException(list_id=b.id, domain="a.example.net"))
    await _on_group(db_session, a, group)
    await _on_group(db_session, b, group)
    await db_session.flush()

    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    # dup, a, b + allowed (a's exception replaces its entry, same owner).
    assert [(r.views, r.entries) for r in est.rpz] == [((), 4)]


@pytest.mark.asyncio
async def test_entries_shared_by_two_lists_count_once_without_exceptions(
    db_session: AsyncSession,
) -> None:
    """The dedup holds with no exception in play: overlapping feeds (the
    Family filter's Hagezi lists share domains) load each owner once."""
    group, _ = await _group(db_session, [], [None])
    a = await _list(db_session, _domains(30))
    b = await _list(db_session, [d.upper() for d in _domains(20)] + _domains(5, "x"))
    await _on_group(db_session, a, group)
    await _on_group(db_session, b, group)
    await db_session.flush()

    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    assert [(r.views, r.entries) for r in est.rpz] == [((), 35)]


@pytest.mark.asyncio
async def test_a_views_own_list_is_folded_into_that_views_zone_only(
    db_session: AsyncSession,
) -> None:
    group, (restricted, _default) = await _group(db_session, ["restricted", "default"], [None])
    g = await _list(db_session, _domains(10, "g"))
    own = await _list(db_session, _domains(5, "o"))
    await _on_group(db_session, g, group)
    await _on_view(db_session, own, restricted)
    await db_session.flush()

    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    loads = {r.zone: (r.views, r.entries) for r in est.rpz}
    # Each view's zone folds the group's lists in (#1706).
    assert loads == {
        "spatium-blocklist-restricted.rpz.": (("restricted",), 15),
        "spatium-blocklist-default.rpz.": (("default",), 10),
    }


@pytest.mark.asyncio
async def test_shared_zones_count_once_and_view_scoped_ones_per_copy(
    db_session: AsyncSession,
) -> None:
    group, (restricted, default) = await _group(db_session, ["restricted", "default"], [None])
    shared = DNSZone(
        group_id=group.id,
        name="example.com.",
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
    )
    split = DNSZone(
        group_id=group.id,
        name="split.example.com.",
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
    )
    db_session.add_all([shared, split])
    await db_session.flush()
    for i in range(4):
        db_session.add(
            DNSRecord(zone_id=shared.id, name=f"h{i}", record_type="A", value=f"192.0.2.{i}")
        )
    db_session.add(DNSRecord(zone_id=split.id, name="www", record_type="A", value="192.0.2.50"))
    db_session.add(
        DNSRecord(
            zone_id=split.id, name="app", record_type="A", value="192.0.2.60", view_id=restricted.id
        )
    )
    db_session.add(
        DNSRecord(
            zone_id=split.id, name="app", record_type="A", value="198.51.100.60", view_id=default.id
        )
    )
    await db_session.flush()

    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    # example.com once (4), split.example.com per view (1 + 1 each).
    assert est.zone_records_loaded == 4 + 2 + 2


@pytest.mark.asyncio
async def test_a_dynamic_zone_counts_once_per_view(db_session: AsyncSession) -> None:
    group, _views = await _group(db_session, ["restricted", "default"], [None])
    zone = DNSZone(
        group_id=group.id,
        name="dyn.example.com.",
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        dynamic_update_enabled=True,
    )
    db_session.add(zone)
    await db_session.flush()
    for i in range(3):
        db_session.add(
            DNSRecord(zone_id=zone.id, name=f"h{i}", record_type="A", value=f"192.0.2.{i}")
        )
    await db_session.flush()

    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    assert est.zone_records_loaded == 3 * 2


@pytest.mark.asyncio
async def test_the_smallest_reported_limit_is_used(db_session: AsyncSession) -> None:
    group, _ = await _group(db_session, [], [2048 * MIB, 1024 * MIB, None])
    est = await group_memory_estimate(db_session, group.id)
    assert est is not None
    assert est.assessment.limit_bytes == 1024 * MIB
    assert est.assessment.limit_source == "agent"
    assert len(est.unknown_limit_servers) == 1


@pytest.mark.asyncio
async def test_a_group_with_no_bind9_server_has_no_estimate(db_session: AsyncSession) -> None:
    group, _ = await _group(db_session, ["default"], [None], driver="powerdns")
    assert await group_memory_estimate(db_session, group.id) is None


async def _warning_group(db: AsyncSession, views: list[str]) -> DNSServerGroup:
    """20,000 entries on the group, 550 MiB limit: one view is ~78 %, two ~83 %."""
    group, _ = await _group(db, views, [550 * MIB])
    bl = await _list(db, _domains(20_000))
    await _on_group(db, bl, group)
    await db.commit()
    return group


@pytest.mark.asyncio
async def test_a_second_view_crosses_the_threshold(db_session: AsyncSession) -> None:
    one = await _warning_group(db_session, ["default"])
    two = await _warning_group(db_session, ["restricted", "default"])
    e1 = await group_memory_estimate(db_session, one.id)
    e2 = await group_memory_estimate(db_session, two.id)
    assert e1 is not None and e2 is not None
    assert not e1.assessment.warn and e1.message is None
    assert e2.assessment.warn
    assert e2.message is not None
    assert "2 views" in e2.message
    assert "restricted 20,000, default 20,000" in e2.message
    assert "fewer views" in e2.message and "memory limit" in e2.message


# ── surfaces ────────────────────────────────────────────────────────────────


async def _reader(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"mem-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="memory estimate",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_group_views_and_blocklists_carry_the_warning(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group = await _warning_group(db_session, ["restricted", "default"])
    headers = await _reader(db_session)

    r = await client.get(f"/api/v1/dns/groups/{group.id}/memory-estimate", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["warn"] is True and body["limit_source"] == "agent"
    assert [r["views"] for r in body["rpz"]] == [["restricted"], ["default"]]

    r = await client.get(f"/api/v1/dns/groups/{group.id}", headers=headers)
    assert r.json()["memory_estimate"]["warn"] is True

    r = await client.get(f"/api/v1/dns/groups/{group.id}/views", headers=headers)
    assert all(v["memory_warning"] for v in r.json())

    r = await client.get("/api/v1/dns/blocklists", headers=headers)
    mine = [b for b in r.json() if str(group.id) in [str(g) for g in b["applied_group_ids"]]]
    assert mine and all(b["memory_warning"] for b in mine)


@pytest.mark.asyncio
async def test_no_warning_below_the_threshold(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group = await _warning_group(db_session, ["default"])
    headers = await _reader(db_session)
    r = await client.get(f"/api/v1/dns/groups/{group.id}/memory-estimate", headers=headers)
    assert r.json()["warn"] is False and r.json()["message"] is None
    r = await client.get(f"/api/v1/dns/groups/{group.id}/views", headers=headers)
    assert all(v["memory_warning"] is None for v in r.json())


@pytest.mark.asyncio
async def test_the_alert_rule_fires_for_the_warning_group_only(db_session: AsyncSession) -> None:
    hot = await _warning_group(db_session, ["restricted", "default"])
    cool = await _warning_group(db_session, ["default"])
    hits = await _matching_dns_memory_pressure_subjects(
        db_session, SimpleNamespace(severity="warning")  # type: ignore[arg-type]
    )
    ids = {h[0] for h in hits}
    assert str(hot.id) in ids
    assert str(cool.id) not in ids
    assert next(h for h in hits if h[0] == str(hot.id))[3] == "warning"


# ── the heartbeat ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_heartbeat_stores_the_limit_and_omission_keeps_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.api.v1.dns.agents import _auth_agent
    from app.main import app

    group, _ = await _group(db_session, [], [None])
    srv = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == group.id))
    ).scalar_one()
    await db_session.commit()
    far = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    app.dependency_overrides[_auth_agent] = lambda: (srv, {"exp": far})

    async def stored() -> int | None:
        return (
            await db_session.execute(
                select(DNSServer.memory_limit_bytes).where(DNSServer.id == srv.id)
            )
        ).scalar_one()

    try:
        r = await client.post("/api/v1/dns/agents/heartbeat", json={"memory_limit_bytes": 1 << 30})
        assert r.status_code == 200, r.text
        assert await stored() == 1 << 30
        r = await client.post("/api/v1/dns/agents/heartbeat", json={})
        assert r.status_code == 200, r.text
        assert await stored() == 1 << 30  # an older agent leaves it alone
        r = await client.post("/api/v1/dns/agents/heartbeat", json={"memory_limit_bytes": None})
        assert r.status_code == 200, r.text
        assert await stored() is None  # no limit any more
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
