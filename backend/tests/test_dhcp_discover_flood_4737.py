"""DHCP DISCOVER-flood alert (#4737): ingest, rule API, evaluator, Trash, MCP.

The agent's opt-in DISCOVER watch posts per-MAC and per-relay DISCOVER counts;
the ``dhcp_discover_flood`` rule names a source whose rate would drain a pool.
What each group below would look like if it broke:

* ingest -- a malformed batch 500s, a replay double-counts, or an old window
  overwrites a newer one;
* rule API -- a nonsense threshold is stored (and the rule then fires on
  everything or nothing), or a non-admin can create a rule;
* evaluator -- a flood goes unnoticed, or one that resolves to a scope in the
  Trash keeps an alert open that nobody can act on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.dhcp import (
    DHCPDiscoverRate,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.alerts import (
    RULE_TYPE_DHCP_DISCOVER_FLOOD,
    _matching_dhcp_discover_flood_subjects,
    evaluate_all,
    seed_dhcp_discover_flood_alert_rule,
)
from tests._signed_in import signed_in_headers
from tests.test_dhcp_pxe_vendor_match_validation import _headers

MAC = "aa:bb:cc:00:11:22"
RELAY = "10.47.0.1"
CIDR = "10.47.0.0/24"


async def _world(db: AsyncSession, *, pool: bool = True):
    """Group + server + a scope for CIDR (with one dynamic pool)."""
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([srv, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="lab")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="lab-scope")
    db.add(scope)
    await db.flush()
    if pool:
        db.add(
            DHCPPool(
                scope_id=scope.id,
                start_ip="10.47.0.10",
                end_ip="10.47.0.99",
                pool_type="dynamic",
            )
        )
    await db.commit()
    return srv.id, scope.id


async def _reading(
    db: AsyncSession,
    server_id,
    *,
    kind: str = "mac",
    subject: str = MAC,
    discovers: int = 120,
    giaddr: str | None = RELAY,
    distinct_macs: int | None = None,
    age: timedelta = timedelta(seconds=20),
    window_seconds: int = 60,
) -> None:
    db.add(
        DHCPDiscoverRate(
            server_id=server_id,
            kind=kind,
            subject=subject,
            giaddr=giaddr,
            discovers=discovers,
            distinct_macs=distinct_macs,
            window_seconds=window_seconds,
            window_end=datetime.now(UTC) - age,
        )
    )
    await db.commit()


def _rule(**kw) -> AlertRule:
    return AlertRule(
        name="flood",
        rule_type=RULE_TYPE_DHCP_DISCOVER_FLOOD,
        severity="warning",
        enabled=True,
        **kw,
    )


async def _post(client: AsyncClient, server: DHCPServer, body: dict):
    from app.api.v1.dhcp.agents import _auth_agent
    from app.main import app

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        return await client.post("/api/v1/dhcp/agents/discover-rates", json=body)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def _live_server(db: AsyncSession) -> DHCPServer:
    sid, _ = await _world(db)
    got = await db.get(DHCPServer, sid)
    assert got is not None
    return got


# ── agent ingest ────────────────────────────────────────────────────────


async def test_ingest_stores_the_latest_reading(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _live_server(db_session)
    sid = srv.id
    body = {
        "window_seconds": 60,
        "clients": [{"mac": "AA-BB-CC-00-11-22", "discovers": 90, "giaddr": RELAY}],
        "relays": [{"giaddr": RELAY, "discovers": 200, "distinct_macs": 150}],
    }
    r = await _post(client, srv, body)
    assert r.status_code == 200, r.text
    assert r.json()["clients"] == 1 and r.json()["relays"] == 1
    rows = (
        (
            await db_session.execute(
                select(DHCPDiscoverRate).where(DHCPDiscoverRate.server_id == sid)
            )
        )
        .scalars()
        .all()
    )
    by_kind = {x.kind: x for x in rows}
    assert by_kind["mac"].subject == MAC  # folded to the canonical form
    assert by_kind["mac"].discovers == 90
    assert by_kind["relay"].distinct_macs == 150


async def test_ingest_is_committed_not_just_flushed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A second connection must see the reading once the 200 is returned.

    The other ingest tests read through the same session the handler used, so
    they pass whether or not the handler commits; the handler once did not,
    and every batch was rolled back when its request session closed.
    """
    from app.db import AsyncSessionLocal

    srv = await _live_server(db_session)
    sid = srv.id
    r = await _post(
        client,
        srv,
        {"window_seconds": 60, "clients": [{"mac": MAC, "discovers": 90, "giaddr": RELAY}]},
    )
    assert r.status_code == 200, r.text
    async with AsyncSessionLocal() as other:
        n = (
            await other.execute(
                select(DHCPDiscoverRate).where(DHCPDiscoverRate.server_id == sid)
            )
        ).scalars().all()
    assert [x.subject for x in n] == [MAC]


async def test_ingest_replaces_rather_than_accumulates_and_ignores_an_older_window(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _live_server(db_session)
    sid = srv.id
    now = datetime.now(UTC)

    def body(n: int, end: datetime) -> dict:
        return {
            "window_end": end.isoformat(),
            "clients": [{"mac": MAC, "discovers": n}],
        }

    assert (await _post(client, srv, body(50, now - timedelta(seconds=30)))).status_code == 200
    assert (await _post(client, srv, body(80, now))).status_code == 200
    # A replayed older window must not win over the newer one.
    assert (await _post(client, srv, body(7, now - timedelta(minutes=3)))).status_code == 200
    row = (
        await db_session.execute(select(DHCPDiscoverRate).where(DHCPDiscoverRate.server_id == sid))
    ).scalar_one()
    await db_session.refresh(row)
    assert row.discovers == 80


async def test_ingest_replayed_batch_is_a_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _live_server(db_session)
    sid = srv.id
    body = {"batch_id": uuid.uuid4().hex, "clients": [{"mac": MAC, "discovers": 40}]}
    assert (await _post(client, srv, body)).json().get("duplicate") in (None, False)
    again = await _post(client, srv, body)
    assert again.status_code == 200
    assert again.json()["duplicate"] is True
    n = len(
        (
            await db_session.execute(
                select(DHCPDiscoverRate).where(DHCPDiscoverRate.server_id == sid)
            )
        )
        .scalars()
        .all()
    )
    assert n == 1


async def test_ingest_rejects_malformed_batches_with_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _live_server(db_session)
    bad = [
        {"window_seconds": 5},
        {"window_seconds": 100000},
        {"clients": [{"mac": MAC, "discovers": 0}]},
        {"clients": [{"mac": MAC, "discovers": 5, "giaddr": "not-an-ip"}]},
        {"clients": [{"mac": "x", "discovers": 5}]},
        {"relays": [{"giaddr": "nope", "discovers": 5, "distinct_macs": 3}]},
        {"clients": [{"mac": MAC, "discovers": 5}] * 501},
    ]
    for body in bad:
        r = await _post(client, srv, body)
        assert r.status_code == 422, (body, r.text)


async def test_ingest_skips_a_mac_that_is_not_a_mac_instead_of_failing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _live_server(db_session)
    r = await _post(client, srv, {"clients": [{"mac": "zzzzzzzzzzzzzz", "discovers": 9}]})
    assert r.status_code == 200, r.text
    assert r.json()["skipped"] == 1 and r.json()["clients"] == 0


async def test_ingest_empty_batch_and_unauthenticated(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An agent with nothing to report, and a caller with no agent token."""
    srv = await _live_server(db_session)
    assert (await _post(client, srv, {})).status_code == 200
    r = await client.post("/api/v1/dhcp/agents/discover-rates", json={})
    assert r.status_code in (401, 403)


# ── rule API ────────────────────────────────────────────────────────────


async def test_rule_type_is_offered_with_both_thresholds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    r = await client.get("/api/v1/alerts/rule-types", headers=h)
    assert r.status_code == 200
    spec = next(s for s in r.json() if s["rule_type"] == RULE_TYPE_DHCP_DISCOVER_FLOOD)
    assert [p["name"] for p in spec["params"]] == ["threshold_percent", "min_free_addresses"]


async def test_rule_create_audited_and_bad_thresholds_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    base = {"name": "my flood", "rule_type": RULE_TYPE_DHCP_DISCOVER_FLOOD}

    for field, value in (("threshold_percent", 0), ("min_free_addresses", 0)):
        r = await client.post("/api/v1/alerts/rules", headers=h, json={**base, field: value})
        assert r.status_code == 422, (field, r.text)
        assert field in r.text

    ok = await client.post(
        "/api/v1/alerts/rules",
        headers=h,
        json={**base, "threshold_percent": 45, "min_free_addresses": 80},
    )
    assert ok.status_code == 201, ok.text
    rid = ok.json()["id"]
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "alert_rule", AuditLog.resource_id == rid
                )
            )
        )
        .scalars()
        .all()
    )
    assert [a.action for a in audit] == ["create"]

    # An out-of-range edit is refused too, and an unknown rule is a 404.
    assert (
        await client.patch(f"/api/v1/alerts/rules/{rid}", headers=h, json={"threshold_percent": 0})
    ).status_code == 422
    assert (
        await client.patch(
            f"/api/v1/alerts/rules/{uuid.uuid4()}", headers=h, json={"threshold_percent": 5}
        )
    ).status_code == 404


async def test_rule_create_refused_for_a_caller_without_the_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await signed_in_headers(db_session)
    r = await client.post(
        "/api/v1/alerts/rules",
        headers=h,
        json={"name": "x", "rule_type": RULE_TYPE_DHCP_DISCOVER_FLOOD},
    )
    assert r.status_code == 403, r.text


async def test_seeded_rule_is_disabled_and_idempotent(db_session: AsyncSession) -> None:
    await db_session.commit()
    await seed_dhcp_discover_flood_alert_rule()
    await seed_dhcp_discover_flood_alert_rule()
    rows = (
        (
            await db_session.execute(
                select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_DHCP_DISCOVER_FLOOD)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].enabled is False
    assert rows[0].threshold_percent == 30


# ── read API + MCP ──────────────────────────────────────────────────────


async def test_discover_sources_api_matches_the_mcp_tool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.auth import User
    from app.services.ai.tools.dhcp import FindDHCPDiscoverSourcesArgs, find_dhcp_discover_sources

    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=120)
    await _reading(db_session, sid, kind="relay", subject=RELAY, discovers=500, distinct_macs=300)
    h = await _headers(db_session)

    r = await client.get(f"/api/v1/dhcp/servers/{sid}/discover-sources", headers=h)
    assert r.status_code == 200, r.text
    sources = r.json()["sources"]
    assert {s["kind"] for s in sources} == {"mac", "relay"}
    mac = next(s for s in sources if s["kind"] == "mac")
    assert mac["per_minute"] == 120.0
    assert mac["subnet"] == CIDR and mac["scope_name"] == "lab-scope"

    only_mac = await client.get(
        f"/api/v1/dhcp/servers/{sid}/discover-sources", headers=h, params={"kind": "mac"}
    )
    assert [s["kind"] for s in only_mac.json()["sources"]] == ["mac"]
    assert (
        await client.get(
            f"/api/v1/dhcp/servers/{sid}/discover-sources", headers=h, params={"kind": "bogus"}
        )
    ).status_code == 422
    assert (
        await client.get(
            f"/api/v1/dhcp/servers/{sid}/discover-sources",
            headers=h,
            params={"min_per_minute": -1},
        )
    ).status_code == 422

    out = await find_dhcp_discover_sources(
        db_session, User(), FindDHCPDiscoverSourcesArgs(server_id=str(sid))
    )
    key = lambda s: (s["kind"], s["subject"], s["per_minute"], s["subnet"])  # noqa: E731
    assert sorted(map(key, out["sources"])) == sorted(map(key, sources))
    assert out["count"] == len(sources)
    bad = await find_dhcp_discover_sources(
        db_session, User(), FindDHCPDiscoverSourcesArgs(server_id=str(uuid.uuid4()))
    )
    assert "not found" in bad["error"]


async def test_discover_sources_unknown_server_404_and_permission_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    assert (
        await client.get(f"/api/v1/dhcp/servers/{uuid.uuid4()}/discover-sources", headers=h)
    ).status_code == 404
    sid, _ = await _world(db_session)
    low = await signed_in_headers(db_session)
    r = await client.get(f"/api/v1/dhcp/servers/{sid}/discover-sources", headers=low)
    assert r.status_code == 403, r.text


def test_mcp_tool_is_registered_in_the_dhcp_module() -> None:
    from app.services.ai.tools import REGISTRY

    tool = REGISTRY.get("find_dhcp_discover_sources")
    assert tool is not None
    assert tool.module == "core.dhcp"
    assert tool.default_enabled is True


# ── evaluator ───────────────────────────────────────────────────────────


async def test_a_mac_over_the_rate_fires_and_names_mac_subnet_and_rate(
    db_session: AsyncSession,
) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=120)  # 120/min, default threshold 30
    matches = await _matching_dhcp_discover_flood_subjects(db_session, _rule())
    assert len(matches) == 1
    subject, display, msg = matches[0]
    assert subject == f"mac:{sid}:{MAC}"
    assert MAC in display and CIDR in display
    assert "120/min" in msg and "threshold 30/min" in msg


async def test_a_mac_under_the_rate_does_not_fire_and_the_threshold_is_honoured(
    db_session: AsyncSession,
) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=20)
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []
    assert (
        len(await _matching_dhcp_discover_flood_subjects(db_session, _rule(threshold_percent=10)))
        == 1
    )


async def test_rate_is_per_minute_whatever_the_window_length(db_session: AsyncSession) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=100, window_seconds=300)  # 20/min
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []


async def test_a_stale_reading_is_not_evidence(db_session: AsyncSession) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=500, age=timedelta(minutes=10))
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []


async def test_relay_signal_is_off_until_the_floor_is_set(db_session: AsyncSession) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, kind="relay", subject=RELAY, discovers=400, distinct_macs=300)
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []
    m = await _matching_dhcp_discover_flood_subjects(db_session, _rule(min_free_addresses=100))
    assert [x[0] for x in m] == [f"relay:{sid}:{RELAY}"]
    assert "300" in m[0][2] and CIDR in m[0][1]
    assert (
        await _matching_dhcp_discover_flood_subjects(db_session, _rule(min_free_addresses=301))
        == []
    )


async def test_a_direct_broadcast_is_reported_against_the_server(
    db_session: AsyncSession,
) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, giaddr=None)
    m = await _matching_dhcp_discover_flood_subjects(db_session, _rule())
    assert len(m) == 1
    assert CIDR not in m[0][1]


async def test_no_readings_means_no_alert(db_session: AsyncSession) -> None:
    """A server whose agent does not run the watch is never alarmed on."""
    await _world(db_session)
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []


# ── Trash ───────────────────────────────────────────────────────────────


async def _open_events(db: AsyncSession, rule_id) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule_id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


async def test_a_trashed_scope_neither_fires_nor_keeps_an_alert_open_and_restore_resumes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sid, scope_id = await _world(db_session)
    await _reading(db_session, sid, discovers=120)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    rid = rule.id
    h = await _headers(db_session)

    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rid)) == 1

    # Trash the scope: the open alert closes, and nothing re-opens.
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)).status_code == 204
    await evaluate_all(db_session)
    assert await _open_events(db_session, rid) == []
    await evaluate_all(db_session)
    assert await _open_events(db_session, rid) == []

    # Restore: the next evaluation fires again off the same reading.
    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=h)
    assert r.status_code == 200, r.text
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rid)) == 1


async def test_a_scope_whose_pools_are_trashed_never_fires(db_session: AsyncSession) -> None:
    sid, scope_id = await _world(db_session)
    await _reading(db_session, sid, discovers=120)
    assert len(await _matching_dhcp_discover_flood_subjects(db_session, _rule())) == 1

    pools = (
        (await db_session.execute(select(DHCPPool).where(DHCPPool.scope_id == scope_id)))
        .scalars()
        .all()
    )
    for p in pools:
        p.deleted_at = datetime.now(UTC)
    await db_session.commit()
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []

    for p in pools:
        p.deleted_at = None
    await db_session.commit()
    assert len(await _matching_dhcp_discover_flood_subjects(db_session, _rule())) == 1


async def test_a_scope_with_no_dynamic_pool_has_nothing_to_exhaust(
    db_session: AsyncSession,
) -> None:
    sid, _ = await _world(db_session, pool=False)
    await _reading(db_session, sid, discovers=120)
    assert await _matching_dhcp_discover_flood_subjects(db_session, _rule()) == []


async def test_purging_the_scope_from_the_trash_clears_the_alert_for_good(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sid, scope_id = await _world(db_session)
    await _reading(db_session, sid, discovers=120)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    rid = rule.id
    h = await _headers(db_session)
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rid)) == 1

    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)).status_code == 204
    assert (
        await client.delete(f"/api/v1/admin/trash/dhcp_scope/{scope_id}", headers=h)
    ).status_code == 204
    await evaluate_all(db_session)
    # Purged: the relay now resolves to no scope at all, so it is reported
    # against the server (a flood is still a flood) -- but it is a different
    # subject than the scope-attributed one, and the old event is closed.
    open_now = await _open_events(db_session, rid)
    assert all("lab-scope" not in e.subject_display for e in open_now)


async def test_deleting_the_server_removes_its_readings_and_closes_the_alert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=120)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    rid = rule.id
    h = await _headers(db_session)
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rid)) == 1

    r = await client.delete(f"/api/v1/dhcp/servers/{sid}", headers=h)
    assert r.status_code in (200, 204), r.text
    left = (
        (
            await db_session.execute(
                select(DHCPDiscoverRate).where(DHCPDiscoverRate.server_id == sid)
            )
        )
        .scalars()
        .all()
    )
    assert left == []
    await evaluate_all(db_session)
    assert await _open_events(db_session, rid) == []


async def test_alert_resolves_when_the_source_stops(db_session: AsyncSession) -> None:
    sid, _ = await _world(db_session)
    await _reading(db_session, sid, discovers=120)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    rid = rule.id
    await evaluate_all(db_session)
    assert len(await _open_events(db_session, rid)) == 1

    row = (await db_session.execute(select(DHCPDiscoverRate))).scalar_one()
    row.window_end = datetime.now(UTC) - timedelta(minutes=10)
    await db_session.commit()
    await evaluate_all(db_session)
    assert await _open_events(db_session, rid) == []
