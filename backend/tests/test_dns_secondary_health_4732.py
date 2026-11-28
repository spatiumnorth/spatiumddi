"""Per-secondary zone health and the two ``dns_secondary_*`` alert rules (#4732).

Covers the agent report route, the REST read routes, the MCP tool, the
matchers, and the Trash behaviour: a trashed zone never fires or keeps an
alert open, a restore resumes evaluation, and a purge clears the rows.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.alerts import AlertEvent, AlertRule
from app.models.auth import Group, Role, User
from app.models.dns import DNSSecondaryZoneState, DNSServer, DNSServerGroup, DNSZone
from app.services import alerts as alerts_svc
from app.services.dns.agent_token import mint_agent_token

NOW = datetime.now(UTC)
REFRESH, RETRY, EXPIRE = 3600, 600, 86400 * 7


async def _setup(
    db: AsyncSession, *, zone_type: str = "secondary"
) -> tuple[DNSServer, DNSZone, dict[str, str]]:
    grp = DNSServerGroup(name=f"g4732-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.9",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type=zone_type,
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, zone, {"Authorization": f"Bearer {token}"}


def _state(
    server: DNSServer,
    zone: DNSZone,
    *,
    last_refresh_ago: timedelta | None,
    serial: int | None = 10,
    reported_ago: timedelta = timedelta(minutes=1),
    first_seen_ago: timedelta = timedelta(days=1),
    timers: tuple[int, int, int] = (REFRESH, RETRY, EXPIRE),
) -> DNSSecondaryZoneState:
    """A report whose last good refresh was ``last_refresh_ago`` ago (None =
    the zone never transferred), on SOA timers ``(refresh, retry, expire)``."""
    refresh, retry, expire = timers
    expires = (
        NOW - last_refresh_ago + timedelta(seconds=expire) if last_refresh_ago is not None else None
    )
    return DNSSecondaryZoneState(
        server_id=server.id,
        zone_id=zone.id,
        serial=serial if last_refresh_ago is not None else None,
        expires_at=expires,
        soa_refresh=refresh,
        soa_retry=retry,
        soa_expire=expire,
        reported_at=NOW - reported_ago,
        created_at=NOW - first_seen_ago,
    )


async def _user(
    db: AsyncSession, *, role: str | None = None, permissions: list[dict[str, Any]] | None = None
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u4732-{tag}",
        email=f"{tag}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=role is None and permissions is None,
    )
    if role is not None or permissions is not None:
        perms = list(_BUILTIN_ROLES[role][1]) if role is not None else list(permissions or [])
        r = Role(name=f"r-{tag}", description="", permissions=perms)
        g = Group(name=f"g-{tag}", description="")
        g.roles = [r]
        g.users = [user]
        db.add_all([r, g])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _rule(db: AsyncSession, rule_type: str, **kw: Any) -> AlertRule:
    rule = AlertRule(name=f"r-{rule_type}", rule_type=rule_type, severity="warning", **kw)
    db.add(rule)
    await db.flush()
    return rule


XFER = alerts_svc.RULE_TYPE_DNS_SECONDARY_TRANSFER_FAILED
STALE = alerts_svc.RULE_TYPE_DNS_SECONDARY_ZONE_STALE


async def _ids(matcher: Any, db: AsyncSession, rule: AlertRule) -> dict[str, str | None]:
    return {sid: sev for sid, _d, _m, sev in await matcher(db, rule, NOW)}


# ── the agent's report ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_report_is_stored_and_replaced(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone, headers = await _setup(db_session)
    zone_id, zone_name = zone.id, zone.name
    await db_session.commit()
    body = {
        "zones": [
            {
                "zone_name": zone_name.rstrip(".").upper(),
                "serial": 7,
                "expires_at": (NOW + timedelta(days=3)).isoformat(),
                "next_refresh_at": (NOW + timedelta(minutes=5)).isoformat(),
                "soa_refresh": REFRESH,
                "soa_retry": RETRY,
                "soa_expire": EXPIRE,
            }
        ]
    }
    r = await client.post("/api/v1/dns/agents/secondary-state", headers=headers, json=body)
    assert r.status_code == 200, r.text
    assert r.json() == {"updated": 1, "skipped": 0}
    body["zones"][0]["serial"] = 8
    r = await client.post("/api/v1/dns/agents/secondary-state", headers=headers, json=body)
    assert r.json()["updated"] == 1
    db_session.expire_all()
    rows = (await db_session.execute(select(DNSSecondaryZoneState))).scalars().all()
    assert [(x.zone_id, x.serial) for x in rows] == [(zone_id, 8)]


@pytest.mark.asyncio
async def test_agent_report_skips_unknown_and_non_secondary_zones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, primary, headers = await _setup(db_session, zone_type="primary")
    await db_session.commit()
    r = await client.post(
        "/api/v1/dns/agents/secondary-state",
        headers=headers,
        json={"zones": [{"zone_name": primary.name}, {"zone_name": "nope.example."}]},
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"updated": 0, "skipped": 2}
    assert (await db_session.execute(select(DNSSecondaryZoneState))).first() is None


@pytest.mark.asyncio
async def test_agent_report_refuses_bad_input_and_no_credentials(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, zone, headers = await _setup(db_session)
    await db_session.commit()
    url = "/api/v1/dns/agents/secondary-state"
    assert (await client.post(url, json={"zones": []})).status_code in (401, 403)
    for bad in (
        {"zones": [{"zone_name": ""}]},
        {"zones": [{"zone_name": zone.name, "serial": -1}]},
        {"zones": [{"zone_name": zone.name, "soa_refresh": "soon"}]},
        {"zones": [{"zone_name": zone.name, "expires_at": "not a time"}]},
        {"nope": 1},
    ):
        r = await client.post(url, headers=headers, json=bad)
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["detail"], r.text


# ── the REST read routes ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rest_routes_permissions_404_and_shape(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone, _h = await _setup(db_session)
    db_session.add(_state(server, zone, last_refresh_ago=timedelta(minutes=10)))
    await db_session.commit()
    zone_url = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/secondary-health"
    server_url = f"/api/v1/dns/servers/{server.id}/secondary-health"

    nobody = await _user(db_session, permissions=[{"action": "read", "resource_type": "subnet"}])
    for url in (zone_url, server_url):
        assert (await client.get(url, headers=nobody)).status_code == 403
        assert (await client.get(url)).status_code in (401, 403)

    viewer = await _user(db_session, role="Viewer")
    admin = await _user(db_session)
    for url in (zone_url, server_url):
        r = await client.get(url, headers=viewer)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["summary"] == {"total": 1, "in_sync": 1}
        item = body["items"][0]
        assert item["server_id"] == str(server.id) and item["zone_id"] == str(zone.id)
        assert item["state"] == "in_sync" and item["serial"] == 10
        assert item["failed_attempts"] == 0

    missing = uuid.uuid4()
    r = await client.get(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{missing}/secondary-health", headers=admin
    )
    assert r.status_code == 404
    r = await client.get(f"/api/v1/dns/servers/{missing}/secondary-health", headers=admin)
    assert r.status_code == 404
    r = await client.get(
        f"/api/v1/dns/groups/{uuid.uuid4()}/zones/{zone.id}/secondary-health", headers=admin
    )
    assert r.status_code == 404
    r = await client.get("/api/v1/dns/servers/not-a-uuid/secondary-health", headers=admin)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_rest_matches_openapi(client: AsyncClient, db_session: AsyncSession) -> None:
    server, zone, _h = await _setup(db_session)
    db_session.add(_state(server, zone, last_refresh_ago=timedelta(minutes=10)))
    server_id = server.id
    await db_session.commit()
    admin = await _user(db_session)
    from app.main import app

    spec = app.openapi()
    for path in (
        "/api/v1/dns/groups/{group_id}/zones/{zone_id}/secondary-health",
        "/api/v1/dns/servers/{server_id}/secondary-health",
    ):
        ref = spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]["$ref"]
        assert ref.endswith("/SecondaryHealthResponse")
    schema = spec["components"]["schemas"]["SecondaryHealthEntry"]
    r = await client.get(f"/api/v1/dns/servers/{server_id}/secondary-health", headers=admin)
    assert set(r.json()["items"][0]) == set(schema["properties"])


# ── the MCP tool ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_tool_matches_rest(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.services.ai.tools.base import REGISTRY
    from app.services.ai.tools.dns import FindDnsSecondaryHealthArgs, find_dns_secondary_health

    tool_def = REGISTRY.get("find_dns_secondary_health")
    assert tool_def is not None and tool_def.permission == ("read", "dns_zone")
    server, zone, _h = await _setup(db_session)
    db_session.add(_state(server, zone, last_refresh_ago=timedelta(hours=1, minutes=30)))
    server_id = server.id
    await db_session.commit()
    admin_headers = await _user(db_session)
    rest = (
        await client.get(f"/api/v1/dns/servers/{server_id}/secondary-health", headers=admin_headers)
    ).json()["items"]
    user = (await db_session.execute(select(User).limit(1))).scalar_one()
    tool = await find_dns_secondary_health(
        db_session, user, FindDnsSecondaryHealthArgs(server_id=str(server_id))
    )
    assert [(t["zone_id"], t["state"], t["serial"]) for t in tool] == [
        (i["zone_id"], i["state"], i["serial"]) for i in rest
    ]
    only = await find_dns_secondary_health(
        db_session, user, FindDnsSecondaryHealthArgs(state="expired")
    )
    assert only == []
    assert (
        await find_dns_secondary_health(
            db_session, user, FindDnsSecondaryHealthArgs(zone_id="nope")
        )
        == []
    )


# ── the matchers ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_transfer_failed_matches_only_past_the_threshold(db_session: AsyncSession) -> None:
    ok, z_ok, _ = await _setup(db_session)
    bad, z_bad, _ = await _setup(db_session)
    soon, z_soon, _ = await _setup(db_session)
    gone, z_gone, _ = await _setup(db_session)
    # Due after 1 h; 3 retries of 10 min past due = 3 missed attempts.
    db_session.add_all(
        [
            _state(ok, z_ok, last_refresh_ago=timedelta(minutes=20)),
            _state(bad, z_bad, last_refresh_ago=timedelta(hours=1, minutes=40)),
            _state(soon, z_soon, last_refresh_ago=timedelta(hours=1, minutes=15)),
            _state(gone, z_gone, last_refresh_ago=timedelta(seconds=EXPIRE + 60)),
        ]
    )
    rule = await _rule(db_session, XFER, threshold_percent=3)
    await db_session.commit()
    got = await _ids(alerts_svc._matching_dns_secondary_transfer_failed_subjects, db_session, rule)
    assert got == {f"{bad.id}:{z_bad.id}": "warning", f"{gone.id}:{z_gone.id}": "critical"}
    # The threshold is the rule's, not a constant.
    # "soon" is 15 min past due: one missed attempt, below 2, at 1.
    rule.threshold_percent = 2
    got = await _ids(alerts_svc._matching_dns_secondary_transfer_failed_subjects, db_session, rule)
    assert f"{soon.id}:{z_soon.id}" not in got
    rule.threshold_percent = 1
    got = await _ids(alerts_svc._matching_dns_secondary_transfer_failed_subjects, db_session, rule)
    assert f"{soon.id}:{z_soon.id}" in got
    assert f"{ok.id}:{z_ok.id}" not in got


@pytest.mark.asyncio
async def test_zone_stale_matches_stale_expiring_and_never_transferred(
    db_session: AsyncSession,
) -> None:
    fresh, z_fresh, _ = await _setup(db_session)
    stale, z_stale, _ = await _setup(db_session)
    expiring, z_exp, _ = await _setup(db_session)
    never, z_never, _ = await _setup(db_session)
    new, z_new, _ = await _setup(db_session)
    db_session.add_all(
        [
            _state(fresh, z_fresh, last_refresh_ago=timedelta(minutes=5)),
            _state(stale, z_stale, last_refresh_ago=timedelta(hours=4)),
            _state(expiring, z_exp, last_refresh_ago=timedelta(seconds=EXPIRE - 3600)),
            _state(never, z_never, last_refresh_ago=None, first_seen_ago=timedelta(hours=5)),
            _state(new, z_new, last_refresh_ago=None, first_seen_ago=timedelta(minutes=5)),
        ]
    )
    rule = await _rule(db_session, STALE, threshold_percent=3, threshold_days=1)
    await db_session.commit()
    got = await _ids(alerts_svc._matching_dns_secondary_zone_stale_subjects, db_session, rule)
    assert got == {
        f"{stale.id}:{z_stale.id}": "warning",
        f"{expiring.id}:{z_exp.id}": "critical",
        f"{never.id}:{z_never.id}": "warning",
    }


@pytest.mark.asyncio
async def test_silent_agent_paused_and_maintenance_servers_do_not_fire(
    db_session: AsyncSession,
) -> None:
    silent, z1, _ = await _setup(db_session)
    paused, z2, _ = await _setup(db_session)
    maint, z3, _ = await _setup(db_session)
    paused.is_enabled = False
    maint.maintenance_mode = True
    old = timedelta(hours=5)
    db_session.add_all(
        [
            _state(silent, z1, last_refresh_ago=old, reported_ago=timedelta(hours=2)),
            _state(paused, z2, last_refresh_ago=old),
            _state(maint, z3, last_refresh_ago=old),
        ]
    )
    rule = await _rule(db_session, STALE)
    await db_session.commit()
    assert (
        await _ids(alerts_svc._matching_dns_secondary_zone_stale_subjects, db_session, rule) == {}
    )


# Timers as live BIND 9.20 runs them (#4732): the lab zone's SOA said refresh 60 /
# retry 30 / expire 600, and named checked it every 4-5 min, backed off after a
# miss, and kept the copy until the 10 min were up.
SHORT = (60, 30, 600)


@pytest.mark.asyncio
async def test_short_soa_timers_do_not_make_a_healthy_zone_fail_or_expire(
    db_session: AsyncSession,
) -> None:
    """named never refreshes faster than 5 min, so a zone with ``refresh 60``
    last checked 4 min ago is on schedule, and one whose whole expire is inside
    the alert's window is not "expiring" while it keeps refreshing."""
    srv, zone, _ = await _setup(db_session)
    db_session.add(
        _state(
            srv,
            zone,
            last_refresh_ago=timedelta(minutes=4),
            timers=SHORT,
            reported_ago=timedelta(seconds=30),
        )
    )
    x = await _rule(db_session, XFER, threshold_percent=1)
    stale = await _rule(db_session, STALE, threshold_percent=3, threshold_days=1)
    await db_session.commit()
    assert (
        await _ids(alerts_svc._matching_dns_secondary_transfer_failed_subjects, db_session, x) == {}
    )
    assert (
        await _ids(alerts_svc._matching_dns_secondary_zone_stale_subjects, db_session, stale) == {}
    )
    from app.services.dns.secondary_health import load_health

    (h,) = await load_health(db_session, now=NOW)
    assert (h.state, h.failed_attempts) == ("in_sync", 0)


@pytest.mark.asyncio
async def test_a_short_expire_zone_that_stops_refreshing_is_expiring(
    db_session: AsyncSession,
) -> None:
    srv, zone, _ = await _setup(db_session)
    db_session.add(
        _state(
            srv,
            zone,
            last_refresh_ago=timedelta(minutes=14),
            timers=(60, 30, 900),
            reported_ago=timedelta(seconds=30),
        )
    )
    stale = await _rule(db_session, STALE, threshold_percent=3, threshold_days=1)
    await db_session.commit()
    assert await _ids(
        alerts_svc._matching_dns_secondary_zone_stale_subjects, db_session, stale
    ) == {f"{srv.id}:{zone.id}": "critical"}


@pytest.mark.asyncio
async def test_a_report_older_than_a_refresh_is_judged_as_of_its_own_time(
    db_session: AsyncSession,
) -> None:
    """The report was taken 2 min ago, 3 s before a refresh fell due. Judged at
    ``now`` that refresh is missed, though it may well have worked since; as of
    the report it is on schedule (seen live: an alert opened and closed within
    two minutes of every refresh)."""
    srv, zone, _ = await _setup(db_session)
    db_session.add(
        _state(
            srv,
            zone,
            last_refresh_ago=timedelta(seconds=3600 + 600 - 3 + 120),
            reported_ago=timedelta(seconds=120),
        )
    )
    x = await _rule(db_session, XFER, threshold_percent=1)
    await db_session.commit()
    assert (
        await _ids(alerts_svc._matching_dns_secondary_transfer_failed_subjects, db_session, x) == {}
    )


@pytest.mark.asyncio
async def test_not_loaded_report_expires_the_copy_and_keeps_alerting(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """named drops an expired copy and rndc then says ``zone not loaded``: the
    agent reports ``loaded: false``, which closes the clock on the stored copy
    and keeps the report fresh, so the alert does not age out after 30 min."""
    srv, zone, headers = await _setup(db_session)
    zone_id, zone_name, srv_id = zone.id, zone.name, srv.id
    # Last good refresh was 9 min ago on a 10 min expire: not expired yet.
    db_session.add(
        _state(
            srv,
            zone,
            last_refresh_ago=timedelta(minutes=9),
            timers=SHORT,
            reported_ago=timedelta(hours=1),
        )
    )
    await db_session.commit()
    r = await client.post(
        "/api/v1/dns/agents/secondary-state",
        headers=headers,
        json={"zones": [{"zone_name": zone_name, "loaded": False}]},
    )
    assert r.json() == {"updated": 1, "skipped": 0}
    db_session.expire_all()
    row = (await db_session.execute(select(DNSSecondaryZoneState))).scalar_one()
    assert (row.server_id, row.zone_id, row.serial, row.soa_expire) == (srv_id, zone_id, 10, 600)
    assert row.expires_at is not None and row.expires_at <= datetime.now(UTC)
    assert row.reported_at >= NOW
    x = await _rule(db_session, XFER)
    await db_session.commit()
    got = await alerts_svc._matching_dns_secondary_transfer_failed_subjects(db_session, x)
    assert [(sid, sev) for sid, _d, _m, sev in got] == [(f"{srv_id}:{zone_id}", "critical")]


@pytest.mark.asyncio
async def test_not_loaded_report_for_a_zone_never_transferred_stays_never_transferred(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv, zone, headers = await _setup(db_session)
    zone_name = zone.name
    await db_session.commit()
    r = await client.post(
        "/api/v1/dns/agents/secondary-state",
        headers=headers,
        json={"zones": [{"zone_name": zone_name, "loaded": False}]},
    )
    assert r.json() == {"updated": 1, "skipped": 0}
    db_session.expire_all()
    row = (await db_session.execute(select(DNSSecondaryZoneState))).scalar_one()
    assert row.expires_at is None and row.serial is None
    from app.services.dns.secondary_health import load_health

    (h,) = await load_health(db_session)
    assert h.state == "never_transferred"


# ── Trash ─────────────────────────────────────────────────────────────────


async def _open_events(db: AsyncSession, rule_id: uuid.UUID) -> list[AlertEvent]:
    db.expire_all()
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


@pytest.mark.asyncio
async def test_trashed_zone_never_fires_and_restore_resumes(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]  # noqa: ARG001
        return (False, False, False)

    monkeypatch.setattr(alerts_svc, "_deliver_or_defer", no_delivery)
    server, zone, _h = await _setup(db_session)
    db_session.add(_state(server, zone, last_refresh_ago=timedelta(hours=6)))
    rule = await _rule(db_session, STALE, enabled=True)
    server_id, zone_id, group_id, rule_id = server.id, zone.id, zone.group_id, rule.id
    await db_session.commit()
    admin = await _user(db_session)

    await alerts_svc.evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1

    # Into the Trash: the open alert closes on the next pass, and none opens.
    r = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=admin)
    assert r.status_code == 204, r.text
    await alerts_svc.evaluate_all(db_session)
    assert await _open_events(db_session, rule_id) == []
    assert (
        await _ids(
            alerts_svc._matching_dns_secondary_zone_stale_subjects,
            db_session,
            AlertRule(rule_type=STALE),
        )
        == {}
    )
    rest = await client.get(f"/api/v1/dns/servers/{server_id}/secondary-health", headers=admin)
    assert rest.json()["items"] == []

    # Restored: evaluation resumes.
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone_id}/restore", headers=admin)
    assert r.status_code == 200, r.text
    await alerts_svc.evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1


@pytest.mark.asyncio
async def test_purging_the_zone_clears_its_state_and_alert(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]  # noqa: ARG001
        return (False, False, False)

    monkeypatch.setattr(alerts_svc, "_deliver_or_defer", no_delivery)
    server, zone, _h = await _setup(db_session)
    db_session.add(_state(server, zone, last_refresh_ago=timedelta(hours=6)))
    rule = await _rule(db_session, STALE, enabled=True)
    zone_id, group_id, rule_id = zone.id, zone.group_id, rule.id
    await db_session.commit()
    admin = await _user(db_session)
    await alerts_svc.evaluate_all(db_session)
    assert len(await _open_events(db_session, rule_id)) == 1

    r = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=admin)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zone_id}", headers=admin)
    assert r.status_code in (200, 204), r.text
    db_session.expire_all()
    assert (await db_session.execute(select(DNSSecondaryZoneState))).first() is None
    await alerts_svc.evaluate_all(db_session)
    assert await _open_events(db_session, rule_id) == []


@pytest.mark.asyncio
async def test_a_server_being_removed_is_not_evaluated(db_session: AsyncSession) -> None:
    server, zone, _h = await _setup(db_session)
    server.removing_at = NOW
    db_session.add(_state(server, zone, last_refresh_ago=timedelta(hours=6)))
    rule = await _rule(db_session, STALE)
    await db_session.commit()
    assert (
        await _ids(alerts_svc._matching_dns_secondary_zone_stale_subjects, db_session, rule) == {}
    )


# ── seeding ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rules_are_seeded_disabled(db_session: AsyncSession) -> None:
    await alerts_svc.seed_dns_secondary_alert_rules()
    await alerts_svc.seed_dns_secondary_alert_rules()  # idempotent
    db_session.expire_all()
    rules = (
        (await db_session.execute(select(AlertRule).where(AlertRule.rule_type.in_([XFER, STALE]))))
        .scalars()
        .all()
    )
    assert sorted(r.rule_type for r in rules) == sorted([XFER, STALE])
    assert all(r.enabled is False for r in rules)
