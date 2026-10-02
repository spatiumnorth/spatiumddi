"""#1171 — a zone's SOA timers reach the agent, and an edit of them moves the
zone's serial.

REFRESH / RETRY / EXPIRE / MINIMUM were stored, returned, editable and
exported, but the per-zone payload of the agent bundle never carried them, so
the BIND9 agent served ``3600 600 86400 300`` for every zone: a PUT of the
timers answered 200, echoed them, and moved neither the wire nor the etag.
They now ship in every zone copy, so an edit shifts the structural etag and
the agent re-renders the SOA; and the edit bumps ``last_serial`` — a secondary
only re-reads a zone whose serial moved. A change to the zone's TTL (its
``$TTL``) changes what the zone serves too, and bumps it for the same reason.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.agent_config import build_config_bundle

TIMERS = ("refresh", "retry", "expire", "minimum")


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"soa-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="SOA Timer Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_with_server(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host=f"dns-{uuid.uuid4().hex[:6]}",
        name=f"dns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return grp, server


def _zone(grp: DNSServerGroup, name: str, **extra: object) -> DNSZone:
    return DNSZone(group_id=grp.id, name=name, zone_type="primary", kind="forward", **extra)


async def _zone_via_api(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, **body: object
) -> dict[str, object]:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": f"z{uuid.uuid4().hex[:6]}.example.test", **body},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    out: dict[str, object] = resp.json()
    return out


# ── The bundle carries the timers ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_every_zone_copy_carries_its_timers(db_session: AsyncSession) -> None:
    grp, server = await _group_with_server(db_session)
    db_session.add(DNSView(group_id=grp.id, name="internal", match_clients=["10.0.0.0/8"]))
    db_session.add(DNSView(group_id=grp.id, name="external", match_clients=["any"], order=10))
    db_session.add(
        _zone(grp, "corp.example.test.", refresh=7200, retry=900, expire=1209600, minimum=60)
    )
    db_session.add(_zone(grp, "lab.example.test."))
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)

    corp = [z for z in bundle["zones"] if z["name"] == "corp.example.test."]
    assert len(corp) == 2  # one per view
    assert {tuple(z[k] for k in TIMERS) for z in corp} == {(7200, 900, 1209600, 60)}
    lab, *_rest = [z for z in bundle["zones"] if z["name"] == "lab.example.test."]
    # The stored defaults: RIPE-203's refresh/retry/expire, RFC 2308's hour.
    assert tuple(lab[k] for k in TIMERS) == (86400, 7200, 3600000, 3600)


@pytest.mark.asyncio
@pytest.mark.parametrize("timer", TIMERS)
async def test_a_timer_edit_alone_moves_the_structural_etag(
    db_session: AsyncSession, timer: str
) -> None:
    """The agent re-renders only when the structural etag moves, so the timer
    itself has to move it, without leaning on the serial bump an edit brings."""
    grp, server = await _group_with_server(db_session)
    zone = _zone(grp, "corp.example.test.")
    db_session.add(zone)
    await db_session.commit()
    before = await build_config_bundle(db_session, server)

    setattr(zone, timer, getattr(zone, timer) + 1)
    await db_session.commit()
    after = await build_config_bundle(db_session, server)

    assert after["structural_etag"] != before["structural_etag"]


# ── An edit moves the serial ────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"refresh": 7200},
        {"retry": 900},
        {"expire": 1209600},
        {"minimum": 60},
        {"refresh": 7200, "retry": 900, "expire": 1209600, "minimum": 60},
        {"ttl": 300},
    ],
)
async def test_an_soa_edit_bumps_the_serial_the_agent_renders(
    client: AsyncClient, db_session: AsyncSession, change: dict[str, int]
) -> None:
    """The issue's own repro: PUT the timers -> 200, and the serial the agent
    renders from must move with them."""
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    zone = await _zone_via_api(client, headers, grp)
    serial_before = int(zone["last_serial"])  # type: ignore[call-overload]

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}", json=change, headers=headers
    )

    assert resp.status_code == 200, resp.text
    assert {k: resp.json()[k] for k in change} == change
    assert resp.json()["last_serial"] > serial_before
    bundle = await build_config_bundle(db_session, server)
    (shipped,) = [z for z in bundle["zones"] if z["id"] == zone["id"]]
    assert shipped["serial"] == resp.json()["last_serial"]
    assert {k: shipped[k] for k in change} == change


@pytest.mark.asyncio
async def test_re_saving_the_same_timers_keeps_the_serial(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The zone form sends every field back; an unchanged value is not a
    change a secondary should transfer the zone for."""
    headers = await _headers(db_session)
    grp, _server = await _group_with_server(db_session)
    zone = await _zone_via_api(client, headers, grp)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}",
        json={k: zone[k] for k in ("ttl", *TIMERS)},
        headers=headers,
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["last_serial"] == zone["last_serial"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [-1, 2**31])
@pytest.mark.parametrize("timer", TIMERS)
async def test_a_timer_bind_would_refuse_is_refused(
    client: AsyncClient, db_session: AsyncSession, timer: str, value: int
) -> None:
    """A negative timer makes BIND refuse the zone file, and with it the
    group's whole config; above 2^31-1 is past RFC 2181's ceiling and the
    column's. Neither is stored."""
    headers = await _headers(db_session)
    grp, _server = await _group_with_server(db_session)

    created = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": f"z{uuid.uuid4().hex[:6]}.example.test", timer: value},
        headers=headers,
    )
    assert created.status_code == 422, created.text

    zone = await _zone_via_api(client, headers, grp)
    updated = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}", json={timer: value}, headers=headers
    )
    assert updated.status_code == 422, updated.text
