"""#1762 — DNSSEC on a multi-server group: each server signs with its own
keys, so signing is refused there, a signed group refuses a second enabled
server, and the agent DS report is group-scoped and not last-writer-wins."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import DNSSECStateBatch, DNSSECStateReport, agent_dnssec_state
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone

DRIVERS = ["bind9", "powerdns", "technitium"]


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"ss-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db, driver="bind9", servers=1, enabled=True):
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    out = []
    for i in range(servers):
        s = DNSServer(
            group_id=g.id,
            driver=driver,
            host=f"10.0.0.{i + 1}",
            name=f"s{i}-{uuid.uuid4().hex[:4]}",
            is_primary=(i == 0),
            is_enabled=enabled,
        )
        db.add(s)
        out.append(s)
    await db.flush()
    return g, out


def _zone(group_id, name="z.example.", signed=False):
    return DNSZone(
        group_id=group_id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="a.example.",
        dnssec_enabled=signed,
    )


def _body(**kw):
    b = {
        "name": f"z{uuid.uuid4().hex[:6]}.example.",
        "zone_type": "primary",
        "kind": "forward",
        "primary_ns": "ns1.example.",
        "admin_email": "admin.example.",
    }
    b.update(kw)
    return b


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", DRIVERS)
async def test_create_update_sign_refused_on_multi_server_group(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, driver, servers=2)
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 422 and "shared DNSSEC keys" in r.text

    z = _zone(g.id)
    db_session.add(z)
    await db_session.flush()
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/zones/{z.id}", json={"dnssec_enabled": True}, headers=h
    )
    assert r.status_code == 422
    r = await client.post(f"/api/v1/dns/groups/{g.id}/zones/{z.id}/dnssec/sign", headers=h)
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_single_enabled_server_may_sign_even_with_disabled_peer(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1)
    db_session.add(
        DNSServer(group_id=g.id, driver="bind9", host="10.9.9.9", name="off", is_enabled=False)
    )
    await db_session.flush()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 201, r.text
    assert r.json()["dnssec_multi_signer"] is False


@pytest.mark.asyncio
async def test_second_server_create_move_and_reenable_refused_on_signed_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=1)
    db_session.add(_zone(g.id, signed=True))
    other, (mover,) = await _group(db_session, "bind9", servers=1)
    off = DNSServer(group_id=g.id, driver="bind9", host="10.9.9.9", name="off", is_enabled=False)
    db_session.add(off)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "second", "driver": "bind9", "host": "10.0.0.50"},
        headers=h,
    )
    assert r.status_code == 422 and "DNSSEC-signed" in r.text
    r = await client.put(
        f"/api/v1/dns/groups/{other.id}/servers/{mover.id}",
        json={"group_id": str(g.id)},
        headers=h,
    )
    assert r.status_code == 422 and "DNSSEC-signed" in r.text
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/servers/{off.id}", json={"is_enabled": True}, headers=h
    )
    assert r.status_code == 422
    # a disabled second server is fine
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "spare", "driver": "bind9", "host": "10.0.0.51", "is_enabled": False},
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_already_signed_multi_server_zone_is_flagged_not_unsigned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g, _ = await _group(db_session, "bind9", servers=2)
    z = _zone(g.id, signed=True)
    db_session.add(z)
    await db_session.flush()
    r = await client.get(f"/api/v1/dns/groups/{g.id}/zones/{z.id}", headers=h)
    assert r.status_code == 200
    assert r.json()["dnssec_enabled"] is True
    assert r.json()["dnssec_multi_signer"] is True


@pytest.mark.asyncio
async def test_dnssec_state_report_is_group_scoped_and_primary_only(
    db_session: AsyncSession,
) -> None:
    g1, (p1, s1) = await _group(db_session, "bind9", servers=2)
    g2, (p2,) = await _group(db_session, "bind9", servers=1)
    z1 = _zone(g1.id, "same.example.", signed=True)
    z2 = _zone(g2.id, "same.example.", signed=True)
    db_session.add_all([z1, z2])
    await db_session.flush()

    def batch(ds: str) -> DNSSECStateBatch:
        return DNSSECStateBatch(
            zones=[DNSSECStateReport(zone_name="same.example.", ds_records=[ds])]
        )

    # group 1's primary must not touch group 2's same-named zone
    await agent_dnssec_state(batch("1 DS-G1"), db_session, (p1, {}))
    await db_session.refresh(z1)
    await db_session.refresh(z2)
    assert z1.dnssec_ds_records == ["1 DS-G1"]
    assert z2.dnssec_ds_records is None

    # a non-primary server of the multi-server group does not overwrite
    out = await agent_dnssec_state(batch("2 DS-OTHER"), db_session, (s1, {}))
    await db_session.refresh(z1)
    assert out == {"updated": 0}
    assert z1.dnssec_ds_records == ["1 DS-G1"]

    # single-server group's own report still lands
    await agent_dnssec_state(batch("3 DS-G2"), db_session, (p2, {}))
    await db_session.refresh(z2)
    assert z2.dnssec_ds_records == ["3 DS-G2"]
    assert (await db_session.execute(select(DNSZone).where(DNSZone.id == z1.id))).scalar_one()
