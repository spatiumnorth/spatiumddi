"""An address's aliases are told from its host record by a stored marker (#2084).

An A / AAAA alias and the address's own host record are both ``auto_generated``
with ``ip_address_id`` set. The DNS sync loaded the aliases as the host record
(renaming one, or deleting it as "a zone the host does not publish to"), and
the alias lists inferred an alias from ``id != ip.dns_record_id``, so a host
record published into an extra zone was listed, counted and deletable as an
alias. ``dns_record.ip_alias`` now says which is which.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _setup


async def _rows(db: AsyncSession, ip_id: str) -> list[DNSRecord]:
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.ip_address_id == uuid.UUID(ip_id))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


def _summary(rows: list[DNSRecord], rtype: str) -> list[tuple[str, str]]:
    return sorted((r.name, str(r.zone_id)) for r in rows if r.record_type == rtype)


async def _extra_zone(db: AsyncSession, like: DNSZone) -> DNSZone:
    z = DNSZone(
        group_id=like.group_id,
        name=f"x{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.commit()
    return z


@pytest.mark.asyncio
@pytest.mark.parametrize("alias_first", [True, False])
async def test_a_alias_in_the_host_zone_survives_a_rename(
    client: AsyncClient, db_session: AsyncSession, alias_first: bool
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    if alias_first:
        # Alias row older than the host row, so no row order can save the old code.
        r = await _alloc(client, headers, sid, "10.98.5.10", "h1")
        ip_id = r.json()["id"]
        await client.post(
            f"/api/v1/ipam/addresses/{ip_id}/aliases",
            headers=headers,
            json={"name": "www", "record_type": "A"},
        )
    else:
        r = await _alloc(
            client,
            headers,
            sid,
            "10.98.5.10",
            "h1",
            aliases=[{"name": "www", "record_type": "A"}],
        )
        ip_id = r.json()["id"]
    assert r.status_code == 201, r.text
    for new_name in ("h1", "h2"):
        put = await client.put(
            f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": new_name}
        )
        assert put.status_code == 200, put.text
        rows = await _rows(db_session, ip_id)
        assert _summary(rows, "A") == sorted([(new_name, str(zone.id)), ("www", str(zone.id))]), [
            (r.name, r.record_type) for r in rows
        ]
        alias = next(r for r in rows if r.name == "www")
        assert alias.value == "10.98.5.10"
        host = [r for r in rows if r.name == new_name and r.record_type == "A"]
        assert len(host) == 1


@pytest.mark.asyncio
async def test_alias_in_a_zone_the_host_does_not_publish_to_survives(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    other = await _extra_zone(db_session, zone)
    r = await _alloc(
        client, headers, sid, "10.98.5.11", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    # The host moves to another zone; the alias stays in the original one.
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"dns_zone_id": str(other.id), "hostname": "h1"},
    )
    assert put.status_code == 200, put.text
    rows = await _rows(db_session, ip_id)
    assert ("www", str(zone.id)) in _summary(rows, "A")
    assert [(n, z) for n, z in _summary(rows, "A") if n == "h1"] == [("h1", str(other.id))]


@pytest.mark.asyncio
async def test_default_gateway_name_keeps_the_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.12", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "gateway"}
    )
    assert put.status_code == 200, put.text
    rows = await _rows(db_session, ip_id)
    assert _summary(rows, "A") == [("www", str(zone.id))]


@pytest.mark.asyncio
async def test_host_in_an_extra_zone_is_not_an_alias(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    r = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.13",
        "h1",
        extra_zone_ids=[str(extra.id)],
        aliases=[{"name": "www", "record_type": "A"}],
    )
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    rows = await _rows(db_session, ip_id)
    host_extra = next(x for x in rows if x.zone_id == extra.id)
    assert host_extra.name == "h1"

    listed = await client.get(f"/api/v1/ipam/addresses/{ip_id}/aliases", headers=headers)
    assert [a["name"] for a in listed.json()] == ["www"]
    sub = await client.get(f"/api/v1/ipam/subnets/{sid}/aliases", headers=headers)
    assert [a["name"] for a in sub.json()] == ["www"]
    ips = await client.get(f"/api/v1/ipam/subnets/{sid}/addresses", headers=headers)
    assert [a["alias_count"] for a in ips.json() if a["id"] == ip_id] == [1]

    refused = await client.delete(
        f"/api/v1/ipam/addresses/{ip_id}/aliases/{host_extra.id}", headers=headers
    )
    assert refused.status_code == 409, refused.text
    assert (await _rows(db_session, ip_id)) and any(
        x.id == host_extra.id for x in await _rows(db_session, ip_id)
    )
    # the real alias still deletes
    alias = next(x for x in rows if x.name == "www")
    ok = await client.delete(f"/api/v1/ipam/addresses/{ip_id}/aliases/{alias.id}", headers=headers)
    assert ok.status_code == 204, ok.text


@pytest.mark.asyncio
async def test_every_alias_writer_sets_the_marker_and_hosts_do_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    r1 = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.14",
        "h1",
        extra_zone_ids=[str(extra.id)],
        aliases=[{"name": "a1", "record_type": "A"}, {"name": "c1", "record_type": "CNAME"}],
    )
    r2 = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h2", "aliases": [{"name": "a2", "record_type": "A"}]},
    )
    r3 = await _alloc(client, headers, sid, "10.98.5.30", "h3")
    add = await client.post(
        f"/api/v1/ipam/addresses/{r3.json()['id']}/aliases",
        headers=headers,
        json={"name": "a3", "record_type": "A"},
    )
    assert add.status_code == 201, add.text
    for resp in (r1, r2, r3):
        for rec in await _rows(db_session, resp.json()["id"]):
            is_alias = rec.name in {"a1", "c1", "a2", "a3"}
            assert rec.ip_alias is is_alias, (rec.name, rec.record_type)
