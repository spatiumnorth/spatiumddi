"""An alias that duplicates an existing record is refused, not dropped (#2122).

Allocate IP and next-IP used to skip, silently, an alias whose
``(zone, name, type)`` another record already held: the request succeeded
and the alias did not exist. ``POST /addresses/{id}/aliases`` answered 409
for the same input. All three paths now refuse it with a 409 naming the
alias, before anything is written. An alias the address already has is a
no-op, and the same alias twice in one request is written once.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace


async def _setup(client: AsyncClient, db: AsyncSession) -> tuple[dict[str, str], str, DNSZone]:
    user = User(
        username=f"u2122-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    grp = DNSServerGroup(name=f"g2122-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"d{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    space = IPSpace(name=f"sp2122-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.97.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.97.5.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return headers, str(resp.json()["id"]), zone


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t)) for n, t in rows)


async def _ip_count(db: AsyncSession, sid: str) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == uuid.UUID(sid))
            .execution_options(populate_existing=True)
        )
        or 0
    )


async def _alloc(
    client: AsyncClient, headers: dict[str, str], sid: str, addr: str, host: str, **extra: object
):
    return await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": addr, "hostname": host, **extra},
    )


@pytest.mark.asyncio
async def test_allocate_with_an_alias_another_address_holds_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    first = await _alloc(
        client, headers, sid, "10.97.5.10", "web", aliases=[{"name": "shared", "record_type": "A"}]
    )
    assert first.status_code == 201, first.text
    before = await _records(db_session, zone.id)
    assert before == [("shared", "A"), ("web", "A")]
    ips_before = await _ip_count(db_session, sid)

    resp = await _alloc(
        client,
        headers,
        sid,
        "10.97.5.11",
        "other",
        aliases=[{"name": "ok", "record_type": "CNAME"}, {"name": "SHARED", "record_type": "A"}],
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "SHARED" in detail or "shared" in detail
    assert "10.97.5.10" in detail
    # Nothing of the refused request was written: no IP row, no host record,
    # not even the alias that was fine on its own.
    assert await _records(db_session, zone.id) == before
    assert await _ip_count(db_session, sid) == ips_before

    nxt = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "other", "aliases": [{"name": "shared", "record_type": "A"}]},
    )
    assert nxt.status_code == 409, nxt.text
    assert "shared" in nxt.json()["detail"]
    assert await _records(db_session, zone.id) == before
    assert await _ip_count(db_session, sid) == ips_before


@pytest.mark.asyncio
async def test_alias_onto_an_operator_record_is_refused_everywhere(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="mail",
            fqdn=f"mail.{zone.name.rstrip('.')}",
            record_type="A",
            value="192.0.2.25",
        )
    )
    await db_session.commit()
    before = await _records(db_session, zone.id)

    resp = await _alloc(
        client, headers, sid, "10.97.5.20", "box", aliases=[{"name": "mail", "record_type": "A"}]
    )
    assert resp.status_code == 409, resp.text
    assert "mail." in resp.json()["detail"]
    assert await _records(db_session, zone.id) == before

    ok = await _alloc(client, headers, sid, "10.97.5.21", "box2")
    assert ok.status_code == 201, ok.text
    add = await client.post(
        f"/api/v1/ipam/addresses/{ok.json()['id']}/aliases",
        headers=headers,
        json={"name": "mail", "record_type": "A"},
    )
    assert add.status_code == 409, add.text
    assert "mail." in add.json()["detail"]


@pytest.mark.asyncio
async def test_re_adding_an_alias_the_address_has_changes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    first = await _alloc(
        client,
        headers,
        sid,
        "10.97.5.30",
        "host",
        aliases=[{"name": "www", "record_type": "CNAME"}, {"name": "alt", "record_type": "A"}],
    )
    assert first.status_code == 201, first.text
    ip_id = first.json()["id"]
    before = await _records(db_session, zone.id)
    audits_before = await db_session.scalar(select(func.count()).select_from(AuditLog))

    for name, rtype in (("www", "CNAME"), ("alt", "A"), ("WWW", "CNAME")):
        resp = await client.post(
            f"/api/v1/ipam/addresses/{ip_id}/aliases",
            headers=headers,
            json={"name": name, "record_type": rtype},
        )
        # 200, not 201: nothing was created.
        assert resp.status_code == 200, resp.text
        assert resp.json()["record_type"] == rtype

    assert await _records(db_session, zone.id) == before
    audits_after = await db_session.scalar(select(func.count()).select_from(AuditLog))
    assert audits_after == audits_before


@pytest.mark.asyncio
async def test_the_same_alias_twice_in_one_request_is_written_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    resp = await _alloc(
        client,
        headers,
        sid,
        "10.97.5.40",
        "dup",
        aliases=[
            {"name": "www", "record_type": "CNAME"},
            {"name": "WWW", "record_type": "CNAME"},
            {"name": "alt", "record_type": "A"},
            {"name": "alt", "record_type": "A"},
        ],
    )
    assert resp.status_code == 201, resp.text
    assert await _records(db_session, zone.id) == [("alt", "A"), ("dup", "A"), ("www", "CNAME")]

    nxt = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={
            "hostname": "dup2",
            "aliases": [
                {"name": "w2", "record_type": "A"},
                {"name": "w2", "record_type": "A"},
            ],
        },
    )
    assert nxt.status_code == 201, nxt.text
    names = [n for n, _ in await _records(db_session, zone.id)]
    assert names.count("w2") == 1


@pytest.mark.asyncio
async def test_a_record_differing_only_in_case_is_the_same_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """DNS names compare case-insensitively, as the CNAME rule does."""
    headers, sid, zone = await _setup(client, db_session)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="Mail",
            fqdn=f"Mail.{zone.name.rstrip('.')}",
            record_type="A",
            value="192.0.2.25",
        )
    )
    await db_session.commit()
    before = await _records(db_session, zone.id)

    resp = await _alloc(
        client, headers, sid, "10.97.5.60", "box", aliases=[{"name": "mail", "record_type": "A"}]
    )
    assert resp.status_code == 409, resp.text
    assert "an A record" in resp.json()["detail"]
    assert await _records(db_session, zone.id) == before


@pytest.mark.asyncio
async def test_same_name_other_type_is_not_a_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A TXT or AAAA at the name does not block an A alias there."""
    headers, sid, zone = await _setup(client, db_session)
    for rtype, value in (("TXT", '"v=spf1 -all"'), ("AAAA", "2001:db8::25")):
        db_session.add(
            DNSRecord(
                zone_id=zone.id,
                name="mail",
                fqdn=f"mail.{zone.name.rstrip('.')}",
                record_type=rtype,
                value=value,
            )
        )
    await db_session.commit()

    resp = await _alloc(
        client, headers, sid, "10.97.5.61", "box", aliases=[{"name": "mail", "record_type": "A"}]
    )
    assert resp.status_code == 201, resp.text
    assert ("mail", "A") in await _records(db_session, zone.id)
