"""A hostname plus its zone must fit a DNS name (#2072).

``validate_hostname`` caps the hostname alone at 253, but IPAM publishes
``<hostname>.<zone>``: four 60-character labels (243) in a 33-character zone
answered 201, and BIND refused the forward zone and the reverse zone holding
the PTR ("ran out of space"). The rule is the wire limit: 255 octets, i.e.
253 characters of dotted presentation name, each label at most 63.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.core.dns_names import bind_check_names_error, name_in_zone_error, name_length_error
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

ZONE = "example-zone.test"  # 17 characters
LONG_HOST = ".".join("abcd"[i] * 60 for i in range(4))  # 243 characters, valid alone


def test_the_limit_is_253_characters_and_63_per_label() -> None:
    fits = ".".join(["a" * 61, "b" * 63, "c" * 63, "d" * 63])
    assert len(fits) == 253
    assert name_length_error(fits) is None
    assert name_length_error(fits + ".") is None  # root dot ignored
    assert "label" in (name_length_error("a" * 64 + ".test") or "")
    assert "255 characters" in (name_length_error(fits + ".e") or "")


def test_a_valid_hostname_in_a_long_zone_is_refused_naming_the_field() -> None:
    assert len(LONG_HOST) == 243
    err = name_in_zone_error(LONG_HOST, ZONE)
    assert err is not None
    assert err.startswith("hostname:")
    assert str(243 + 1 + len(ZONE)) in err
    assert name_in_zone_error("web01", ZONE) is None
    # a trailing root dot on the zone changes nothing
    assert name_in_zone_error("web01", ZONE + ".") is None
    assert name_in_zone_error(LONG_HOST, ZONE + ".") is not None


def test_the_record_check_covers_owner_and_target_lengths() -> None:
    owner = f"{LONG_HOST}.{ZONE}."
    assert bind_check_names_error("TXT", owner, "x", origin=ZONE + ".") is not None
    short = f"w.{ZONE}."
    assert bind_check_names_error("CNAME", short, LONG_HOST, origin=ZONE + ".") is not None
    assert bind_check_names_error("CNAME", short, "web01", origin=ZONE + ".") is None


async def _setup(db: AsyncSession, zone_name: str = ZONE) -> tuple[Subnet, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=zone_name + ".",
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{zone_name}.",
        admin_email=f"admin.{zone_name}.",
    )
    db.add(zone)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.82.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.82.1.0/24",
        name="s",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    return subnet, zone


async def _record_count(db: AsyncSession, zone: DNSZone) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_sync_strict_refuses_and_writes_nothing(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.10", status="allocated", hostname=LONG_HOST
    )
    db_session.add(ip)
    await db_session.flush()
    with pytest.raises(HTTPException) as exc:
        await _sync_dns_record(db_session, ip, subnet, action="create", strict=True)
    assert exc.value.status_code == 422
    assert "hostname" in exc.value.detail
    assert await _record_count(db_session, zone) == 0


@pytest.mark.asyncio
async def test_sync_non_strict_skips_the_name_and_its_ptr(db_session: AsyncSession) -> None:
    """DDNS / importers: no exception, no A, no PTR, no fqdn."""
    subnet, zone = await _setup(db_session)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.11", status="allocated", hostname=LONG_HOST
    )
    db_session.add(ip)
    await db_session.flush()
    assert await _sync_dns_record(db_session, ip, subnet, action="create") is False
    assert await _record_count(db_session, zone) == 0
    assert not ip.fqdn


@pytest.mark.asyncio
async def test_a_hostname_that_fits_still_publishes(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    ip = IPAddress(subnet_id=subnet.id, address="10.82.1.12", status="allocated", hostname="web01")
    db_session.add(ip)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet, action="create", strict=True)
    assert ip.fqdn == f"web01.{ZONE}"
    assert await _record_count(db_session, zone) >= 1


@pytest.mark.asyncio
async def test_allocate_ip_api_answers_422_and_stores_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, zone = await _setup(db_session)
    subnet_id, zone_id = subnet.id, zone.id
    user = User(
        username=f"n-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="n",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        json={"address": "10.82.1.20", "hostname": LONG_HOST, "status": "allocated"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "hostname" in str(resp.json()["detail"])
    # Production's request-scoped session closes uncommitted on the 422; the
    # test client shares one session, so end that transaction the same way.
    await db_session.rollback()
    stored = (
        await db_session.execute(
            select(func.count()).select_from(IPAddress).where(IPAddress.address == "10.82.1.20")
        )
    ).scalar_one()
    assert stored == 0
    count = (
        await db_session.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone_id)
        )
    ).scalar_one()
    assert count == 0
