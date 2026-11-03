"""spatiumddi#3362 — DDNS never publishes a name another record holds.

A DHCP client that calls itself ``www`` used to get ``www A <lease ip>``
written beside the operator's ``www A <other ip>`` (only a CNAME, or an
operator record with the same value, stopped it). RFC 4703: a client may
publish a name only when nobody holds it, or when it already owns it. On a
clash the lease is published under its generated ``dhcp-<ip>`` name and the
holder's record is left alone.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from app.models.ipam import IPAddress
from tests.test_ddns_lease_rename_1618 import MAC, _lease, _post, _records, _row, _setup


async def _a_records(db: AsyncSession, zone_id: Any, name: str) -> list[DNSRecord]:
    db.expunge_all()
    return list(
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zone_id,
                    DNSRecord.name == name,
                    DNSRecord.record_type.in_(["A", "AAAA"]),
                )
            )
        )
        .scalars()
        .all()
    )


def _operator_www(zone_id: Any, value: str, rtype: str = "A") -> DNSRecord:
    return DNSRecord(
        zone_id=zone_id,
        name="www",
        fqdn="www",
        record_type=rtype,
        value=value,
        auto_generated=False,
    )


@pytest.mark.asyncio
async def test_lease_named_like_an_operator_record_gets_the_generated_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 31)
    zone_id = zone.id
    db_session.add(_operator_www(zone_id, "203.0.113.10"))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "www"))

    www = await _a_records(db_session, zone_id, "www")
    assert [(r.value, r.auto_generated) for r in www] == [("203.0.113.10", False)]
    row = await _row(db_session, subnet.id, ip)
    assert row.hostname == "dhcp-31-50"
    assert await _records(db_session, row) == {
        "A": [("dhcp-31-50", ip)],
        "PTR": [("50", f"dhcp-31-50.{zone.name}")],
    }

    # A renewal keeps the one record per name.
    await _post(client, db_session, server, _lease(ip, "www"))
    assert len(await _a_records(db_session, zone_id, "www")) == 1
    assert len(await _a_records(db_session, zone_id, "dhcp-31-50")) == 1


@pytest.mark.asyncio
async def test_lease_named_like_a_static_ipam_host_gets_the_generated_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 32)
    zone_id = zone.id
    static = IPAddress(
        subnet_id=subnet.id,
        address="10.93.32.10",
        status="allocated",
        hostname="www",
        auto_from_lease=False,
    )
    db_session.add(static)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=zone_id,
            name="www",
            fqdn="www",
            record_type="A",
            value="10.93.32.10",
            auto_generated=True,
            ip_address_id=static.id,
        )
    )
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "www"))

    assert [r.value for r in await _a_records(db_session, zone_id, "www")] == ["10.93.32.10"]
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-32-50"
    assert len(await _a_records(db_session, zone_id, "dhcp-32-50")) == 1


@pytest.mark.asyncio
async def test_second_lease_cannot_take_the_name_the_first_lease_published(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 33)
    zone_id = zone.id
    other_ip = "10.93.33.51"

    await _post(client, db_session, server, _lease(other_ip, "laptop"))
    assert [r.value for r in await _a_records(db_session, zone_id, "laptop")] == [other_ip]

    await _post(client, db_session, server, _lease(ip, "laptop"))

    assert [r.value for r in await _a_records(db_session, zone_id, "laptop")] == [other_ip]
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-33-50"
    assert len(await _a_records(db_session, zone_id, "dhcp-33-50")) == 1


@pytest.mark.asyncio
async def test_renewal_of_an_owned_name_still_publishes_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 34)
    zone_id = zone.id
    await _post(client, db_session, server, _lease(ip, "laptop"))
    await _post(client, db_session, server, _lease(ip, "laptop"))
    await _post(client, db_session, server, _lease(ip, "laptop"))

    assert [r.value for r in await _a_records(db_session, zone_id, "laptop")] == [ip]
    row = await _row(db_session, subnet.id, ip)
    assert row.hostname == "laptop"
    assert await _a_records(db_session, zone_id, "dhcp-34-50") == []


@pytest.mark.asyncio
async def test_operator_twin_with_the_same_value_is_still_adopted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 35)
    zone_id = zone.id
    db_session.add(_operator_www(zone_id, ip))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "www"))

    assert [(r.value, r.auto_generated) for r in await _a_records(db_session, zone_id, "www")] == [
        (ip, False)
    ]
    assert (await _row(db_session, subnet.id, ip)).hostname == "www"
    assert await _a_records(db_session, zone_id, "dhcp-35-50") == []


@pytest.mark.asyncio
async def test_release_never_touches_the_operator_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.dns.ddns import revoke_ddns_for_lease

    server, subnet, zone, ip = await _setup(db_session, 36)
    zone_id = zone.id
    db_session.add(_operator_www(zone_id, "203.0.113.10"))
    await db_session.commit()
    await _post(client, db_session, server, _lease(ip, "www"))

    row = await _row(db_session, subnet.id, ip)
    sub = await db_session.get(type(subnet), subnet.id)
    assert await revoke_ddns_for_lease(db_session, subnet=sub, ipam_row=row) is True
    await db_session.commit()

    assert [(r.value, r.auto_generated) for r in await _a_records(db_session, zone_id, "www")] == [
        ("203.0.113.10", False)
    ]
    assert await _a_records(db_session, zone_id, "dhcp-36-50") == []


@pytest.mark.asyncio
async def test_v6_lease_named_like_an_operator_aaaa_gets_the_generated_name(
    db_session: AsyncSession,
) -> None:
    from app.services.dns.ddns import apply_ddns_for_lease

    _server, subnet, zone, _ip = await _setup(db_session, 37)
    zone_id = zone.id
    db_session.add(_operator_www(zone_id, "2001:db8::10", "AAAA"))
    row = IPAddress(
        subnet_id=subnet.id,
        address="2001:db8::50",
        status="dhcp",
        auto_from_lease=True,
        hostname="www",
        mac_address=MAC,
    )
    db_session.add(row)
    await db_session.commit()
    sub = await db_session.get(type(subnet), subnet.id)

    await apply_ddns_for_lease(db_session, subnet=sub, ipam_row=row, client_hostname="www")
    await db_session.commit()

    assert [r.value for r in await _a_records(db_session, zone_id, "www")] == ["2001:db8::10"]
    assert row.hostname == "dhcp-00000050"
