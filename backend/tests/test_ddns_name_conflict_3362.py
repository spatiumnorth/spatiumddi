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
from app.models.ipam import IPAddress, IPBlock, Subnet
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
    assert row.hostname == "dhcp-10-93-31-50"
    assert await _records(db_session, row) == {
        "A": [("dhcp-10-93-31-50", ip)],
        "PTR": [("50", f"dhcp-10-93-31-50.{zone.name}")],
    }

    # A renewal keeps the one record per name.
    await _post(client, db_session, server, _lease(ip, "www"))
    assert len(await _a_records(db_session, zone_id, "www")) == 1
    assert len(await _a_records(db_session, zone_id, "dhcp-10-93-31-50")) == 1


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
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-32-50"
    assert len(await _a_records(db_session, zone_id, "dhcp-10-93-32-50")) == 1


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
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-33-50"
    assert len(await _a_records(db_session, zone_id, "dhcp-10-93-33-50")) == 1


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
    assert await _a_records(db_session, zone_id, "dhcp-10-93-34-50") == []


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
    assert await _a_records(db_session, zone_id, "dhcp-10-93-35-50") == []


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
    assert await _a_records(db_session, zone_id, "dhcp-10-93-36-50") == []


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
    assert row.hostname == "dhcp-20010db8000000000000000000000050"


def _operator(zone_id: Any, name: str, rtype: str, value: str, **kw: Any) -> DNSRecord:
    return DNSRecord(
        zone_id=zone_id,
        name=name,
        fqdn=name,
        record_type=rtype,
        value=value,
        auto_generated=False,
        **kw,
    )


async def _all_at(db: AsyncSession, zone_id: Any, name: str) -> list[tuple[str, str, bool]]:
    db.expunge_all()
    rows = (
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone_id, DNSRecord.name == name)
                .order_by(DNSRecord.record_type)
            )
        )
        .scalars()
        .all()
    )
    return [(r.record_type, r.value, r.auto_generated) for r in rows]


@pytest.mark.asyncio
async def test_operator_cname_at_the_name_gets_the_generated_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 40)
    zone_id = zone.id
    db_session.add(_operator(zone_id, "www", "CNAME", "web.example.net."))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "www"))

    assert await _all_at(db_session, zone_id, "www") == [("CNAME", "web.example.net.", False)]
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-40-50"
    assert len(await _a_records(db_session, zone_id, "dhcp-10-93-40-50")) == 1


@pytest.mark.parametrize(
    ("rtype", "value"),
    [("MX", "mx1.example.net."), ("TXT", '"v=spf1 -all"'), ("NS", "ns1.child.example.net.")],
)
@pytest.mark.asyncio
async def test_a_name_holding_only_non_address_records_is_held(
    client: AsyncClient, db_session: AsyncSession, rtype: str, value: str
) -> None:
    """An MX- or TXT-only name, or an NS delegation, is the operator's: an A
    beside it would give the name an address the operator never published (and
    under a delegation, out-of-zone data)."""
    server, subnet, zone, ip = await _setup(db_session, 41)
    zone_id = zone.id
    db_session.add(_operator(zone_id, "mail", rtype, value))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "mail"))

    assert await _all_at(db_session, zone_id, "mail") == [(rtype, value, False)]
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-41-50"


@pytest.mark.asyncio
async def test_operator_twin_plus_a_txt_is_still_adopted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 42)
    zone_id = zone.id
    db_session.add(_operator(zone_id, "printer", "A", ip))
    db_session.add(_operator(zone_id, "printer", "TXT", '"floor 2"'))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "printer"))

    assert (await _row(db_session, subnet.id, ip)).hostname == "printer"
    assert await _a_records(db_session, zone_id, "dhcp-10-93-42-50") == []
    assert [
        (r.value, r.auto_generated) for r in await _a_records(db_session, zone_id, "printer")
    ] == [(ip, False)]


@pytest.mark.asyncio
async def test_a_client_cannot_take_another_address_generated_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``dhcp-10-93-43-51`` is the name 10.93.43.51 falls back to; a client on .50
    asking for it gets its own generated name, and .51 keeps its own."""
    server, subnet, zone, ip = await _setup(db_session, 43)
    zone_id = zone.id

    await _post(client, db_session, server, _lease(ip, "dhcp-10-93-43-51"))
    assert await _a_records(db_session, zone_id, "dhcp-10-93-43-51") == []
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-43-50"

    ev = _lease("10.93.43.51", "")
    ev["mac_address"] = "aa:bb:cc:dd:43:51"
    await _post(client, db_session, server, ev)
    assert [r.value for r in await _a_records(db_session, zone_id, "dhcp-10-93-43-51")] == [
        "10.93.43.51"
    ]


@pytest.mark.asyncio
async def test_when_the_fallback_is_held_too_the_row_keeps_no_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Nothing is published, and the row is left blank so neither Sync DNS nor
    the auto-sync backstop publishes the client's name from it later."""
    from app.services.dns.sync_check import compute_subnet_dns_drift

    server, subnet, zone, ip = await _setup(db_session, 44)
    zone_id = zone.id
    await _post(client, db_session, server, _lease(ip, "laptop"))
    assert len(await _a_records(db_session, zone_id, "laptop")) == 1

    db_session.add(_operator(zone_id, "www", "A", "203.0.113.10"))
    db_session.add(_operator(zone_id, "dhcp-10-93-44-50", "A", "203.0.113.11"))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "www"))

    row = await _row(db_session, subnet.id, ip)
    assert (row.hostname or "") == ""
    assert await _records(db_session, row) == {}
    assert await _a_records(db_session, zone_id, "laptop") == []
    assert [r.value for r in await _a_records(db_session, zone_id, "www")] == ["203.0.113.10"]
    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert [m for m in report.missing if m.ip_id == row.id] == []


@pytest.mark.asyncio
async def test_a_held_name_renewal_enqueues_no_dns_ops(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from tests.test_ddns_lease_rename_1618 import _op_count

    server, subnet, zone, ip = await _setup(db_session, 45)
    db_session.add(_operator(zone.id, "www", "A", "203.0.113.10"))
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "www"))
    before = await _op_count(db_session)
    await _post(client, db_session, server, _lease(ip, "www"))
    await _post(client, db_session, server, _lease(ip, "www"))
    assert await _op_count(db_session) == before
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-45-50"


@pytest.mark.asyncio
async def test_two_leases_asking_for_one_name_in_one_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.api.v1.dhcp.agents import _auth_agent
    from app.main import app

    server, subnet, zone, ip = await _setup(db_session, 46)
    zone_id = zone.id
    second = _lease("10.93.46.51", "laptop")
    second["mac_address"] = "aa:bb:cc:dd:46:51"
    db_session.expunge_all()
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dhcp/agents/lease-events",
            json={"leases": [_lease(ip, "laptop"), second]},
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text

    assert len(await _a_records(db_session, zone_id, "laptop")) == 1
    names = sorted(
        [
            (await _row(db_session, subnet.id, ip)).hostname,
            (await _row(db_session, subnet.id, "10.93.46.51")).hostname,
        ]
    )
    assert "laptop" in names
    assert any(n.startswith("dhcp-10-93-46-") for n in names)


@pytest.mark.asyncio
async def test_a_client_cycling_held_names_raises_one_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from sqlalchemy import func

    from app.models.audit import AuditLog

    server, subnet, zone, ip = await _setup(db_session, 47)
    for n in ("www", "mail", "vpn", "portal"):
        db_session.add(_operator(zone.id, n, "A", "203.0.113.10"))
    await db_session.commit()

    for n in ("www", "mail", "vpn", "portal", "www"):
        await _post(client, db_session, server, _lease(ip, n))

    db_session.expunge_all()
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "ddns_name_conflict")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    audit = rows[0]
    assert audit.result == "denied"
    assert audit.user_id is None
    assert audit.resource_type == "ip_address"
    assert audit.new_value["requested_name"] == "www"
    assert audit.new_value["published_name"] == "dhcp-10-93-47-50"
    assert audit.new_value["holder_value"] == "203.0.113.10"
    assert (await db_session.execute(select(func.count()).select_from(AuditLog))).scalar_one() >= 1


# --- #3364: generated names carry the whole address ---------------------------


@pytest.mark.asyncio
async def test_two_subnets_sharing_a_zone_publish_distinct_generated_names(
    db_session: AsyncSession,
) -> None:
    """10.93.50.5 and 10.94.50.5 both ended in ``50-5``: one name, one loser."""
    from app.services.dns.ddns import apply_ddns_for_lease

    _server, subnet, zone, _ip = await _setup(db_session, 50)
    zone_id = zone.id
    block2 = IPBlock(space_id=subnet.space_id, network="10.94.0.0/16", name="blk2")
    db_session.add(block2)
    await db_session.flush()
    subnet2 = Subnet(
        space_id=subnet.space_id,
        block_id=block2.id,
        network="10.94.50.0/24",
        name="sn2",
        dns_zone_id=str(zone_id),
        dns_group_ids=subnet.dns_group_ids,
        dns_inherit_settings=False,
        ddns_enabled=True,
        ddns_inherit_settings=False,
        ddns_hostname_policy="client_or_generated",
    )
    db_session.add(subnet2)
    await db_session.flush()
    rows = []
    for sn, ip in ((subnet, "10.93.50.5"), (subnet2, "10.94.50.5")):
        row = IPAddress(
            subnet_id=sn.id, address=ip, status="dhcp", auto_from_lease=True, mac_address=MAC
        )
        db_session.add(row)
        rows.append((sn, row))
    await db_session.commit()

    for sn, row in rows:
        await apply_ddns_for_lease(db_session, subnet=sn, ipam_row=row, client_hostname=None)
        await db_session.commit()

    assert [r.value for r in await _a_records(db_session, zone_id, "dhcp-10-93-50-5")] == [
        "10.93.50.5"
    ]
    assert [r.value for r in await _a_records(db_session, zone_id, "dhcp-10-94-50-5")] == [
        "10.94.50.5"
    ]
    assert await _a_records(db_session, zone_id, "dhcp-50-5") == []


@pytest.mark.asyncio
async def test_a_legacy_named_lease_moves_to_the_full_name_on_renewal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A record published as ``dhcp-<x>-<y>`` is retracted when the lease next
    renews and the generated name is the whole-address one."""
    server, subnet, zone, ip = await _setup(db_session, 51)
    zone_id = zone.id
    # Own legacy form is the pre-#3364 generated name for this address.
    await _post(client, db_session, server, _lease(ip, "dhcp-51-50"))
    assert len(await _a_records(db_session, zone_id, "dhcp-51-50")) == 1

    await _post(client, db_session, server, _lease(ip, ""))

    assert await _a_records(db_session, zone_id, "dhcp-51-50") == []
    assert [r.value for r in await _a_records(db_session, zone_id, "dhcp-10-93-51-50")] == [ip]
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-51-50"


@pytest.mark.asyncio
async def test_a_client_cannot_take_the_legacy_generated_name_of_another_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 52)
    zone_id = zone.id
    await _post(client, db_session, server, _lease(ip, "dhcp-52-51"))
    assert await _a_records(db_session, zone_id, "dhcp-52-51") == []
    assert (await _row(db_session, subnet.id, ip)).hostname == "dhcp-10-93-52-50"


def test_generated_names_fit_a_label_and_v6_is_not_truncated() -> None:
    from app.services.dns.ddns import _generate_hostname

    assert _generate_hostname("10.1.20.5") == "dhcp-10-1-20-5"
    a = _generate_hostname("2001:db8:1::5")
    b = _generate_hostname("2001:db8:2::5")
    assert a != b and len(a) <= 63
