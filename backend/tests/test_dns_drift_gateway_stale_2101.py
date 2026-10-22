"""#2101 — a stale forward record on a ``gateway``-named IP carries the live IP id.

The GUI uses ``ip_id`` to stop reading "in sync" on a row whose records Sync
DNS is about to delete, and maps ``reason`` to a plain-words sentence. The
behaviour (forward skipped, record stale) is unchanged.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.sync_check import compute_subnet_dns_drift


@pytest.mark.asyncio
async def test_gateway_forward_record_is_stale_with_ip_id(
    db_session: AsyncSession,
) -> None:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="gw.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.gw.example.",
        admin_email="admin.gw.example.",
    )
    db_session.add(zone)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="blk")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.20.1.0/24",
        name="sn",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db_session.add(subnet)
    await db_session.flush()
    ip = IPAddress(subnet_id=subnet.id, address="10.20.1.1", status="allocated", hostname="gateway")
    db_session.add(ip)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="gateway",
            fqdn="gateway.gw.example.",
            record_type="A",
            value="10.20.1.1",
            auto_generated=True,
            ip_address_id=ip.id,
        )
    )
    await db_session.commit()

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert report.missing == []
    assert len(report.stale) == 1
    item = report.stale[0]
    assert item.reason == "default-gateway-name"
    assert item.ip_id == ip.id
    assert item.zone_name == "gw.example."


@pytest.mark.asyncio
async def test_gateway_extra_zone_record_is_stale_not_missing(
    db_session: AsyncSession,
) -> None:
    """A ``gateway`` host skips every forward zone, its extra zones included
    (``_sync_dns_record`` tears them all down), so a record in an extra zone is
    stale with the live ``ip_id`` and no extra-zone record is reported missing.
    """
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zones = []
    for name in ("gwp.example.", "gwx.example."):
        z = DNSZone(
            group_id=grp.id,
            name=name,
            zone_type="primary",
            kind="forward",
            primary_ns=f"ns1.{name}",
            admin_email=f"admin.{name}",
        )
        db_session.add(z)
        zones.append(z)
    primary, extra = zones
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.21.0.0/16", name="blk")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.21.1.0/24",
        name="sn",
        dns_zone_id=str(primary.id),
        dns_inherit_settings=False,
    )
    db_session.add(subnet)
    await db_session.flush()
    ip = IPAddress(
        subnet_id=subnet.id,
        address="10.21.1.1",
        status="allocated",
        hostname="gateway",
        extra_zone_ids=[str(extra.id)],
    )
    db_session.add(ip)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=extra.id,
            name="gateway",
            fqdn="gateway.gwx.example.",
            record_type="A",
            value="10.21.1.1",
            auto_generated=True,
            ip_address_id=ip.id,
        )
    )
    await db_session.commit()

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    assert [m for m in report.missing if m.record_type in ("A", "AAAA")] == []
    assert report.mismatched == []
    assert [(s.reason, s.ip_id, s.zone_id) for s in report.stale] == [
        ("default-gateway-name", ip.id, extra.id)
    ]
