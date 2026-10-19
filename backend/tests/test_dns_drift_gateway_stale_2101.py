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
