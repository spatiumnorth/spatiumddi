"""#3764 — catalog zones are producer-only for an agent group.

Since #170 every agent in a group receives every zone in its own bundle, so a
member that also consumed the catalog loaded each zone twice and named
refused the next ``rndc reconfig``. Only the group primary gets a catalog
block (the producer, published for secondaries outside the group); every
other member gets none.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns.agent_config import build_config_bundle


async def _group(db: AsyncSession, driver: str) -> tuple[DNSServer, DNSServer]:
    group = DNSServerGroup(
        name=f"g-{uuid.uuid4().hex[:6]}",
        description="",
        catalog_zones_enabled=True,
        catalog_zone_name="catalog.invalid.",
        tsig_key_name=f"spatium-{uuid.uuid4().hex[:6]}",
        tsig_key_secret_encrypted=encrypt_str("c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="),
    )
    db.add(group)
    await db.flush()
    producer = DNSServer(
        group_id=group.id,
        name="prod",
        driver=driver,
        host="ns1.example.com",
        port=53,
        is_primary=True,
        last_seen_ip="192.0.2.7",
        agent_id=uuid.uuid4(),
    )
    member = DNSServer(
        group_id=group.id,
        name="member",
        driver=driver,
        host="ns2.example.com",
        port=53,
        agent_id=uuid.uuid4(),
    )
    db.add_all([producer, member])
    db.add(
        DNSZone(
            group_id=group.id,
            name="a.test.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.a.test.",
            admin_email="hostmaster.a.test.",
        )
    )
    await db.flush()
    return producer, member


@pytest.mark.parametrize("driver", ["bind9", "powerdns", "technitium"])
async def test_non_primary_member_gets_no_catalog(db_session: AsyncSession, driver: str) -> None:
    _, member = await _group(db_session, driver)
    bundle = await build_config_bundle(db_session, member)
    assert bundle["catalog"] is None
    # ...while it still gets the zone the catalog would have listed.
    assert "a.test." in {z["name"] for z in bundle["zones"]}


async def test_primary_still_produces_the_catalog(db_session: AsyncSession) -> None:
    producer, _ = await _group(db_session, "bind9")
    bundle = await build_config_bundle(db_session, producer)
    assert bundle["catalog"] == {
        "mode": "producer",
        "zone_name": "catalog.invalid.",
        "members": [{"zone_name": "a.test."}],
    }
