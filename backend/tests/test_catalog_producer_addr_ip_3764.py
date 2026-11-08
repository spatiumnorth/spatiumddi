"""#3764 — the catalog consumer's ``producer_addr`` must be an IP literal.

BIND's ``catalog-zones { default-masters { … } }`` accepts only addresses; an
agent's ``host`` is usually a hostname, which made ``named-checkconf`` reject
the whole config.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _consumer_catalog(db: AsyncSession, host: str, last_seen_ip: str | None) -> dict | None:
    group = DNSServerGroup(
        name=f"g-{uuid.uuid4().hex[:6]}",
        description="",
        catalog_zones_enabled=True,
        catalog_zone_name="catalog.invalid.",
    )
    db.add(group)
    await db.flush()
    producer = DNSServer(
        group_id=group.id,
        name="prod",
        driver="bind9",
        host=host,
        port=53,
        is_primary=True,
        last_seen_ip=last_seen_ip,
    )
    consumer = DNSServer(group_id=group.id, name="cons", driver="bind9", host="10.9.9.9", port=53)
    db.add_all([producer, consumer])
    await db.flush()
    bundle = await build_config_bundle(db, consumer)
    return bundle["catalog"]


async def test_hostname_producer_uses_last_seen_ip(db_session: AsyncSession) -> None:
    cat = await _consumer_catalog(db_session, "ns1.example.com", "192.0.2.7")
    assert cat is not None and cat["mode"] == "consumer"
    assert cat["producer_addr"] == "192.0.2.7"


async def test_ip_host_passes_through(db_session: AsyncSession) -> None:
    cat = await _consumer_catalog(db_session, "192.0.2.5", "192.0.2.7")
    assert cat is not None and cat["producer_addr"] == "192.0.2.5"


async def test_unresolvable_producer_omits_addr(db_session: AsyncSession) -> None:
    cat = await _consumer_catalog(db_session, "ns1.example.com", None)
    assert cat is not None and cat["mode"] == "consumer"
    assert "producer_addr" not in cat
