"""#2942 — the record API refuses a TTL the zone's hosted provider cannot hold.

Publishing a stored 0 as 0 (rather than as a default) is right for BIND9,
PowerDNS, Windows, Route 53 and Google, and wrong for the providers that
cannot represent it: Cloudflare refuses the write (so the record never
publishes) and Vultr / Linode read 0 as "automatic" (so a different TTL
publishes). Neither is acceptable, so the API answers 422 up front.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import _check_driver_refusals
from app.core.security import create_access_token, hash_password
from app.drivers.dns import _DRIVERS, PROVIDER_TTL_RANGES, ttl_refusal
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone


def test_every_ranged_driver_is_registered() -> None:
    # A typo here would make the gate silently pass for that provider.
    assert set(PROVIDER_TTL_RANGES) <= set(_DRIVERS)


@pytest.mark.parametrize(
    ("driver", "ttl", "refused"),
    [
        ("cloudflare", 0, True),
        ("cloudflare", 1, True),  # "automatic" sentinel, not a 1 s TTL
        ("cloudflare", 30, False),
        ("cloudflare", 86400, False),
        ("cloudflare", 86401, True),
        ("vultr", 0, True),
        ("vultr", 1, False),
        ("linode", 0, True),
        ("azure_dns", 0, True),
        ("azure_dns", 1, False),
        ("digitalocean", 29, True),
        ("digitalocean", 30, False),
        ("hetzner", 59, True),
        ("hetzner", 60, False),
        # Drivers that publish 0 exactly are never gated.
        ("bind9", 0, False),
        ("powerdns", 0, False),
        ("route53", 0, False),
        ("google_dns", 0, False),
        ("windows_dns", 0, False),
    ],
)
def test_ttl_refusal(driver: str, ttl: int, refused: bool) -> None:
    assert (ttl_refusal(driver, ttl) is not None) is refused


@pytest.mark.parametrize("driver", sorted(PROVIDER_TTL_RANGES))
def test_inherit_is_never_refused(driver: str) -> None:
    assert ttl_refusal(driver, None) is None


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ttl-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TTL Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession, driver: str) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
    )
    db.add(zone)
    await db.flush()
    return zone


def _url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


@pytest.mark.asyncio
async def test_create_ttl_zero_on_cloudflare_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session, "cloudflare")
    resp = await client.post(
        _url(zone),
        headers=headers,
        json={"name": "www", "record_type": "A", "value": "192.0.2.1", "ttl": 0},
    )
    assert resp.status_code == 422, resp.text
    assert "30-86400" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_ttl_zero_on_bind9_is_kept(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session, "bind9")
    resp = await client.post(
        _url(zone),
        headers=headers,
        json={"name": "www", "record_type": "A", "value": "192.0.2.1", "ttl": 0},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["ttl"] == 0


@pytest.mark.asyncio
async def test_update_to_ttl_zero_on_vultr_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session, "vultr")
    row = DNSRecord(
        zone_id=zone.id,
        name="www",
        fqdn=f"www.{zone.name}",
        record_type="A",
        value="192.0.2.1",
        ttl=300,
    )
    db_session.add(row)
    await db_session.flush()
    resp = await client.put(f"{_url(zone)}/{row.id}", headers=headers, json={"ttl": 0})
    assert resp.status_code == 422, resp.text
    assert "vultr" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_bulk_create_ttl_zero_on_linode_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session, "linode")
    resp = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={
            "records": [
                {"name": "a", "record_type": "A", "value": "192.0.2.1"},
                {"name": "b", "record_type": "A", "value": "192.0.2.2", "ttl": 0},
            ]
        },
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_gate_passes_inherit_and_in_range(db_session: AsyncSession) -> None:
    zone = await _zone(db_session, "cloudflare")
    await _check_driver_refusals([("A", None, None), ("A", None, 300)], zone.group_id, db_session)
    with pytest.raises(HTTPException) as exc:
        await _check_driver_refusals([("A", None, None), ("A", None, 0)], zone.group_id, db_session)
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_gate_passes_an_empty_group(db_session: AsyncSession) -> None:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    await _check_driver_refusals([("A", None, 0)], grp.id, db_session)
