"""A malformed port or zone id answers a 4xx, never a 500 (#2922, #2923)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dns.named_conf_validation import ViewValidationError, _validate_port
from tests.test_dns_zone_named_conf_validation import _group, _superadmin
from tests.test_ipam_zone_none_2466 import _setup

NOT_UUID = "not-a-uuid"


@pytest.mark.parametrize("port", ["²", "٣", "①", "99999", "0", "x"])
def test_validate_port_refuses_non_ascii_and_out_of_range(port: str):
    with pytest.raises(ViewValidationError):
        _validate_port(port, field="f", element="e")


@pytest.mark.parametrize("port", ["53", "5353", "65535"])
def test_validate_port_accepts_ascii(port: str):
    _validate_port(port, field="f", element="e")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"zone_type": "forward", "forwarders": ["192.0.2.1@²"]},
        {"zone_type": "forward", "forwarders": ["192.0.2.1 port ²"]},
        {"zone_type": "forward", "forwarders": ["192.0.2.1@99999"]},
        {"also_notify": ["192.0.2.1 port ²"]},
    ],
)
async def test_zone_port_is_422(client: AsyncClient, db_session: AsyncSession, payload):
    headers = await _superadmin(db_session)
    group: DNSServerGroup = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={"name": "example.com", **payload},
        headers=headers,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_zone_port_positive_control(client: AsyncClient, db_session: AsyncSession):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={"name": "example.com", "also_notify": ["192.0.2.1 port 5353"]},
        headers=headers,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_ipam_zone_id_not_uuid_is_422_everywhere(
    client: AsyncClient, db_session: AsyncSession
):
    headers, sid, zone = await _setup(client, db_session)
    sub = await db_session.get(Subnet, uuid.UUID(sid))
    assert sub is not None
    space_id, block_id = str(sub.space_id), str(sub.block_id)

    r = await client.post(
        "/api/v1/ipam/spaces", headers=headers, json={"name": "zid-space", "dns_zone_id": NOT_UUID}
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=headers,
        json={"space_id": space_id, "network": "198.51.100.0/24", "dns_zone_id": NOT_UUID},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h3", "dns_zone_id": NOT_UUID},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.97.5.60", "dns_zone_id": NOT_UUID},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h4", "extra_zone_ids": [NOT_UUID]},
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/blocks/{block_id}", headers=headers, json={"dns_zone_id": NOT_UUID}
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/spaces/{space_id}", headers=headers, json={"dns_zone_id": NOT_UUID}
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"dns_zone_id": NOT_UUID}
    )
    assert r.status_code == 422, r.text
    assert await db_session.get(IPSpace, uuid.UUID(space_id)) is not None
    assert await db_session.get(IPBlock, uuid.UUID(block_id)) is not None


@pytest.mark.asyncio
async def test_ipam_zone_id_positive_controls(client: AsyncClient, db_session: AsyncSession):
    headers, sid, zone = await _setup(client, db_session)
    r = await client.post(
        "/api/v1/ipam/spaces", headers=headers, json={"name": "zid-ok", "dns_zone_id": str(zone.id)}
    )
    assert r.status_code == 201, r.text
    assert r.json()["dns_zone_id"] == str(zone.id)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h5", "dns_zone_id": str(zone.id)},
    )
    assert r.status_code == 201, r.text
    # "" keeps meaning "no DNS record" on an address.
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h6", "dns_zone_id": ""},
    )
    assert r.status_code == 201, r.text
