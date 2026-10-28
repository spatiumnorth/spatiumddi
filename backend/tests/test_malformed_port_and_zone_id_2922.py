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


@pytest.mark.asyncio
async def test_group_ids_not_uuid_is_422(client: AsyncClient, db_session: AsyncSession):
    headers, sid, _zone = await _setup(client, db_session)
    sub = await db_session.get(Subnet, uuid.UUID(sid))
    assert sub is not None
    space_id = str(sub.space_id)
    r = await client.post(
        "/api/v1/ipam/spaces", headers=headers, json={"name": "gid", "dns_group_ids": [NOT_UUID]}
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/spaces/{space_id}", headers=headers, json={"dns_group_ids": [NOT_UUID]}
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/subnets/{sid}",
        headers=headers,
        json={"dns_additional_zone_ids": [NOT_UUID]},
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_empty_zone_on_subnet_update_does_not_flip_inheritance(
    client: AsyncClient, db_session: AsyncSession
):
    """``""`` on a subnet update is "no zone", stored as null; it is not a
    binding, so it leaves ``dns_inherit_settings`` as it was (#1066)."""
    headers, sid, _zone = await _setup(client, db_session)
    r = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"dns_zone_id": ""})
    assert r.status_code == 200, r.text
    assert r.json()["dns_zone_id"] is None
    assert r.json()["dns_inherit_settings"] is False
    # And an inheriting subnet stays inheriting.
    sub = await db_session.get(Subnet, uuid.UUID(sid))
    assert sub is not None
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(sub.space_id),
            "block_id": str(sub.block_id),
            "network": "10.97.6.0/24",
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["dns_inherit_settings"] is True
    r = await client.put(
        f"/api/v1/ipam/subnets/{r.json()['id']}", headers=headers, json={"dns_zone_id": ""}
    )
    assert r.status_code == 200, r.text
    assert r.json()["dns_zone_id"] is None
    assert r.json()["dns_inherit_settings"] is True


@pytest.mark.asyncio
async def test_legacy_non_uuid_binding_reads_as_no_zone(
    client: AsyncClient, db_session: AsyncSession
):
    """A value an older build stored is not re-validated by an unrelated
    write, and the effective-DNS walk reads it as no zone instead of 500."""
    headers, _sid, _zone = await _setup(client, db_session)
    space = IPSpace(
        name=f"legacy-{uuid.uuid4().hex[:6]}",
        description="",
        dns_zone_id=NOT_UUID,
        dns_group_ids=[NOT_UUID],
        dns_additional_zone_ids=[NOT_UUID],
    )
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.98.0.0/16", name="lb", dns_zone_id=NOT_UUID)
    db_session.add(block)
    await db_session.commit()
    space_id, block_id = str(space.id), str(block.id)

    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": "10.98.1.0/24",
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    sub_id = r.json()["id"]

    r = await client.put(
        f"/api/v1/ipam/spaces/{space_id}", headers=headers, json={"description": "x"}
    )
    assert r.status_code == 200, r.text
    r = await client.put(
        f"/api/v1/ipam/blocks/{block_id}", headers=headers, json={"description": "x"}
    )
    assert r.status_code == 200, r.text
    r = await client.get(f"/api/v1/ipam/subnets/{sub_id}/effective-dns", headers=headers)
    assert r.status_code == 200, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sub_id}/next", headers=headers, json={"hostname": "legacy"}
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_template_zone_id_not_uuid_is_422(client: AsyncClient, db_session: AsyncSession):
    headers, _sid, zone = await _setup(client, db_session)
    base = {"name": f"t-{uuid.uuid4().hex[:6]}", "applies_to": "subnet"}
    r = await client.post(
        "/api/v1/ipam/templates", headers=headers, json={**base, "dns_zone_id": NOT_UUID}
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/ipam/templates",
        headers=headers,
        json={**base, "dns_additional_zone_ids": [NOT_UUID]},
    )
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/ipam/templates", headers=headers, json={**base, "dns_zone_id": str(zone.id)}
    )
    assert r.status_code == 201, r.text
    r = await client.put(
        f"/api/v1/ipam/templates/{r.json()['id']}",
        headers=headers,
        json={"dns_zone_id": NOT_UUID},
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["dns_zone_id", "dns_group_id", "dhcp_server_group_id", "vlan_ref_id"]
)
async def test_plan_binding_not_uuid_is_a_conflict(
    client: AsyncClient, db_session: AsyncSession, field: str
):
    """A plan node's resource ids are checked before apply: a non-UUID used
    to be stored onto the new row (zone, group) or raise a 500 (the rest)."""
    headers, _sid, _zone = await _setup(client, db_session)
    space = IPSpace(name=f"plan-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.commit()
    tree = {
        "id": "root",
        "network": "10.99.0.0/16",
        "kind": "block",
        "children": [{"id": "s1", "network": "10.99.1.0/24", "kind": "subnet", field: NOT_UUID}],
    }
    r = await client.post(
        "/api/v1/ipam/plans",
        headers=headers,
        json={"name": "p", "space_id": str(space.id), "tree": tree},
    )
    assert r.status_code == 201, r.text
    plan_id = r.json()["id"]
    r = await client.post(f"/api/v1/ipam/plans/{plan_id}/validate", headers=headers)
    assert r.status_code == 200, r.text
    kinds = {c["kind"] for c in r.json()["conflicts"]}
    assert "invalid_binding" in kinds, r.json()
    r = await client.post(f"/api/v1/ipam/plans/{plan_id}/apply", headers=headers)
    assert r.status_code == 409, r.text


@pytest.mark.parametrize("bad", ["²", "١٢", "²²²"])
def test_non_ascii_digits_never_reach_int(bad: str):
    """The other ``str.isdigit()`` → ``int()`` sites: a superscript passes
    ``isdigit`` and crashes ``int``; each now reads it as "not a number"."""
    from app.core.dns_names import bind_check_names_error
    from app.drivers.dns._cloud_base import split_structured_rdata
    from app.services.dns.sync_check import reverse_zone_network
    from app.services.technitium.rdata import _svcb_key_num, _svcb_norm_key

    assert split_structured_rdata("MX", f"{bad} mail.example.") == (
        f"{bad} mail.example.",
        None,
        None,
        None,
    )
    assert split_structured_rdata("SRV", f"{bad} 1 1 t.example.")[1] is None
    assert reverse_zone_network(f"{bad}.10.in-addr.arpa") is None
    assert _svcb_norm_key(bad) == bad
    assert _svcb_key_num(f"key{bad}") == 65536
    # Must not raise.
    bind_check_names_error("SVCB", "_x.example.", f"{bad} target.example.", origin="example.")
