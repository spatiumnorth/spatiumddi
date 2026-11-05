"""The other ways in to an address whose subnet is in the Trash (#3537).

The IPAM by-id routes are covered by ``test_ipam_address_trashed_subnet_3537``.
These are the sibling surfaces that also take an address id, or list
addresses with no subnet in the query, and so reached a trashed subnet's
addresses the same way: binding a BACnet / OT / DICOM descriptor, a multicast
membership or an nmap scan to one, reading the per-address sidecars, the
Ansible inventory, the copilot's ``find_ip``, and the routes the first test
stopped short of. And after a restore, nothing refused while the subnet was
in the Trash raises a new-device or squat alert.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertRule
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.alerts import (
    RULE_TYPE_NEW_MAC_SEEN,
    RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE,
    _matching_new_mac_seen_subjects,
    _matching_unknown_mac_in_static_range_subjects,
)
from tests.test_ipam_alias_cname_exclusive_2080 import _headers

MAC = "00:00:5e:00:53:c8"


async def _trashed_address(
    client: AsyncClient, db: AsyncSession, h: dict[str, str], status: str = "allocated"
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """(space_id, subnet_id, address_id), with the subnet already in the Trash."""
    for m in ("network.bacnet", "network.ot", "network.dicom", "network.multicast", "tools.nmap"):
        db.add(FeatureModule(id=m, enabled=True))
    space = IPSpace(name=f"sp3537s-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.84.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.84.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    ip = IPAddress(
        subnet_id=subnet.id, address="10.84.1.10", status=status, hostname="trashed-host"
    )
    db.add(ip)
    await db.commit()
    space_id, subnet_id, ip_id = space.id, subnet.id, ip.id
    r = await client.delete(f"/api/v1/ipam/subnets/{subnet_id}", headers=h)
    assert r.status_code == 204, r.text
    return space_id, subnet_id, ip_id


@pytest.mark.asyncio
async def test_descriptors_cannot_bind_to_a_trashed_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    space_id, _subnet_id, ip_id = await _trashed_address(client, db_session, h)
    ip = str(ip_id)

    creates = [
        (
            "/api/v1/bacnet/devices",
            {"ip_address_id": ip, "device_instance": 3537, "device_name": "AHU"},
        ),
        (
            "/api/v1/ot/devices",
            {"ip_address_id": ip, "ot_protocol": "modbus_tcp", "ot_role": "plc"},
        ),
        ("/api/v1/dicom/aes", {"ae_title": "TRASH3537", "ip_address_id": ip}),
        ("/api/v1/nmap/scans", {"target_ip": "", "ip_address_id": ip}),
    ]
    for url, body in creates:
        resp = await client.post(url, headers=h, json=body)
        assert resp.status_code == 422, (url, resp.status_code, resp.text)

    grp = await client.post(
        "/api/v1/multicast/groups",
        headers=h,
        json={"space_id": str(space_id), "address": "239.83.5.37", "name": "g3537"},
    )
    assert grp.status_code == 201, grp.text
    mem = await client.post(
        f"/api/v1/multicast/groups/{grp.json()['id']}/memberships",
        headers=h,
        json={"ip_address_id": ip, "role": "producer"},
    )
    assert mem.status_code == 422, mem.text

    for url in (
        f"/api/v1/bacnet/by-address/{ip}",
        f"/api/v1/ot/by-address/{ip}",
        f"/api/v1/dicom/by-address/{ip}",
    ):
        resp = await client.get(url, headers=h)
        assert resp.status_code == 404, (url, resp.status_code, resp.text)


@pytest.mark.asyncio
async def test_remaining_address_routes_are_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    _space_id, _subnet_id, ip_id = await _trashed_address(client, db_session, h)
    base = f"/api/v1/ipam/addresses/{ip_id}"
    for method, url in (
        ("POST", f"{base}/profile"),
        ("GET", f"{base}/dhcp-fingerprint"),
        ("DELETE", f"{base}/aliases/{uuid.uuid4()}"),
        ("POST", f"{base}/wake"),
    ):
        kw = {"json": {}} if method == "POST" else {}
        resp = await client.request(method, url, headers=h, **kw)
        assert resp.status_code == 404, (method, url, resp.status_code, resp.text)


@pytest.mark.asyncio
async def test_inventory_and_copilot_do_not_list_a_trashed_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ai.tools.ipam import FindIPArgs, find_ip

    h = await _headers(db_session)
    _space_id, _subnet_id, _ip_id = await _trashed_address(client, db_session, h)

    inv = await client.get("/api/v1/ansible/inventory", headers=h)
    assert inv.status_code == 200, inv.text
    assert "trashed-host" not in inv.json()["_meta"]["hostvars"]
    assert "10.84.1.10" not in inv.json()["_meta"]["hostvars"]

    from app.models.auth import User

    admin = (await db_session.execute(select(User).where(User.is_superadmin))).scalars().first()
    assert admin is not None
    out = await find_ip(db_session, admin, FindIPArgs(address="10.84.1.10"))
    assert out == {"matches": []}, out


@pytest.mark.asyncio
async def test_no_alert_after_restore_for_a_mac_refused_in_the_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's alert half: the refused PUT leaves nothing for the
    new-MAC-seen or squat rule to find once the subnet is back."""
    h = await _headers(db_session)
    _space_id, subnet_id, ip_id = await _trashed_address(client, db_session, h, "reserved")

    put = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=h, json={"mac_address": MAC})
    assert put.status_code == 404, put.text
    rr = await client.post(f"/api/v1/admin/trash/subnet/{subnet_id}/restore", headers=h)
    assert rr.status_code == 200, rr.text

    db_session.expire_all()
    new_mac = AlertRule(
        name="n", rule_type=RULE_TYPE_NEW_MAC_SEEN, severity="info", threshold_days=7
    )
    squat = AlertRule(
        name="q", rule_type=RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE, severity="info", threshold_days=7
    )
    seen = {sid for sid, _d, _m in await _matching_new_mac_seen_subjects(db_session, new_mac)}
    squats = {
        sid
        for sid, _d, _m in await _matching_unknown_mac_in_static_range_subjects(db_session, squat)
    }
    # new_mac_seen keys its subject ``<ip id>:<mac>``; the squat rule the ip id.
    assert not [sid for sid in seen | squats if sid.startswith(str(ip_id))], (seen, squats)
