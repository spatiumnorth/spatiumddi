"""A service's summary and attach follow the grants on the attached rows.

A ``NetworkService`` points at VRFs, circuits, sites and subnets, each of
which has its own router and its own ``read`` grant. The service routes are
gated on ``network_service`` alone, so:

* ``GET /services/{id}/summary`` fills its L3VPN sections only with rows the
  caller may read, and counts the rest in ``withheld`` with no name, id or
  value;
* ``POST /services/{id}/resources`` needs ``read`` on the row being attached.

The built-in IPAM Editor holds admin on ``network_service`` but nothing on
``vrf`` or ``circuit``, which is the role these tests use.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.auth import Group, Role, User
from app.models.circuit import Circuit
from app.models.network_service import NetworkService, NetworkServiceResource
from app.models.ownership import Customer, Provider, Site
from app.models.vrf import VRF

pytestmark = pytest.mark.asyncio


async def _headers(
    db: AsyncSession, permissions: list[dict[str, Any]], *, superadmin: bool = False
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"svc-{tag}",
        email=f"{tag}@example.test",
        display_name="Service user",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    r = Role(name=f"r-{tag}", description="", permissions=permissions)
    g = Group(name=f"g-{tag}", description="")
    g.roles = [r]
    g.users = [user]
    db.add_all([r, g, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _ipam_editor() -> list[dict[str, Any]]:
    return list(_BUILTIN_ROLES["IPAM Editor"][1])


async def _l3vpn(db: AsyncSession) -> dict[str, Any]:
    tag = uuid.uuid4().hex[:6]
    customer = Customer(name=f"cust-{tag}")
    provider = Provider(name=f"prov-{tag}")
    vrf = VRF(
        name=f"vrf-{tag}",
        route_distinguisher="65000:98",
        import_targets=["65000:98"],
        export_targets=["65000:99"],
    )
    site_a = Site(name=f"site-a-{tag}", code="SA")
    site_b = Site(name=f"site-b-{tag}", code="SB")
    db.add_all([customer, provider, vrf, site_a, site_b])
    await db.flush()
    ckt = Circuit(
        name=f"ckt-{tag}",
        ckt_id="XP-98",
        provider_id=provider.id,
        transport_class="internet_broadband",
        bandwidth_mbps_down=500,
        bandwidth_mbps_up=100,
    )
    db.add(ckt)
    await db.flush()
    svc = NetworkService(name=f"svc-{tag}", kind="mpls_l3vpn", customer_id=customer.id)
    db.add(svc)
    await db.flush()
    for kind, rid in (
        ("vrf", vrf.id),
        ("circuit", ckt.id),
        ("site", site_a.id),
        ("site", site_b.id),
    ):
        db.add(NetworkServiceResource(service_id=svc.id, resource_kind=kind, resource_id=rid))
    await db.flush()
    return {"svc": svc, "vrf": vrf, "ckt": ckt, "customer": customer}


async def test_ipam_editor_summary_withholds_vrf_and_circuits(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = await _l3vpn(db_session)
    headers = await _headers(db_session, _ipam_editor())

    # The direct reads refuse this role.
    assert (await client.get(f"/api/v1/vrfs/{rows['vrf'].id}", headers=headers)).status_code == 403

    resp = await client.get(f"/api/v1/services/{rows['svc'].id}/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["vrf"] is None
    assert body["edge_circuits"] == []
    assert body["withheld"] == {"vrf": 1, "edge_circuits": 1}
    # Sites are readable to the IPAM Editor and stay in the answer.
    assert len(body["edge_sites"]) == 2
    # A withheld VRF is not reported as missing.
    assert not any("no VRF attached" in w for w in body["warnings"])
    text = resp.text
    for value in ("65000:98", "65000:99", "XP-98", rows["vrf"].name, rows["ckt"].name):
        assert value not in text
    assert str(rows["vrf"].id) not in text
    assert str(rows["ckt"].id) not in text


async def test_reader_of_vrf_and_circuit_gets_the_sections(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = await _l3vpn(db_session)
    headers = await _headers(
        db_session,
        _ipam_editor()
        + [
            {"action": "read", "resource_type": "vrf"},
            {"action": "read", "resource_type": "circuit"},
        ],
    )
    resp = await client.get(f"/api/v1/services/{rows['svc'].id}/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["withheld"] == {}
    assert body["vrf"]["route_distinguisher"] == "65000:98"
    assert body["vrf"]["export_targets"] == ["65000:99"]
    assert [c["ckt_id"] for c in body["edge_circuits"]] == ["XP-98"]
    assert body["edge_circuits"][0]["bandwidth_mbps_down"] == 500


async def test_a_grant_on_one_vrf_shows_only_that_vrf(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = await _l3vpn(db_session)
    other = await _headers(
        db_session,
        _ipam_editor()
        + [{"action": "read", "resource_type": "vrf", "resource_id": str(uuid.uuid4())}],
    )
    body = (await client.get(f"/api/v1/services/{rows['svc'].id}/summary", headers=other)).json()
    assert body["vrf"] is None and body["withheld"]["vrf"] == 1

    this = await _headers(
        db_session,
        _ipam_editor()
        + [{"action": "read", "resource_type": "vrf", "resource_id": str(rows["vrf"].id)}],
    )
    body = (await client.get(f"/api/v1/services/{rows['svc'].id}/summary", headers=this)).json()
    assert body["vrf"]["name"] == rows["vrf"].name
    assert "vrf" not in body["withheld"]


async def test_superadmin_summary_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = await _l3vpn(db_session)
    auth_headers = await _headers(db_session, [], superadmin=True)
    resp = await client.get(f"/api/v1/services/{rows['svc'].id}/summary", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["withheld"] == {}
    assert body["vrf"]["route_distinguisher"] == "65000:98"
    assert len(body["edge_circuits"]) == 1


async def test_attaching_a_vrf_needs_read_on_vrf(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = await _l3vpn(db_session)
    other_vrf = VRF(name=f"vrf-x-{uuid.uuid4().hex[:6]}", route_distinguisher="65000:7")
    db_session.add(other_vrf)
    svc = NetworkService(
        name=f"svc-own-{uuid.uuid4().hex[:6]}", kind="mpls_l3vpn", customer_id=rows["customer"].id
    )
    db_session.add(svc)
    await db_session.flush()

    editor = await _headers(db_session, _ipam_editor())
    resp = await client.post(
        f"/api/v1/services/{svc.id}/resources",
        json={"resource_kind": "vrf", "resource_id": str(other_vrf.id)},
        headers=editor,
    )
    assert resp.status_code == 403, resp.text

    # An id that does not exist answers the same, so the refusal says nothing
    # about which VRF ids exist.
    resp = await client.post(
        f"/api/v1/services/{svc.id}/resources",
        json={"resource_kind": "vrf", "resource_id": str(uuid.uuid4())},
        headers=editor,
    )
    assert resp.status_code == 403, resp.text

    # Attaching a kind the role does read still works.
    site = Site(name=f"site-own-{uuid.uuid4().hex[:6]}")
    db_session.add(site)
    await db_session.flush()
    resp = await client.post(
        f"/api/v1/services/{svc.id}/resources",
        json={"resource_kind": "site", "resource_id": str(site.id)},
        headers=editor,
    )
    assert resp.status_code == 200, resp.text

    reader = await _headers(
        db_session, _ipam_editor() + [{"action": "read", "resource_type": "vrf"}]
    )
    resp = await client.post(
        f"/api/v1/services/{svc.id}/resources",
        json={"resource_kind": "vrf", "resource_id": str(other_vrf.id)},
        headers=reader,
    )
    assert resp.status_code == 200, resp.text
