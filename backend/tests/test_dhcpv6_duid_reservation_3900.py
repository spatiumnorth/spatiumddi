"""DUID-keyed DHCPv6 reservations, from the DHCP dialog and from IPAM (#3900).

A DHCPv6 client is identified by its DUID. The reservation model carried one
(#368) but required a MAC as well, and an IPAM address row had nowhere to hold
one, so a v6 reservation made from IPAM could not be keyed on the DUID.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dhcp.base import StaticAssignmentDef
from app.drivers.dhcp.kea import _render_reservation
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam_io.importer import commit_address_import
from app.services.ipam_io.parser import ParsedPayload

MAC = "aa:bb:cc:dd:ee:01"
DUID = "00:01:00:01:2a:3b:4c:5d:aa:bb:cc:dd:ee:01"


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"s-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dual_stack(db: AsyncSession) -> tuple[DHCPScope, DHCPScope]:
    """One DHCP group serving a v4 and a v6 subnet: the dual-stack shape."""
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    b4 = IPBlock(space_id=space.id, network="172.16.0.0/16", name="b4")
    b6 = IPBlock(space_id=space.id, network="2a11:6c7:1100::/48", name="b6")
    db.add_all([b4, b6])
    await db.flush()
    s4 = Subnet(space_id=space.id, block_id=b4.id, network="172.16.10.0/24", name="v4")
    s6 = Subnet(space_id=space.id, block_id=b6.id, network="2a11:6c7:1100:6e84::/64", name="v6")
    db.add_all([s4, s6])
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(DHCPServer(name="k", driver="kea", host="127.0.0.1", server_group_id=group.id))
    sc4 = DHCPScope(group_id=group.id, subnet_id=s4.id, name="sc4", address_family="ipv4")
    sc6 = DHCPScope(group_id=group.id, subnet_id=s6.id, name="sc6", address_family="ipv6")
    db.add_all([sc4, sc6])
    await db.flush()
    return sc4, sc6


async def _all(db: AsyncSession) -> list[DHCPStaticAssignment]:
    return list((await db.execute(select(DHCPStaticAssignment))).scalars().all())


@pytest.mark.asyncio
async def test_v6_static_with_only_a_duid_is_created(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    scope_id = sc6.id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={
            "ip_address": "2a11:6c7:1100:6e84::45",
            "duid": "000100012A3B4C5D-AABBCCDDEE01".replace("-", ""),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["mac_address"] is None
    assert body["duid"] == DUID  # canonical colon-hex


@pytest.mark.asyncio
async def test_v4_static_still_needs_a_mac_and_refuses_a_duid(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    sc4, _ = await _dual_stack(db_session)
    scope_id = sc4.id
    await db_session.commit()
    url = f"/api/v1/dhcp/scopes/{scope_id}/statics"

    no_mac = await client.post(url, headers=headers, json={"ip_address": "172.16.10.45"})
    assert no_mac.status_code == 422
    assert "MAC" in no_mac.text

    duid_only = await client.post(
        url, headers=headers, json={"ip_address": "172.16.10.45", "duid": DUID}
    )
    assert duid_only.status_code == 422
    assert "DHCPv6" in duid_only.text


@pytest.mark.asyncio
async def test_v6_static_needs_a_duid_or_a_mac(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    scope_id = sc6.id
    await db_session.commit()
    url = f"/api/v1/dhcp/scopes/{scope_id}/statics"

    neither = await client.post(url, headers=headers, json={"ip_address": "2a11:6c7:1100:6e84::45"})
    assert neither.status_code == 422

    mac_only = await client.post(
        url, headers=headers, json={"ip_address": "2a11:6c7:1100:6e84::46", "mac_address": MAC}
    )
    assert mac_only.status_code == 201, mac_only.text
    assert mac_only.json()["duid"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", ["zz:zz:zz", "00:01", "00:01:0", "00:01:00:01:" + ":".join(["aa"] * 130)]
)
async def test_bad_duid_is_a_422(client: AsyncClient, db_session: AsyncSession, bad: str) -> None:
    _, headers = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    scope_id = sc6.id
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": "2a11:6c7:1100:6e84::45", "duid": bad},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_duplicate_duid_in_a_scope_is_a_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    scope_id = sc6.id
    await db_session.commit()
    url = f"/api/v1/dhcp/scopes/{scope_id}/statics"
    first = await client.post(
        url, headers=headers, json={"ip_address": "2a11:6c7:1100:6e84::45", "duid": DUID}
    )
    assert first.status_code == 201
    # Same DUID, spelled differently, at another address.
    dup = await client.post(
        url,
        headers=headers,
        json={"ip_address": "2a11:6c7:1100:6e84::46", "duid": DUID.replace(":", "-").upper()},
    )
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_same_mac_on_a_v4_and_a_v6_scope_is_one_dual_stack_host(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The v4 and the v6 reservation of one host share a MAC without a 409."""
    _, headers = await _admin(db_session)
    sc4, sc6 = await _dual_stack(db_session)
    id4, id6 = sc4.id, sc6.id
    await db_session.commit()
    r4 = await client.post(
        f"/api/v1/dhcp/scopes/{id4}/statics",
        headers=headers,
        json={"ip_address": "172.16.10.45", "mac_address": MAC, "hostname": "archibald-pc"},
    )
    r6 = await client.post(
        f"/api/v1/dhcp/scopes/{id6}/statics",
        headers=headers,
        json={
            "ip_address": "2a11:6c7:1100:6e84::45",
            "mac_address": MAC,
            "hostname": "archibald-pc",
        },
    )
    assert r4.status_code == 201, r4.text
    assert r6.status_code == 201, r6.text
    # ...but a second v4 reservation on that MAC is still refused.
    dup = await client.post(
        f"/api/v1/dhcp/scopes/{id4}/statics",
        headers=headers,
        json={"ip_address": "172.16.10.46", "mac_address": MAC},
    )
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_update_can_swap_a_v6_mac_for_a_duid_but_not_clear_both(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    scope_id = sc6.id
    await db_session.commit()
    created = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": "2a11:6c7:1100:6e84::45", "mac_address": MAC},
    )
    sid = created.json()["id"]
    swapped = await client.put(
        f"/api/v1/dhcp/statics/{sid}", headers=headers, json={"duid": DUID, "mac_address": None}
    )
    assert swapped.status_code == 200, swapped.text
    assert swapped.json()["mac_address"] is None
    assert swapped.json()["duid"] == DUID
    cleared = await client.put(f"/api/v1/dhcp/statics/{sid}", headers=headers, json={"duid": None})
    assert cleared.status_code == 422


@pytest.mark.asyncio
async def test_ipam_static_dhcp_v6_address_with_a_duid_mirrors_a_duid_reservation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    sc4, sc6 = await _dual_stack(db_session)
    v6_subnet = sc6.subnet_id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{v6_subnet}/addresses",
        headers=headers,
        json={
            "address": "2a11:6c7:1100:6e84::45",
            "status": "static_dhcp",
            "hostname": "archibald-pc",
            "duid": DUID.upper(),
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["duid"] == DUID
    assert resp.json().get("dhcp_static_warning") is None
    statics = await _all(db_session)
    assert len(statics) == 1
    assert statics[0].mac_address is None
    assert statics[0].duid == DUID
    assert str(statics[0].ip_address) == "2a11:6c7:1100:6e84::45"


@pytest.mark.asyncio
async def test_ipam_static_dhcp_v6_without_any_identifier_is_refused_with_the_v6_wording(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    sc4, sc6 = await _dual_stack(db_session)
    v4_subnet, v6_subnet = sc4.subnet_id, sc6.subnet_id
    await db_session.commit()
    v6 = await client.post(
        f"/api/v1/ipam/subnets/{v6_subnet}/addresses",
        headers=headers,
        json={"address": "2a11:6c7:1100:6e84::45", "status": "static_dhcp", "hostname": "h"},
    )
    assert v6.status_code == 422
    assert "duid" in v6.text
    v4 = await client.post(
        f"/api/v1/ipam/subnets/{v4_subnet}/addresses",
        headers=headers,
        json={"address": "172.16.10.45", "status": "static_dhcp", "hostname": "h", "duid": DUID},
    )
    assert v4.status_code == 422  # a DUID on an IPv4 address matches nothing


@pytest.mark.asyncio
async def test_ipam_edit_adds_a_duid_to_an_existing_v6_reservation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    v6_subnet = sc6.subnet_id
    await db_session.commit()
    created = await client.post(
        f"/api/v1/ipam/subnets/{v6_subnet}/addresses",
        headers=headers,
        json={
            "address": "2a11:6c7:1100:6e84::45",
            "status": "static_dhcp",
            "hostname": "h",
            "mac_address": MAC,
        },
    )
    assert created.status_code == 201, created.text
    ip_id = created.json()["id"]
    upd = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"duid": DUID})
    assert upd.status_code == 200, upd.text
    db_session.expire_all()
    statics = await _all(db_session)
    assert len(statics) == 1
    assert statics[0].duid == DUID
    assert str(statics[0].mac_address) == MAC


@pytest.mark.asyncio
async def test_csv_import_duid_column_creates_a_duid_reservation(
    db_session: AsyncSession,
) -> None:
    user, _ = await _admin(db_session)
    _, sc6 = await _dual_stack(db_session)
    await db_session.flush()
    result = await commit_address_import(
        db_session,
        ParsedPayload(
            addresses=[
                {
                    "address": "2a11:6c7:1100:6e84::45",
                    "status": "static_dhcp",
                    "hostname": "h",
                    "duid": DUID,
                }
            ]
        ),
        subnet_id=sc6.subnet_id,
        strategy="fail",
        current_user=user,
    )
    assert result.created == 1, result.errors
    statics = await _all(db_session)
    assert [s.duid for s in statics] == [DUID]
    ip = (await db_session.execute(select(IPAddress))).scalars().first()
    assert ip is not None and ip.duid == DUID


def test_kea_renders_a_duid_only_v6_reservation_on_duid() -> None:
    r = _render_reservation(
        StaticAssignmentDef(ip_address="2a11::45", mac_address=None, duid=DUID),
        address_family="ipv6",
    )
    assert r == {"duid": DUID, "ip-addresses": ["2a11::45"]}


def test_kea_renders_a_mac_only_v6_reservation_on_hw_address() -> None:
    r = _render_reservation(
        StaticAssignmentDef(ip_address="2a11::45", mac_address=MAC), address_family="ipv6"
    )
    assert r == {"hw-address": MAC, "ip-addresses": ["2a11::45"]}
