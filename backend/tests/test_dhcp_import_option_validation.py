"""The DHCP importer holds options to the scope API's save-time check (#3730).

``validate_options`` refuses a name the platform does not map and a value Kea
cannot load; the import commit stored both, and the second reached the
rendered Kea config, whose load then fails for the whole server group. The
importer's convention for an invalid item is to drop it, keep the scope and
name the item in the warnings, on the preview and again on the commit.
"""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPClientClass, DHCPScope, DHCPStaticAssignment
from tests.test_dhcp_import import _make_admin, _make_block, _make_group, _make_space

_CONF = json.dumps(
    {
        "Dhcp4": {
            "subnet4": [
                {
                    "subnet": "192.0.2.0/24",
                    "pools": [{"pool": "192.0.2.10 - 192.0.2.50"}],
                    "option-data": [
                        {"name": "dhcp-renewal-time", "data": "300"},
                        {"name": "routers", "data": "10.250.4.999"},
                        {"name": "ntp-servers", "data": "192.0.2.1"},
                    ],
                    "reservations": [
                        {
                            "hw-address": "aa:bb:cc:dd:ee:01",
                            "ip-address": "192.0.2.20",
                            "option-data": [
                                {"name": "routers", "data": "10.250.4.999"},
                                {"name": "ntp-servers", "data": "192.0.2.2"},
                            ],
                        }
                    ],
                }
            ],
            "client-classes": [
                {
                    "name": "voip",
                    "test": "option[60].exists",
                    "option-data": [
                        {"name": "dhcp-renewal-time", "data": "300"},
                        {"name": "ntp-servers", "data": "192.0.2.3"},
                    ],
                }
            ],
        }
    }
).encode()


async def _setup(db_session: AsyncSession):
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    await db_session.commit()
    return token, group, space, block


async def _preview(client, token, group, space) -> dict:
    resp = await client.post(
        "/api/v1/dhcp/import/kea/preview",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("kea.conf", _CONF, "application/json")},
        data={"target_group_id": str(group.id), "ipam_space_id": str(space.id)},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _refused(warnings: list[str]) -> list[str]:
    return [w for w in warnings if "not imported" in w and "option" in w]


@pytest.mark.asyncio
async def test_preview_names_every_refused_option(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token, group, space, _ = await _setup(db_session)
    body = await _preview(client, token, group, space)
    w = _refused(body["warnings"])
    assert any("192.0.2.0/24: option 'dhcp-renewal-time'" in x for x in w), w
    assert any("192.0.2.0/24: option 'routers'" in x and "10.250.4.999" in x for x in w), w
    assert any("reservation 192.0.2.20" in x and "'routers'" in x for x in w), w
    assert any("client class 'voip'" in x and "dhcp-renewal-time" in x for x in w), w
    scope = body["scopes"][0]
    assert set(scope["options"]) == {"ntp-servers"}
    assert set(scope["reservations"][0]["options"]) == {"ntp-servers"}
    assert set(body["client_classes"][0]["options"]) == {"ntp-servers"}


@pytest.mark.asyncio
async def test_commit_does_not_store_refused_options(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token, group, space, block = await _setup(db_session)
    preview = await _preview(client, token, group, space)
    # A plan edited on the way back: the commit re-checks what the client sends.
    preview["scopes"][0]["options"].update({"dhcp-renewal-time": "300", "routers": "10.250.4.999"})
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": preview,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    scope = (await db_session.execute(select(DHCPScope))).scalars().one()
    assert set(scope.options) == {"ntp-servers"}
    static = (await db_session.execute(select(DHCPStaticAssignment))).scalars().one()
    assert set(static.options_override) == {"ntp-servers"}
    cc = (await db_session.execute(select(DHCPClientClass))).scalars().one()
    assert set(cc.options) == {"ntp-servers"}
    assert any("'routers'" in x for x in _refused(resp.json()["warnings"]))


_RAW_CONF = json.dumps(
    {
        "Dhcp4": {
            "subnet4": [
                {
                    "subnet": "192.0.2.0/24",
                    "pools": [{"pool": "192.0.2.10 - 192.0.2.50"}],
                    "option-data": [{"code": 43, "data": "zz"}, {"code": 43, "data": "0a0b"}],
                    "reservations": [
                        {
                            "hw-address": "aa:bb:cc:dd:ee:01",
                            "ip-address": "192.0.2.20",
                            "option-data": [{"code": 43, "data": "zz"}],
                        }
                    ],
                }
            ],
            "client-classes": [
                {
                    "name": "voip",
                    "test": "option[60].exists",
                    "option-data": [{"code": 43, "data": "zz"}],
                }
            ],
        }
    }
).encode()


@pytest.mark.asyncio
async def test_raw_code_with_a_bad_value_is_dropped_on_every_owner(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """``code:NN`` keys skip the name check but must not skip the value check."""
    token, group, space, block = await _setup(db_session)
    resp = await client.post(
        "/api/v1/dhcp/import/kea/preview",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("kea.conf", _RAW_CONF, "application/json")},
        data={"target_group_id": str(group.id), "ipam_space_id": str(space.id)},
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    # Force a known-bad value into every owner, whatever the parser kept.
    plan["scopes"][0]["options"] = {"code:43": "zz"}
    plan["scopes"][0]["reservations"][0]["options"] = {"code:43": "zz"}
    plan["client_classes"][0]["options"] = {"code:43": "zz"}
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": plan,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    scope = (await db_session.execute(select(DHCPScope))).scalars().one()
    assert not scope.options
    static = (await db_session.execute(select(DHCPStaticAssignment))).scalars().one()
    assert not static.options_override
    cc = (await db_session.execute(select(DHCPClientClass))).scalars().one()
    assert not cc.options
    assert sum("code:43" in w for w in resp.json()["warnings"]) >= 3


_ISC = b"""
subnet 192.0.2.0 netmask 255.255.255.0 {
  range 192.0.2.10 192.0.2.50;
  option routers 10.250.4.999;
  option dhcp-renewal-time 300;
  option domain-name-servers 192.0.2.1;
  host h1 { hardware ethernet aa:bb:cc:dd:ee:01; fixed-address 192.0.2.20;
            option routers 10.250.4.999; option ntp-servers 192.0.2.2; }
}
"""


@pytest.mark.asyncio
async def test_isc_import_drops_refused_options(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token, group, space, block = await _setup(db_session)
    headers = {"Authorization": f"Bearer {token}"}
    resp = await client.post(
        "/api/v1/dhcp/import/isc/preview",
        headers=headers,
        files={"file": ("dhcpd.conf", _ISC, "text/plain")},
        data={"target_group_id": str(group.id), "ipam_space_id": str(space.id)},
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    w = _refused(plan["warnings"])
    assert any("'routers'" in x for x in w) and any("'dhcp-renewal-time'" in x for x in w), w
    assert set(plan["scopes"][0]["options"]) == {"dns-servers"}
    resp = await client.post(
        "/api/v1/dhcp/import/isc/commit",
        headers=headers,
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": plan,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    scope = (await db_session.execute(select(DHCPScope))).scalars().one()
    assert set(scope.options) == {"dns-servers"}
    static = (await db_session.execute(select(DHCPStaticAssignment))).scalars().one()
    assert set(static.options_override) == {"ntp-servers"}
