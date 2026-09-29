"""DHCP option names and values are checked on write (#1228).

A value Kea cannot parse makes it reject the WHOLE config for the server
group, and a name the renderer does not know is dropped with nothing but an
agent log line. Both used to be accepted by every options endpoint. The value
rules below were measured against ``kea-dhcp4 -t`` 3.0.3, not assumed.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.option_validation import (
    normalize_options,
    renderer_vocabularies,
    validate_options,
)

# ── The validator ────────────────────────────────────────────────────────────


def test_the_checked_names_are_exactly_the_renderers() -> None:
    """A name the Kea driver renders with no value check here would be refused
    as unknown — so adding one to the driver must fail this first."""
    v4, standard, kea_v4, v6, kea_v6 = renderer_vocabularies()
    assert v4 == standard == kea_v4
    assert v6 == kea_v6


@pytest.mark.parametrize(
    "options",
    [
        {"routers": ["10.0.0.1"], "dns-servers": "10.0.0.2, 10.0.0.3"},
        {"broadcast-address": "10.0.0.255"},
        {"broadcast-address": ["10.0.0.255"]},  # the Windows importer's shape
        {"mtu": 9000, "time-offset": "-3600"},
        {"domain-name": "corp.example", "domain-search": ["a.example", "b.example"]},
        {"tftp-server-name": "tftp.example", "bootfile-name": "pxelinux.0"},
        {"tftp-server-address": ["10.0.0.9", "10.0.0.10"]},
        {"code:43": "0104c0a80001"},
        {"code:150": "10.0.0.9"},
        {"code:160": "https://prov.example/{mac}"},
        {"opt-252": "http://wpad.example/wpad.dat"},
        {"routers": [], "ntp-servers": None, "dns-servers": ""},  # unset, skipped
    ],
)
def test_renderable_options_pass(options: dict) -> None:
    validate_options(options)


@pytest.mark.parametrize(
    ("options", "fragment"),
    [
        ({"routers": "10.0.0.1, bogus"}, "'bogus' is not an IPv4 address"),
        ({"dns-servers": ["ns1.example"]}, "not an IPv4 address"),
        ({"ntp-servers": ["2001:db8::1"]}, "not an IPv4 address"),
        ({"broadcast-address": ["10.0.0.255", "10.0.0.1"]}, "single value"),
        ({"mtu": 70000}, "outside 68..65535"),
        ({"mtu": "abc"}, "not an integer"),
        ({"mtu": True}, "must be an integer"),
        ({"time-offset": 3_000_000_000}, "outside"),
        ({"tftp-server-name": "  "}, "blank"),
        ({"bootfile-name": "a\nb"}, "control characters"),
        ({"domain-name": "bad name"}, "domain-name"),
        ({"domain-search": ["ok.example", ""]}, "blank entry"),
        ({"code:43": "hello"}, "hex digits only"),
        ({"code:43": "0x0104"}, "hex digits only"),
        ({"code:43": "01:04"}, "hex digits only"),
        ({"code:43": "abc"}, "even number"),
        ({"code:43": ""}, "has no value"),
        ({"code:150": "tftp.example"}, "not an IPv4 address"),
        ({"code:44": "10.0.0.1"}, "option 44 (netbios-name-servers)"),
        ({"code:999": "x"}, "cannot deliver"),
        ({"opt-300": "x"}, "1..254"),
        ({"netbios-name-servers": ["10.0.0.1"]}, "unknown DHCP option"),
        ({"option-44": "10.0.0.1"}, "unknown DHCP option"),
        ({"option_data": [{"name": "routers", "data": "x"}]}, "raw Kea option-data"),
    ],
)
def test_options_kea_cannot_load_are_refused_by_name(options: dict, fragment: str) -> None:
    (key,) = options
    with pytest.raises(ValueError) as exc:
        validate_options(options)
    assert f"'{key}'" in str(exc.value)
    assert fragment in str(exc.value)


def test_dhcpv6_has_its_own_vocabulary() -> None:
    validate_options({"dns-servers": ["2001:db8::53"]}, address_family="ipv6")
    with pytest.raises(ValueError, match="not an IPv6 address"):
        validate_options({"dns-servers": ["10.0.0.53"]}, address_family="ipv6")
    with pytest.raises(ValueError, match="no DHCPv6 equivalent"):
        validate_options({"routers": ["2001:db8::1"]}, address_family="ipv6")
    with pytest.raises(ValueError, match="DHCPv4 only"):
        validate_options({"code:43": "01"}, address_family="ipv6")


def test_a_client_class_accepts_either_family() -> None:
    validate_options({"routers": ["10.0.0.1"]}, address_family="any")
    validate_options({"dns-servers": ["2001:db8::53"]}, address_family="any")
    validate_options({"dns-servers": ["10.0.0.53"]}, address_family="any")


def test_an_unchanged_grandfathered_option_does_not_block_an_edit() -> None:
    stored = {"routers": "bogus", "option-44": "x"}
    validate_options({**stored, "mtu": 1500}, previous=stored)
    with pytest.raises(ValueError, match="'routers'"):
        validate_options({**stored, "routers": "still bogus"}, previous=stored)


def test_a_catalogue_pick_is_keyed_by_the_code_the_renderer_can_deliver() -> None:
    """The custom-options editor sends the IANA name, which the renderer does
    not know, beside a code it can deliver."""
    got = normalize_options(
        [
            {"code": 43, "name": "vendor-encapsulated-options", "value": "0104"},
            {"code": 6, "name": "domain-name-servers", "value": ["10.0.0.1"]},
            {"code": 26, "name": "interface-mtu", "value": "9000"},
            {"code": 252, "value": "x"},
        ]
    )
    assert got == {"code:43": "0104", "dns-servers": ["10.0.0.1"], "mtu": "9000", "code:252": "x"}


# ── Every write path refuses ─────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _subnet_and_group(db: AsyncSession) -> tuple[Subnet, DHCPServerGroup]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="192.0.2.0/24", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="192.0.2.0/24", name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    return subnet, grp


async def test_scope_create_and_update(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    url = f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes"

    bad = await client.post(
        url, headers=h, json={"group_id": str(grp.id), "options": {"routers": "bogus"}}
    )
    assert bad.status_code == 422, bad.text
    assert "'routers'" in bad.json()["detail"]

    ok = await client.post(
        url, headers=h, json={"group_id": str(grp.id), "options": {"routers": ["192.0.2.1"]}}
    )
    assert ok.status_code == 201, ok.text
    scope_id = ok.json()["id"]

    resp = await client.put(
        f"/api/v1/dhcp/scopes/{scope_id}", headers=h, json={"options": {"mtu": 70000}}
    )
    assert resp.status_code == 422, resp.text
    assert "'mtu'" in resp.json()["detail"]


async def test_a_scope_stored_before_the_check_can_still_be_edited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    scope = DHCPScope(
        subnet_id=subnet.id, group_id=grp.id, name="old", options={"option-44": "10.0.0.1"}
    )
    db_session.add(scope)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dhcp/scopes/{scope.id}",
        headers=h,
        json={"options": {"option-44": "10.0.0.1", "routers": ["192.0.2.1"]}},
    )
    assert resp.status_code == 200, resp.text


async def test_a_raw_code_reads_back_under_its_number(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={
            "group_id": str(grp.id),
            "options": [{"code": 43, "name": "vendor-encapsulated-options", "value": "0104"}],
        },
    )
    assert resp.status_code == 201, resp.text
    assert {"code": 43, "name": "code:43", "value": "0104"} in resp.json()["options"]


async def test_pool_static_template_class_and_policy_refuse(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    scope = DHCPScope(subnet_id=subnet.id, group_id=grp.id, name="s", options={})
    db_session.add(scope)
    await db_session.commit()
    bad = {"routers": "bogus"}

    cases = [
        (
            f"/api/v1/dhcp/scopes/{scope.id}/pools",
            {"start_ip": "192.0.2.100", "end_ip": "192.0.2.150", "options_override": bad},
        ),
        (
            f"/api/v1/dhcp/scopes/{scope.id}/statics",
            {
                "ip_address": "192.0.2.20",
                "mac_address": "aa:bb:cc:dd:ee:01",
                "options_override": bad,
            },
        ),
        (
            f"/api/v1/dhcp/server-groups/{grp.id}/option-templates",
            {"name": "t", "options": bad},
        ),
        (
            f"/api/v1/dhcp/server-groups/{grp.id}/client-classes",
            {"name": "c", "options": bad},
        ),
        (
            f"/api/v1/dhcp/server-groups/{grp.id}/device-policies",
            {"name": "p", "device_classes": ["HP Print Server"], "options": bad},
        ),
    ]
    for url, body in cases:
        resp = await client.post(url, headers=h, json=body)
        assert resp.status_code == 422, (url, resp.text)
        assert "'routers'" in str(resp.json()["detail"]), (url, resp.text)


async def test_applying_a_template_checks_the_result_against_the_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A v6 template is valid on its own terms and not on a v4 scope."""
    h = await _headers(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    scope = DHCPScope(subnet_id=subnet.id, group_id=grp.id, name="s", options={})
    db_session.add(scope)
    await db_session.commit()
    tpl = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/option-templates",
        headers=h,
        json={"name": "v6", "address_family": "ipv6", "options": {"dns-servers": ["2001:db8::53"]}},
    )
    assert tpl.status_code == 201, tpl.text
    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/apply-option-template",
        headers=h,
        json={"template_id": tpl.json()["id"]},
    )
    assert resp.status_code == 422, resp.text
    assert "'dns-servers'" in resp.json()["detail"]
