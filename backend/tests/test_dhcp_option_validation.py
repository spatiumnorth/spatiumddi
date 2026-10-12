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
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.option_validation import (
    RAW_CODES_KEA,
    RAW_CODES_NONE,
    RAW_CODES_WINDOWS,
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


def test_a_client_class_is_checked_against_its_own_family() -> None:
    """Since #1229 a class names the daemons it renders into; a ``dual`` one
    takes an option either family accepts, and the bundle routes it
    (``test_dhcp_client_class_family.py``)."""
    validate_options({"routers": ["10.0.0.1"]}, address_family="ipv4")
    with pytest.raises(ValueError, match="not an IPv4 address"):
        validate_options({"dns-servers": ["2001:db8::53"]}, address_family="ipv4")
    validate_options({"dns-servers": ["2001:db8::53"]}, address_family="dual")


def test_an_aliased_stored_key_still_counts_as_unchanged() -> None:
    stored = {"domain-name-servers": "bogus"}
    validate_options({"dns-servers": "bogus"}, previous=stored)


def test_a_retyped_raw_code_is_not_lost_to_the_stale_name() -> None:
    from app.services.dhcp.option_validation import normalize_options

    assert normalize_options([{"code": 132, "name": "code:43", "value": "x"}]) == {"code:132": "x"}
    assert normalize_options([{"code": 43, "name": "code:43", "value": "01"}]) == {"code:43": "01"}
    # A canonical name keeps its key whatever the code — v6 codes differ.
    assert normalize_options([{"code": 23, "name": "dns-servers", "value": ["2001:db8::1"]}]) == {
        "dns-servers": ["2001:db8::1"]
    }


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


# ── #1296: the raw-code spelling follows the group's servers ─────────────────
#
# Kea and FortiGate read ``code:NN`` and drop ``opt-NN``; Windows reads
# ``opt-NN`` and drops ``code:NN``. Each drop is silent: the option is saved
# and never served.


def test_opt_nn_is_the_windows_spelling_only() -> None:
    validate_options({"opt-252": "http://wpad.example/wpad.dat"}, raw_codes=RAW_CODES_WINDOWS)
    with pytest.raises(ValueError) as exc:
        validate_options({"opt-252": "http://wpad.example/wpad.dat"})
    assert "'opt-252'" in str(exc.value)
    assert "use code:252" in str(exc.value)


def test_code_nn_is_refused_on_windows_pointing_at_opt_nn() -> None:
    with pytest.raises(ValueError) as exc:
        validate_options({"code:43": "0104"}, raw_codes=RAW_CODES_WINDOWS)
    assert "'code:43'" in str(exc.value)
    assert "use opt-43" in str(exc.value)


def test_a_windows_code_is_still_range_checked() -> None:
    with pytest.raises(ValueError, match="1..254"):
        validate_options({"opt-300": "x"}, raw_codes=RAW_CODES_WINDOWS)


@pytest.mark.parametrize("key", ["code:43", "opt-43"])
def test_a_mixed_group_takes_neither_raw_spelling(key: str) -> None:
    with pytest.raises(ValueError, match="mixes Windows and non-Windows"):
        validate_options({key: "0104"}, raw_codes=RAW_CODES_NONE)


@pytest.mark.parametrize("key", ["code:43", "opt-43"])
def test_a_v6_raw_code_is_refused_as_v4_only_not_as_the_other_spelling(key: str) -> None:
    """Naming the other spelling on a v6 scope would send the operator to a
    key that is refused too."""
    with pytest.raises(ValueError, match="DHCPv4 only"):
        validate_options({key: "0104"}, address_family="ipv6")


def test_named_options_are_accepted_whatever_the_group() -> None:
    for raw_codes in (RAW_CODES_KEA, RAW_CODES_WINDOWS, RAW_CODES_NONE):
        validate_options({"routers": ["10.0.0.1"]}, raw_codes=raw_codes)


def test_an_imported_opt_nn_stays_editable_on_a_kea_group() -> None:
    """The #597 / #1228 rule: an unchanged stored key is not re-checked."""
    stored = {"opt-252": "http://wpad.example/wpad.dat"}
    validate_options({**stored, "routers": ["10.0.0.1"]}, previous=stored)


async def _group_with(db: AsyncSession, *drivers: str) -> DHCPServerGroup:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    for i, driver in enumerate(drivers):
        db.add(
            DHCPServer(
                name=f"s{i}-{uuid.uuid4().hex[:6]}",
                driver=driver,
                host=f"192.0.2.{10 + i}",
                port=67,
                server_group_id=grp.id,
            )
        )
    await db.flush()
    return grp


@pytest.mark.parametrize(
    ("drivers", "key", "status", "fragment"),
    [
        (("kea",), "opt-252", 422, "use code:252"),
        (("kea",), "code:43", 201, None),
        ((), "opt-252", 422, "use code:252"),  # no servers yet: the Kea rule
        (("fortigate",), "opt-252", 422, "use code:252"),
        (("windows_dhcp",), "opt-252", 201, None),
        (("windows_dhcp", "windows_dhcp"), "code:43", 422, "use opt-43"),
        (("kea", "windows_dhcp"), "opt-252", 422, "mixes Windows"),
    ],
    ids=["kea-opt", "kea-code", "empty-opt", "fortigate-opt", "win-opt", "win-code", "mixed"],
)
async def test_an_option_template_takes_the_groups_raw_spelling(
    client: AsyncClient,
    db_session: AsyncSession,
    drivers: tuple[str, ...],
    key: str,
    status: int,
    fragment: str | None,
) -> None:
    """Templates are applied to scopes, whose options a Windows server renders."""
    h = await _headers(db_session)
    grp = await _group_with(db_session, *drivers)
    await db_session.commit()
    value = "0104" if key.startswith("code:") else "http://wpad.example/wpad.dat"
    resp = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/option-templates",
        headers=h,
        json={"name": "t", "options": {key: value}},
    )
    assert resp.status_code == status, resp.text
    if fragment:
        assert fragment in str(resp.json()["detail"])


@pytest.mark.parametrize(
    "drivers", [("windows_dhcp",), ("kea", "windows_dhcp")], ids=["win", "mixed"]
)
async def test_kea_only_constructs_take_the_kea_spelling_on_any_group(
    client: AsyncClient, db_session: AsyncSession, drivers: tuple[str, ...]
) -> None:
    """Client classes are rendered by Kea / FortiGate alone, never Windows, so
    a Windows member does not change what they accept: code:NN is served by
    the Kea side of a mixed group, and opt-NN would be served by nothing."""
    h = await _headers(db_session)
    grp = await _group_with(db_session, *drivers)
    await db_session.commit()
    url = f"/api/v1/dhcp/server-groups/{grp.id}/client-classes"
    ok = await client.post(url, headers=h, json={"name": "c", "options": {"code:150": "10.0.0.9"}})
    assert ok.status_code == 201, ok.text
    bad = await client.post(
        url, headers=h, json={"name": "d", "options": {"opt-252": "http://wpad.example/wpad.dat"}}
    )
    assert bad.status_code == 422, bad.text
    assert "use code:252" in str(bad.json()["detail"])


async def test_a_kea_scope_refuses_opt_nn_on_every_write_path(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's case: saved on a Kea group, dropped by the agent."""
    h = await _headers(db_session)
    subnet, _ = await _subnet_and_group(db_session)
    grp = await _group_with(db_session, "kea")
    scope = DHCPScope(subnet_id=subnet.id, group_id=grp.id, name="s", options={})
    db_session.add(scope)
    await db_session.commit()
    opt = {"opt-252": "http://wpad.example/wpad.dat"}

    cases = [
        ("put", f"/api/v1/dhcp/scopes/{scope.id}", {"options": opt}),
        (
            "post",
            f"/api/v1/dhcp/scopes/{scope.id}/pools",
            {"start_ip": "192.0.2.100", "end_ip": "192.0.2.150", "options_override": opt},
        ),
        (
            "post",
            f"/api/v1/dhcp/scopes/{scope.id}/statics",
            {
                "ip_address": "192.0.2.20",
                "mac_address": "aa:bb:cc:dd:ee:01",
                "options_override": opt,
            },
        ),
        (
            "post",
            f"/api/v1/dhcp/server-groups/{grp.id}/option-templates",
            {"name": "t", "options": opt},
        ),
        (
            "post",
            f"/api/v1/dhcp/server-groups/{grp.id}/device-policies",
            {"name": "p", "device_classes": ["HP Print Server"], "options": opt},
        ),
    ]
    for method, url, body in cases:
        resp = await getattr(client, method)(url, headers=h, json=body)
        assert resp.status_code == 422, (url, resp.text)
        assert "use code:252" in str(resp.json()["detail"]), (url, resp.text)
