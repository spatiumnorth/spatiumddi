"""Raw option spellings are checked beyond the write path (#1347).

#1296 made scope and template writes refuse the raw-code spelling a group's
servers drop (Windows reads ``opt-NN``, Kea and FortiGate ``code:NN``). Three
other ways in still produced options saved and never served: a server joining
a group whose scopes already held the other spelling, the Windows importer
writing ``opt-NN`` into a Kea group, and a catalogue pick keyed ``code:NN``
on a Windows group. The spelling also moves onto the driver classes.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dhcp import get_driver
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.option_spelling import spelling_for_drivers
from app.services.dhcp.option_validation import (
    RAW_CODES_KEA,
    RAW_CODES_NONE,
    RAW_CODES_WINDOWS,
    normalize_options,
    raw_keys_dropped_by,
    rekey_raw_options,
    validate_options,
)

# ── The spelling lives on the drivers ────────────────────────────────────────


def test_each_driver_declares_its_spelling() -> None:
    assert get_driver("windows_dhcp").raw_option_spelling == RAW_CODES_WINDOWS
    assert get_driver("kea").raw_option_spelling == RAW_CODES_KEA
    assert get_driver("fortigate").raw_option_spelling == RAW_CODES_KEA


def test_a_groups_spelling_follows_its_drivers() -> None:
    assert spelling_for_drivers([]) == RAW_CODES_KEA
    assert spelling_for_drivers(["windows_dhcp", "windows_dhcp"]) == RAW_CODES_WINDOWS
    assert spelling_for_drivers(["fortigate", "kea"]) == RAW_CODES_KEA
    assert spelling_for_drivers(["windows_dhcp", "fortigate"]) == RAW_CODES_NONE


# ── Pure helpers ─────────────────────────────────────────────────────────────


def test_which_raw_keys_a_spelling_drops() -> None:
    opts = {"code:43": "0104", "opt-252": "x", "routers": ["10.0.0.1"]}
    assert raw_keys_dropped_by(opts, RAW_CODES_KEA) == ["opt-252"]
    assert raw_keys_dropped_by(opts, RAW_CODES_WINDOWS) == ["code:43"]
    assert raw_keys_dropped_by(opts, RAW_CODES_NONE) == ["code:43", "opt-252"]


def test_rekey_for_a_kea_group_keeps_what_kea_can_deliver() -> None:
    out, dropped = rekey_raw_options(
        {"opt-43": "0104", "opt-200": "x", "routers": ["10.0.0.1"]}, raw_codes=RAW_CODES_KEA
    )
    assert out == {"code:43": "0104", "routers": ["10.0.0.1"]}
    assert dropped == ["opt-200"]


def test_rekey_for_a_windows_group() -> None:
    out, dropped = rekey_raw_options({"code:43": "0104"}, raw_codes=RAW_CODES_WINDOWS)
    assert out == {"opt-43": "0104"}
    assert dropped == []


def test_rekey_drops_raw_codes_on_v6_and_on_a_mixed_group() -> None:
    assert rekey_raw_options({"opt-43": "x"}, raw_codes=RAW_CODES_WINDOWS, address_family="ipv6")[
        1
    ] == ["opt-43"]
    assert rekey_raw_options({"opt-43": "x"}, raw_codes=RAW_CODES_NONE)[1] == ["opt-43"]


def test_a_catalogue_pick_is_keyed_in_the_groups_spelling() -> None:
    pick = [{"code": 43, "name": "vendor-encapsulated-options", "value": "0104"}]
    assert normalize_options(pick) == {"code:43": "0104"}
    assert normalize_options(pick, raw_codes=RAW_CODES_WINDOWS) == {"opt-43": "0104"}


def test_opt_nn_on_v6_is_refused_even_on_a_windows_group() -> None:
    """Windows writes options with Set-DhcpServerv4OptionValue only, so an
    opt-NN on a v6 scope reaches no server."""
    with pytest.raises(ValueError, match="DHCPv4 only"):
        validate_options({"opt-43": "0104"}, address_family="ipv6", raw_codes=RAW_CODES_WINDOWS)


# ── A server joining a group ─────────────────────────────────────────────────


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


async def _group_with_scope(db: AsyncSession, options: dict[str, object]) -> DHCPServerGroup:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    net = f"198.51.{uuid.uuid4().int % 250}.0/24"
    block = IPBlock(space_id=space.id, network=net, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=net, name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    db.add(DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="office", options=options))
    await db.flush()
    return grp


async def _windows_server(db: AsyncSession) -> DHCPServer:
    home = DHCPServerGroup(name=f"home-{uuid.uuid4().hex[:6]}")
    db.add(home)
    await db.flush()
    server = DHCPServer(
        name=f"win-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="192.0.2.50",
        port=67,
        server_group_id=home.id,
    )
    db.add(server)
    await db.flush()
    return server


@pytest.mark.asyncio
async def test_moving_a_windows_server_into_a_group_with_code_nn_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    target = await _group_with_scope(db_session, {"code:43": "0104"})
    server = await _windows_server(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/servers/{server.id}", headers=h, json={"server_group_id": str(target.id)}
    )

    assert r.status_code == 422, r.text
    assert "office" in r.json()["detail"] and "code:43" in r.json()["detail"]
    await db_session.refresh(server)
    assert server.server_group_id != target.id


@pytest.mark.asyncio
async def test_a_group_whose_scopes_hold_only_named_options_takes_the_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    target = await _group_with_scope(db_session, {"routers": ["198.51.100.1"]})
    server = await _windows_server(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/servers/{server.id}", headers=h, json={"server_group_id": str(target.id)}
    )

    assert r.status_code == 200, r.text


# ── The importer re-keys to the target group's spelling ──────────────────────


@pytest.mark.asyncio
async def test_a_windows_import_into_a_kea_group_is_rekeyed(db_session: AsyncSession) -> None:
    """The Windows importer keeps an unmapped option as ``opt-NN``; stored as
    is in a Kea group, every one was dropped at render."""
    from sqlalchemy import select

    from app.services.dhcp_import.canonical import ImportedScope, ImportPreview
    from app.services.dhcp_import.commit import commit_import

    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, space, grp])
    await db_session.flush()
    db_session.add(
        DHCPServer(
            name=f"kea-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="192.0.2.60",
            port=67,
            server_group_id=grp.id,
        )
    )
    block = IPBlock(space_id=space.id, network="203.0.113.0/24", name="b")
    db_session.add(block)
    await db_session.commit()
    cidr = "203.0.113.0/24"
    preview = ImportPreview(
        source="windows_dhcp",
        scopes=[
            ImportedScope(
                subnet_cidr=cidr,
                address_family="ipv4",
                name="branch",
                options={"opt-43": "0104", "opt-200": "x", "routers": ["203.0.113.1"]},
            )
        ],
        client_classes=[],
        conflicts=[],
        warnings=[],
        unsupported=[],
        total_pools=0,
        total_reservations=0,
        address_family_histogram={"ipv4": 1},
    )

    result = await commit_import(
        db_session,
        preview=preview,
        target_group_id=grp.id,
        ipam_space_id=space.id,
        ipam_block_id=block.id,
        conflict_actions={},
        current_user=user,
    )

    assert result.total_scopes_created == 1, result.scopes
    scope = (
        await db_session.execute(select(DHCPScope).where(DHCPScope.group_id == grp.id))
    ).scalar_one()
    assert scope.options == {"code:43": "0104", "routers": ["203.0.113.1"]}
    assert any("opt-200" in w for w in result.warnings)
