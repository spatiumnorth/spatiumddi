"""An untouched DHCP update dialog Save audits no field as changed (#3086),
and a MAC block's free-text reason survives an untouched Save (#3083)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.update_nulls import changed_keys
from app.models.audit import AuditLog
from app.models.dhcp import DHCPMACBlock
from tests.test_dhcp_mac_blocks import _make_group_with_server, _make_user
from tests.test_dhcp_scope_ddns_inert_2270 import _create, _world


async def _updates(db: AsyncSession, rtype: str) -> list[list[str]]:
    rows = (
        (
            await db.execute(
                select(AuditLog.changed_fields)
                .where(AuditLog.action == "update", AuditLog.resource_type == rtype)
                .order_by(AuditLog.timestamp)
            )
        )
        .scalars()
        .all()
    )
    return [list(r or []) for r in rows]


def test_changed_keys_compares_normalised_values() -> None:
    before = {
        "a": None,
        "b": ["x", "y"],
        "c": {"k": ["1"]},
        "d": uuid.UUID(int=1),
        "e": 3600,
        "f": False,
    }
    same = {
        "a": "",
        "b": ["y", "x"],
        "c": {"k": ["1"]},
        "d": str(uuid.UUID(int=1)),
        "e": 3600,
        "f": False,
    }
    assert changed_keys(before, same, unordered={"b"}) == []
    assert changed_keys(before, same) == ["b"]  # order counts unless declared moot
    assert changed_keys(before, {"e": 3601, "f": None, "g": 1}) == ["e", "f", "g"]


@pytest.mark.asyncio
async def test_untouched_scope_save_audits_no_changed_field(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, subnet, grp, _ = await _world(db_session)
    r = await _create(
        client,
        h,
        subnet,
        grp,
        description="d",
        lease_time=3600,
        relay_addresses=["192.0.2.2", "192.0.2.3"],
        options=[{"code": 6, "name": "dns-servers", "value": ["192.0.2.53"]}],
    )
    assert r.status_code in (200, 201), r.text
    stored = r.json()
    sid = stored["id"]
    body = {
        "name": stored["name"],
        "description": stored["description"],
        "lease_time": stored["lease_time"],
        "min_lease_time": stored["min_lease_time"],
        "max_lease_time": stored["max_lease_time"],
        "lease_cache_threshold": stored.get("lease_cache_threshold"),
        "lease_cache_max_age": stored.get("lease_cache_max_age"),
        "options": [{"code": 6, "name": "dns-servers", "value": ["192.0.2.53"]}],
        "relay_addresses": list(reversed(stored["relay_addresses"])),
        "enabled": stored.get("enabled", True),
        "hostname_sync_mode": stored.get("hostname_sync_mode", stored.get("hostname_to_ipam_sync")),
    }
    r = await client.put(f"/api/v1/dhcp/scopes/{sid}", headers=h, json=body)
    assert r.status_code == 200, r.text
    assert await _updates(db_session, "dhcp_scope") == [[]]

    # A real change is still named, and only it.
    body["lease_time"] = 7200
    r = await client.put(f"/api/v1/dhcp/scopes/{sid}", headers=h, json=body)
    assert r.status_code == 200, r.text
    assert (await _updates(db_session, "dhcp_scope"))[-1] == ["lease_time"]


@pytest.mark.asyncio
async def test_mac_block_free_text_reason_survives_untouched_save(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, token = await _make_user(db_session)
    grp, _ = await _make_group_with_server(db_session)
    block = DHCPMACBlock(
        group_id=grp.id, mac_address="02:98:14:00:00:99", reason="xp found on desk"
    )
    db_session.add(block)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.put(
        f"/api/v1/dhcp/mac-blocks/{block.id}",
        headers=h,
        json={"reason": "xp found on desk", "description": "", "enabled": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "xp found on desk"
    assert (await _updates(db_session, "dhcp_mac_block"))[-1] == []

    # Another free-text reason is still refused; a code is still accepted.
    r = await client.put(f"/api/v1/dhcp/mac-blocks/{block.id}", headers=h, json={"reason": "nope"})
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/dhcp/mac-blocks/{block.id}", headers=h, json={"reason": "policy"}
    )
    assert r.status_code == 200 and r.json()["reason"] == "policy"


def test_changed_keys_keeps_an_empty_list_apart_from_null() -> None:
    # Empty text is NULL, but an empty list is not: a DNS zone's allow_transfer
    # of NULL inherits the server's list while ``[]`` narrows transfers to the
    # group's keys, so NULL -> [] is a real change the audit row must name.
    assert changed_keys({"a": None}, {"a": []}) == ["a"]
    assert changed_keys({"a": []}, {"a": None}) == ["a"]
    assert changed_keys({"a": None}, {"a": {}}) == ["a"]
    # ...while [] and {} for one column are the same "no options".
    assert changed_keys({"o": {}}, {"o": []}) == []


@pytest.mark.asyncio
async def test_zone_allow_transfer_null_to_empty_is_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from tests.test_dns_untouched_save_2463 import _setup

    h, zone = await _setup(db_session)
    assert zone.allow_transfer is None
    r = await client.put(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}",
        headers=h,
        json={"allow_transfer": []},
    )
    assert r.status_code == 200, r.text
    assert r.json()["allow_transfer"] == []
    assert (await _updates(db_session, "dns_zone"))[-1] == ["allow_transfer"]


@pytest.mark.asyncio
async def test_scope_pxe_detach_is_audited(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.models.dhcp import DHCPPXEProfile

    h, subnet, grp, _ = await _world(db_session)
    prof = DHCPPXEProfile(group_id=grp.id, name="p", next_server="192.0.2.9")
    db_session.add(prof)
    await db_session.commit()
    r = await _create(client, h, subnet, grp, lease_time=3600, pxe_profile_id=str(prof.id))
    assert r.status_code in (200, 201), r.text
    sid = r.json()["id"]
    assert r.json()["pxe_profile_id"] == str(prof.id)

    r = await client.put(
        f"/api/v1/dhcp/scopes/{sid}",
        headers=h,
        json={"pxe_profile_id": None, "clear_pxe_profile": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["pxe_profile_id"] is None
    assert (await _updates(db_session, "dhcp_scope"))[-1] == ["pxe_profile_id"]
