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
