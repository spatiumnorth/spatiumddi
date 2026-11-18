"""#4060: a binding names its target (the address, not the address row's id)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import ERLBinding
from app.models.ipam import IPAddress
from tests.test_e911_delete_guard_3891 import _admin, _erl, _subnet, _vlan


@pytest.mark.asyncio
async def test_bindings_carry_a_readable_target(client: AsyncClient, db_session: AsyncSession):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    sub = await _subnet(db_session)
    _, vlan = await _vlan(db_session)
    ip = IPAddress(subnet_id=sub.id, address="10.47.1.50", status="allocated")
    db_session.add(ip)
    await db_session.flush()
    db_session.add_all(
        [
            ERLBinding(erl_id=erl.id, rule_kind="ip", ip_address_id=ip.id),
            ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=sub.id),
            ERLBinding(erl_id=erl.id, rule_kind="vlan", vlan_ref_id=vlan.id),
        ]
    )
    await db_session.flush()

    resp = await client.get("/api/v1/e911/bindings", headers=h)
    assert resp.status_code == 200, resp.text
    by_kind = {i["rule_kind"]: i for i in resp.json()["items"]}
    assert by_kind["ip"]["target_label"] == "10.47.1.50 (subnet 10.47.1.0/24)"
    assert by_kind["ip"]["ip_address_id"] == str(ip.id)  # id kept for links
    assert by_kind["ip"]["target_missing"] is False
    assert by_kind["subnet"]["target_label"] == "10.47.1.0/24 (lan)"
    assert "3901" in by_kind["vlan"]["target_label"]
    assert "voice" in by_kind["vlan"]["target_label"]


@pytest.mark.asyncio
async def test_binding_whose_target_is_trashed_says_so(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    sub = await _subnet(db_session)
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=sub.id, is_active=False))
    # Trashed, not hard-deleted: the binding FK is CASCADE, so a trashed
    # subnet is how a binding outlives a target the operator can still see.
    sub.deleted_at = datetime.now(UTC)
    await db_session.flush()

    resp = await client.get("/api/v1/e911/bindings", headers=h)
    assert resp.status_code == 200, resp.text
    (item,) = resp.json()["items"]
    assert item["target_label"] is None
    assert item["target_missing"] is True
