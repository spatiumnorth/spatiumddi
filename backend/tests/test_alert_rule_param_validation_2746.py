"""#2746 — each rule type's parameters are validated against its OWN
catalogue entry, not one rule shared by every type."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User

pytestmark = pytest.mark.asyncio


async def _hdr(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _body(rule_type: str, **kw: object) -> dict[str, object]:
    return {"name": f"r-{uuid.uuid4().hex[:6]}", "rule_type": rule_type, "enabled": False, **kw}


async def test_new_mac_seen_include_randomised_is_stored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body("new_mac_seen", classification="all"), headers=h
    )
    assert r.status_code == 201, r.text
    assert r.json()["classification"] == "all"
    rid = r.json()["id"]
    # Exclude -> Include through PATCH
    r2 = await client.patch(f"/api/v1/alerts/rules/{rid}", json={"classification": ""}, headers=h)
    assert r2.status_code == 200, r2.text
    r3 = await client.patch(
        f"/api/v1/alerts/rules/{rid}", json={"classification": "all"}, headers=h
    )
    assert r3.status_code == 200, r3.text


async def test_new_mac_seen_bogus_choice_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body("new_mac_seen", classification="pci_scope"), headers=h
    )
    assert r.status_code == 422


async def test_compliance_classification_still_enforced(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body("compliance_change", classification="all"), headers=h
    )
    assert r.status_code == 422


@pytest.mark.parametrize("rule_type", ["voice_lease_count_below", "stale_ip_count"])
async def test_counts_above_100_are_stored(
    client: AsyncClient, db_session: AsyncSession, rule_type: str
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body(rule_type, threshold_percent=150), headers=h
    )
    assert r.status_code == 201, r.text
    assert r.json()["threshold_percent"] == 150
    r2 = await client.patch(
        f"/api/v1/alerts/rules/{r.json()['id']}", json={"threshold_percent": 300}, headers=h
    )
    assert r2.status_code == 200, r2.text


async def test_percent_rule_still_capped_at_100(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body("subnet_utilization", threshold_percent=150), headers=h
    )
    assert r.status_code == 422
    assert "Threshold" in r.text


@pytest.mark.parametrize("rule_type", ["backup_stale", "bgp_lg_route_flap"])
async def test_zero_below_field_minimum_refused(
    client: AsyncClient, db_session: AsyncSession, rule_type: str
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body(rule_type, threshold_percent=0), headers=h
    )
    assert r.status_code == 422, r.text
    ok = await client.post(
        "/api/v1/alerts/rules", json=_body(rule_type, threshold_percent=3), headers=h
    )
    assert ok.status_code == 201
    bad = await client.patch(
        f"/api/v1/alerts/rules/{ok.json()['id']}", json={"threshold_percent": 0}, headers=h
    )
    assert bad.status_code == 422
    row = await db_session.get(AlertRule, uuid.UUID(ok.json()["id"]))
    assert row is not None
