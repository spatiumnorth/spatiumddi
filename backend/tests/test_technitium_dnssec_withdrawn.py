"""#1783 — SpatiumDDI no longer claims DNSSEC signing on Technitium.

Signing is one-shot there (never re-signed on a new server, a re-created
zone or a lost volume), so the sign surfaces refuse with a 422 naming #1767,
while unsign keeps working and a zone already flagged signed gets a warning.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"tn-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="tn",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, driver: str) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    await db.flush()
    return grp


def _body(**kw: object) -> dict[str, object]:
    b: dict[str, object] = {
        "name": f"z{uuid.uuid4().hex[:6]}.example.",
        "zone_type": "primary",
        "kind": "forward",
        "primary_ns": "ns1.example.",
        "admin_email": "admin.example.",
    }
    b.update(kw)
    return b


async def _signed_zone(db: AsyncSession, grp: DNSServerGroup) -> DNSZone:
    z = DNSZone(
        group_id=grp.id,
        name=f"s{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        dnssec_enabled=True,
    )
    db.add(z)
    await db.commit()
    return z


@pytest.mark.asyncio
async def test_sign_endpoint_422_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    z = await _signed_zone(db_session, grp)
    z.dnssec_enabled = False
    await db_session.commit()
    r = await client.post(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/sign", headers=h)
    assert r.status_code == 422, r.text
    assert "1767" in r.json()["detail"]


@pytest.mark.asyncio
async def test_create_and_update_with_dnssec_422_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 422, r.text
    r = await client.post(f"/api/v1/dns/groups/{grp.id}/zones", json=_body(), headers=h)
    assert r.status_code == 201, r.text
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{r.json()['id']}",
        json={"dnssec_enabled": True},
        headers=h,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", "powerdns"])
async def test_sign_still_allowed_single_server(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, driver)
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 201, r.text
    assert r.json()["dnssec_unmanaged_warning"] is False


@pytest.mark.asyncio
async def test_unsign_still_works_and_enqueues_op_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    z = await _signed_zone(db_session, grp)
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{z.id}",
        json={"dnssec_enabled": False},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["dnssec_enabled"] is False
    ops = await db_session.execute(
        select(DNSRecordOp.op).where(
            DNSRecordOp.zone_name == z.name, DNSRecordOp.op == "dnssec_unsign"
        )
    )
    assert len(ops.scalars().all()) == 1
    r = await client.post(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/unsign", headers=h)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_already_signed_technitium_zone_carries_warning(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    tn = await _group(db_session, "technitium")
    bd = await _group(db_session, "bind9")
    zt = await _signed_zone(db_session, tn)
    zb = await _signed_zone(db_session, bd)
    r = await client.get(f"/api/v1/dns/groups/{tn.id}/zones/{zt.id}", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["dnssec_enabled"] is True
    assert r.json()["dnssec_unmanaged_warning"] is True
    r = await client.get(f"/api/v1/dns/groups/{bd.id}/zones/{zb.id}", headers=h)
    assert r.json()["dnssec_unmanaged_warning"] is False


# ── Stacked on #1762: one signer list, Technitium still counted ──────────


def test_one_signer_list_without_technitium() -> None:
    from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS
    from app.services.dns import dnssec_signers
    from app.services.dns.zone_move import DNSSEC_SIGN_DRIVERS

    assert _DRIVER_GATED_OPERATIONS["dnssec_sign"] is dnssec_signers.SIGNING_DRIVERS
    assert DNSSEC_SIGN_DRIVERS is dnssec_signers.SIGNING_DRIVERS
    assert "technitium" not in dnssec_signers.SIGNING_DRIVERS
    # A zone signed before #1783 is still held with per-server keys.
    assert "technitium" in dnssec_signers.PER_SERVER_SIGNING_DRIVERS


@pytest.mark.asyncio
async def test_signed_technitium_group_still_refuses_a_second_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A second Technitium server would serve the already-signed zone
    unsigned under the parent's DS, so #1762's refusal must still apply."""
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    await _signed_zone(db_session, grp)
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/servers",
        json={"name": "tn2", "host": "10.0.0.2", "driver": "technitium"},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "signed" in r.json()["detail"]


@pytest.mark.asyncio
async def test_zone_list_flags_each_signed_technitium_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    signed = [await _signed_zone(db_session, grp) for _ in range(3)]
    plain = DNSZone(
        group_id=grp.id,
        name=f"p{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(plain)
    await db_session.commit()
    r = await client.get(f"/api/v1/dns/groups/{grp.id}/zones", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    rows = body["items"] if isinstance(body, dict) else body
    flags = {row["id"]: row["dnssec_unmanaged_warning"] for row in rows}
    for z in signed:
        assert flags[str(z.id)] is True
    assert flags[str(plain.id)] is False


@pytest.mark.asyncio
async def test_dnssec_info_and_copilot_report_unmanaged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    z = await _signed_zone(db_session, grp)
    r = await client.get(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/info", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["signing_unmanaged"] is True
    assert r.json()["dnssec_unmanaged_warning"] is True

    from app.services.ai.operations_writes import (
        SignZoneDNSSECArgs,
        _preview_sign_zone_dnssec,
    )

    user = (await db_session.execute(select(User).where(User.username.like("tn-%")))).scalar_one()
    z.dnssec_enabled = False
    await db_session.commit()
    preview = await _preview_sign_zone_dnssec(
        db_session, user, SignZoneDNSSECArgs(group_id=grp.id, zone_id=z.id)
    )
    assert preview.ok is False
    assert "1767" in (preview.detail or "")
