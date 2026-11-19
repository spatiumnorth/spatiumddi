"""#1767 — DNSSEC signing is back on agent-managed Technitium.

The agent now reconciles signing state from every bundle (a new server, a
re-created zone or a lost volume is signed again), maps the zone's policy onto
the sign call and reports key state back, so the control plane no longer
withdraws it (#1783). The agentless ``technitium_api`` driver has no agent to
do that and keeps the explicit 422. Manual rollover is wired to Technitium's
``rolloverDnsKey``.
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
async def test_sign_endpoint_allowed_on_technitium_and_enqueues_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    z = await _signed_zone(db_session, grp)
    z.dnssec_enabled = False
    await db_session.commit()
    r = await client.post(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/sign", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["dnssec_enabled"] is True
    assert r.json()["dnssec_unmanaged_warning"] is False
    ops = await db_session.execute(
        select(DNSRecordOp.op).where(
            DNSRecordOp.zone_name == z.name, DNSRecordOp.op == "dnssec_sign"
        )
    )
    assert len(ops.scalars().all()) == 1


@pytest.mark.asyncio
async def test_sign_endpoint_422_explains_on_technitium_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The agentless driver keeps an explicit refusal, not the generic
    "requires one of [...]" text."""
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium_api")
    z = await _signed_zone(db_session, grp)
    z.dnssec_enabled = False
    await db_session.commit()
    r = await client.post(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/sign", headers=h)
    assert r.status_code == 422, r.text
    assert "agentless Technitium" in r.json()["detail"]
    await db_session.refresh(z)
    assert z.dnssec_enabled is False


@pytest.mark.asyncio
async def test_dnssec_info_flags_signing_unsupported_only_for_api_driver(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The flag the UI reads to disable the Sign button."""
    h = await _headers(db_session)
    for driver, expected in (("technitium", False), ("technitium_api", True)):
        grp = await _group(db_session, driver)
        z = await _signed_zone(db_session, grp)
        z.dnssec_enabled = False
        await db_session.commit()
        r = await client.get(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/info", headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["signing_unmanaged"] is expected, driver


@pytest.mark.asyncio
async def test_create_with_dnssec_allowed_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 201, r.text
    assert r.json()["dnssec_unmanaged_warning"] is False
    api = await _group(db_session, "technitium_api")
    r = await client.post(
        f"/api/v1/dns/groups/{api.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_unsign_enqueues_op_on_technitium(
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


@pytest.mark.asyncio
async def test_rollover_enqueues_op_on_technitium(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    z = await _signed_zone(db_session, grp)
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/rollover",
        json={"key_tag": 4242},
        headers=h,
    )
    assert r.status_code == 200, r.text
    op = (
        await db_session.execute(
            select(DNSRecordOp).where(
                DNSRecordOp.zone_name == z.name, DNSRecordOp.op == "dnssec_rollover"
            )
        )
    ).scalar_one()
    assert op.record["key_tag"] == 4242


@pytest.mark.asyncio
async def test_rollover_still_refused_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "powerdns")
    z = await _signed_zone(db_session, grp)
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{z.id}/dnssec/rollover",
        json={"key_tag": 1},
        headers=h,
    )
    assert r.status_code == 422, r.text


# ── One signer list; the single-signer rule counts Technitium ────────────


def test_one_signer_list_includes_technitium_agent_only() -> None:
    from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS
    from app.services.dns import dnssec_signers
    from app.services.dns.zone_move import DNSSEC_SIGN_DRIVERS

    assert _DRIVER_GATED_OPERATIONS["dnssec_sign"] is dnssec_signers.SIGNING_DRIVERS
    assert DNSSEC_SIGN_DRIVERS is dnssec_signers.SIGNING_DRIVERS
    assert "technitium" in dnssec_signers.SIGNING_DRIVERS
    assert "technitium_api" not in dnssec_signers.SIGNING_DRIVERS
    assert "technitium" in dnssec_signers.PER_SERVER_SIGNING_DRIVERS


@pytest.mark.asyncio
async def test_signed_technitium_group_refuses_a_second_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Each Technitium server signs with its own keys, so #1762's refusal
    applies."""
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
async def test_signing_a_zone_on_a_two_server_technitium_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "technitium")
    db_session.add(
        DNSServer(
            group_id=grp.id,
            driver="technitium",
            host="10.0.0.9",
            name="tn-second",
            is_primary=False,
            is_enabled=True,
        )
    )
    await db_session.flush()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json=_body(dnssec_enabled=True), headers=h
    )
    assert r.status_code == 422, r.text
    assert "own keys" in r.json()["detail"]
