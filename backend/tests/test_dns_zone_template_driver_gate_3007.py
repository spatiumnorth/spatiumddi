"""#3007 — create-zone-from-template runs the provider-refusal gate.

The gate (TTL range per hosted provider, #2942) covered record create, update,
bulk and both imports, but not the template path, so a template record the
provider refuses could be stored and then fail at push time.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import router as dns_router
from app.core.security import create_access_token, hash_password
from app.drivers.dns import PROVIDER_TTL_RANGES
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import zone_templates

_PARAMS = {
    "mail-basic": {"mx_host": "mail.example.com."},
    "active-directory": {"dc_hostname": "dc1.example.com."},
    "web-basic": {"origin_ip": "192.0.2.10"},
    "k8s-external-dns": {},
}


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"t-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="T",
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


def _zero_ttl_template(monkeypatch: pytest.MonkeyPatch) -> None:
    real = zone_templates.get_template("web-basic")
    assert real is not None
    bad = zone_templates.ZoneTemplate(
        id="zero-ttl",
        name="x",
        category="x",
        description="x",
        parameters=[],
        records=[
            zone_templates.TemplateRecord(
                name="www",
                record_type="A",
                value="192.0.2.1",
                ttl=0,
                priority=None,
                weight=None,
                port=None,
                skip_if_empty=[],
            )
        ],
    )
    monkeypatch.setattr(dns_router, "get_template", lambda tid: bad if tid == "zero-ttl" else None)


async def _zone_count(db: AsyncSession, name: str) -> int:
    return (
        await db.execute(select(func.count()).select_from(DNSZone).where(DNSZone.name == name))
    ).scalar_one()


@pytest.mark.asyncio
async def test_template_ttl_cloudflare_cannot_hold_is_422_and_creates_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _zero_ttl_template(monkeypatch)
    headers = await _headers(db_session)
    grp = await _group(db_session, "cloudflare")
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/from-template",
        headers=headers,
        json={"template_id": "zero-ttl", "zone_name": "refused.example."},
    )
    assert resp.status_code == 422, resp.text
    assert "TTL 0 cannot be published on cloudflare" in resp.json()["detail"]
    assert await _zone_count(db_session, "refused.example.") == 0


@pytest.mark.asyncio
async def test_template_ttl_zero_on_bind9_still_creates(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _zero_ttl_template(monkeypatch)
    headers = await _headers(db_session)
    grp = await _group(db_session, "bind9")
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/from-template",
        headers=headers,
        json={"template_id": "zero-ttl", "zone_name": "kept.example."},
    )
    assert resp.status_code == 201, resp.text
    n = (
        await db_session.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.ttl == 0)
        )
    ).scalar_one()
    assert n == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("template_id", sorted(_PARAMS))
async def test_every_shipped_template_creates_on_bind9(
    client: AsyncClient, db_session: AsyncSession, template_id: str
) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session, "bind9")
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/from-template",
        headers=headers,
        json={
            "template_id": template_id,
            "zone_name": f"{template_id}.example.",
            "params": _PARAMS[template_id],
        },
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", sorted(PROVIDER_TTL_RANGES))
async def test_every_shipped_template_passes_the_gate_on_every_ranged_provider(
    db_session: AsyncSession, driver: str
) -> None:
    grp = await _group(db_session, driver)
    for tid, params in _PARAMS.items():
        tpl = zone_templates.get_template(tid)
        assert tpl is not None
        recs: list[dict[str, Any]] = zone_templates.materialize(tpl, "z.example.", params)
        await dns_router._check_driver_refusals(
            [(r["record_type"], r["value"], r["ttl"]) for r in recs], grp.id, db_session
        )
