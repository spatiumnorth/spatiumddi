"""Bulk allocate only generates names that are host names (#2071).

``web{n}-`` expanded to ``web1-`` / ``web2-`` and ``web{n:_}`` to ``web1_000``;
the preview and the commit accepted both, A records were written, and BIND's
check-names refused the zone. Preview and commit now apply the same host-label
rule as the single allocate path (core/dns_names) and refuse token forms the
console's live preview does not mirror, so preview == stored.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _rig(db: AsyncSession) -> tuple[dict[str, str], uuid.UUID]:
    user = User(
        username=f"u2071-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.71.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.71.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, subnet.id


def _body(template: str, start: int = 1, **kw: Any) -> dict[str, Any]:
    return {
        "range_start": "10.71.1.10",
        "range_end": "10.71.1.11",
        "hostname_template": template,
        "template_start": start,
        "create_dns_records": False,
        **kw,
    }


async def _count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(IPAddress))).scalar_one()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("template", "start"),
    [("web{n}-", 1), ("web{n:_}", 999), ("web{n:,}", 999), ("web{n:5d}", 1), ("web{n!r}", 1)],
)
async def test_non_host_names_are_refused_and_nothing_is_stored(
    client: AsyncClient, db_session: AsyncSession, template: str, start: int
) -> None:
    headers, sid = await _rig(db_session)
    base = f"/api/v1/ipam/subnets/{sid}/bulk-allocate"
    for path in (f"{base}/preview", base):
        r = await client.post(path, json=_body(template, start), headers=headers)
        assert r.status_code == 422, (path, r.text)
    assert await _count(db_session) == 0


@pytest.mark.asyncio
async def test_422_names_the_offending_names(client: AsyncClient, db_session: AsyncSession) -> None:
    headers, sid = await _rig(db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/bulk-allocate/preview",
        json=_body("web{n}-"),
        headers=headers,
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "web1-" in detail and "web2-" in detail and "#2" in detail


@pytest.mark.asyncio
async def test_valid_template_still_works_and_is_normalized(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid = await _rig(db_session)
    base = f"/api/v1/ipam/subnets/{sid}/bulk-allocate"
    r = await client.post(f"{base}/preview", json=_body("Web-{n:03d}", 7), headers=headers)
    assert r.status_code == 200, r.text
    assert [i["hostname"] for i in r.json()["sample"]] == ["web-007", "web-008"]
    r = await client.post(base, json=_body("Web-{n:03d}", 7), headers=headers)
    assert r.status_code == 200, r.text
    rows = (await db_session.execute(select(IPAddress.hostname).order_by(IPAddress.address))).all()
    assert [h for (h,) in rows if h and h.startswith("web")] == ["web-007", "web-008"]
