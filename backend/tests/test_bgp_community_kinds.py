"""#2624 — BGP community create validates the value against its own kind.

``value`` is declared before ``kind``, so a field validator never saw the
kind and judged every value as a regular community: every valid large
community (the only form carrying a 4-byte ASN) and every standard name
was refused with a message about the two-part form.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _asn(client: AsyncClient, h: dict[str, str]) -> str:
    r = await client.post("/api/v1/asns", json={"number": 4221370486}, headers=h)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


@pytest.mark.asyncio
async def test_valid_large_community_is_stored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    asn = await _asn(client, h)
    r = await client.post(
        f"/api/v1/asns/{asn}/communities",
        json={"kind": "large", "value": "4221370486:100:200"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["kind"] == "large"
    assert r.json()["value"] == "4221370486:100:200"


@pytest.mark.asyncio
async def test_standard_name_is_stored(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    asn = await _asn(client, h)
    r = await client.post(
        f"/api/v1/asns/{asn}/communities",
        json={"kind": "standard", "value": "no-export"},
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_regular_community_still_stored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    asn = await _asn(client, h)
    r = await client.post(
        f"/api/v1/asns/{asn}/communities",
        json={"kind": "regular", "value": "65000:100"},
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_refusals_name_the_right_kind(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    asn = await _asn(client, h)
    url = f"/api/v1/asns/{asn}/communities"
    r = await client.post(url, json={"kind": "large", "value": "65000:100"}, headers=h)
    assert r.status_code == 422
    assert "large community must be ASN:N:M" in r.text
    r = await client.post(url, json={"kind": "regular", "value": "65000:100:200"}, headers=h)
    assert r.status_code == 422
    assert "regular community must be ASN:N" in r.text
    r = await client.post(url, json={"kind": "standard", "value": "bogus"}, headers=h)
    assert r.status_code == 422
    assert "standard community must be one of" in r.text
    r = await client.post(url, json={"kind": "large", "value": "  "}, headers=h)
    assert r.status_code == 422
