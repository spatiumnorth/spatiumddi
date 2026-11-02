"""A customer in the Trash must not break what still names it (#3192).

The customer delete leaves services / overlays / circuits pointing at the hidden
row. An update that keeps that reference must save; only a NEW or CHANGED
reference to a trashed customer is refused.
"""

from __future__ import annotations

import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"t3192-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="T3192",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _post(
    c: AsyncClient, h: dict[str, str], url: str, body: dict[str, Any]
) -> dict[str, Any]:
    r = await c.post(url, json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


async def _setup(c: AsyncClient, h: dict[str, str]) -> dict[str, Any]:
    tag = uuid.uuid4().hex[:6]
    cust = await _post(c, h, "/api/v1/customers", {"name": f"c-{tag}"})
    live = await _post(c, h, "/api/v1/customers", {"name": f"live-{tag}"})
    svc = await _post(c, h, "/api/v1/services", {"name": f"s-{tag}", "customer_id": cust["id"]})
    ovl = await _post(c, h, "/api/v1/overlays", {"name": f"o-{tag}", "customer_id": cust["id"]})
    prov = await _post(c, h, "/api/v1/providers", {"name": f"p-{tag}"})
    ckt = await _post(
        c,
        h,
        "/api/v1/circuits",
        {"name": f"k-{tag}", "provider_id": prov["id"], "customer_id": cust["id"]},
    )
    r = await c.delete(f"/api/v1/customers/{cust['id']}", headers=h)
    assert r.status_code == 204, r.text
    return {"cust": cust, "live": live, "svc": svc, "ovl": ovl, "ckt": ckt, "prov": prov}


async def test_unchanged_trashed_customer_saves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    s = await _setup(client, h)
    cid = s["cust"]["id"]

    r = await client.put(
        f"/api/v1/services/{s['svc']['id']}",
        json={"customer_id": cid, "notes": "edited"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["customer_id"] == cid and r.json()["notes"] == "edited"

    r = await client.put(
        f"/api/v1/overlays/{s['ovl']['id']}",
        json={"customer_id": cid, "notes": "edited"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["customer_id"] == cid

    r = await client.put(
        f"/api/v1/circuits/{s['ckt']['id']}",
        json={"customer_id": cid, "notes": "edited"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["customer_id"] == cid


async def test_new_reference_to_trashed_customer_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    s = await _setup(client, h)
    cid = s["cust"]["id"]
    live = s["live"]["id"]

    # Create paths.
    r = await client.post("/api/v1/services", json={"name": "n1", "customer_id": cid}, headers=h)
    assert r.status_code == 422, r.text
    r = await client.post("/api/v1/overlays", json={"name": "n2", "customer_id": cid}, headers=h)
    assert r.status_code == 422, r.text
    r = await client.post(
        "/api/v1/circuits",
        json={"name": "n3", "provider_id": s["prov"]["id"], "customer_id": cid},
        headers=h,
    )
    assert r.status_code == 422, r.text

    # Moving a row from a live customer onto the trashed one is refused.
    svc = await _post(client, h, "/api/v1/services", {"name": "mv", "customer_id": live})
    r = await client.put(f"/api/v1/services/{svc['id']}", json={"customer_id": cid}, headers=h)
    assert r.status_code == 422, r.text
    ovl = await _post(client, h, "/api/v1/overlays", {"name": "mvo", "customer_id": live})
    r = await client.put(f"/api/v1/overlays/{ovl['id']}", json={"customer_id": cid}, headers=h)
    assert r.status_code == 422, r.text
    ckt = await _post(
        client,
        h,
        "/api/v1/circuits",
        {"name": "mvc", "provider_id": s["prov"]["id"], "customer_id": live},
    )
    r = await client.put(f"/api/v1/circuits/{ckt['id']}", json={"customer_id": cid}, headers=h)
    assert r.status_code == 422, r.text


async def test_purge_refused_names_the_service(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    s = await _setup(client, h)
    r = await client.delete(f"/api/v1/admin/trash/customer/{s['cust']['id']}", headers=h)
    assert r.status_code == 409, r.text
    assert s["svc"]["name"] in r.json()["detail"]


async def test_update_omitting_customer_id_behaves_like_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A PUT that leaves ``customer_id`` out keeps the trashed customer and saves."""
    h = await _admin(db_session)
    s = await _setup(client, h)
    cid = s["cust"]["id"]
    for url in (
        f"/api/v1/services/{s['svc']['id']}",
        f"/api/v1/overlays/{s['ovl']['id']}",
        f"/api/v1/circuits/{s['ckt']['id']}",
    ):
        r = await client.put(url, json={"notes": "omitted"}, headers=h)
        assert r.status_code == 200, (url, r.text)
        assert r.json()["customer_id"] == cid, url


async def test_service_explicit_null_customer_is_refused_not_500(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A service must have a customer: an explicit null is a 422, never a 500."""
    h = await _admin(db_session)
    s = await _setup(client, h)
    r = await client.put(
        f"/api/v1/services/{s['svc']['id']}", json={"customer_id": None}, headers=h
    )
    assert r.status_code == 422, r.text
    r = await client.get(f"/api/v1/services/{s['svc']['id']}", headers=h)
    assert r.json()["customer_id"] == s["cust"]["id"]


async def test_overlay_explicit_null_customer_clears(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An overlay's customer is optional: an explicit null clears it."""
    h = await _admin(db_session)
    s = await _setup(client, h)
    r = await client.put(
        f"/api/v1/overlays/{s['ovl']['id']}", json={"customer_id": None}, headers=h
    )
    assert r.status_code == 200, r.text
    assert r.json()["customer_id"] is None
