"""Customers, overlays and services are Trash types (#2738).

They were soft-deleted but never listed, restorable or purgeable, and their
name keys were full unique constraints, so a deleted name was taken forever and
re-creating it answered the generic 409. Every case drives the real endpoints.
"""

from __future__ import annotations

import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ownership import Customer


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"t2738-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Trash Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _mk_customer(c: AsyncClient, h: dict[str, str], name: str) -> dict[str, Any]:
    r = await c.post("/api/v1/customers", json={"name": name}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


async def _mk_overlay(c: AsyncClient, h: dict[str, str], name: str) -> dict[str, Any]:
    r = await c.post("/api/v1/overlays", json={"name": name}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


async def _mk_service(
    c: AsyncClient, h: dict[str, str], name: str, customer_id: str
) -> dict[str, Any]:
    r = await c.post("/api/v1/services", json={"name": name, "customer_id": customer_id}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


async def _trash(c: AsyncClient, h: dict[str, str], typ: str) -> list[dict[str, Any]]:
    r = await c.get("/api/v1/admin/trash", params={"type": typ}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["items"]


def _restore(c: AsyncClient, h: dict[str, str], typ: str, rid: str):
    return c.post(f"/api/v1/admin/trash/{typ}/{rid}/restore", headers=h)


def _purge(c: AsyncClient, h: dict[str, str], typ: str, rid: str):
    return c.delete(f"/api/v1/admin/trash/{typ}/{rid}", headers=h)


async def test_customer_delete_lists_restores_and_purges(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    name = f"acme-{uuid.uuid4().hex[:6]}"
    cust = await _mk_customer(client, h, name)
    assert (await client.delete(f"/api/v1/customers/{cust['id']}", headers=h)).status_code == 204

    items = await _trash(client, h, "customer")
    assert [i["id"] for i in items] == [cust["id"]]
    assert items[0]["name_or_cidr"] == name
    assert items[0]["deletion_batch_id"] is not None

    r = await _restore(client, h, "customer", cust["id"])
    assert r.status_code == 200, r.text
    assert (await client.get(f"/api/v1/customers/{cust['id']}", headers=h)).status_code == 200
    assert await _trash(client, h, "customer") == []

    # Purge: delete again, then remove for good.
    await client.delete(f"/api/v1/customers/{cust['id']}", headers=h)
    assert (await _purge(client, h, "customer", cust["id"])).status_code == 204
    assert await _trash(client, h, "customer") == []
    db_session.expire_all()
    left = (
        await db_session.execute(
            select(Customer.id)
            .where(Customer.id == uuid.UUID(cust["id"]))
            .execution_options(include_deleted=True)
        )
    ).first()
    assert left is None


async def test_deleted_name_is_free_to_reuse(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    name = f"reuse-{uuid.uuid4().hex[:6]}"
    cust = await _mk_customer(client, h, name)
    ov = await _mk_overlay(client, h, name)
    svc = await _mk_service(client, h, "hq", cust["id"])
    await client.delete(f"/api/v1/services/{svc['id']}", headers=h)
    await client.delete(f"/api/v1/overlays/{ov['id']}", headers=h)

    # Same name again, while the deleted ones sit in the Trash.
    assert (await _mk_overlay(client, h, name))["id"] != ov["id"]
    assert (await _mk_service(client, h, "hq", cust["id"]))["id"] != svc["id"]
    await client.delete(f"/api/v1/customers/{cust['id']}", headers=h)
    assert (await _mk_customer(client, h, name))["id"] != cust["id"]


async def test_restore_collides_with_live_same_name_is_409_with_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    name = f"clash-{uuid.uuid4().hex[:6]}"
    cust = await _mk_customer(client, h, name)
    ov = await _mk_overlay(client, h, name)
    await client.delete(f"/api/v1/customers/{cust['id']}", headers=h)
    await client.delete(f"/api/v1/overlays/{ov['id']}", headers=h)
    live_c = await _mk_customer(client, h, name)
    await _mk_overlay(client, h, name)

    for typ, rid in (("customer", cust["id"]), ("overlay_network", ov["id"])):
        r = await _restore(client, h, typ, rid)
        assert r.status_code == 409, r.text
        conflict = r.json()["detail"]["conflicts"][0]
        assert conflict["type"] == typ
        assert name in conflict["reason"]
        # Still in the Trash.
        assert [i["id"] for i in await _trash(client, h, typ)] == [rid]

    # Service: same customer + name.
    svc = await _mk_service(client, h, "web", live_c["id"])
    await client.delete(f"/api/v1/services/{svc['id']}", headers=h)
    await _mk_service(client, h, "web", live_c["id"])
    r = await _restore(client, h, "network_service", svc["id"])
    assert r.status_code == 409, r.text
    assert "web" in r.json()["detail"]["conflicts"][0]["reason"]


async def test_service_restore_refused_while_its_customer_is_in_the_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    cust = await _mk_customer(client, h, f"parent-{uuid.uuid4().hex[:6]}")
    svc = await _mk_service(client, h, "dia", cust["id"])
    await client.delete(f"/api/v1/services/{svc['id']}", headers=h)
    await client.delete(f"/api/v1/customers/{cust['id']}", headers=h)

    r = await _restore(client, h, "network_service", svc["id"])
    assert r.status_code == 409, r.text
    conflict = r.json()["detail"]["conflicts"][0]
    assert conflict["parent_type"] == "customer"
    assert conflict["parent_id"] == cust["id"]

    assert (await _restore(client, h, "customer", cust["id"])).status_code == 200
    assert (await _restore(client, h, "network_service", svc["id"])).status_code == 200


async def test_customer_purge_refused_while_services_hold_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    cust = await _mk_customer(client, h, f"held-{uuid.uuid4().hex[:6]}")
    svc = await _mk_service(client, h, "mpls", cust["id"])
    await client.delete(f"/api/v1/customers/{cust['id']}", headers=h)

    r = await _purge(client, h, "customer", cust["id"])
    assert r.status_code == 409, r.text
    assert "mpls" in r.json()["detail"]

    await client.delete(f"/api/v1/services/{svc['id']}", headers=h)
    assert (await _purge(client, h, "network_service", svc["id"])).status_code == 204
    assert (await _purge(client, h, "customer", cust["id"])).status_code == 204


async def test_bulk_delete_goes_to_the_trash_one_batch_each(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    a = await _mk_overlay(client, h, f"bulk-a-{uuid.uuid4().hex[:6]}")
    b = await _mk_overlay(client, h, f"bulk-b-{uuid.uuid4().hex[:6]}")
    r = await client.post(
        "/api/v1/overlays/bulk-delete", json={"ids": [a["id"], b["id"]]}, headers=h
    )
    assert r.status_code == 200, r.text
    items = await _trash(client, h, "overlay_network")
    assert {i["id"] for i in items} == {a["id"], b["id"]}
    assert len({i["deletion_batch_id"] for i in items}) == 2
    assert (await _restore(client, h, "overlay_network", a["id"])).status_code == 200
    assert [i["id"] for i in await _trash(client, h, "overlay_network")] == [b["id"]]


async def test_create_conflict_names_the_field(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    name = f"dup-{uuid.uuid4().hex[:6]}"
    await _mk_overlay(client, h, name)
    dup = await client.post("/api/v1/overlays", json={"name": name}, headers=h)
    assert dup.status_code == 409
    assert name in dup.json()["detail"]
    cust = await _mk_customer(client, h, f"c-{uuid.uuid4().hex[:6]}")
    await _mk_service(client, h, "svc", cust["id"])
    dup = await client.post(
        "/api/v1/services", json={"name": "svc", "customer_id": cust["id"]}, headers=h
    )
    assert dup.status_code == 409
    assert "'svc'" in dup.json()["detail"]


def test_unique_violation_message_names_the_columns() -> None:
    from app.core.integrity_errors import unique_violation_message

    one = unique_violation_message("Key (name)=(Acme) already exists.")
    assert "'name'" in one and "Acme" not in one
    two = unique_violation_message("Key (customer_id, name)=(1b2, Acme) already exists.")
    assert "'customer_id', 'name'" in two and "Acme" not in two
    assert unique_violation_message("") == "The request conflicts with existing data."
    assert unique_violation_message("garbage") == "The request conflicts with existing data."


async def test_partial_unique_index_is_in_the_schema(db_session: AsyncSession) -> None:
    rows = (
        await db_session.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes WHERE indexname IN "
                "('uq_customer_name','uq_overlay_network_name','uq_network_service_customer_name')"
            )
        )
    ).all()
    assert len(rows) == 3
    assert all("WHERE (deleted_at IS NULL)" in r.indexdef for r in rows), rows


async def test_rows_deleted_before_the_upgrade_are_listed_and_restorable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The old handlers stamped deleted_at only (no batch id, no user)."""
    h = await _admin(db_session)
    ov = await _mk_overlay(client, h, f"legacy-{uuid.uuid4().hex[:6]}")
    await db_session.execute(
        text("UPDATE overlay_network SET deleted_at = now() WHERE id = :i"), {"i": ov["id"]}
    )
    await db_session.commit()
    items = await _trash(client, h, "overlay_network")
    assert [i["id"] for i in items] == [ov["id"]]
    assert items[0]["deletion_batch_id"] is None and items[0]["batch_size"] == 1
    assert (await _restore(client, h, "overlay_network", ov["id"])).status_code == 200
    assert (await client.get(f"/api/v1/overlays/{ov['id']}", headers=h)).status_code == 200


async def test_retention_sweep_purges_expired_rows_and_holds_a_customer_with_services(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.settings import PlatformSettings
    from app.tasks.trash_purge import _sweep

    h = await _admin(db_session)
    if (await db_session.execute(select(PlatformSettings).limit(1))).scalar_one_or_none() is None:
        db_session.add(PlatformSettings())
    free = await _mk_customer(client, h, f"free-{uuid.uuid4().hex[:6]}")
    held = await _mk_customer(client, h, f"held-{uuid.uuid4().hex[:6]}")
    svc = await _mk_service(client, h, "keep", held["id"])
    ov = await _mk_overlay(client, h, f"old-{uuid.uuid4().hex[:6]}")
    for path in (
        f"/customers/{free['id']}",
        f"/customers/{held['id']}",
        f"/overlays/{ov['id']}",
    ):
        await client.delete(f"/api/v1{path}", headers=h)
    # The held customer's service stays live (a customer delete leaves it).
    await db_session.execute(
        text(
            "UPDATE customer SET deleted_at = now() - interval '60 days' WHERE deleted_at IS NOT NULL"
        )
    )
    await db_session.execute(
        text(
            "UPDATE overlay_network SET deleted_at = now() - interval '60 days' "
            "WHERE deleted_at IS NOT NULL"
        )
    )
    await db_session.commit()

    result = await _sweep()
    assert result["per_type"]["customer"] == 1, result
    assert result["per_type"]["overlay_network"] == 1, result
    assert result["held_back_live_children"].get("customer") == 1, result
    ids = {i["id"] for i in await _trash(client, h, "customer")}
    assert ids == {held["id"]}
    assert (await client.get(f"/api/v1/services/{svc['id']}", headers=h)).status_code == 200
