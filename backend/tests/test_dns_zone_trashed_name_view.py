"""A trashed DNS zone in a view no longer holds its name there (#3824)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSView

_BODY = {
    "name": "example.test.",
    "zone_type": "primary",
    "kind": "forward",
    "primary_ns": "ns1.example.test.",
    "admin_email": "admin.example.test.",
}


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DNSServerGroup, DNSView]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    view = DNSView(group_id=group.id, name="internal")
    db.add(view)
    await db.flush()
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, group, view


@pytest.mark.asyncio
async def test_trashed_zone_in_view_frees_name_and_restore_refuses(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, group, view = await _setup(db_session)
    base = f"/api/v1/dns/groups/{group.id}/zones"
    body = {**_BODY, "view_id": str(view.id)}

    first = await client.post(base, json=body, headers=headers)
    assert first.status_code == 201, first.text
    old_id = first.json()["id"]
    assert (await client.delete(f"{base}/{old_id}", headers=headers)).status_code == 204

    again = await client.post(base, json=body, headers=headers)
    assert again.status_code == 201, again.text

    # Restoring the trashed namesake now refuses cleanly, naming the live zone.
    restore = await client.post(f"/api/v1/admin/trash/dns_zone/{old_id}/restore", headers=headers)
    assert restore.status_code == 409, restore.text
    assert "already exists" in str(restore.json()["detail"])


def test_unique_violation_message_names_the_zone_not_the_columns() -> None:
    from app.core.integrity_errors import unique_violation_message

    detail = "Key (group_id, view_id, name)=(1, 2, example.test.) already exists."
    msg = unique_violation_message(detail, "uq_dns_zone_group_view_name")
    assert "DNS zone" in msg and "group_id" not in msg
    # Any other key keeps the column-naming sentence.
    assert "group_id" in unique_violation_message(detail, "uq_something_else")


@pytest.mark.asyncio
async def test_repin_and_rename_onto_trashed_name_in_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, group, view = await _setup(db_session)
    base = f"/api/v1/dns/groups/{group.id}/zones"
    trashed = await client.post(base, json={**_BODY, "view_id": str(view.id)}, headers=headers)
    assert trashed.status_code == 201, trashed.text
    assert (
        await client.delete(f"{base}/{trashed.json()['id']}", headers=headers)
    ).status_code == 204
    live = await client.post(base, json=_BODY, headers=headers)  # no view
    assert live.status_code == 201, live.text
    repin = await client.put(
        f"{base}/{live.json()['id']}", json={"view_id": str(view.id)}, headers=headers
    )
    assert repin.status_code == 200, repin.text
