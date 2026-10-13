"""#1634 -- ``fields_written`` lists the columns an apply changed, no more.

``_stamp`` used to count a write as soon as the target column was empty, so a
template with no tags, custom fields or zones "wrote" its own empty value over
the subnet's empty column and listed it. The apply's audit row carries the same
list, so an operator reading it saw columns the apply never touched.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPAMTemplate, IPBlock, IPSpace, Subnet


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ta-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TA",
        hashed_password=hash_password("x" * 10),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _subnet(db: AsyncSession, net: str, **cols: object) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=net, name="s", **cols)
    db.add(subnet)
    return subnet


@pytest.mark.asyncio
async def test_only_changed_columns_are_listed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _headers(db_session)
    subnet = await _subnet(db_session, "10.81.0.0/24", ddns_inherit_settings=False)
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}",
        applies_to="subnet",
        ddns_enabled=False,
        ddns_ttl=120,
    )
    db_session.add(template)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/templates/{template.id}/apply",
        headers=hdr,
        json={"subnet_id": str(subnet.id)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["fields_written"] == ["ddns_ttl"]

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == str(template.id), AuditLog.action == "apply"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].new_value["fields_written"] == ["ddns_ttl"]


@pytest.mark.asyncio
async def test_force_lists_only_columns_that_changed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _headers(db_session)
    subnet = await _subnet(
        db_session, "10.82.0.0/24", ddns_inherit_settings=False, tags={"a": "1"}, ddns_ttl=120
    )
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}", applies_to="subnet", ddns_ttl=120, tags={"a": "2"}
    )
    db_session.add(template)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/templates/{template.id}/apply",
        headers=hdr,
        json={"subnet_id": str(subnet.id), "force": True},
    )
    assert resp.status_code == 200, resp.text
    # ddns_ttl is already 120 and the other empty columns stay empty.
    assert resp.json()["fields_written"] == ["tags"]
    await db_session.refresh(subnet)
    # force still stamps: the changed column holds the template's value.
    assert subnet.tags == {"a": "2"}
    assert subnet.ddns_ttl == 120


@pytest.mark.asyncio
async def test_reapply_lists_nothing(client: AsyncClient, db_session: AsyncSession) -> None:
    """A second apply of the same template changes nothing, so lists nothing."""
    hdr = await _headers(db_session)
    subnet = await _subnet(db_session, "10.83.0.0/24")
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}",
        applies_to="subnet",
        ddns_enabled=True,
        ddns_hostname_policy="always_generate",
        ddns_ttl=120,
    )
    db_session.add(template)
    await db_session.commit()

    url = f"/api/v1/ipam/templates/{template.id}/apply"
    first = await client.post(url, headers=hdr, json={"subnet_id": str(subnet.id)})
    assert first.status_code == 200, first.text
    # The issue's case: a default (inheriting) subnet. Only DDNS columns the
    # template sets, plus the #1421 inheritance lock, are listed.
    assert first.json()["fields_written"] == [
        "ddns_enabled",
        "ddns_hostname_policy",
        "ddns_ttl",
        "ddns_inherit_settings",
    ]

    second = await client.post(url, headers=hdr, json={"subnet_id": str(subnet.id)})
    assert second.status_code == 200, second.text
    assert second.json()["fields_written"] == []

    forced = await client.post(url, headers=hdr, json={"subnet_id": str(subnet.id), "force": True})
    assert forced.status_code == 200, forced.text
    assert forced.json()["fields_written"] == []


@pytest.mark.asyncio
async def test_block_apply_lists_only_changed_columns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _headers(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    # An empty-string override is the same "unset" as None to every reader
    # (resolve_effective_ddns, _resolve_override_zone_id), so force writing
    # the template's None over it is not a change worth listing.
    block = IPBlock(
        space_id=space.id,
        network="10.84.0.0/16",
        name="b",
        ddns_inherit_settings=False,
        ddns_domain_override="",
    )
    db_session.add(block)
    template = IPAMTemplate(
        name=f"t-{uuid.uuid4().hex[:6]}",
        applies_to="block",
        custom_fields={"owner": "net"},
    )
    db_session.add(template)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/templates/{template.id}/apply",
        headers=hdr,
        json={"block_id": str(block.id), "force": True},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["fields_written"] == ["custom_fields"]
