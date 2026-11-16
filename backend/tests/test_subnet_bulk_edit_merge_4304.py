"""Subnet bulk edit merges tags / custom_fields per key (#4304).

It used to ``setattr`` the sent dict, replacing each subnet's whole
``custom_fields`` / ``tags``. The address bulk edit merges, with null removing
a key; the subnet one now does the same.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _two_subnets(db: AsyncSession) -> list[Subnet]:
    space = IPSpace(name=f"sp4304-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.84.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subs = []
    for i in (1, 2):
        s = Subnet(
            space_id=space.id,
            block_id=block.id,
            network=f"10.84.{i}.0/24",
            name=f"s{i}",
            custom_fields={"a": f"a{i}", "b": f"b{i}"},
            tags={"t1": f"x{i}", "t2": f"y{i}"},
        )
        db.add(s)
        subs.append(s)
    await db.commit()
    return subs


async def _bulk(client, headers, subs, changes):
    r = await client.post(
        "/api/v1/ipam/subnets/bulk-edit",
        headers=headers,
        json={"subnet_ids": [str(s.id) for s in subs], "changes": changes},
    )
    assert r.status_code == 200, r.text
    return r


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["custom_fields", "tags"])
async def test_set_key_keeps_the_others(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _headers(db_session)
    subs = await _two_subnets(db_session)
    keys = ("a", "b") if field == "custom_fields" else ("t1", "t2")
    await _bulk(client, headers, subs, {field: {keys[0]: "NEW"}})
    for s in subs:
        await db_session.refresh(s)
        assert getattr(s, field)[keys[0]] == "NEW"
        assert keys[1] in getattr(s, field)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["custom_fields", "tags"])
async def test_null_removes_key_keeps_the_others(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _headers(db_session)
    subs = await _two_subnets(db_session)
    keys = ("a", "b") if field == "custom_fields" else ("t1", "t2")
    await _bulk(client, headers, subs, {field: {keys[0]: None}})
    for s in subs:
        await db_session.refresh(s)
        assert keys[0] not in getattr(s, field)
        assert keys[1] in getattr(s, field)
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "subnet",
                    AuditLog.resource_id == str(subs[0].id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert audit and audit[-1].new_value[field] == {keys[0]: None}


@pytest.mark.asyncio
async def test_multi_select_set_and_clear_merge_with_the_validator(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#4288 validates multi_select on bulk edit; the merge keeps other keys."""
    from app.models.ipam import CustomFieldDefinition

    headers = await _headers(db_session)
    subs = await _two_subnets(db_session)
    db_session.add(
        CustomFieldDefinition(
            resource_type="subnet",
            name="teams",
            label="Teams",
            field_type="multi_select",
            options=["net", "sec"],
        )
    )
    await db_session.commit()
    await _bulk(client, headers, subs, {"custom_fields": {"teams": ["net"]}})
    for s in subs:
        await db_session.refresh(s)
        n = subs.index(s) + 1
        assert s.custom_fields == {"a": f"a{n}", "b": f"b{n}", "teams": ["net"]}
    await _bulk(client, headers, subs, {"custom_fields": {"teams": None}})
    for s in subs:
        await db_session.refresh(s)
        assert "teams" not in s.custom_fields and "a" in s.custom_fields
    r = await client.post(
        "/api/v1/ipam/subnets/bulk-edit",
        headers=headers,
        json={
            "subnet_ids": [str(subs[0].id)],
            "changes": {"custom_fields": {"teams": ["bogus"]}},
        },
    )
    assert r.status_code == 422
