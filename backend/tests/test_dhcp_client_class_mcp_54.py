"""Copilot / MCP surface for option 82 client classes (#54)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.dhcp import DHCPClientClass, DHCPServer, DHCPServerGroup
from app.services.ai import operations
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.dhcp import (
    CountDHCPClientClassesArgs,
    ListDHCPClientClassesArgs,
    count_dhcp_client_classes,
    list_dhcp_client_classes,
)
from app.services.ai.tools.proposals import propose_create_dhcp_client_class

SPEC = {"conditions": [{"sub_option": 1, "op": "starts_with", "value": "eth0/"}]}
COMPILED = "(substring(relay4[1].hex, 0, 5) == 0x657468302F)"


async def _admin(db: AsyncSession) -> User:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Root",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u


async def _group(db: AsyncSession, driver: str = "kea") -> DHCPServerGroup:
    g = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    db.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver=driver,
            host="10.0.0.1",
            port=67,
            server_group_id=g.id,
        )
    )
    await db.commit()
    return g


def test_the_tools_are_registered_enabled_and_gated() -> None:
    for name in ("count_dhcp_client_classes", "propose_create_dhcp_client_class"):
        tool = REGISTRY.get(name)
        assert tool is not None, name
        assert tool.default_enabled is True
        assert tool.module == "core.dhcp"
        assert tool.permission[1] == "dhcp_client_class"
    assert REGISTRY.get("propose_create_dhcp_client_class").writes is False
    op = operations.get_operation("create_dhcp_client_class")
    assert op is not None and op.required_permission == ("write", "dhcp_client_class")


async def test_list_and_count_carry_match_spec(db_session: AsyncSession) -> None:
    user = await _admin(db_session)
    g = await _group(db_session)
    db_session.add_all(
        [
            DHCPClientClass(
                group_id=g.id,
                name="built",
                match_expression=COMPILED,
                match_spec={"kind": "relay_agent"},
            ),
            DHCPClientClass(group_id=g.id, name="hand", match_expression="pkt4.mac == 0x01"),
        ]
    )
    await db_session.commit()
    rows = await list_dhcp_client_classes(db_session, user, ListDHCPClientClassesArgs())
    by = {r["name"]: r for r in rows}
    assert by["built"]["match_spec"] == {"kind": "relay_agent"}
    assert by["hand"]["match_spec"] is None
    assert (await count_dhcp_client_classes(db_session, user, CountDHCPClientClassesArgs()))[
        "count"
    ] == 2
    only = CountDHCPClientClassesArgs(group_id=str(g.id), option82_only=True)
    assert (await count_dhcp_client_classes(db_session, user, only))["count"] == 1


async def test_propose_previews_the_compiled_test_then_apply_creates_it(
    db_session: AsyncSession,
) -> None:
    user = await _admin(db_session)
    g = await _group(db_session)
    args = operations.get_operation("create_dhcp_client_class").args_model(
        group_id=str(g.id), name="port", match_spec=SPEC
    )
    out = await propose_create_dhcp_client_class(db_session, user, args)
    assert out["kind"] == "proposal", out
    assert COMPILED in out["preview"] or COMPILED in str(out)
    assert (await db_session.execute(select(DHCPClientClass))).first() is None  # nothing yet

    op = operations.get_operation("create_dhcp_client_class")
    result = await op.apply(db_session, user, args)
    assert result["match_expression"] == COMPILED
    row = (await db_session.execute(select(DHCPClientClass))).scalar_one()
    assert row.match_spec["conditions"][0]["sub_option"] == 1


async def test_propose_refuses_what_the_rest_create_refuses(db_session: AsyncSession) -> None:
    user = await _admin(db_session)
    op = operations.get_operation("create_dhcp_client_class")
    kea = await _group(db_session)
    win = await _group(db_session, "windows_dhcp")

    async def preview(**kw: object) -> operations.PreviewResult:
        return await op.preview(db_session, user, op.args_model(**kw))

    assert not (await preview(group_id=str(win.id), name="p", match_spec=SPEC)).ok
    assert not (
        await preview(group_id=str(kea.id), name="p", match_spec=SPEC, address_family="ipv6")
    ).ok
    assert not (
        await preview(
            group_id=str(kea.id), name="p", match_spec=SPEC, match_expression="relay4[1].exists"
        )
    ).ok
    bad = await preview(
        group_id=str(kea.id),
        name="p",
        match_spec={"conditions": [{"sub_option": 1, "op": "equals", "value": ""}]},
    )
    assert not bad.ok and "value" in bad.detail
    assert not (await preview(group_id="nope", name="p", match_spec=SPEC)).ok
    assert not (await preview(group_id=str(uuid.uuid4()), name="p", match_spec=SPEC)).ok
    ok = await preview(group_id=str(kea.id), name="p", match_spec=SPEC)
    assert ok.ok and COMPILED in ok.preview_text
