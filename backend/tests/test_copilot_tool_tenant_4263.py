"""Copilot / MCP tools and tenant users (#4263).

A tenant user is offered, and may call, only tools that declare
``tenant_aware``; each of those reads IPAM rows through the session filter.
"""

from __future__ import annotations

import json

import pytest

from app.services.ai.tools import REGISTRY
from app.services.ai.tools.base import ToolPermissionDenied, tool_callable_by
from app.services.tenancy import tenant_scope_for
from tests._tenancy_helpers import make_side, reload_user, reset_scope

# Every tool a tenant user may call. Each was read and touches only the IPAM
# tables the tenant filter narrows. Adding one is a reviewed decision.
AUDITED_TENANT_TOOLS = frozenset(
    {
        "list_ip_spaces",
        "list_ip_blocks",
        "list_subnets",
        "find_subnets_decommissioning",
        "get_subnet_summary",
        "find_subnet_reconciliation",
        "get_subnet_utilization_trend",
        "find_stale_ips",
        "find_ip",
        "find_ip_addresses",
        "count_ipam_resources",
        "find_ip_hygiene_findings",
    }
)


def test_tenant_aware_declarations_match_the_audited_list() -> None:
    declared = {t.name for t in REGISTRY.all() if t.tenant_aware}
    assert declared == AUDITED_TENANT_TOOLS


def test_tenant_aware_tools_are_read_only() -> None:
    assert not [t.name for t in REGISTRY.all() if t.tenant_aware and t.writes]


@pytest.mark.asyncio
async def test_tenant_user_is_offered_only_aware_tools(db_session) -> None:
    a = await make_side(db_session, "Acme")
    user = await reload_user(db_session, a.user)
    assert tenant_scope_for(user) == frozenset({a.tenant.id})
    offered = {t.name for t in REGISTRY.all() if tool_callable_by(user, t)}
    assert offered <= AUDITED_TENANT_TOOLS
    assert offered  # not vacuous


@pytest.mark.asyncio
async def test_unaware_tool_is_refused_to_a_tenant_user(db_session) -> None:
    a = await make_side(db_session, "Acme")
    user = await reload_user(db_session, a.user)
    with pytest.raises(ToolPermissionDenied):
        await REGISTRY.call("find_dns_servers", {}, db=db_session, user=user)


@pytest.mark.asyncio
async def test_tools_answer_for_the_tenant_only(db_session) -> None:
    a = await make_side(db_session, "Acme")
    b = await make_side(db_session, "Beta")
    reset_scope(db_session)
    user = await reload_user(db_session, a.user)

    spaces = await REGISTRY.call("list_ip_spaces", {}, db=db_session, user=user)
    assert [s["id"] for s in spaces] == [str(a.space.id)]
    counts = await REGISTRY.call("count_ipam_resources", {}, db=db_session, user=user)
    assert counts["ip_spaces"] == 1 and counts["subnets"] == 1 and counts["ip_addresses"] == 1
    ips = await REGISTRY.call("find_ip", {"address": "10.50.1.10"}, db=db_session, user=user)
    assert [m["id"] for m in ips["matches"]] == [str(a.address.id)]
    found = await REGISTRY.call("find_ip_addresses", {"q": "host"}, db=db_session, user=user)
    assert "beta-host" not in json.dumps(found, default=str)
    summary = await REGISTRY.call(
        "get_subnet_summary", {"subnet_id": str(b.subnet.id)}, db=db_session, user=user
    )
    assert summary.get("error") == "subnet not found"
    reset_scope(db_session)


@pytest.mark.asyncio
async def test_find_tenants_is_superadmin_only_and_counts(db_session) -> None:
    from app.models.auth import User

    a = await make_side(db_session, "Acme")
    reset_scope(db_session)
    tool = REGISTRY.get("find_tenants")
    assert tool is not None and not tool.tenant_aware and not tool.writes
    admin = User(
        username="adm",
        email="a@example.test",
        display_name="a",
        hashed_password="x",
        is_superadmin=True,
    )
    admin.groups = []
    db_session.add(admin)
    await db_session.commit()
    out = await REGISTRY.call("find_tenants", {}, db=db_session, user=admin)
    (row,) = out["tenants"]
    assert row["name"] == "Acme" and row["ip_spaces"] == 1 and row["groups"] == 1
    user = await reload_user(db_session, a.user)
    with pytest.raises(ToolPermissionDenied):
        await REGISTRY.call("find_tenants", {}, db=db_session, user=user)
