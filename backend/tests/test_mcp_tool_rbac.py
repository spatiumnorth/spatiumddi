"""Copilot / MCP tools enforce the caller's permissions (GHSA-4wrc-78rq-vgcg).

Before the fix ``ToolRegistry.call`` validated arguments and ran the
executor with no authorization at all, so any signed-in account — or a
read-scoped API token bound to a single DNS zone — could read DNS, DHCP and
IPAM data its role does not grant by calling the read tools over
``POST /api/v1/ai/mcp``. MCP also dispatched every non-write tool, ignoring
the Tool Catalog, ``default_enabled`` and feature-module gating that the
in-app chat honours, and ``tls_cert_check`` opened a raw socket to any host.

These tests drive the MCP dispatcher directly (the same function the HTTP
route calls), so no LLM or provider is involved — exactly the reported path.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai import mcp as mcp_mod
from app.core.security import hash_password
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.feature_module import FeatureModule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import feature_modules
from app.services.ai.tools import REGISTRY


async def _user(
    db: AsyncSession,
    *,
    superadmin: bool = False,
    permissions: list[dict] | None = None,
) -> User:
    u = User(
        username=f"mcp-rbac-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="MCP RBAC",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
        is_active=True,
    )
    u.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        u.groups = [group]
        db.add_all([role, group])
    db.add(u)
    await db.commit()
    return u


async def _two_zones(db: AsyncSession) -> tuple[DNSZone, DNSZone]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    zones = []
    for label in ("zone-a", "zone-b"):
        zone = DNSZone(
            group_id=group.id,
            name=f"{label}-{uuid.uuid4().hex[:4]}.example.",
            zone_type="primary",
            kind="forward",
        )
        db.add(zone)
        await db.flush()
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name="www",
                fqdn=f"www.{zone.name}",
                record_type="A",
                value="192.0.2.10",
            )
        )
        zones.append(zone)
    await db.commit()
    return zones[0], zones[1]


async def _subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.20.5.0/24", name="s")
    db.add(subnet)
    await db.commit()
    return subnet


async def _call(db: AsyncSession, user: User, name: str, args: dict | None = None) -> dict:
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    }
    return await mcp_mod._dispatch_one(frame, db, user)


def _denied(resp: dict) -> bool:
    """A refusal is either a JSON-RPC error or an ``isError`` tool result —
    never a successful result carrying rows."""
    if "error" in resp:
        return True
    return bool(resp.get("result", {}).get("isError"))


def _payload(resp: dict) -> Any:
    assert "result" in resp and not resp["result"].get("isError"), resp
    return json.loads(resp["result"]["content"][0]["text"])


async def _listed(db: AsyncSession, user: User) -> set[str]:
    resp = await mcp_mod._dispatch_one(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, db, user
    )
    return {t["name"] for t in resp["result"]["tools"]}


# ── no grant → denied ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_without_dns_grant_cannot_read_dns_over_mcp(db_session: AsyncSession) -> None:
    zone_a, _ = await _two_zones(db_session)
    user = await _user(db_session)

    resp = await _call(db_session, user, "list_dns_zones")
    assert _denied(resp), resp
    assert zone_a.name not in json.dumps(resp)

    resp = await _call(db_session, user, "query_dns_records", {"zone_id": str(zone_a.id)})
    assert _denied(resp), resp
    assert "192.0.2.10" not in json.dumps(resp)


@pytest.mark.asyncio
async def test_user_without_ipam_grant_cannot_list_subnets_over_mcp(
    db_session: AsyncSession,
) -> None:
    await _subnet(db_session)
    # A DNS-only reader: has a grant, just not an IPAM one.
    user = await _user(db_session, permissions=[{"action": "read", "resource_type": "dns_zone"}])
    resp = await _call(db_session, user, "list_subnets")
    assert _denied(resp), resp
    assert "10.20.5.0" not in json.dumps(resp)


@pytest.mark.asyncio
async def test_tools_list_only_advertises_callable_tools(db_session: AsyncSession) -> None:
    user = await _user(db_session)
    listed = await _listed(db_session, user)
    for name in ("list_dns_zones", "query_dns_records", "list_subnets", "find_dhcp_leases"):
        assert name not in listed


# ── allowed role still works ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dns_reader_can_list_zones_and_records(db_session: AsyncSession) -> None:
    zone_a, zone_b = await _two_zones(db_session)
    user = await _user(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "dns_zone"},
            {"action": "read", "resource_type": "dns_record"},
        ],
    )
    names = {z["name"] for z in _payload(await _call(db_session, user, "list_dns_zones"))}
    assert {zone_a.name, zone_b.name} <= names
    rows = _payload(await _call(db_session, user, "query_dns_records", {"zone_id": str(zone_b.id)}))
    assert [r["value"] for r in rows] == ["192.0.2.10"]
    assert "list_dns_zones" in await _listed(db_session, user)


@pytest.mark.asyncio
async def test_ipam_reader_can_list_subnets(db_session: AsyncSession) -> None:
    await _subnet(db_session)
    user = await _user(db_session, permissions=[{"action": "read", "resource_type": "subnet"}])
    rows = _payload(await _call(db_session, user, "list_subnets"))
    assert any(r["network"] == "10.20.5.0/24" for r in rows)


# ── resource-scoped API token ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zone_bound_token_cannot_read_other_zone(db_session: AsyncSession) -> None:
    zone_a, zone_b = await _two_zones(db_session)
    await _subnet(db_session)
    # Owner is a superadmin; the token narrows it to read on zone A only —
    # exactly the reported reproduction.
    user = await _user(db_session, superadmin=True)
    user._api_token_resource_grants = [  # type: ignore[attr-defined]
        {"action": "read", "resource_type": "dns_zone", "resource_id": str(zone_a.id)}
    ]

    names = {z["name"] for z in _payload(await _call(db_session, user, "list_dns_zones"))}
    assert names == {zone_a.name}

    resp = await _call(db_session, user, "query_dns_records", {"zone_id": str(zone_b.id)})
    assert _denied(resp) or _payload(resp) == [], resp
    assert str(zone_b.id) not in json.dumps(resp.get("result", {}))

    # Unfiltered record search only returns zone A's rows.
    rows = _payload(await _call(db_session, user, "query_dns_records"))
    assert {r["zone_id"] for r in rows} == {str(zone_a.id)}

    # A DNS-zone token is not an IPAM credential.
    resp = await _call(db_session, user, "list_subnets")
    assert _denied(resp), resp


# ── catalog / module gating ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disabled_tool_is_refused_over_mcp(db_session: AsyncSession) -> None:
    user = await _user(db_session, superadmin=True)
    # default_enabled=False, so chat never offers it — MCP must not either.
    resp = await _call(db_session, user, "tls_cert_check", {"host": "192.0.2.1", "port": 443})
    assert "error" in resp and resp["error"]["code"] == mcp_mod._METHOD_NOT_FOUND, resp
    # A tool whose feature module the operator turned off.
    db_session.add(FeatureModule(id="tools.pcap", enabled=False))
    await db_session.commit()
    feature_modules.invalidate_cache()
    resp = await _call(db_session, user, "find_packet_captures")
    assert "error" in resp and resp["error"]["code"] == mcp_mod._METHOD_NOT_FOUND, resp
    listed = await _listed(db_session, user)
    assert "tls_cert_check" not in listed
    assert "find_packet_captures" not in listed


# ── tls_cert_check SSRF guard ──────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "localhost"])
async def test_tls_cert_check_refuses_blocked_targets(db_session: AsyncSession, host: str) -> None:
    tool = REGISTRY.get("tls_cert_check")
    assert tool is not None
    out = await tool.executor(
        db_session, await _user(db_session, superadmin=True), tool.args_model(host=host, port=443)
    )
    assert "blocked" in str(out.get("error", "")), out


# ── declaration coverage ───────────────────────────────────────────────────


def test_every_tool_declares_a_permission() -> None:
    from app.services.ai.tools.base import validate_tool_permission

    missing = [t.name for t in REGISTRY.all() if getattr(t, "permission", None) is None]
    assert not missing, f"tools without a permission declaration: {missing}"
    for tool in REGISTRY.all():
        validate_tool_permission(tool.name, tool.permission)


@pytest.mark.asyncio
async def test_registry_call_enforces_permission_for_chat_too(db_session: AsyncSession) -> None:
    """The gate lives in ``ToolRegistry.call``, so the in-process chat path
    (which passes its own effective set) is covered as well as MCP."""
    from app.services.ai.tools.base import ToolPermissionDenied

    user = await _user(db_session)
    with pytest.raises(ToolPermissionDenied):
        await REGISTRY.call(
            "list_dns_zones", {}, db=db_session, user=user, effective={"list_dns_zones"}
        )
