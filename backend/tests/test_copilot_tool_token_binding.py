"""Copilot / MCP tools and API tokens bound to specific zones or subnets.

An API token can be bound to individual DNS zones or subnets (#374). The
tool registry's coarse permission check only sees the resource TYPE, so such
a token passes it for every DNS (or IPAM) tool. Whether it then sees only its
own zone depends on the tool narrowing its output — which the REST routers
stopped trusting per handler long ago (``app.api.token_path_scope``).

The registry now applies the same floor: a token bound to specific instances
may only call tools that declare ``honours_token_binding=True``, and every
such declaration is pinned here against an audited list, so adding one is a
reviewed decision rather than a default.

The dispatch tests drive the MCP dispatcher directly (the function the HTTP
route calls) and ``ToolRegistry.call`` (the in-app chat path), so no LLM is
involved.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai import mcp as mcp_mod
from app.core.security import hash_password
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.base import ToolPermissionDenied

# Every tool a zone- or subnet-bound token may call. Each entry was read and
# narrows its output to the bound instances (or returns no resource data at
# all). Adding a tool here means doing that review for it.
AUDITED_TOKEN_BINDING_TOOLS = frozenset(
    {
        # DNS — list filtered by the bound zones, or by-id gated on them.
        "list_dns_zones",
        "query_dns_records",
        "list_dns_records",
        "preview_dns_zone_move",
        "find_zone_dnssec_info",
        "find_dns_zone_drift",
        "find_zone_update_acls",
        # IPAM — list filtered by the bound subnets, or by-id gated on them.
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
        "find_by_tag",
        # Shared search engine, which narrows results to the bound instances.
        "global_search",
        # No resource data.
        "ask_yes_no",
        "help_write_permission",
        "maintenance_status",
    }
)


# ── fixtures ────────────────────────────────────────────────────────────────


async def _user(
    db: AsyncSession,
    *,
    superadmin: bool = False,
    permissions: list[dict] | None = None,
) -> User:
    u = User(
        username=f"tok-bind-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token binding",
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


def _bind_token(user: User, resource_type: str, resource_id: object) -> User:
    """What the auth dependency stashes for a token bound to one instance."""
    user._api_token_resource_grants = [  # type: ignore[attr-defined]
        {"action": "read", "resource_type": resource_type, "resource_id": str(resource_id)}
    ]
    return user


class _Estate:
    """Two of everything: an A the token is bound to and a B it is not."""

    group_a: DNSServerGroup
    group_b: DNSServerGroup
    zone_a: DNSZone
    zone_b: DNSZone
    server_b: DNSServer
    subnet_a: Subnet
    subnet_b: Subnet
    ip_b: IPAddress

    def b_markers(self) -> list[str]:
        """Strings that only appear in a response carrying B's data. Ids are
        deliberately absent: a refusal may echo back the id it was asked
        for, which is not a disclosure."""
        return [
            self.zone_b.name,
            "192.0.2.20",
            self.server_b.name,
            str(self.subnet_b.network),
            str(self.subnet_b.name),
            str(self.ip_b.hostname),
        ]


async def _estate(db: AsyncSession) -> _Estate:
    e = _Estate()
    tag = uuid.uuid4().hex[:6]
    e.group_a = DNSServerGroup(name=f"grp-a-{tag}", description="")
    e.group_b = DNSServerGroup(name=f"grp-b-{tag}", description="")
    db.add_all([e.group_a, e.group_b])
    await db.flush()
    e.server_b = DNSServer(
        name=f"ns-b-{tag}",
        host="192.0.2.53",
        port=53,
        driver="bind9",
        group_id=e.group_b.id,
        is_primary=True,
        is_enabled=True,
    )
    db.add(e.server_b)
    zones = []
    for label, group, value in (("a", e.group_a, "192.0.2.10"), ("b", e.group_b, "192.0.2.20")):
        zone = DNSZone(
            group_id=group.id,
            name=f"zone-{label}-{tag}.example.",
            zone_type="primary",
            kind="forward",
            tags={"env": "lab"},
        )
        db.add(zone)
        await db.flush()
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name="www",
                fqdn=f"www.{zone.name}",
                record_type="A",
                value=value,
                tags={"env": "lab"},
            )
        )
        zones.append(zone)
    e.zone_a, e.zone_b = zones

    space = IPSpace(name=f"sp-{tag}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name=f"blk-{tag}")
    db.add(block)
    await db.flush()
    subnets = []
    for label, net in (("a", "10.20.5.0/24"), ("b", "10.20.6.0/24")):
        subnet = Subnet(
            space_id=space.id,
            block_id=block.id,
            network=net,
            name=f"subnet-{label}-{tag}",
            tags={"env": "lab"},
        )
        db.add(subnet)
        subnets.append(subnet)
    await db.flush()
    e.subnet_a, e.subnet_b = subnets
    e.ip_b = IPAddress(
        subnet_id=e.subnet_b.id,
        address=ipaddress.ip_address("10.20.6.5"),
        status="allocated",
        hostname=f"host-b-{tag}",
        description="",
        tags={"env": "lab"},
    )
    db.add(e.ip_b)
    await db.commit()
    return e


async def _mcp_call(db: AsyncSession, user: User, name: str, args: dict | None = None) -> dict:
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    }
    return await mcp_mod._dispatch_one(frame, db, user)


def _refused(resp: dict) -> bool:
    if "error" in resp:
        return True
    return bool(resp.get("result", {}).get("isError"))


# ── declaration guards ──────────────────────────────────────────────────────


def test_token_binding_declarations_match_the_audited_list() -> None:
    declared = {t.name for t in REGISTRY.all() if t.honours_token_binding}
    assert declared == AUDITED_TOKEN_BINDING_TOOLS, (
        "honours_token_binding changed without updating the audited list: "
        f"added {sorted(declared - AUDITED_TOKEN_BINDING_TOOLS)}, "
        f"removed {sorted(AUDITED_TOKEN_BINDING_TOOLS - declared)}"
    )


def test_token_binding_tools_are_read_only() -> None:
    for tool in REGISTRY.all():
        if tool.honours_token_binding:
            assert not tool.writes, tool.name
            assert not tool.name.startswith("propose_"), tool.name


@pytest.mark.parametrize("resource_type", ["dns_zone", "subnet"])
def test_bound_token_can_only_reach_audited_tools(resource_type: str) -> None:
    """Enumerates the whole registry: whatever a bound token is offered must
    be on the audited list, for the chat schema and ``tools/list`` alike."""
    owner = User(username="owner", is_superadmin=True, is_active=True)
    owner.groups = []
    user = _bind_token(owner, resource_type, uuid.uuid4())
    offered = {t.name for t in REGISTRY.callable_by(user, REGISTRY.all())}
    assert offered, "a bound token should still reach its narrowing tools"
    assert offered <= AUDITED_TOKEN_BINDING_TOOLS, sorted(offered - AUDITED_TOKEN_BINDING_TOOLS)


# ── dispatch: tools that do not narrow are refused ─────────────────────────


@pytest.mark.asyncio
async def test_zone_bound_token_is_refused_dns_inventory_tools(db_session: AsyncSession) -> None:
    e = await _estate(db_session)
    user = _bind_token(await _user(db_session, superadmin=True), "dns_zone", e.zone_a.id)

    for name in ("find_dns_servers", "list_dns_server_groups", "list_dns_views"):
        resp = await _mcp_call(db_session, user, name)
        assert _refused(resp), (name, resp)
        assert e.server_b.name not in json.dumps(resp), name
        assert e.group_b.name not in json.dumps(resp), name

    listed = await mcp_mod._dispatch_one(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, db_session, user
    )
    names = {t["name"] for t in listed["result"]["tools"]}
    assert "find_dns_servers" not in names
    assert "list_dns_zones" in names


@pytest.mark.asyncio
async def test_subnet_bound_token_is_refused_estate_wide_ipam_tools(
    db_session: AsyncSession,
) -> None:
    e = await _estate(db_session)
    user = _bind_token(await _user(db_session, superadmin=True), "subnet", e.subnet_a.id)

    for name in ("count_ipam_resources", "find_ip_hygiene_findings", "find_devices_by_vendor"):
        with pytest.raises(ToolPermissionDenied):
            await REGISTRY.call(name, {}, db=db_session, user=user)


@pytest.mark.asyncio
async def test_session_caller_is_unaffected_by_token_binding_rule(
    db_session: AsyncSession,
) -> None:
    """The rule only narrows bound tokens: a DNS reader on a session still
    reaches the inventory tools."""
    e = await _estate(db_session)
    user = await _user(
        db_session,
        permissions=[{"action": "read", "resource_type": "dns_group"}],
    )
    resp = await _mcp_call(db_session, user, "find_dns_servers")
    assert not _refused(resp), resp
    assert e.server_b.name in json.dumps(resp)


# ── narrowly-scoped role ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_instance_scoped_role_does_not_reach_other_zone(db_session: AsyncSession) -> None:
    e = await _estate(db_session)
    user = await _user(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "dns_zone", "resource_id": str(e.zone_a.id)},
            {"action": "read", "resource_type": "dns_record", "resource_id": str(e.zone_a.id)},
        ],
    )
    for name, args in (
        ("list_dns_zones", {}),
        ("query_dns_records", {"zone_id": str(e.zone_b.id)}),
        ("list_dns_records", {}),
        ("find_dns_servers", {}),
    ):
        resp = await _mcp_call(db_session, user, name, args)
        body = json.dumps(resp)
        assert e.zone_b.name not in body, name
        assert "192.0.2.20" not in body, name
        assert e.server_b.name not in body, name


# ── every audited tool narrows ─────────────────────────────────────────────


def _args_for(tool_name: str, fields: set[str], e: _Estate) -> list[dict[str, Any]]:
    """Arguments that point each tool at B wherever it takes a target."""
    if tool_name == "global_search":
        return [{"query": "www"}, {"query": "10.20"}, {"query": "host-b"}]
    args: dict[str, Any] = {}
    if "zone_id" in fields:
        args["zone_id"] = str(e.zone_b.id)
    if "subnet_id" in fields:
        args["subnet_id"] = str(e.subnet_b.id)
    if "target_group_id" in fields:
        args["target_group_id"] = str(e.group_a.id)
    if "address" in fields:
        args["address"] = "10.20.6.5"
    if "key" in fields:
        args["key"] = "env"
    if tool_name == "find_by_tag":
        args["resource_kinds"] = ["ip_space", "ip_block", "subnet", "ip_address"]
        return [args, {**args, "resource_kinds": ["dns_zone", "dns_record"]}]
    if tool_name == "help_write_permission":
        args.update({"action": "read", "resource_type": "subnet"})
    out = [args]
    # A list tool asked for nothing in particular must still filter.
    if args and not fields & {"address", "key", "target_group_id"}:
        out.append({})
    return out


@pytest.mark.asyncio
@pytest.mark.parametrize("resource_type", ["dns_zone", "subnet"])
async def test_audited_tools_return_nothing_outside_the_binding(
    db_session: AsyncSession, resource_type: str
) -> None:
    e = await _estate(db_session)
    owner = await _user(db_session, superadmin=True)
    bound = e.zone_a.id if resource_type == "dns_zone" else e.subnet_a.id
    user = _bind_token(owner, resource_type, bound)
    markers = e.b_markers()

    ran = 0
    outside: list[str] = []
    for name in sorted(AUDITED_TOKEN_BINDING_TOOLS):
        tool = REGISTRY.get(name)
        assert tool is not None, name
        fields = set(tool.args_model.model_fields)
        for args in _args_for(name, fields, e):
            try:
                args = tool.args_model.model_validate(args).model_dump(mode="json")
            except Exception:
                continue  # needs an argument this estate has nothing truthful for
            savepoint = await db_session.begin_nested()
            try:
                result = await REGISTRY.call(name, args, db=db_session, user=user)
            except ToolPermissionDenied:
                continue  # a DNS tool for a subnet token, and vice versa
            finally:
                if savepoint.is_active:
                    await savepoint.rollback()
            ran += 1
            body = json.dumps(result, default=str)
            outside.extend(f"{name}({args}) -> {m}" for m in markers if m in body)
    assert ran >= 10, ran
    assert not outside, outside
