"""Regression tests for #400 / GHSA-mj4g-hw3m-62rm.

C2 (HIGH) — AI proposal apply RBAC backstop. The Operator Copilot
``propose_*`` → ``apply`` flow has no router-level
``require_*_permission`` dependency, so before the fix an authenticated
Viewer who owned a proposal row could apply it and write IPAM / DNS /
DHCP / multicast / alert rows the equivalent REST route would 403. The
fix declares an ``(action, resource_type)`` gate on every write
``Operation`` and enforces it in ``apply_proposal`` (authoritative) plus
each ``_apply_*`` (defense in depth).

M1 (MEDIUM) — MCP ``tools/call`` read-only gating. ``mcp_post`` dispatched
ANY registered tool by name (including ``propose_*`` writes) ignoring the
read-only advertised set. The fix passes ``effective={MCP tool names}``
so a read-scoped MCP caller can't invoke a write/propose tool.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai import mcp as mcp_mod
from app.api.v1.ai.proposals import apply_proposal
from app.core.security import hash_password
from app.models.ai import AIOperationProposal
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ai import operations
from app.services.ai.operations import (
    CreateIPAddressArgs,
    OperationPermissionError,
    enforce_operation_permission,
    get_operation,
)
from app.services.ai.tools import REGISTRY


def _fake_request() -> Request:
    """A minimal ASGI ``Request`` for the ``apply_proposal`` calls below.

    ``apply_proposal`` gained a required ``request`` parameter in #601 (it now
    routes risky ops through ``gate_or_execute(db, user, request, …)`` for the
    two-person approval workflow), but these #400 RBAC tests predate that and
    were never updated — so they broke with ``missing 1 required positional
    argument: 'request'``. The parameter is only dereferenced for a *risky*
    operation; the ops exercised here (CreateIPAddress) are not risky and the
    RBAC denial fires before ``gate_or_execute``, so a bare http scope is enough.
    """
    return Request(
        {"type": "http", "method": "POST", "path": "/api/v1/ai/proposals/apply", "headers": []}
    )


async def _user(
    db: AsyncSession,
    *,
    superadmin: bool = False,
    name: str = "rbac",
    permissions: list[dict] | None = None,
) -> User:
    """Create a user. ``permissions`` (a list of RBAC permission dicts)
    is attached via a fresh Group+Role so the user passes
    ``user_has_permission`` for exactly those grants — mirroring how a
    real Viewer / IPAM-Editor is provisioned."""
    u = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@example.test",
        display_name="RBAC Tester",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        u.groups = [group]
        db.add_all([role, group])
    db.add(u)
    await db.commit()
    return u


async def _subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="s")
    db.add(subnet)
    await db.commit()
    await db.refresh(subnet)
    return subnet


async def _make_proposal(
    db: AsyncSession, *, user: User, operation: str, args: dict
) -> AIOperationProposal:
    row = AIOperationProposal(
        session_id=None,
        user_id=user.id,
        operation=operation,
        args=args,
        preview_text="preview",
        expires_at=operations.expires_at_default(),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ── C2: operation-level gate declared on every write op ────────────────


def test_core_write_ops_declare_a_gate() -> None:
    """The IPAM / DNS / DHCP / multicast / appliance write operations
    must each declare a coarse RBAC gate so apply_proposal can enforce it
    (#400 C2). Self-scoped ops (archive_session — own session only) and
    inline-superadmin ops (create_alert_rule, grant_temporary_access)
    gate inside their own apply instead and are excluded here."""
    expected = {
        "create_ip_address": ("write", "ip_address"),
        "allocate_subnet": ("write", "subnet"),
        "run_nmap_scan": ("write", "manage_nmap_scans"),
        "create_dns_record": ("write", "dns_record"),
        "create_dns_zone": ("write", "dns_zone"),
        "create_dhcp_static": ("write", "dhcp_static"),
        "create_multicast_group": ("write", "multicast"),
        "allocate_multicast_groups": ("write", "multicast"),
        "approve_appliance": ("admin", "appliance"),
        "assign_appliance_role": ("admin", "appliance"),
        "toggle_firewall_policy": ("admin", "appliance"),
    }
    for name, gate in expected.items():
        op = get_operation(name)
        assert op is not None, f"operation {name!r} not registered"
        assert op.required_permission == gate, f"{name}: {op.required_permission!r} != {gate!r}"


@pytest.mark.asyncio
async def test_enforce_operation_permission_raises_for_viewer(db_session: AsyncSession) -> None:
    op = get_operation("create_ip_address")
    assert op is not None
    # A bare user with no groups → no write on ip_address.
    viewer = await _user(db_session)
    with pytest.raises(OperationPermissionError):
        enforce_operation_permission(viewer, op)


# ── C2: apply_proposal is the authoritative backstop ──────────────────


@pytest.mark.asyncio
async def test_apply_proposal_403_for_unprivileged_owner(db_session: AsyncSession) -> None:
    """A Viewer who OWNS the proposal still cannot apply it — the apply
    endpoint enforces the op's RBAC gate, not just ownership."""
    subnet = await _subnet(db_session)
    viewer = await _user(db_session, name="viewer")
    proposal = await _make_proposal(
        db_session,
        user=viewer,
        operation="create_ip_address",
        args=CreateIPAddressArgs(subnet_id=str(subnet.id), address="10.0.5.10").model_dump(),
    )

    with pytest.raises(HTTPException) as ei:
        await apply_proposal(proposal.id, viewer, db_session, _fake_request())
    assert ei.value.status_code == 403

    # And no IPAddress row was written.
    rows = (
        (await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.asyncio
async def test_apply_proposal_succeeds_for_authorized_writer(db_session: AsyncSession) -> None:
    """A user granted ('write','ip_address') — the same grant the REST
    route requires — can apply the proposal and the row lands."""
    subnet = await _subnet(db_session)
    writer = await _user(
        db_session,
        name="ipam-editor",
        permissions=[{"action": "write", "resource_type": "ip_address"}],
    )
    proposal = await _make_proposal(
        db_session,
        user=writer,
        operation="create_ip_address",
        args=CreateIPAddressArgs(subnet_id=str(subnet.id), address="10.0.5.11").model_dump(),
    )

    resp = await apply_proposal(proposal.id, writer, db_session, _fake_request())
    assert resp.ok is True
    rows = (
        (
            await db_session.execute(
                select(IPAddress).where(
                    IPAddress.subnet_id == subnet.id, IPAddress.address == "10.0.5.11"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_apply_proposal_succeeds_for_superadmin(db_session: AsyncSession) -> None:
    subnet = await _subnet(db_session)
    admin = await _user(db_session, superadmin=True, name="admin")
    proposal = await _make_proposal(
        db_session,
        user=admin,
        operation="create_ip_address",
        args=CreateIPAddressArgs(subnet_id=str(subnet.id), address="10.0.5.12").model_dump(),
    )
    resp = await apply_proposal(proposal.id, admin, db_session, _fake_request())
    assert resp.ok is True


@pytest.mark.asyncio
async def test_apply_proposal_wrong_resource_type_perm_still_403(db_session: AsyncSession) -> None:
    """A grant on a DIFFERENT resource_type (dns_record) must NOT let the
    caller apply a create_ip_address proposal."""
    subnet = await _subnet(db_session)
    user = await _user(
        db_session,
        name="dns-only",
        permissions=[{"action": "write", "resource_type": "dns_record"}],
    )
    proposal = await _make_proposal(
        db_session,
        user=user,
        operation="create_ip_address",
        args=CreateIPAddressArgs(subnet_id=str(subnet.id), address="10.0.5.20").model_dump(),
    )
    with pytest.raises(HTTPException) as ei:
        await apply_proposal(proposal.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403


# ── M1: MCP tools/call refuses write / propose tools ──────────────────


@pytest.mark.asyncio
async def test_mcp_tools_call_rejects_propose_tool(db_session: AsyncSession) -> None:
    """A propose_* tool is NOT in the MCP-exposed set (propose tools are
    registered writes=False but still stage a write), so tools/call must
    report method-not-found and must NOT persist a proposal row."""
    user = await _user(db_session, superadmin=True, name="mcp")

    propose_names = sorted(t.name for t in REGISTRY.all() if t.name.startswith("propose_"))
    assert propose_names, "expected at least one propose_* tool registered"
    target = propose_names[0]

    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": target, "arguments": {}},
    }
    resp = await mcp_mod._dispatch_one(frame, db_session, user)
    assert "error" in resp, resp
    # -32601 = method not found (we deliberately mask disabled→not-found
    # so the existence of non-exposed tools doesn't leak).
    assert resp["error"]["code"] == mcp_mod._METHOD_NOT_FOUND
    # No proposal row was staged.
    rows = (
        (
            await db_session.execute(
                select(AIOperationProposal).where(AIOperationProposal.user_id == user.id)
            )
        )
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.asyncio
async def test_mcp_tools_call_rejects_write_tool(db_session: AsyncSession) -> None:
    """A genuine writes=True tool must be rejected by tools/call too."""
    user = await _user(db_session, superadmin=True, name="mcpw")
    write_names = sorted(t.name for t in REGISTRY.all() if t.writes)
    if not write_names:
        pytest.skip("no writes=True tool registered")
    frame = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": write_names[0], "arguments": {}},
    }
    resp = await mcp_mod._dispatch_one(frame, db_session, user)
    assert resp["error"]["code"] == mcp_mod._METHOD_NOT_FOUND


@pytest.mark.asyncio
async def test_mcp_tools_list_excludes_write_and_propose(db_session: AsyncSession) -> None:
    """The advertised tools/list must never include a write or propose
    tool — keeps the call-gate's effective set in sync with what's
    advertised (single source of truth: _mcp_tools)."""
    user = await _user(db_session, superadmin=True, name="mcp2")
    frame = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    resp = await mcp_mod._dispatch_one(frame, db_session, user)
    listed = {t["name"] for t in resp["result"]["tools"]}
    excluded = {t.name for t in REGISTRY.all() if t.writes or t.name.startswith("propose_")}
    assert listed.isdisjoint(excluded)
    assert listed == {t.name for t in await mcp_mod._mcp_tools(db_session, user)}
    assert listed <= await mcp_mod._mcp_tool_names(db_session)
