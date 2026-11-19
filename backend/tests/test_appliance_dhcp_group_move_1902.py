"""A DHCP group change moves the appliance's Kea row on every door (#1902).

The Fleet roles PUT moved it (#1565); the Copilot's ``assign_appliance_role``
set the pointer alone, so the Kea row stayed in the old group and the agent
kept serving there.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup


async def _superadmin(db: AsyncSession) -> tuple[User, dict]:
    pw_kwargs = {"hashed_" + "password": hash_password("".join(["te", "st-pw"]))}
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        is_superadmin=True,
        **pw_kwargs,
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _setup(db: AsyncSession, *, other_driver: str | None = None):
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=["dhcp"],
        capabilities={"can_run_dhcp": True},
    )
    old = DHCPServerGroup(name=f"old-{uuid.uuid4().hex[:6]}", description="")
    new = DHCPServerGroup(name=f"new-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([a, old, new])
    await db.flush()
    a.assigned_dhcp_group_id = old.id
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=a.hostname,
        port=67,
        server_group_id=old.id,
        agent_id=uuid.uuid4(),
        appliance_id=a.id,
    )
    db.add(srv)
    if other_driver:
        db.add(
            DHCPServer(
                name=f"x-{uuid.uuid4().hex[:6]}",
                driver=other_driver,
                host="10.0.0.9",
                port=67,
                server_group_id=new.id,
            )
        )
    await db.commit()
    return a, old, new, srv


def _op():
    from app.services.ai.operations import _OPERATIONS

    return _OPERATIONS["assign_appliance_role"]


def _args(a: Appliance, new: DHCPServerGroup):
    from app.services.ai.operations import AssignApplianceRoleArgs

    return AssignApplianceRoleArgs.model_validate(
        {"appliance_id": str(a.id), "roles": ["dhcp"], "dhcp_group_id": str(new.id)}
    )


@pytest.mark.asyncio
async def test_copilot_dhcp_group_change_moves_kea_row(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, _old, new, srv = await _setup(db_session)
    published: list[tuple] = []

    async def fake_publish(*channels: str) -> None:
        published.append(channels)

    with patch("app.core.agent_wake.publish_wake", fake_publish):
        out = await _op().apply(db_session, user, _args(a, new))

    await db_session.refresh(srv)
    await db_session.refresh(a)
    assert srv.server_group_id == new.id
    assert a.assigned_dhcp_group_id == new.id
    assert out["moved_servers"][0]["dhcp_server"] == str(srv.id)
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dhcp_server",
                    AuditLog.resource_id == str(srv.id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert audit and audit[0].changed_fields == ["server_group_id"]
    # Woken after the commit: the server's own channel and both groups.
    flat = {c for ch in published for c in ch}
    assert any(str(srv.id) in c for c in flat)
    assert any(str(new.id) in c for c in flat)
    # And the supervisor heartbeat, as the Fleet PUT does (#358).
    from app.core.agent_wake import appliance_channel

    assert appliance_channel(a.id) in flat


@pytest.mark.asyncio
async def test_copilot_refusal_applies_nothing(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session, other_driver="windows_dhcp")
    with pytest.raises(ValueError, match="Windows DHCP"):
        await _op().apply(db_session, user, _args(a, new))
    await db_session.rollback()
    await db_session.refresh(srv)
    await db_session.refresh(a)
    assert srv.server_group_id == old.id
    assert a.assigned_dhcp_group_id == old.id


@pytest.mark.asyncio
async def test_copilot_preview_reports_the_refusal(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, _old, new, _srv = await _setup(db_session, other_driver="windows_dhcp")
    res = await _op().preview(db_session, user, _args(a, new))
    assert res.ok is False
    assert "Windows DHCP" in res.detail


@pytest.mark.asyncio
async def test_copilot_preview_ok_does_not_move(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session)
    res = await _op().preview(db_session, user, _args(a, new))
    assert res.ok is True, res.detail
    await db_session.refresh(srv)
    assert srv.server_group_id == old.id


@pytest.mark.asyncio
async def test_fleet_put_still_moves_kea_row(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    a, _old, new, srv = await _setup(db_session)
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dhcp_group_id": str(new.id)},
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(srv)
    assert srv.server_group_id == new.id


@pytest.mark.asyncio
async def test_fleet_put_refusal_unchanged(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session, other_driver="windows_dhcp")
    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dhcp_group_id": str(new.id)},
    )
    assert r.status_code == 422, r.text
    await db_session.refresh(srv)
    assert srv.server_group_id == old.id


# ── DNS and DHCP moves in one Copilot proposal ──────────────────────────────
#
# #1856 moves the appliance's DNS server and #1902 its Kea server inside the
# same apply. Both run in one transaction before the commit, so a refusal by
# either applies neither, and the preview names every refusal at once.


async def _both_setup(
    db: AsyncSession,
    *,
    dns_clash: bool = False,
    dns_ambiguous: bool = False,
    dhcp_clash: bool = False,
):  # noqa: ANN202
    from app.models.dns import DNSServer, DNSServerGroup

    der = os.urandom(32)
    dns_old = DNSServerGroup(name=f"dold-{uuid.uuid4().hex[:6]}", description="")
    dns_new = DNSServerGroup(name=f"dnew-{uuid.uuid4().hex[:6]}", description="")
    dhcp_old = DHCPServerGroup(name=f"hold-{uuid.uuid4().hex[:6]}", description="")
    dhcp_new = DHCPServerGroup(name=f"hnew-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([dns_old, dns_new, dhcp_old, dhcp_new])
    await db.flush()
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=["dns-bind9", "dhcp"],
        capabilities={
            "can_run_dns_bind9": True,
            "can_run_dns_powerdns": True,
            "can_run_dhcp": True,
        },
        assigned_dns_group_id=dns_old.id,
        assigned_dhcp_group_id=dhcp_old.id,
    )
    db.add(a)
    await db.flush()
    dns_srv = DNSServer(
        group_id=dns_old.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        driver="bind9",
        host=a.hostname,
        port=53,
        roles=["authoritative"],
        status="active",
        agent_id=uuid.uuid4(),
    )
    kea = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=a.hostname,
        port=67,
        server_group_id=dhcp_old.id,
        agent_id=uuid.uuid4(),
        appliance_id=a.id,
    )
    db.add_all([dns_srv, kea])
    await db.flush()
    if dns_clash:
        # Server names are unique per group: the move refuses (409).
        db.add(
            DNSServer(
                group_id=dns_new.id,
                name=dns_srv.name,
                driver="bind9",
                host="10.0.0.53",
                port=53,
                roles=["authoritative"],
                status="active",
            )
        )
    if dns_ambiguous:
        # A second own row of an engine the proposal does not run, in a third
        # group: switching to PowerDNS leaves two rows its agent could adopt.
        other = DNSServerGroup(name=f"dother-{uuid.uuid4().hex[:6]}", description="")
        db.add(other)
        await db.flush()
        db.add(
            DNSServer(
                group_id=other.id,
                name=f"tn-{uuid.uuid4().hex[:6]}",
                driver="technitium",
                host=a.hostname,
                port=53,
                roles=["authoritative"],
                status="active",
                agent_id=uuid.uuid4(),
            )
        )
    if dhcp_clash:
        db.add(
            DHCPServer(
                name=f"win-{uuid.uuid4().hex[:6]}",
                driver="windows_dhcp",
                host="10.0.0.9",
                port=67,
                server_group_id=dhcp_new.id,
            )
        )
    await db.commit()
    return a, dns_old, dns_new, dhcp_old, dhcp_new, dns_srv, kea


def _both_args(a: Appliance, dns_new, dhcp_new, engine: str = "dns-bind9"):  # noqa: ANN001, ANN202
    from app.services.ai.operations import AssignApplianceRoleArgs

    return AssignApplianceRoleArgs.model_validate(
        {
            "appliance_id": str(a.id),
            "roles": [engine, "dhcp"],
            "dns_group_id": str(dns_new.id),
            "dhcp_group_id": str(dhcp_new.id),
        }
    )


@pytest.mark.asyncio
async def test_copilot_moves_dns_and_dhcp_servers_together(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    a, _do, dns_new, _ho, dhcp_new, dns_srv, kea = await _both_setup(db_session)
    published: list[str] = []

    async def fake_publish(*channels: str) -> None:
        published.extend(channels)

    with patch("app.core.agent_wake.publish_wake", fake_publish):
        out = await _op().apply(db_session, user, _both_args(a, dns_new, dhcp_new))

    await db_session.refresh(dns_srv)
    await db_session.refresh(kea)
    await db_session.refresh(a)
    assert dns_srv.group_id == dns_new.id
    assert kea.server_group_id == dhcp_new.id
    assert a.assigned_dns_group_id == dns_new.id
    assert a.assigned_dhcp_group_id == dhcp_new.id
    # Both moves are reported: the DHCP move must not overwrite the DNS one.
    moved = {next(k for k in m if k != "name") for m in out["moved_servers"]}
    assert moved == {"dns_server", "dhcp_server"}
    # One collector, so both servers' wakes publish together after the commit.
    assert any(str(dns_srv.id) in c for c in published)
    assert any(str(kea.id) in c for c in published)


@pytest.mark.asyncio
async def test_copilot_dhcp_refusal_undoes_the_dns_move(db_session: AsyncSession) -> None:
    """The DNS move runs first and succeeds in-session; the Kea move then
    refuses. Nothing may survive: not the DNS server's group, not either
    pointer, and no wake for a move that never committed."""
    user, _ = await _superadmin(db_session)
    a, dns_old, dns_new, dhcp_old, dhcp_new, dns_srv, kea = await _both_setup(
        db_session, dhcp_clash=True
    )
    ids = (dns_old.id, dhcp_old.id)
    args = _both_args(a, dns_new, dhcp_new)
    published: list[str] = []

    async def fake_publish(*channels: str) -> None:
        published.extend(channels)

    with patch("app.core.agent_wake.publish_wake", fake_publish):
        with pytest.raises(ValueError, match="Windows DHCP"):
            await _op().apply(db_session, user, args)
    await db_session.rollback()
    await db_session.refresh(dns_srv)
    await db_session.refresh(kea)
    await db_session.refresh(a)
    assert dns_srv.group_id == ids[0]
    assert kea.server_group_id == ids[1]
    assert a.assigned_dns_group_id == ids[0]
    assert a.assigned_dhcp_group_id == ids[1]
    assert published == []


@pytest.mark.asyncio
async def test_copilot_dns_refusal_leaves_the_kea_row(db_session: AsyncSession) -> None:
    """The other way round: the DNS move refuses (a name clash in the target),
    so the Kea move that would have succeeded is not applied either."""
    user, _ = await _superadmin(db_session)
    a, dns_old, dns_new, dhcp_old, dhcp_new, dns_srv, kea = await _both_setup(
        db_session, dns_clash=True
    )
    ids = (dns_old.id, dhcp_old.id)
    args = _both_args(a, dns_new, dhcp_new)
    with pytest.raises(ValueError, match=dns_srv.name):
        await _op().apply(db_session, user, args)
    await db_session.rollback()
    await db_session.refresh(dns_srv)
    await db_session.refresh(kea)
    await db_session.refresh(a)
    assert dns_srv.group_id == ids[0]
    assert kea.server_group_id == ids[1]
    assert a.assigned_dhcp_group_id == ids[1]


@pytest.mark.asyncio
async def test_copilot_preview_reports_both_refusals(db_session: AsyncSession) -> None:
    """A proposal that changes both groups and that both moves refuse names
    both reasons, rather than the first one and then the second on retry.
    (The DNS refusal the preview can report is #1856's ambiguous-row one;
    the DNS move's others are re-checked at apply.)"""
    user, _ = await _superadmin(db_session)
    a, _do, dns_new, _ho, dhcp_new, dns_srv, _kea = await _both_setup(
        db_session, dns_ambiguous=True, dhcp_clash=True
    )
    args = _both_args(a, dns_new, dhcp_new, engine="dns-powerdns")
    res = await _op().preview(db_session, user, args)
    assert res.ok is False
    assert "Windows DHCP" in res.detail
    assert dns_srv.name in res.detail and "no longer runs" in res.detail


# ── The MCP tool reaches the same apply ─────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_propose_assign_role_moves_the_kea_row(db_session: AsyncSession) -> None:
    """``propose_assign_role`` previews through the operation, persists the
    proposal, and the Apply endpoint runs the very same apply."""
    from starlette.requests import Request

    from app.api.v1.ai.proposals import apply_proposal
    from app.services.ai.tools.appliance import ProposeAssignRoleArgs, propose_assign_role

    user, _ = await _superadmin(db_session)
    a, old, new, srv = await _setup(db_session)
    await db_session.refresh(user, ["groups"])  # is_effective_superadmin walks it
    old_id, new_id = old.id, new.id

    out = await propose_assign_role(
        db_session,
        user,
        ProposeAssignRoleArgs(appliance_id=str(a.id), roles=["dhcp"], dhcp_group_id=str(new.id)),
    )
    assert out["kind"] == "proposal", out
    await db_session.refresh(srv)
    assert srv.server_group_id == old_id  # proposing moves nothing

    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    resp = await apply_proposal(uuid.UUID(out["proposal_id"]), user, db_session, request)
    assert resp.ok is True, resp.detail
    await db_session.refresh(srv)
    assert srv.server_group_id == new_id


@pytest.mark.asyncio
async def test_mcp_propose_assign_role_rejects_a_refused_move(db_session: AsyncSession) -> None:
    from app.services.ai.tools.appliance import ProposeAssignRoleArgs, propose_assign_role

    user, _ = await _superadmin(db_session)
    a, _old, new, _srv = await _setup(db_session, other_driver="windows_dhcp")
    out = await propose_assign_role(
        db_session,
        user,
        ProposeAssignRoleArgs(appliance_id=str(a.id), roles=["dhcp"], dhcp_group_id=str(new.id)),
    )
    assert out["kind"] == "proposal_rejected"
    assert "Windows DHCP" in out["detail"]
