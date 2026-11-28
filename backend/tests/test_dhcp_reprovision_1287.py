"""Re-provision a dynamic DHCP lease onto a static address (#1287).

A device on a dynamic lease (factory hostname, first contact) moves to a
permanent address: a reservation for its MAC in the scope's static range,
A + PTR under the new name, and the old lease — every copy in the group, its
IPAM mirror, its DDNS records, and the lease in Kea itself (``lease4_del``) —
gone.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.ai import AIOperationProposal
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dhcp import (
    DHCPConfigOp,
    DHCPLease,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.reprovision import (
    LEASE4_DEL_OP,
    ReprovisionError,
    commit_reprovision,
    preview_reprovision,
)

MAC = "aa:bb:cc:00:12:87"
OLD_IP = "10.81.0.150"


async def _superadmin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"rp-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Reprovision Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _operator(db: AsyncSession) -> tuple[User, dict[str, str]]:
    """Not a superadmin, but holding every DHCP / IPAM / DNS write grant."""
    tag = uuid.uuid4().hex[:8]
    role = Role(
        name=f"r-{tag}",
        permissions=[
            {"action": "admin", "resource_type": rt}
            for rt in ("dhcp_server", "dhcp_static", "subnet", "ip_address", "dns_zone")
        ],
    )
    group = Group(name=f"g-{tag}")
    group.roles = [role]
    user = User(
        username=f"op-{tag}",
        email=f"{tag}@example.test",
        display_name="DHCP Operator",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _setup(
    db: AsyncSession,
    *,
    reserved_pool: bool = True,
    driver: str = "kea",
    live: bool = True,
) -> dict:
    dns_group = DNSServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
    db.add(dns_group)
    await db.flush()
    zone = DNSZone(
        group_id=dns_group.id,
        name="rp.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.rp.example.",
        admin_email="admin.rp.example.",
    )
    db.add(zone)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.81.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.81.0.0/24",
        name="mgmt",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()

    group = DHCPServerGroup(name=f"kg-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    servers = [
        DHCPServer(
            name=f"kea-{i}-{uuid.uuid4().hex[:4]}",
            driver=driver if i == 0 else "kea",
            host=f"127.0.0.{i + 1}",
            server_group_id=group.id,
        )
        for i in range(2)
    ]
    db.add_all(servers)
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="mgmt", address_family="ipv4")
    db.add(scope)
    await db.flush()
    db.add(
        DHCPPool(
            scope_id=scope.id,
            name="first-contact",
            start_ip="10.81.0.100",
            end_ip="10.81.0.199",
            pool_type="dynamic",
        )
    )
    if reserved_pool:
        db.add(
            DHCPPool(
                scope_id=scope.id,
                name="static",
                start_ip="10.81.0.20",
                end_ip="10.81.0.29",
                pool_type="reserved",
            )
        )
    # Something already sits at the first reserved address.
    db.add(IPAddress(subnet_id=subnet.id, address="10.81.0.20", status="allocated"))

    now = datetime.now(UTC)
    leases = [
        DHCPLease(
            server_id=srv.id,
            scope_id=scope.id,
            ip_address=OLD_IP,
            mac_address=MAC,
            hostname="APC-1A2B3C",
            starts_at=now - timedelta(hours=1 if live else 3),
            ends_at=now + timedelta(hours=1 if live else -2),
            expires_at=now + timedelta(hours=1 if live else -2),
            state="active" if live else "expired",
            last_seen_at=now,
        )
        for srv in servers
    ]
    db.add_all(leases)
    mirror = IPAddress(
        subnet_id=subnet.id,
        address=OLD_IP,
        status="dhcp",
        hostname="apc-1a2b3c",
        mac_address=MAC,
        auto_from_lease=True,
        forward_zone_id=zone.id,
    )
    db.add(mirror)
    await db.flush()
    rec = DNSRecord(
        zone_id=zone.id,
        name="apc-1a2b3c",
        record_type="A",
        value=OLD_IP,
        auto_generated=True,
        ip_address_id=mirror.id,
    )
    db.add(rec)
    await db.flush()
    mirror.dns_record_id = rec.id
    await db.flush()
    return {
        "zone": zone,
        "subnet": subnet,
        "scope": scope,
        "servers": servers,
        "lease": leases[0],
        "mirror": mirror,
    }


# ── preview ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_preview_picks_first_free_address_in_reserved_pool(db_session: AsyncSession) -> None:
    s = await _setup(db_session)
    await db_session.commit()

    plan = await preview_reprovision(db_session, s["lease"].id, hostname="ups-rack1")

    assert plan.old_ip == OLD_IP
    assert plan.target_ip == "10.81.0.21"  # .20 is taken
    assert plan.target_source == "reserved_pool"
    assert "static" in plan.target_reason
    assert plan.fqdn == "ups-rack1.rp.example"
    assert "A ups-rack1.rp.example -> 10.81.0.21" in plan.dns_create
    assert any("apc-1a2b3c.rp.example" in r for r in plan.dns_remove)
    assert len(plan.servers) == 2
    assert plan.t1_at is not None
    assert "renewal" in plan.expected_move and "reboot" in plan.expected_move
    # Read-only: nothing changed.
    assert await db_session.get(DHCPLease, s["lease"].id) is not None
    assert (await db_session.execute(select(DHCPStaticAssignment))).first() is None


@pytest.mark.asyncio
async def test_preview_without_reserved_pool_stays_out_of_the_dynamic_pool(
    db_session: AsyncSession,
) -> None:
    s = await _setup(db_session, reserved_pool=False)
    await db_session.commit()

    plan = await preview_reprovision(db_session, s["lease"].id)

    assert plan.target_source == "outside_dynamic_pools"
    assert plan.target_ip == "10.81.0.1"
    # Without a new name the lease's client name is kept, sanitized.
    assert plan.hostname == "apc-1a2b3c"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "status", "fragment"),
    [
        ("10.81.0.120", 422, "dynamic pool"),
        ("10.81.0.20", 409, "already in use"),
        (OLD_IP, 422, "own address"),
        ("10.82.0.5", 422, "not a usable host"),
    ],
)
async def test_preview_refuses_bad_targets(
    db_session: AsyncSession, target: str, status: int, fragment: str
) -> None:
    s = await _setup(db_session)
    await db_session.commit()

    with pytest.raises(ReprovisionError) as exc:
        await preview_reprovision(db_session, s["lease"].id, target_ip=target)
    assert exc.value.status_code == status
    assert fragment in exc.value.detail


@pytest.mark.asyncio
async def test_preview_refuses_windows_group(db_session: AsyncSession) -> None:
    s = await _setup(db_session, driver="windows_dhcp")
    await db_session.commit()

    with pytest.raises(ReprovisionError) as exc:
        await preview_reprovision(db_session, s["lease"].id)
    assert exc.value.status_code == 422
    assert "Windows" in exc.value.detail


@pytest.mark.asyncio
async def test_preview_refuses_mac_already_reserved(db_session: AsyncSession) -> None:
    s = await _setup(db_session)
    db_session.add(
        DHCPStaticAssignment(scope_id=s["scope"].id, ip_address="10.81.0.25", mac_address=MAC)
    )
    await db_session.commit()

    with pytest.raises(ReprovisionError) as exc:
        await preview_reprovision(db_session, s["lease"].id)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_preview_refuses_name_held_by_another_address(db_session: AsyncSession) -> None:
    s = await _setup(db_session)
    db_session.add(
        DNSRecord(zone_id=s["zone"].id, name="printer", record_type="A", value="10.81.0.9")
    )
    await db_session.commit()

    with pytest.raises(ReprovisionError) as exc:
        await preview_reprovision(db_session, s["lease"].id, hostname="printer")
    assert exc.value.status_code == 409
    # Keeping the lease's own name is fine: that record goes with the cleanup.
    plan = await preview_reprovision(db_session, s["lease"].id, hostname="apc-1a2b3c")
    assert plan.hostname == "apc-1a2b3c"


# ── commit ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_commit_with_a_live_lease(client: AsyncClient, db_session: AsyncSession) -> None:
    """The reservation and the new name land now; the old lease stays.

    The device still uses its address until Kea NAKs its renewal. Deleting the
    lease up front would make Kea answer that RENEW with silence (it holds no
    lease for it) and free the address while the device still uses it.
    """
    _, headers = await _superadmin(db_session)
    s = await _setup(db_session)
    lease_id, mirror_id, scope_id = s["lease"].id, s["mirror"].id, s["scope"].id
    await db_session.commit()

    preview = await client.get(
        f"/api/v1/dhcp/leases/{lease_id}/reprovision/preview",
        params={"hostname": "ups-rack1"},
        headers=headers,
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["old_lease"] == "kept_until_moved"
    target = preview.json()["target_ip"]
    assert target == "10.81.0.21"

    resp = await client.post(
        f"/api/v1/dhcp/leases/{lease_id}/reprovision",
        json={"target_ip": target, "hostname": "ups-rack1"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()

    # The reservation, its IPAM row and the new name.
    st = (await db_session.execute(select(DHCPStaticAssignment))).scalar_one()
    assert st.scope_id == scope_id
    assert str(st.ip_address) == target
    assert str(st.mac_address) == MAC
    assert st.hostname == "ups-rack1"
    row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == target))
    ).scalar_one()
    assert row.status == "static_dhcp"
    assert row.static_assignment_id == str(st.id)
    new_rec = (
        await db_session.execute(
            select(DNSRecord).where(DNSRecord.name == "ups-rack1", DNSRecord.record_type == "A")
        )
    ).scalar_one()
    assert new_rec.value == target

    # The live lease, its mirror and its record are untouched; no lease4_del.
    assert len((await db_session.execute(select(DHCPLease))).scalars().all()) == 2
    assert await db_session.get(IPAddress, mirror_id) is not None
    old = (
        await db_session.execute(select(DNSRecord).where(DNSRecord.name == "apc-1a2b3c"))
    ).scalar_one()
    assert old.value == OLD_IP
    ops = await db_session.execute(
        select(DHCPConfigOp).where(DHCPConfigOp.op_type == LEASE4_DEL_OP)
    )
    assert ops.first() is None
    actions = {
        a.action
        for a in (
            await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "dhcp_lease"))
        ).scalars()
    }
    assert actions == {"reprovision"}


@pytest.mark.asyncio
async def test_commit_with_an_expired_lease_removes_it(db_session: AsyncSession) -> None:
    """A lease the device no longer holds goes now: rows, mirror, DNS and Kea."""
    user, _ = await _superadmin(db_session)
    s = await _setup(db_session, live=False)
    mirror_id = s["mirror"].id
    server_ids = {srv.id for srv in s["servers"]}
    await db_session.commit()

    plan = await preview_reprovision(db_session, s["lease"].id)
    assert plan.old_lease == "removed_now"
    out = await commit_reprovision(
        db_session, user, s["lease"].id, target_ip=plan.target_ip, hostname="ups-rack1"
    )
    db_session.expire_all()

    assert (await db_session.execute(select(DHCPLease))).scalars().all() == []
    assert await db_session.get(IPAddress, mirror_id) is None
    gone = await db_session.execute(select(DNSRecord).where(DNSRecord.name == "apc-1a2b3c"))
    assert gone.first() is None
    ops = (
        (
            await db_session.execute(
                select(DHCPConfigOp).where(DHCPConfigOp.op_type == LEASE4_DEL_OP)
            )
        )
        .scalars()
        .all()
    )
    # Every Kea server drops its copy, so no lease snapshot can bring it back.
    assert {op.server_id for op in ops} == server_ids
    assert all(op.payload["ip_address"] == OLD_IP for op in ops)
    assert out["static_assignment_id"]


@pytest.mark.asyncio
async def test_commit_keeping_the_factory_name(db_session: AsyncSession) -> None:
    """Same name, new address: the old A goes before the new A comes (#1489)."""
    user, _ = await _superadmin(db_session)
    s = await _setup(db_session, live=False)
    await db_session.commit()

    out = await commit_reprovision(db_session, user, s["lease"].id, target_ip="10.81.0.22")
    db_session.expire_all()

    recs = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "apc-1a2b3c")))
        .scalars()
        .all()
    )
    assert [r.value for r in recs] == ["10.81.0.22"]
    assert out["target_ip"] == "10.81.0.22"


@pytest.mark.asyncio
async def test_commit_revalidates_the_target(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    s = await _setup(db_session)
    lease_id = s["lease"].id
    # Taken between preview and commit.
    db_session.add(IPAddress(subnet_id=s["subnet"].id, address="10.81.0.21", status="allocated"))
    await db_session.commit()

    with pytest.raises(ReprovisionError) as exc:
        await commit_reprovision(db_session, user, lease_id, target_ip="10.81.0.21")
    assert exc.value.status_code == 409
    assert await db_session.get(DHCPLease, lease_id) is not None  # nothing cleaned up


@pytest.mark.asyncio
async def test_commit_needs_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    _, headers = await _operator(db_session)
    s = await _setup(db_session)
    lease_id = s["lease"].id
    await db_session.commit()

    preview = await client.get(
        f"/api/v1/dhcp/leases/{lease_id}/reprovision/preview", headers=headers
    )
    assert preview.status_code == 200, preview.text
    resp = await client.post(
        f"/api/v1/dhcp/leases/{lease_id}/reprovision",
        json={"target_ip": preview.json()["target_ip"]},
        headers=headers,
    )
    assert resp.status_code == 403
    assert await db_session.get(DHCPLease, lease_id) is not None


@pytest.mark.asyncio
async def test_preview_unknown_lease_404(client: AsyncClient, db_session: AsyncSession) -> None:
    _, headers = await _superadmin(db_session)
    await db_session.commit()
    resp = await client.get(
        f"/api/v1/dhcp/leases/{uuid.uuid4()}/reprovision/preview", headers=headers
    )
    assert resp.status_code == 404


# ── MCP ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_preview_and_propose(db_session: AsyncSession) -> None:
    from app.services.ai.operations import ReprovisionLeaseArgs, get_operation
    from app.services.ai.tools.dhcp import PreviewReprovisionLeaseArgs, preview_reprovision_lease
    from app.services.ai.tools.proposals import propose_reprovision_lease

    user, _ = await _superadmin(db_session)
    s = await _setup(db_session)
    lease_id = str(s["lease"].id)
    await db_session.commit()

    out = await preview_reprovision_lease(
        db_session, user, PreviewReprovisionLeaseArgs(lease_id=lease_id)
    )
    assert out["target_ip"] == "10.81.0.21"

    res = await propose_reprovision_lease(
        db_session, user, ReprovisionLeaseArgs(lease_id=lease_id, hostname="ups-rack1")
    )
    assert res.get("kind") == "proposal", res
    proposal = await db_session.get(AIOperationProposal, uuid.UUID(res["proposal_id"]))
    # The picked address is pinned, so Apply moves the device where the
    # operator saw it go.
    assert proposal.args["target_ip"] == "10.81.0.21"

    op = get_operation("reprovision_lease")
    assert op is not None
    assert op.required_permission == ("write", "dhcp_static")


def test_mcp_registration_defaults() -> None:
    """Broad-blast-radius write is opt-in (#13); the read-only preview is on."""
    import app.services.ai.tools.dhcp  # noqa: F401 — registers the tools
    import app.services.ai.tools.proposals  # noqa: F401
    from app.services.ai.tools.base import REGISTRY

    preview = REGISTRY.get("preview_reprovision_lease")
    propose = REGISTRY.get("propose_reprovision_lease")
    assert preview is not None and propose is not None
    assert preview.default_enabled is True
    assert propose.default_enabled is False
    # Same gates as the REST preview (read on dhcp_server) and commit (superadmin).
    assert preview.permission == ("read", "dhcp_server")
    assert propose.permission == "superadmin"


@pytest.mark.asyncio
async def test_mcp_propose_needs_superadmin(db_session: AsyncSession) -> None:
    import app.services.ai.tools.dhcp  # noqa: F401 — registers the tools
    import app.services.ai.tools.proposals  # noqa: F401
    from app.services.ai.tools.base import REGISTRY, ToolPermissionDenied

    user, _ = await _operator(db_session)
    s = await _setup(db_session)
    lease_id = str(s["lease"].id)
    await db_session.commit()

    out = await REGISTRY.call(
        "preview_reprovision_lease", {"lease_id": lease_id}, db=db_session, user=user
    )
    assert out["target_ip"] == "10.81.0.21"
    with pytest.raises(ToolPermissionDenied):
        await REGISTRY.call(
            "propose_reprovision_lease", {"lease_id": lease_id}, db=db_session, user=user
        )
    assert (await db_session.execute(select(AIOperationProposal))).first() is None


def test_routes_publish_a_typed_schema() -> None:
    """Generated clients get the plan's fields, not an untyped object (#917)."""
    from app.main import app

    doc = app.openapi()
    for path, method in (
        ("/api/v1/dhcp/leases/{lease_id}/reprovision/preview", "get"),
        ("/api/v1/dhcp/leases/{lease_id}/reprovision", "post"),
    ):
        body = doc["paths"][path][method]["responses"]["200"]["content"]["application/json"]
        ref = body["schema"]["$ref"].rsplit("/", 1)[-1]
        assert "target_ip" in doc["components"]["schemas"][ref]["properties"]
