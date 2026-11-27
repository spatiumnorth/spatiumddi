"""MCP find / propose tools for DNS group options and trust anchors (#4429).

The REST twins are superadmin-only for writes and readable by ``dns_group``
readers. The propose tools stage a proposal through the shared preview, which
runs the PUT / POST / DELETE refusals, and Apply writes through the same
helpers, so a proposal is refused for what the route refuses.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.security import hash_password
from app.db import _json_serializer
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSTrustAnchor
from app.services.ai import operations
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.base import ToolArgumentError, ToolPermissionDenied


@pytest_asyncio.fixture
async def db_session(db_session: AsyncSession):  # type: ignore[no-untyped-def]
    """A session whose engine serializes JSONB as the app's does: a proposal's
    stored args carry UUIDs."""
    engine = create_async_engine(
        db_session.bind.url, poolclass=NullPool, json_serializer=_json_serializer
    )
    async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as s:
        yield s
    await engine.dispose()


READS = ("find_dns_group_options", "find_dns_trust_anchors")
WRITES = (
    "propose_update_dns_group_options",
    "propose_add_dns_trust_anchor",
    "propose_delete_dns_trust_anchor",
)
OPS = ("update_dns_group_options", "add_dns_trust_anchor", "delete_dns_trust_anchor")


async def _user(
    db: AsyncSession, *, superadmin: bool = False, permissions: list[dict] | None = None
) -> User:
    u = User(
        username=f"opt-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Opt",
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


async def _group(db: AsyncSession, driver: str = "bind9") -> uuid.UUID:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(g)
    await db.flush()
    db.add(DNSServer(group_id=g.id, name="ns1", driver=driver, host="10.0.0.53", port=53))
    await db.commit()
    return g.id


async def _call(db: AsyncSession, user: User, name: str, args: dict[str, Any]) -> Any:
    return await REGISTRY.call(name, args, db=db, user=user, effective={name})


async def _apply(db: AsyncSession, user: User, op_name: str, proposal: dict[str, Any]) -> Any:
    from app.models.ai import AIOperationProposal

    row = await db.get(AIOperationProposal, uuid.UUID(proposal["proposal_id"]))
    assert row is not None
    op = operations.get_operation(op_name)
    assert op is not None
    return await op.apply(db, user, op.args_model(**row.args))


def test_registration_and_defaults() -> None:
    for name in READS:
        t = REGISTRY.get(name)
        assert t is not None and t.default_enabled and not t.writes
        assert t.permission == ("read", "dns_group") and t.module == "core.dns"
    for name in WRITES:
        t = REGISTRY.get(name)
        assert t is not None and not t.default_enabled and not t.writes
        assert t.module == "core.dns"
    for name in OPS:
        op = operations.get_operation(name)
        assert op is not None and op.requires_superadmin


async def test_reads_need_dns_group_read(db_session: AsyncSession) -> None:
    gid = await _group(db_session)
    nobody = await _user(db_session)
    for name, args in (
        ("find_dns_group_options", {"group_id": str(gid)}),
        ("find_dns_trust_anchors", {}),
    ):
        with pytest.raises(ToolPermissionDenied):
            await _call(db_session, nobody, name, args)
    reader = await _user(db_session, permissions=[{"action": "read", "resource_type": "dns_group"}])
    out = await _call(db_session, reader, "find_dns_group_options", {"group_id": str(gid)})
    # No stored row yet: the defaults, and nothing was written for it.
    assert out["id"] is None and out["recursion_enabled"] is True
    assert (await db_session.execute(select(DNSServerOptions))).first() is None


async def test_find_trust_anchors_lists_group_anchors(db_session: AsyncSession) -> None:
    gid, other = await _group(db_session), await _group(db_session)
    sa = await _user(db_session, superadmin=True)
    out = await _call(
        db_session,
        sa,
        "propose_add_dns_trust_anchor",
        {
            "group_id": str(gid),
            "zone_name": "corp.example",
            "algorithm": 13,
            "key_tag": 1234,
            "public_key": "AwEAAQ==",
        },
    )
    await _apply(db_session, sa, "add_dns_trust_anchor", out)
    rows = await _call(db_session, sa, "find_dns_trust_anchors", {"group_id": str(gid)})
    assert [(r["zone_name"], r["key_tag"]) for r in rows] == [("corp.example", 1234)]
    assert await _call(db_session, sa, "find_dns_trust_anchors", {"group_id": str(other)}) == []


async def test_options_non_superadmin_is_refused(db_session: AsyncSession) -> None:
    gid = await _group(db_session)
    writer = await _user(db_session, permissions=[{"action": "*", "resource_type": "dns_group"}])
    out = await _call(
        db_session,
        writer,
        "propose_update_dns_group_options",
        {"group_id": str(gid), "blackhole": ["192.0.2.0/24"]},
    )
    assert out["kind"] == "proposal_rejected" and "superadmin" in out["detail"]
    with pytest.raises(ValueError, match="superadmin"):
        op = operations.get_operation("update_dns_group_options")
        assert op is not None
        await op.apply(db_session, writer, op.args_model(group_id=gid, blackhole=["192.0.2.0/24"]))


async def test_options_preview_changes_nothing_and_apply_writes(
    db_session: AsyncSession,
) -> None:
    gid = await _group(db_session)
    sa = await _user(db_session, superadmin=True)
    out = await _call(
        db_session,
        sa,
        "propose_update_dns_group_options",
        {"group_id": str(gid), "blackhole": ["192.0.2.0/24"], "rrl_qps_scale": 10},
    )
    assert out["kind"] == "proposal", out
    assert "blackhole" in out["preview"]
    # Previewing did not create the options row.
    assert (await db_session.execute(select(DNSServerOptions))).first() is None

    res = await _apply(db_session, sa, "update_dns_group_options", out)
    assert res["changed_fields"] == ["blackhole", "rrl_qps_scale"]
    shown = await _call(db_session, sa, "find_dns_group_options", {"group_id": str(gid)})
    assert shown["blackhole"] == ["192.0.2.0/24"] and shown["rrl_qps_scale"] == 10
    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_type == "dns_server_options")
        )
    ).scalar_one()
    assert audit.new_value["via"] == "ai_proposal"

    # ``clear`` survives the proposal's round-trip and returns a knob to default.
    out = await _call(
        db_session,
        sa,
        "propose_update_dns_group_options",
        {"group_id": str(gid), "clear": ["rrl_qps_scale"]},
    )
    await _apply(db_session, sa, "update_dns_group_options", out)
    shown = await _call(db_session, sa, "find_dns_group_options", {"group_id": str(gid)})
    assert shown["rrl_qps_scale"] is None and shown["blackhole"] == ["192.0.2.0/24"]


async def test_options_refusals_match_the_route(db_session: AsyncSession) -> None:
    sa = await _user(db_session, superadmin=True)
    pdns = await _group(db_session, "powerdns")
    out = await _call(
        db_session,
        sa,
        "propose_update_dns_group_options",
        {"group_id": str(pdns), "blackhole": ["192.0.2.0/24"]},
    )
    assert out["kind"] == "proposal_rejected" and "PowerDNS" in out["detail"]
    out = await _call(db_session, sa, "propose_update_dns_group_options", {"group_id": str(pdns)})
    assert out["kind"] == "proposal_rejected" and "nothing to change" in out["detail"]
    out = await _call(
        db_session,
        sa,
        "propose_update_dns_group_options",
        {"group_id": str(pdns), "clear": ["recursion_enabled"]},
    )
    assert out["kind"] == "proposal_rejected" and "cannot clear" in out["detail"]
    # Nothing was stored by any of the refused previews.
    assert (await db_session.execute(select(DNSServerOptions))).first() is None


async def test_trust_anchor_add_and_delete_refusals(db_session: AsyncSession) -> None:
    sa = await _user(db_session, superadmin=True)
    pdns = await _group(db_session, "powerdns")
    bind = await _group(db_session)
    base = {"algorithm": 8, "key_tag": 20326, "public_key": "AwEAAQ=="}

    out = await _call(
        db_session,
        sa,
        "propose_add_dns_trust_anchor",
        {"group_id": str(pdns), "zone_name": "corp.example", **base},
    )
    assert out["kind"] == "proposal_rejected" and "only applied by BIND9" in out["detail"]
    out = await _call(
        db_session,
        sa,
        "propose_add_dns_trust_anchor",
        {"group_id": str(bind), "zone_name": ".", "is_initial_key": False, **base},
    )
    assert out["kind"] == "proposal_rejected"

    out = await _call(
        db_session,
        sa,
        "propose_add_dns_trust_anchor",
        {"group_id": str(bind), "zone_name": ".", **base},
    )
    assert out["kind"] == "proposal", out
    res = await _apply(db_session, sa, "add_dns_trust_anchor", out)

    # With validation 'yes' the last anchor cannot go, as for the DELETE route.
    opts = (
        await db_session.execute(select(DNSServerOptions).where(DNSServerOptions.group_id == bind))
    ).scalar_one()
    opts.dnssec_validation = "yes"
    await db_session.commit()
    out = await _call(
        db_session,
        sa,
        "propose_delete_dns_trust_anchor",
        {"group_id": str(bind), "anchor_id": res["id"]},
    )
    assert out["kind"] == "proposal_rejected" and "last trust anchor" in out["detail"]

    opts.dnssec_validation = "auto"
    await db_session.commit()
    out = await _call(
        db_session,
        sa,
        "propose_delete_dns_trust_anchor",
        {"group_id": str(bind), "anchor_id": res["id"]},
    )
    assert out["kind"] == "proposal", out
    await _apply(db_session, sa, "delete_dns_trust_anchor", out)
    assert (await db_session.execute(select(DNSTrustAnchor))).first() is None
    actions = sorted(
        r.action
        for r in (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "dns_trust_anchor")
            )
        ).scalars()
    )
    assert actions == ["create", "delete"]


async def test_missing_group_and_foreign_anchor_are_refused_cleanly(
    db_session: AsyncSession,
) -> None:
    """Unknown group / anchor ids answer a refusal, never an exception, and an
    anchor of another group cannot be deleted through this group (#4429)."""
    sa = await _user(db_session, superadmin=True)
    ghost = uuid.uuid4()
    out = await _call(db_session, sa, "find_dns_group_options", {"group_id": str(ghost)})
    assert "not found" in out["error"]
    for name, args in (
        (
            "propose_update_dns_group_options",
            {"group_id": str(ghost), "blackhole": ["192.0.2.0/24"]},
        ),
        (
            "propose_add_dns_trust_anchor",
            {
                "group_id": str(ghost),
                "zone_name": ".",
                "algorithm": 8,
                "key_tag": 20326,
                "public_key": "AwEAAQ==",
            },
        ),
        (
            "propose_delete_dns_trust_anchor",
            {"group_id": str(ghost), "anchor_id": str(uuid.uuid4())},
        ),
    ):
        out = await _call(db_session, sa, name, args)
        assert out["kind"] == "proposal_rejected", (name, out)

    a, b = await _group(db_session), await _group(db_session)
    added = await _call(
        db_session,
        sa,
        "propose_add_dns_trust_anchor",
        {
            "group_id": str(a),
            "zone_name": "corp.example",
            "algorithm": 8,
            "key_tag": 1,
            "public_key": "AwEAAQ==",
        },
    )
    res = await _apply(db_session, sa, "add_dns_trust_anchor", added)
    out = await _call(
        db_session,
        sa,
        "propose_delete_dns_trust_anchor",
        {"group_id": str(b), "anchor_id": res["id"]},
    )
    assert out["kind"] == "proposal_rejected"
    # Apply-time (a stale proposal) raises a ValueError, not an HTTPException.
    op = operations.get_operation("delete_dns_trust_anchor")
    assert op is not None
    with pytest.raises(ValueError):
        await op.apply(db_session, sa, op.args_model(group_id=b, anchor_id=uuid.UUID(res["id"])))
    assert (await db_session.execute(select(DNSTrustAnchor))).scalar_one() is not None


async def test_invalid_args_are_rejected_not_500(db_session: AsyncSession) -> None:
    sa = await _user(db_session, superadmin=True)
    gid = await _group(db_session)
    with pytest.raises(ToolArgumentError, match="forward_policy"):
        await _call(
            db_session,
            sa,
            "propose_update_dns_group_options",
            {"group_id": str(gid), "forward_policy": "bogus"},
        )
