"""Every Operator Copilot write operation declares the gate the apply
endpoint enforces.

``apply_proposal`` calls ``enforce_operation_permission(user, op)`` before it
dispatches a proposal. That check only does something when the operation
declares a gate: ``required_permission`` (the RBAC pair its REST endpoint
requires) or ``requires_superadmin`` (its REST endpoint is superadmin-only).
An operation that declares neither is checked only when the proposal is
staged, so a user whose role was removed afterwards could still apply it.

The guard below walks every registered operation and fails for any that
declares neither, so a new operation cannot ship without one. The tests after
it pin the conformity-policy and multicast-domain operations, which used to
declare none.
"""

from __future__ import annotations

import inspect
import uuid

import pytest
from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.main  # noqa: F401 — registers every operation module the app loads
import app.services.ai.operations_control  # noqa: F401
import app.services.ai.operations_risky  # noqa: F401
import app.services.ai.operations_writes  # noqa: F401
from app.api.v1.ai.proposals import apply_proposal
from app.core.security import hash_password
from app.models.ai import AIOperationProposal
from app.models.auth import Group, Role, User
from app.models.conformity import ConformityPolicy
from app.models.multicast import MulticastDomain
from app.services.ai import operations
from app.services.ai.operations import all_operations, get_operation

# Operations that declare no gate on purpose. Each one must check
# authorization inside its own apply; the reason says how.
_NO_DECLARED_GATE: dict[str, str] = {
    # Archives the caller's OWN chat session. There is no RBAC resource to
    # name: the apply loads the session and refuses unless
    # ``session.user_id == user.id``.
    "archive_session": "self-scoped: ownership checked in _apply_archive_session",
}


# ── Guard ──────────────────────────────────────────────────────────────


def test_every_operation_declares_a_gate() -> None:
    ops = all_operations()
    # The registry is populated at import time; an empty or tiny registry
    # means the imports above stopped registering anything, and the check
    # below would pass vacuously.
    assert len(ops) >= 50, f"only {len(ops)} operations registered"

    missing = sorted(
        op.name
        for op in ops
        if op.required_permission is None
        and not op.requires_superadmin
        and op.name not in _NO_DECLARED_GATE
    )
    assert missing == [], (
        "operations with no declared gate (set required_permission to the "
        "pair the matching REST endpoint enforces, or requires_superadmin=True "
        f"when that endpoint is superadmin-only): {missing}"
    )


def test_no_declared_gate_allow_list_is_current() -> None:
    """Every allow-listed name is registered, declares no gate, and its
    apply really does check ownership — so the list cannot quietly cover an
    operation that has since changed."""
    for name in _NO_DECLARED_GATE:
        op = get_operation(name)
        assert op is not None, f"{name} is allow-listed but not registered"
        assert (
            op.required_permission is None and not op.requires_superadmin
        ), f"{name} now declares a gate; drop it from the allow-list"
    archive = get_operation("archive_session")
    assert archive is not None
    assert "user_id != user.id" in inspect.getsource(archive.apply)


def test_gates_match_the_rest_endpoints() -> None:
    expected = {
        # conformity/router.py: _require_admin → ("admin", "conformity")
        "create_conformity_policy": ("admin", "conformity"),
        "update_conformity_policy": ("admin", "conformity"),
        "evaluate_conformity_policy": ("admin", "conformity"),
        # multicast/router.py: require_resource_permission("multicast"),
        # POST/PUT → write, DELETE → delete
        "create_multicast_domain": ("write", "multicast"),
        "update_multicast_domain": ("write", "multicast"),
        "delete_multicast_domain": ("delete", "multicast"),
    }
    for name, gate in expected.items():
        op = get_operation(name)
        assert op is not None, name
        assert op.required_permission == gate, f"{name}: {op.required_permission!r}"

    superadmin_only = [
        "create_webhook",
        "update_webhook",
        "test_webhook",
        "sign_zone_dnssec",
        "unsign_zone_dnssec",
        "set_zone_update_acl",
        "update_snmp_settings",
        "update_ntp_settings",
        "update_syslog_settings",
        "commit_dns_import",
        "commit_dhcp_import",
        "commit_netbox_import",
        "create_alert_rule",
        "grant_temporary_access",
        "restart_service",
    ]
    for name in superadmin_only:
        op = get_operation(name)
        assert op is not None, name
        assert op.requires_superadmin is True, name


# ── Apply-time enforcement ─────────────────────────────────────────────


def _fake_request() -> Request:
    return Request(
        {"type": "http", "method": "POST", "path": "/api/v1/ai/proposals/apply", "headers": []}
    )


async def _user(
    db: AsyncSession,
    *,
    name: str,
    permissions: list[dict] | None = None,
    superadmin: bool = False,
) -> User:
    u = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@example.test",
        display_name="Gate Tester",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
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


async def _proposal(
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


def _conformity_args(name: str) -> dict:
    from app.services.conformity.checks import CHECK_REGISTRY  # noqa: PLC0415

    return {
        "name": name,
        "target_kind": "subnet",
        "check_kind": sorted(CHECK_REGISTRY)[0],
        "severity": "warning",
        "enabled": False,
    }


async def _conformity_rows(db: AsyncSession, name: str) -> list[ConformityPolicy]:
    res = await db.execute(select(ConformityPolicy).where(ConformityPolicy.name == name))
    return list(res.scalars().all())


@pytest.mark.asyncio
async def test_create_conformity_policy_apply_refused_without_admin(
    db_session: AsyncSession,
) -> None:
    # Holds read on conformity (what the read tools need) but not admin.
    user = await _user(
        db_session,
        name="conf-reader",
        permissions=[{"action": "read", "resource_type": "conformity"}],
    )
    name = f"pol-{uuid.uuid4().hex[:8]}"
    row = await _proposal(
        db_session, user=user, operation="create_conformity_policy", args=_conformity_args(name)
    )
    with pytest.raises(HTTPException) as ei:
        await apply_proposal(row.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403
    assert await _conformity_rows(db_session, name) == []


@pytest.mark.asyncio
async def test_create_conformity_policy_apply_allowed_with_admin(
    db_session: AsyncSession,
) -> None:
    user = await _user(
        db_session,
        name="conf-admin",
        permissions=[{"action": "admin", "resource_type": "conformity"}],
    )
    name = f"pol-{uuid.uuid4().hex[:8]}"
    row = await _proposal(
        db_session, user=user, operation="create_conformity_policy", args=_conformity_args(name)
    )
    resp = await apply_proposal(row.id, user, db_session, _fake_request())
    assert resp.ok is True, resp
    assert len(await _conformity_rows(db_session, name)) == 1


@pytest.mark.asyncio
async def test_delete_multicast_domain_apply_refused_with_write_only(
    db_session: AsyncSession,
) -> None:
    """``write`` on multicast is what create/update need; deleting needs
    ``delete``, as DELETE /multicast/domains/{id} does."""
    domain = MulticastDomain(name=f"dom-{uuid.uuid4().hex[:8]}", pim_mode="sparse")
    db_session.add(domain)
    await db_session.commit()
    user = await _user(
        db_session,
        name="mc-writer",
        permissions=[{"action": "write", "resource_type": "multicast"}],
    )
    row = await _proposal(
        db_session,
        user=user,
        operation="delete_multicast_domain",
        args={"domain_id": str(domain.id)},
    )
    with pytest.raises(HTTPException) as ei:
        await apply_proposal(row.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403
    assert await db_session.get(MulticastDomain, domain.id) is not None


@pytest.mark.asyncio
async def test_delete_multicast_domain_apply_allowed_with_delete(
    db_session: AsyncSession,
) -> None:
    domain = MulticastDomain(name=f"dom-{uuid.uuid4().hex[:8]}", pim_mode="sparse")
    db_session.add(domain)
    await db_session.commit()
    domain_id = domain.id
    user = await _user(
        db_session,
        name="mc-deleter",
        permissions=[{"action": "delete", "resource_type": "multicast"}],
    )
    row = await _proposal(
        db_session,
        user=user,
        operation="delete_multicast_domain",
        args={"domain_id": str(domain_id)},
    )
    resp = await apply_proposal(row.id, user, db_session, _fake_request())
    assert resp.ok is True, resp
    db_session.expire_all()
    res = await db_session.execute(select(MulticastDomain).where(MulticastDomain.id == domain_id))
    assert res.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_create_multicast_domain_apply_refused_without_write(
    db_session: AsyncSession,
) -> None:
    user = await _user(
        db_session,
        name="mc-reader",
        permissions=[{"action": "read", "resource_type": "multicast"}],
    )
    name = f"dom-{uuid.uuid4().hex[:8]}"
    row = await _proposal(
        db_session,
        user=user,
        operation="create_multicast_domain",
        args={"name": name, "pim_mode": "none"},
    )
    with pytest.raises(HTTPException) as ei:
        await apply_proposal(row.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403
    res = await db_session.execute(select(MulticastDomain).where(MulticastDomain.name == name))
    assert res.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_superadmin_only_operation_refused_for_non_superadmin(
    db_session: AsyncSession,
) -> None:
    """A superadmin-only operation is refused by the shared gate for a user
    holding every action on the zone's resource type but not superadmin —
    the REST sign endpoint is superadmin-only too."""
    user = await _user(
        db_session,
        name="dns-all",
        permissions=[{"action": "*", "resource_type": "dns_zone"}],
    )
    op = get_operation("sign_zone_dnssec")
    assert op is not None
    with pytest.raises(operations.OperationPermissionError):
        operations.enforce_operation_permission(user, op)

    admin = await _user(db_session, name="sa", superadmin=True)
    operations.enforce_operation_permission(admin, op)
