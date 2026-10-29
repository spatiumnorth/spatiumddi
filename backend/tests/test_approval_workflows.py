"""Regression tests for the two-person approval workflow (#62).

Covers the acceptance criteria pinned in the issue:

* **Module off (default)** → a covered ``DELETE /subnets/{id}`` executes
  inline (204) and creates NO ``change_request`` — zero behaviour change.
* **Policy on** → the same DELETE returns ``202`` with a ``pending``
  change_request, and the subnet still exists.
* **Self-approval** is blocked (403).
* **Two-person approve** — a *different* approver holding both
  ``{approve, change_request}`` and ``{delete, subnet}`` approves; the
  subnet is soft-deleted and the ``executed`` audit row carries the
  requester id (in ``old_value.requested_by``) AND the approver id
  (``user_id``).
* **Stale request** — the subnet became non-empty between submit and
  approve; approve re-runs preview, which refuses: the row ends
  ``failed`` with the reason (#2911) and the subnet is untouched.
* **Expiry sweep** flips a ``pending`` row past its TTL to ``expired``.
* **Superadmin** still needs a *second* superadmin to approve when the
  matched policy has ``applies_to_superadmin=True``.

The ``client`` + ``db_session`` fixtures share one session (handlers
commit on it), so a fixture write is visible to the HTTP handler and a
post-call DB read sees the handler's committed mutation. The
``governance.approvals`` feature-module cache is reset around every test
by the autouse ``_reset_global_caches`` fixture; ``_enable_module``
re-invalidates after inserting the override row so the gate observes it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.change_request import ApprovalPolicy, ChangeRequest
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import feature_modules

# ── Fixtures ──────────────────────────────────────────────────────────────────


async def _user(
    db: AsyncSession,
    *,
    name: str,
    permissions: list[dict] | None = None,
    superadmin: bool = False,
) -> tuple[User, str]:
    """Create a user with exactly ``permissions`` (via a fresh Group+Role)
    and return ``(user, bearer_token)``."""
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@t.io",
        display_name=name,
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    user.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _subnet(db: AsyncSession, network: str = "10.0.5.0/24") -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="s")
    db.add(subnet)
    await db.flush()
    return subnet


async def _enable_module(db: AsyncSession, *, enabled: bool = True) -> None:
    """Upsert the ``governance.approvals`` override + bust the global cache
    so the next ``is_module_enabled`` call observes the change."""
    existing = await db.get(FeatureModule, "governance.approvals")
    if existing is None:
        db.add(FeatureModule(id="governance.approvals", enabled=enabled))
    else:
        existing.enabled = enabled
    await db.flush()
    feature_modules.invalidate_cache()


async def _enable_delete_subnet_policy(
    db: AsyncSession, *, applies_to_superadmin: bool = True, ttl_hours: int = 168
) -> ApprovalPolicy:
    """Seed an enabled ``delete:subnet`` approval policy (built-in rows are
    normally seeded by migration; tests run on create_all so we seed our
    own)."""
    policy = ApprovalPolicy(
        name="delete:subnet",
        resource_type="subnet",
        action="delete",
        min_count=None,
        enabled=True,
        applies_to_superadmin=applies_to_superadmin,
        ttl_hours=ttl_hours,
        is_builtin=True,
    )
    db.add(policy)
    await db.flush()
    return policy


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _add_ip(db: AsyncSession, subnet: Subnet, address: str) -> None:
    """Make a subnet non-empty (an allocated, non-lease IP) — what the
    permanent-delete preview's stale check counts."""
    db.add(IPAddress(subnet_id=subnet.id, address=address, status="allocated"))
    await db.flush()


# ── Module off (default) → inline, no change_request ──────────────────────────


@pytest.mark.asyncio
async def test_module_off_deletes_inline(client: AsyncClient, db_session: AsyncSession) -> None:
    """With the module off (default), a covered delete executes inline (204)
    and creates no change_request — even if a policy row exists."""
    await _enable_module(db_session, enabled=False)
    await _enable_delete_subnet_policy(db_session)  # exists but never consulted
    subnet = await _subnet(db_session)
    _, token = await _user(
        db_session,
        name="op-a",
        permissions=[{"action": "delete", "resource_type": "subnet"}],
    )

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(token))
    assert r.status_code == 204, r.text

    n_cr = (await db_session.execute(select(func.count(ChangeRequest.id)))).scalar_one()
    assert n_cr == 0
    # Soft-deleted inline.
    await db_session.refresh(subnet)
    assert subnet.deleted_at is not None


# ── Policy on → 202 + pending row, subnet survives ────────────────────────────


@pytest.mark.asyncio
async def test_policy_on_queues_request(client: AsyncClient, db_session: AsyncSession) -> None:
    """Module on + delete:subnet policy enabled → DELETE returns 202 with a
    pending change_request, and the subnet still exists."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session)
    requester, token = await _user(
        db_session,
        name="requester",
        permissions=[{"action": "delete", "resource_type": "subnet"}],
    )

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(token))
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["state"] == "pending"
    cr_id = body["change_request_id"]

    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None
    assert cr.state == "pending"
    assert cr.operation == "delete_subnet"
    assert cr.resource_type == "subnet"
    assert cr.requested_by_user_id == requester.id

    # The subnet is NOT deleted — it's queued.
    await db_session.refresh(subnet)
    assert subnet.deleted_at is None

    # The ``requested`` audit row was committed before the response (NN #4).
    n_requested = (
        await db_session.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == "requested",
                AuditLog.resource_type == "change_request",
            )
        )
    ).scalar_one()
    assert n_requested == 1


# ── Self-approval blocked ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_self_approval_forbidden(client: AsyncClient, db_session: AsyncSession) -> None:
    """The requester cannot approve their own request (403) even if they
    hold the approve capability."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session)
    # The requester holds BOTH delete:subnet AND approve:change_request — the
    # only thing stopping them is the self-approval invariant.
    _, token = await _user(
        db_session,
        name="self-approver",
        permissions=[
            {"action": "delete", "resource_type": "subnet"},
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
        ],
    )

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(token))
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]

    r2 = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(token), json={}
    )
    assert r2.status_code == 403, r2.text
    assert "your own" in r2.json()["detail"].lower()

    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"


# ── Two-person approve → subnet deleted + audit carries both ids ──────────────


@pytest.mark.asyncio
async def test_two_person_approve_executes(client: AsyncClient, db_session: AsyncSession) -> None:
    """A different approver with {approve, change_request} + {delete, subnet}
    approves → the subnet is soft-deleted and the executed audit row carries
    requester (old_value.requested_by) and approver (user_id)."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session)
    requester, rtoken = await _user(
        db_session,
        name="requester",
        permissions=[{"action": "delete", "resource_type": "subnet"}],
    )
    approver, atoken = await _user(
        db_session,
        name="approver",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "delete", "resource_type": "subnet"},
        ],
    )

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(rtoken))
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]

    r2 = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve",
        headers=_auth(atoken),
        json={"decision_note": "looks fine"},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["state"] == "executed"

    # Subnet is now soft-deleted.
    await db_session.refresh(subnet)
    assert subnet.deleted_at is not None

    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None
    assert cr.state == "executed"
    assert cr.decided_by_user_id == approver.id
    assert cr.decision_note == "looks fine"

    # The executed audit row carries BOTH user ids.
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "executed",
                AuditLog.resource_type == "change_request",
                AuditLog.resource_id == cr_id,
            )
        )
    ).scalar_one()
    assert row.user_id == approver.id
    assert row.old_value is not None
    assert row.old_value.get("requested_by") == str(requester.id)


# ── Approver lacking the underlying op permission → 403 ───────────────────────


@pytest.mark.asyncio
async def test_approver_without_underlying_perm_denied(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An approver who holds {approve, change_request} but NOT {delete,
    subnet} cannot rubber-stamp a delete they couldn't perform (403)."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session)
    _, rtoken = await _user(
        db_session,
        name="requester",
        permissions=[{"action": "delete", "resource_type": "subnet"}],
    )
    _, atoken = await _user(
        db_session,
        name="approver-noperm",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
        ],
    )

    cr_id = (
        await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(rtoken))
    ).json()["change_request_id"]
    r = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atoken), json={}
    )
    assert r.status_code == 403, r.text


# ── Stale request → approve refuses, subnet untouched ─────────────────────────


@pytest.mark.asyncio
async def test_stale_request_refuses(client: AsyncClient, db_session: AsyncSession) -> None:
    """A permanent-delete request whose subnet became non-empty between
    submit and approve re-runs preview, which refuses: the request ends
    ``failed`` with the reason (#2911), and the subnet survives."""
    await _enable_module(db_session)
    # applies_to_superadmin so the superadmin requester is gated (needed
    # because the permanent path requires superadmin).
    await _enable_delete_subnet_policy(db_session, applies_to_superadmin=True)
    subnet = await _subnet(db_session)
    _, rtoken = await _user(db_session, name="sa-requester", superadmin=True)
    _, atoken = await _user(db_session, name="sa-approver", superadmin=True)

    # Submit on the permanent path while the subnet is empty → preview ok.
    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}?permanent=true", headers=_auth(rtoken)
    )
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]

    # The subnet becomes non-empty after submission — the stale case.
    await _add_ip(db_session, subnet, "10.0.5.42")
    await db_session.commit()

    r2 = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atoken), json={}
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["state"] == "failed"
    assert "not empty" in r2.json()["error"].lower()

    # Recorded failed; subnet untouched.
    db_session.expire_all()
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "failed"
    await db_session.refresh(subnet)
    assert subnet.deleted_at is None


# ── Expiry sweep flips pending → expired ──────────────────────────────────────


@pytest.mark.asyncio
async def test_expiry_sweep(db_session: AsyncSession) -> None:
    """A pending row past its TTL is flipped to ``expired`` by the sweep and
    never executes."""
    from app.services.approvals.service import mark_expired

    subnet = await _subnet(db_session)
    requester, _ = await _user(db_session, name="requester")
    cr = ChangeRequest(
        operation="delete_subnet",
        resource_type="subnet",
        resource_id=str(subnet.id),
        resource_display="s",
        args={"subnet_id": str(subnet.id), "force": False, "permanent": False},
        preview_text="Soft-delete subnet",
        risk_reason="delete:subnet",
        state="pending",
        requested_by_user_id=requester.id,
        requested_by_display="requester",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    db_session.add(cr)
    await db_session.flush()

    # Drive the sweep's per-row transition directly (the Celery wrapper opens
    # its own task_session against a different DB; the transition logic is the
    # unit under test).
    await mark_expired(db_session, cr)
    await db_session.commit()

    await db_session.refresh(cr)
    assert cr.state == "expired"
    assert cr.decided_at is not None

    n_expired = (
        await db_session.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == "expired",
                AuditLog.resource_type == "change_request",
            )
        )
    ).scalar_one()
    assert n_expired == 1


# ── Superadmin still needs a second superadmin ────────────────────────────────


@pytest.mark.asyncio
async def test_superadmin_needs_second_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """With applies_to_superadmin=True a superadmin's covered delete is
    queued (202), they can't self-approve (403), and a *second* superadmin
    approves it (200 → executed)."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session, applies_to_superadmin=True)
    subnet = await _subnet(db_session)
    _, token_a = await _user(db_session, name="super-a", superadmin=True)
    _, token_b = await _user(db_session, name="super-b", superadmin=True)

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(token_a))
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]

    # Self-approve refused.
    r_self = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(token_a), json={}
    )
    assert r_self.status_code == 403, r_self.text

    # Second superadmin approves.
    r_b = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(token_b), json={}
    )
    assert r_b.status_code == 200, r_b.text
    assert r_b.json()["state"] == "executed"

    await db_session.refresh(subnet)
    assert subnet.deleted_at is not None


# ── Superadmin bypass when applies_to_superadmin=False ────────────────────────


@pytest.mark.asyncio
async def test_superadmin_bypass_when_not_applies(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """With applies_to_superadmin=False a superadmin's covered delete runs
    inline (204) — the policy doesn't gate them."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session, applies_to_superadmin=False)
    subnet = await _subnet(db_session)
    _, token = await _user(db_session, name="super", superadmin=True)

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(token))
    assert r.status_code == 204, r.text
    n_cr = (await db_session.execute(select(func.count(ChangeRequest.id)))).scalar_one()
    assert n_cr == 0


# ── Reject by a second operator ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reject_by_second_operator(client: AsyncClient, db_session: AsyncSession) -> None:
    """An approver can reject; the subnet is never touched and the row is
    terminal-rejected."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session)
    _, rtoken = await _user(
        db_session,
        name="requester",
        permissions=[{"action": "delete", "resource_type": "subnet"}],
    )
    _, atoken = await _user(
        db_session,
        name="approver",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
        ],
    )

    cr_id = (
        await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(rtoken))
    ).json()["change_request_id"]
    r = await client.post(
        f"/api/v1/change-requests/{cr_id}/reject",
        headers=_auth(atoken),
        json={"decision_note": "no"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "rejected"

    await db_session.refresh(subnet)
    assert subnet.deleted_at is None


# ── Cancel by the requester ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancel_by_requester(client: AsyncClient, db_session: AsyncSession) -> None:
    """The original requester can withdraw their own pending request."""
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session)
    _, rtoken = await _user(
        db_session,
        name="requester",
        permissions=[
            {"action": "delete", "resource_type": "subnet"},
            {"action": "read", "resource_type": "change_request"},
        ],
    )

    cr_id = (
        await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(rtoken))
    ).json()["change_request_id"]
    r = await client.post(f"/api/v1/change-requests/{cr_id}/cancel", headers=_auth(rtoken), json={})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "cancelled"


# ── Router is module-gated (404 when off) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_router_404_when_module_off(client: AsyncClient, db_session: AsyncSession) -> None:
    """The whole change-requests router 404s when the module is off (NN #14)."""
    await _enable_module(db_session, enabled=False)
    _, token = await _user(
        db_session,
        name="reader",
        permissions=[{"action": "read", "resource_type": "change_request"}],
    )
    r = await client.get("/api/v1/change-requests", headers=_auth(token))
    assert r.status_code == 404, r.text
