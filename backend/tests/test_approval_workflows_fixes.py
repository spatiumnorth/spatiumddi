"""Regression tests for the #62 code-review fixes (inline-fidelity contract).

These pin the seven findings the review surfaced on top of the original
two-person approval workflow (covered by ``test_approval_workflows.py``):

* **#7 — ValueError→500.** A module-OFF DELETE of a *missing* subnet must
  surface the original handler's ``404`` (the factored ``apply()`` used to
  raise a bare ``ValueError`` → 500).
* **#7/#17 — not-empty 409.** A module-OFF permanent DELETE of a *non-empty*
  subnet without ``force`` must surface ``409`` (not 500), exactly like the
  pre-#62 handler.
* **#1 — no inline permission re-check.** A delegate admitted by the IPAM
  router's coarse gate via a scoped ``{delete, address_set, <id>}`` grant
  (#103) must be able to soft-delete inline WITHOUT the factored ``apply()``
  403/500-ing on a permission re-check it shouldn't run.
* **#8 — approve-path superadmin parity.** ``delete_zone`` / ``delete_scope``
  / ``delete_group`` were fully ``SuperAdmin``-gated at the route, so their
  ``apply()`` must require superadmin ALWAYS — the approve path (which
  bypasses the route's dependency) relies on this.
* **#5 — fail-closed on a deleted requester.** When ``requested_by_user_id``
  is NULL (requester deleted), approval is REFUSED (409), not fail-open.
* **#4 — non-gateable policy rejected.** Creating an approval policy with an
  action that isn't wired to a registered risky op → ``422``.
* **#10 — single-namespaced event type.** The ``change_request.approved``
  event type derives once (no ``change_request.change_request.*``), and the
  webhook catalog advertises the real lifecycle events.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.change_request import ChangeRequest
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import feature_modules

# ── Fixtures (mirrors test_approval_workflows.py) ──────────────────────────────


async def _user(
    db: AsyncSession,
    *,
    name: str,
    permissions: list[dict] | None = None,
    superadmin: bool = False,
) -> tuple[User, str]:
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


async def _subnet(db: AsyncSession, network: str = "10.9.5.0/24") -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.9.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="s")
    db.add(subnet)
    await db.flush()
    return subnet


async def _enable_module(db: AsyncSession, *, enabled: bool = True) -> None:
    existing = await db.get(FeatureModule, "governance.approvals")
    if existing is None:
        db.add(FeatureModule(id="governance.approvals", enabled=enabled))
    else:
        existing.enabled = enabled
    await db.flush()
    feature_modules.invalidate_cache()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── #7: missing subnet → 404 (not 500) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_module_off_delete_missing_subnet_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Module-OFF DELETE of a non-existent subnet surfaces 404, not a 500 from
    a bare ValueError in the factored apply()."""
    await _enable_module(db_session, enabled=False)
    _, token = await _user(
        db_session,
        name="op",
        permissions=[{"action": "delete", "resource_type": "subnet"}],
    )
    r = await client.delete(f"/api/v1/ipam/subnets/{uuid.uuid4()}", headers=_auth(token))
    assert r.status_code == 404, r.text


# ── #7/#17: non-empty permanent delete without force → 409 ─────────────────────


@pytest.mark.asyncio
async def test_module_off_delete_nonempty_permanent_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Module-OFF permanent DELETE of a non-empty subnet without force surfaces
    409 (the inline handler's not-empty conflict), not a 500."""
    await _enable_module(db_session, enabled=False)
    subnet = await _subnet(db_session)
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.9.5.42", status="allocated"))
    await db_session.flush()
    # Permanent path requires superadmin; use one so we exercise the 409 branch.
    _, token = await _user(db_session, name="sa", superadmin=True)

    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}?permanent=true", headers=_auth(token)
    )
    assert r.status_code == 409, r.text
    assert "not empty" in r.json()["detail"].lower()
    # Untouched.
    await db_session.refresh(subnet)
    assert subnet.deleted_at is None


# ── #1: scoped address-set delegate deletes inline without a perm re-check ─────


@pytest.mark.asyncio
async def test_scoped_delegate_inline_delete_no_500(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A delegate the IPAM router gate admits via a scoped {delete,
    address_set, <id>} grant (#103) must get a clean 403 on a subnet delete,
    never a 500 from the factored apply()'s permission re-check.

    This used to assert 204: the inline soft-delete ran for a delegate with
    no {delete, subnet} grant at all, which is the cross-type escalation
    GHSA-6g57-4vj6-87mv closes. The per-type gate now refuses it before
    apply() runs, so the 500 this test was written against can't occur
    either."""
    await _enable_module(db_session, enabled=False)
    subnet = await _subnet(db_session)
    # ONLY an instance-scoped address_set delete grant — no {delete, subnet}.
    _, token = await _user(
        db_session,
        name="delegate",
        permissions=[
            {
                "action": "delete",
                "resource_type": "address_set",
                "resource_id": str(uuid.uuid4()),
            }
        ],
    )

    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(token))
    assert r.status_code == 403, r.text
    assert "delete" in r.json()["detail"] and "subnet" in r.json()["detail"]
    await db_session.refresh(subnet)
    assert subnet.deleted_at is None


# ── #8: apply() requires superadmin ALWAYS for zone / scope / group ────────────


@pytest.mark.asyncio
async def test_delete_zone_apply_requires_superadmin(db_session: AsyncSession) -> None:
    """delete_zone.apply() raises 403 for a non-superadmin — the route was
    fully SuperAdmin-gated, so the approve path (which bypasses the route's
    SuperAdmin dependency) must enforce it inside apply() (#8). The superadmin
    check runs before the zone lookup, so random ids suffice."""
    from fastapi import HTTPException

    from app.services.ai.operations_risky import DeleteZoneArgs, _apply_delete_zone

    nonadmin, _ = await _user(
        db_session,
        name="zone-editor",
        permissions=[{"action": "delete", "resource_type": "dns_zone"}],
    )
    args = DeleteZoneArgs(group_id=uuid.uuid4(), zone_id=uuid.uuid4(), permanent=False)
    with pytest.raises(HTTPException) as ei:
        await _apply_delete_zone(db_session, nonadmin, args)
    assert ei.value.status_code == 403


@pytest.mark.asyncio
async def test_delete_scope_apply_requires_superadmin(db_session: AsyncSession) -> None:
    """delete_scope.apply() requires superadmin always (#8)."""
    from fastapi import HTTPException

    from app.services.ai.operations_risky import DeleteScopeArgs, _apply_delete_scope

    nonadmin, _ = await _user(
        db_session,
        name="scope-editor",
        permissions=[{"action": "delete", "resource_type": "dhcp_scope"}],
    )
    # Missing scope would 404 — but superadmin is checked first, so a
    # non-superadmin gets 403 before the lookup.
    args = DeleteScopeArgs(scope_id=uuid.uuid4(), permanent=False)
    with pytest.raises(HTTPException) as ei:
        await _apply_delete_scope(db_session, nonadmin, args)
    assert ei.value.status_code == 403


@pytest.mark.asyncio
async def test_delete_group_apply_requires_superadmin(db_session: AsyncSession) -> None:
    """delete_group.apply() requires superadmin always (#8)."""
    from fastapi import HTTPException

    from app.services.ai.operations_risky import DeleteGroupArgs, _apply_delete_group

    nonadmin, _ = await _user(
        db_session,
        name="group-editor",
        permissions=[{"action": "delete", "resource_type": "dhcp_server_group"}],
    )
    args = DeleteGroupArgs(group_id=uuid.uuid4())
    with pytest.raises(HTTPException) as ei:
        await _apply_delete_group(db_session, nonadmin, args)
    assert ei.value.status_code == 403


# ── #5: approval refused when the requester was deleted (requested_by NULL) ────


@pytest.mark.asyncio
async def test_approve_refused_when_requester_deleted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A pending request whose requested_by_user_id is NULL (requester deleted)
    is refused on approve (409) — fail CLOSED, not fail open."""
    await _enable_module(db_session)
    subnet = await _subnet(db_session)
    cr = ChangeRequest(
        operation="delete_subnet",
        resource_type="subnet",
        resource_id=str(subnet.id),
        resource_display="s",
        args={"subnet_id": str(subnet.id), "force": False, "permanent": False},
        preview_text="Soft-delete subnet",
        risk_reason="delete:subnet",
        state="pending",
        requested_by_user_id=None,  # requester deleted → SET NULL
        requested_by_display="gone",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(cr)
    await db_session.flush()
    await db_session.commit()

    _, atoken = await _user(
        db_session,
        name="approver",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "delete", "resource_type": "subnet"},
        ],
    )
    r = await client.post(
        f"/api/v1/change-requests/{cr.id}/approve", headers=_auth(atoken), json={}
    )
    assert r.status_code == 409, r.text
    assert "no longer exists" in r.json()["detail"].lower()

    refreshed = await db_session.get(ChangeRequest, cr.id)
    assert refreshed is not None and refreshed.state == "pending"
    await db_session.refresh(subnet)
    assert subnet.deleted_at is None


# ── #4: policy create with a non-gateable action → 422 ─────────────────────────


@pytest.mark.asyncio
async def test_policy_create_nongateable_action_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An approval policy for an action that isn't wired to a registered risky
    op (e.g. bulk_delete in P1) is rejected 422 — no enabled-but-inert rules."""
    await _enable_module(db_session)
    _, token = await _user(db_session, name="super", superadmin=True)

    r = await client.post(
        "/api/v1/change-requests/policies",
        headers=_auth(token),
        json={
            "name": "Bulk delete",
            "resource_type": "subnet",
            "action": "bulk_delete",
            "enabled": True,
        },
    )
    assert r.status_code == 422, r.text
    assert "not gateable" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_policy_create_nongateable_resource_type_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A delete policy against a non-gateable resource_type (e.g. the '*'
    wildcard, P2 only) is rejected 422."""
    await _enable_module(db_session)
    _, token = await _user(db_session, name="super2", superadmin=True)

    r = await client.post(
        "/api/v1/change-requests/policies",
        headers=_auth(token),
        json={"name": "Wildcard delete", "resource_type": "*", "action": "delete"},
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_policy_create_gateable_ok(client: AsyncClient, db_session: AsyncSession) -> None:
    """A delete:subnet policy (gateable) is accepted (201) — the validator
    rejects only the un-wired surface."""
    await _enable_module(db_session)
    _, token = await _user(db_session, name="super3", superadmin=True)

    r = await client.post(
        "/api/v1/change-requests/policies",
        headers=_auth(token),
        json={"name": "Delete subnet (custom)", "resource_type": "subnet", "action": "delete"},
    )
    assert r.status_code == 201, r.text


# ── #10: event type single-namespaced + catalog advertises lifecycle ──────────


def test_change_request_event_type_single_namespaced() -> None:
    """change_request.approved derives once — no change_request.change_request.*
    doubling — and the webhook catalog advertises the real lifecycle events,
    not the never-fired created/updated/deleted trio."""
    from app.services.event_publisher import (
        _RESOURCE_NAMESPACE,
        _SPECIAL_EVENT_MAP,
        _VERB_MAP,
        _audit_to_event_type,
    )

    for verb in ("requested", "approved", "rejected", "cancelled", "executed", "failed", "expired"):
        assert _audit_to_event_type(verb, "change_request") == f"change_request.{verb}"

    # Reproduce the catalog enumeration (webhooks router) and assert shape.
    catalog: set[str] = set()
    for ns in set(_RESOURCE_NAMESPACE.values()):
        for v in _VERB_MAP.values():
            catalog.add(f"{ns}.{v}")
    catalog.update(_SPECIAL_EVENT_MAP.values())

    assert not any("change_request.change_request" in t for t in catalog)
    assert "change_request.approved" in catalog
    assert "change_request.requested" in catalog
    assert "change_request.created" not in catalog
    assert "change_request.deleted" not in catalog


# ── #1: queue read scoping (REST list / get + MCP find) ────────────────────────


async def _pending_cr(
    db: AsyncSession, subnet: Subnet, requester: User, *, display: str = "owned"
) -> ChangeRequest:
    """Seed a pending delete_subnet change request owned by ``requester``."""
    cr = ChangeRequest(
        operation="delete_subnet",
        resource_type="subnet",
        resource_id=str(subnet.id),
        resource_display=display,
        args={"subnet_id": str(subnet.id), "force": False, "permanent": False},
        preview_text=f"Soft-delete subnet ({display})",
        risk_reason="delete:subnet",
        state="pending",
        requested_by_user_id=requester.id,
        requested_by_display=requester.display_name,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db.add(cr)
    await db.flush()
    return cr


@pytest.mark.asyncio
async def test_read_only_user_sees_only_own_requests(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """READ RULE (#1): a plain {read, change_request} holder (not approve, not
    superadmin) sees ONLY their own rows via the list endpoint — never another
    user's — and ``mine=false`` can't widen that."""
    await _enable_module(db_session)
    subnet_a = await _subnet(db_session, "10.20.1.0/24")
    subnet_b = await _subnet(db_session, "10.20.2.0/24")

    reader, rtok = await _user(
        db_session,
        name="reader",
        permissions=[{"action": "read", "resource_type": "change_request"}],
    )
    other, _ = await _user(db_session, name="other")

    mine = await _pending_cr(db_session, subnet_a, reader, display="mine")
    theirs = await _pending_cr(db_session, subnet_b, other, display="theirs")
    await db_session.commit()

    # Even with mine=false the read-only user is forced to own-scope.
    r = await client.get("/api/v1/change-requests?mine=false", headers=_auth(rtok))
    assert r.status_code == 200, r.text
    ids = {row["id"] for row in r.json()}
    assert str(mine.id) in ids
    assert str(theirs.id) not in ids


@pytest.mark.asyncio
async def test_read_only_user_404_on_another_users_request(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """READ RULE (#1): get/{id} on a row the read-only caller doesn't own 404s
    (not 403) — existence isn't confirmed."""
    await _enable_module(db_session)
    subnet = await _subnet(db_session, "10.21.1.0/24")
    _, rtok = await _user(
        db_session,
        name="reader2",
        permissions=[{"action": "read", "resource_type": "change_request"}],
    )
    owner, _ = await _user(db_session, name="owner2")
    theirs = await _pending_cr(db_session, subnet, owner, display="theirs")
    await db_session.commit()

    r = await client.get(f"/api/v1/change-requests/{theirs.id}", headers=_auth(rtok))
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_approve_holder_sees_all_requests(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """READ RULE (#1): an {approve, change_request} holder sees EVERY row (an
    eligible approver needs the whole queue) — list + get."""
    await _enable_module(db_session)
    subnet_a = await _subnet(db_session, "10.22.1.0/24")
    subnet_b = await _subnet(db_session, "10.22.2.0/24")
    approver, atok = await _user(
        db_session,
        name="approver-reader",
        permissions=[
            {"action": "read", "resource_type": "change_request"},
            {"action": "approve", "resource_type": "change_request"},
        ],
    )
    other, _ = await _user(db_session, name="other3")
    a = await _pending_cr(db_session, subnet_a, approver, display="approvers-own")
    b = await _pending_cr(db_session, subnet_b, other, display="someone-elses")
    await db_session.commit()

    r = await client.get("/api/v1/change-requests", headers=_auth(atok))
    assert r.status_code == 200, r.text
    ids = {row["id"] for row in r.json()}
    assert str(a.id) in ids
    assert str(b.id) in ids

    # And get/{id} on someone else's row succeeds for an approve-holder.
    r2 = await client.get(f"/api/v1/change-requests/{b.id}", headers=_auth(atok))
    assert r2.status_code == 200, r2.text


@pytest.mark.asyncio
async def test_mcp_find_change_requests_scopes_to_own(db_session: AsyncSession) -> None:
    """READ RULE (#1) parity in the MCP surface: find_change_requests scopes a
    plain read-only user to their own rows, and lets an approve-holder see all.
    The MCP tools have no router gate, so the scope is enforced in-tool."""
    from app.services.ai.tools.changes import (
        FindChangeRequestsArgs,
        find_change_requests,
    )

    subnet_a = await _subnet(db_session, "10.23.1.0/24")
    subnet_b = await _subnet(db_session, "10.23.2.0/24")
    reader, _ = await _user(
        db_session,
        name="mcp-reader",
        permissions=[{"action": "read", "resource_type": "change_request"}],
    )
    approver, _ = await _user(
        db_session,
        name="mcp-approver",
        permissions=[{"action": "approve", "resource_type": "change_request"}],
    )
    mine = await _pending_cr(db_session, subnet_a, reader, display="mcp-mine")
    theirs = await _pending_cr(db_session, subnet_b, approver, display="mcp-theirs")
    await db_session.commit()

    # Read-only user: own row only, even with mine=False.
    res = await find_change_requests(db_session, reader, FindChangeRequestsArgs(mine=False))
    ids = {row["id"] for row in res["change_requests"]}
    assert str(mine.id) in ids
    assert str(theirs.id) not in ids

    # Approve-holder: sees both.
    res2 = await find_change_requests(db_session, approver, FindChangeRequestsArgs(mine=False))
    ids2 = {row["id"] for row in res2["change_requests"]}
    assert str(mine.id) in ids2
    assert str(theirs.id) in ids2


# ── #2: policies list gated on SuperAdmin ──────────────────────────────────────


@pytest.mark.asyncio
async def test_policies_list_forbidden_for_non_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The policy LIST leaks un-gated (resource, threshold) pairs +
    applies_to_superadmin → SuperAdmin-only (#2). A read-holder is 403."""
    await _enable_module(db_session)
    _, rtok = await _user(
        db_session,
        name="policy-reader",
        permissions=[{"action": "read", "resource_type": "change_request"}],
    )
    r = await client.get("/api/v1/change-requests/policies", headers=_auth(rtok))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_policies_list_ok_for_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A superadmin can still read the policy list (#2)."""
    await _enable_module(db_session)
    _, stok = await _user(db_session, name="policy-super", superadmin=True)
    r = await client.get("/api/v1/change-requests/policies", headers=_auth(stok))
    assert r.status_code == 200, r.text


# ── #3b: approve refuses with 409 when the blast radius drifted ────────────────


@pytest.mark.asyncio
async def test_approve_refuses_on_scope_drift(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3: a permanent+force delete request whose subnet GREW IP rows between
    submit and approve has a changed preview blast radius → approve refuses
    (409 scope drift); the row stays pending and the subnet survives.

    force=true keeps the op preview ``ok`` (it skips the non-empty check), so
    the refusal is driven purely by the blast-radius drift compare, not the
    pre-existing non-empty stale check."""
    from app.models.change_request import ApprovalPolicy

    await _enable_module(db_session)
    db_session.add(
        ApprovalPolicy(
            name="delete:subnet",
            resource_type="subnet",
            action="delete",
            min_count=None,
            enabled=True,
            applies_to_superadmin=True,
            ttl_hours=168,
            is_builtin=True,
        )
    )
    await db_session.flush()

    subnet = await _subnet(db_session, "10.24.1.0/24")
    _, rtok = await _user(db_session, name="drift-requester", superadmin=True)
    _, atok = await _user(db_session, name="drift-approver", superadmin=True)

    # Submit a permanent+force delete while the subnet is empty.
    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}?permanent=true&force=true", headers=_auth(rtok)
    )
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]
    frozen = (await db_session.get(ChangeRequest, uuid.UUID(cr_id))).preview_text

    # Blast radius grows: add IP rows after submission.
    for i in range(3):
        db_session.add(
            IPAddress(subnet_id=subnet.id, address=f"10.24.1.{10 + i}", status="allocated")
        )
    await db_session.flush()
    await db_session.commit()

    r2 = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atok), json={})
    assert r2.status_code == 409, r2.text
    assert "scope changed" in r2.json()["detail"].lower()

    # Left pending; subnet untouched; frozen preview unchanged.
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"
    assert cr.preview_text == frozen
    await db_session.refresh(subnet)
    assert subnet.deleted_at is None


# ── #4: import-time assert rejects a non-gateable risky op ─────────────────────


def test_gate_import_assert_rejects_non_gateable_pair() -> None:
    """#4: the gate's import-time assert fails loudly when a registered risky
    op declares a (action, resource_type) outside the gateable sets — such an
    op would pass a 'permission exists' check but match_policy could never gate
    it (fail-open). Simulate by monkeypatching the registry's view."""
    from app.services.approvals import gate

    real_get = gate.get_operation

    class _FakeOp:
        required_permission = ("delete", "totally_not_gateable")

    def _fake_get(name: str):
        return _FakeOp()

    gate.get_operation = _fake_get  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError) as ei:
            gate._assert_risky_ops_have_permission()
        assert "non-gateable" in str(ei.value).lower()
    finally:
        gate.get_operation = real_get  # type: ignore[assignment]
