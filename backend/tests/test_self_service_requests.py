"""Regression tests for the self-service request portal (#696).

#62 shipped the approval engine as a *brake*; #696 points it the other way —
a low-privilege user asks for something they cannot do themselves, and
approving **provisions** it. The two share one table and one approve spine,
so these tests concentrate on the things that are genuinely new or that could
regress #62:

* **Module off (default)** → the whole ``/requests`` surface 404s.
* **Submit does not require the operation's permission** — that inversion is
  the entire feature; a Requester holding only ``create,provisioning_request``
  can queue a subnet request without ``write,subnet``.
* **Submitting provisions nothing** — the row is pending and no subnet exists.
* **Approve provisions**, under the approver's identity, and only when the
  approver holds the underlying operation's own permission.
* **Self-approval is blocked** even though the requester "owns" the request.
* **Catalog is an allow-list** — an operation outside it (e.g. a delete or a
  control op) cannot be reached through the portal, which matters precisely
  because submit skips the op permission check.
* **Queue isolation** — portal rows never appear in #62's ``/change-requests``
  surface and vice versa, in both directions, REST and MCP.
* **Read scoping** — a requester sees only their own rows; an unreadable id
  404s rather than 403s.
* **A failed execution lands in ``failed`` carrying the error** — #696 calls
  silent disappearance the failure mode that destroys trust in a portal.

The ``client`` + ``db_session`` fixtures share one session, so a fixture write
is visible to the handler and a post-call read sees the handler's commit.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.change_request import ChangeRequest
from app.models.feature_module import FeatureModule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import feature_modules

MODULE = "governance.requests"


# ── Fixtures ──────────────────────────────────────────────────────────────────


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


async def _enable_module(db: AsyncSession, module: str = MODULE, *, enabled: bool = True) -> None:
    existing = await db.get(FeatureModule, module)
    if existing is None:
        db.add(FeatureModule(id=module, enabled=enabled))
    else:
        existing.enabled = enabled
    await db.flush()
    feature_modules.invalidate_cache()


async def _block(db: AsyncSession, network: str = "10.20.0.0/16") -> IPBlock:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name="b")
    db.add(block)
    await db.flush()
    return block


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# The built-in Requester role's grants, as handed out to a department.
BARE_REQUESTER_PERMS = [
    {"action": "write", "resource_type": "provisioning_request"},
    {"action": "read", "resource_type": "provisioning_request"},
]
# A requester who can also read the resources a request names: submit refuses
# a payload naming a resource the requester cannot read, answering it like an
# unknown id, so the read grant is what makes a target requestable.
REQUESTER_PERMS = [
    *BARE_REQUESTER_PERMS,
    {"action": "read", "resource_type": "subnet"},
    {"action": "read", "resource_type": "ip_block"},
    {"action": "read", "resource_type": "dns_zone"},
    {"action": "read", "resource_type": "dhcp_scope"},
]
# An approver who can decide AND holds the underlying op permission.
APPROVER_PERMS = [
    {"action": "approve", "resource_type": "change_request"},
    {"action": "read", "resource_type": "change_request"},
    {"action": "write", "resource_type": "subnet"},
    {"action": "read", "resource_type": "subnet"},
    {"action": "read", "resource_type": "ip_block"},
]


async def _submit_subnet_request(
    client: AsyncClient, token: str, block: IPBlock, *, prefix_len: int = 26
) -> dict:
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={
            "kind": "subnet",
            "args": {
                "block_id": str(block.id),
                "prefix_len": prefix_len,
                "name": f"lab-{uuid.uuid4().hex[:6]}",
            },
            "justification": "New lab segment for the imaging team.",
        },
    )
    return {"status": resp.status_code, "body": resp.json() if resp.content else None}


# ── Module gating ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_module_off_hides_the_whole_surface(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Default-off means the portal does not exist at all — NN #14."""
    await _enable_module(db_session, enabled=False)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    for path in ("/api/v1/requests", "/api/v1/requests/catalog"):
        resp = await client.get(path, headers=_auth(token))
        assert resp.status_code == 404, (path, resp.status_code)


# ── Submit ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_without_the_operation_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """THE feature: a requester with no ``write,subnet`` can still ask for one.

    #62 inverted — there the requester was a permitted operator whose action
    got intercepted. Here they are by definition someone who cannot do it.
    """
    await _enable_module(db_session)
    block = await _block(db_session)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)

    out = await _submit_subnet_request(client, token, block)
    assert out["status"] == 201, out
    assert out["body"]["state"] == "pending"
    assert out["body"]["justification"].startswith("New lab segment")

    # Nothing was provisioned.
    count = len((await db_session.execute(select(Subnet))).scalars().all())
    assert count == 0


@pytest.mark.asyncio
async def test_submit_requires_the_requester_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Skipping the op permission is not the same as skipping authorization."""
    await _enable_module(db_session)
    block = await _block(db_session)
    _, token = await _user(db_session, name="nobody", permissions=[])
    out = await _submit_subnet_request(client, token, block)
    assert out["status"] == 403, out


@pytest.mark.asyncio
async def test_submit_rejects_an_uncatalogued_kind(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The catalog is an allow-list, and it is load-bearing security: submit
    skips the op permission, so without it a requester could queue ANY
    registered operation (delete / factory_reset / grant_temporary_access)
    and wait for a rubber stamp."""
    await _enable_module(db_session)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    for kind in ("delete_subnet", "factory_reset", "grant_temporary_access", "nonsense"):
        resp = await client.post(
            "/api/v1/requests",
            headers=_auth(token),
            json={"kind": kind, "args": {}, "justification": "x"},
        )
        assert resp.status_code == 400, (kind, resp.status_code)
        assert "Unknown request kind" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_submit_validates_args_against_the_operation_schema(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A typo is refused at submit, while the requester is present to fix it —
    not hours later in front of an approver who can only reject it."""
    await _enable_module(db_session)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={"kind": "subnet", "args": {"prefix_len": "not-a-number"}},
    )
    # FastAPI's own 422 shape (#3253): each entry names its field under
    # ``body.args`` and carries the error type, so the form can label it.
    # Nothing echoes the input back.
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    by_field = {e["loc"][-1]: e for e in detail}
    assert all(e["loc"][:2] == ["body", "args"] for e in detail)
    assert by_field["prefix_len"]["type"] == "int_parsing"
    assert by_field["block_id"]["type"] == "missing"
    assert "input" not in resp.text and "not-a-number" not in resp.text


@pytest.mark.asyncio
async def test_catalog_lists_the_four_kinds_with_schemas(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    resp = await client.get("/api/v1/requests/catalog", headers=_auth(token))
    assert resp.status_code == 200
    kinds = {k["kind"] for k in resp.json()}
    assert kinds == {"subnet", "ip_address", "dns_record", "dhcp_reservation"}
    for entry in resp.json():
        # The form is rendered from this, so an empty schema is a real defect.
        assert entry["args_schema"].get("properties"), entry["kind"]


# ── Approve ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approve_provisions_the_subnet(client: AsyncClient, db_session: AsyncSession) -> None:
    """Approving runs the SAME service-layer carve a manual create would."""
    await _enable_module(db_session)
    block = await _block(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    _, appr_token = await _user(db_session, name="appr", permissions=APPROVER_PERMS)

    out = await _submit_subnet_request(client, req_token, block)
    assert out["status"] == 201
    req_id = out["body"]["id"]

    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers=_auth(appr_token),
        json={"decision_note": "Approved for Q3 lab build."},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed"

    subnets = (await db_session.execute(select(Subnet))).scalars().all()
    assert len(subnets) == 1
    # ``network`` is an ipaddress object, not a string.
    assert subnets[0].network.prefixlen == 26


@pytest.mark.asyncio
async def test_self_approval_is_blocked(client: AsyncClient, db_session: AsyncSession) -> None:
    """Holding both roles must not let one person round-trip their own ask."""
    await _enable_module(db_session)
    block = await _block(db_session)
    _, token = await _user(db_session, name="both", permissions=REQUESTER_PERMS + APPROVER_PERMS)
    out = await _submit_subnet_request(client, token, block)
    assert out["status"] == 201
    resp = await client.post(
        f"/api/v1/requests/{out['body']['id']}/approve", headers=_auth(token), json={}
    )
    assert resp.status_code == 403
    assert not (await db_session.execute(select(Subnet))).scalars().all()


@pytest.mark.asyncio
async def test_approver_needs_the_underlying_operation_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An approver who could not create the subnet themselves cannot approve
    one into existence — otherwise the portal would be a privilege-escalation
    path around ``write,subnet``."""
    await _enable_module(db_session)
    block = await _block(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    # Can decide, but holds no subnet write.
    _, weak_token = await _user(
        db_session,
        name="weak",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
        ],
    )
    out = await _submit_subnet_request(client, req_token, block)
    resp = await client.post(
        f"/api/v1/requests/{out['body']['id']}/approve",
        headers=_auth(weak_token),
        json={},
    )
    assert resp.status_code == 403, resp.text
    assert not (await db_session.execute(select(Subnet))).scalars().all()


@pytest.mark.asyncio
async def test_reject_leaves_nothing_provisioned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    block = await _block(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    _, appr_token = await _user(db_session, name="appr", permissions=APPROVER_PERMS)
    out = await _submit_subnet_request(client, req_token, block)
    resp = await client.post(
        f"/api/v1/requests/{out['body']['id']}/reject",
        headers=_auth(appr_token),
        json={"decision_note": "Use the existing lab range."},
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "rejected"
    assert resp.json()["decision_note"] == "Use the existing lab range."
    assert not (await db_session.execute(select(Subnet))).scalars().all()


@pytest.mark.asyncio
async def test_requester_can_withdraw_their_own(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    block = await _block(db_session)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    out = await _submit_subnet_request(client, token, block)
    resp = await client.post(
        f"/api/v1/requests/{out['body']['id']}/cancel", headers=_auth(token), json={}
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "cancelled"


# ── Read scoping ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_requester_sees_only_their_own(client: AsyncClient, db_session: AsyncSession) -> None:
    await _enable_module(db_session)
    block = await _block(db_session)
    _, alice = await _user(db_session, name="alice", permissions=REQUESTER_PERMS)
    _, bob = await _user(db_session, name="bob", permissions=REQUESTER_PERMS)
    a = await _submit_subnet_request(client, alice, block)
    await _submit_subnet_request(client, bob, block)

    resp = await client.get("/api/v1/requests", headers=_auth(bob))
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()}
    assert a["body"]["id"] not in ids
    assert len(ids) == 1

    # And an id they may not see 404s rather than 403s, so existence isn't
    # confirmed by probing.
    resp = await client.get(f"/api/v1/requests/{a['body']['id']}", headers=_auth(bob))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_approver_sees_the_whole_queue(client: AsyncClient, db_session: AsyncSession) -> None:
    await _enable_module(db_session)
    block = await _block(db_session)
    _, alice = await _user(db_session, name="alice", permissions=REQUESTER_PERMS)
    _, appr = await _user(db_session, name="appr", permissions=APPROVER_PERMS)
    await _submit_subnet_request(client, alice, block)
    resp = await client.get("/api/v1/requests", headers=_auth(appr))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# ── Queue isolation against #62 ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_portal_rows_never_appear_in_the_gate_queue(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Both live in ``change_request``; the two surfaces must stay disjoint or
    #62's admin page fills up with other people's provisioning asks."""
    await _enable_module(db_session)
    await _enable_module(db_session, "governance.approvals")
    block = await _block(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    _, admin_token = await _user(db_session, name="admin", superadmin=True)

    out = await _submit_subnet_request(client, req_token, block)
    portal_id = out["body"]["id"]

    resp = await client.get("/api/v1/change-requests", headers=_auth(admin_token))
    assert resp.status_code == 200
    assert portal_id not in {r["id"] for r in resp.json()}

    # Nor readable through the gate's get-by-id side door.
    resp = await client.get(f"/api/v1/change-requests/{portal_id}", headers=_auth(admin_token))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_gate_rows_never_appear_in_the_portal_queue(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The other direction — a gate row must not leak into the portal, where
    requesters who are not approvers can reach the surface."""
    await _enable_module(db_session)
    _, admin_token = await _user(db_session, name="admin", superadmin=True)
    gate_row = ChangeRequest(
        operation="delete_subnet",
        resource_type="subnet",
        resource_id=str(uuid.uuid4()),
        resource_display="10.9.9.0/24",
        args={},
        preview_text="delete it",
        risk_reason="policy",
        origin="gate",
        state="pending",
        requested_by_display="someone",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(gate_row)
    await db_session.flush()

    resp = await client.get("/api/v1/requests", headers=_auth(admin_token))
    assert resp.status_code == 200
    assert str(gate_row.id) not in {r["id"] for r in resp.json()}

    resp = await client.get(f"/api/v1/requests/{gate_row.id}", headers=_auth(admin_token))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_default_origin_is_gate(client: AsyncClient, db_session: AsyncSession) -> None:
    """#62's inserts never pass ``origin``; the column default is what keeps
    their behaviour byte-identical after this migration."""
    row = ChangeRequest(
        operation="delete_subnet",
        resource_type="subnet",
        resource_id=str(uuid.uuid4()),
        resource_display="x",
        args={},
        preview_text="p",
        risk_reason="r",
        state="pending",
        requested_by_display="someone",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(row)
    await db_session.flush()
    await db_session.refresh(row)
    assert row.origin == "gate"
    assert row.justification is None


# ── Code-review regressions ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gate_endpoints_cannot_decide_a_portal_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The gate's decision endpoints must not be a side door into the portal.

    The approve spine is origin-agnostic by design, so without an explicit pin
    a portal request could be approved — and therefore PROVISIONED — through
    /change-requests even with ``governance.requests`` DISABLED, bypassing the
    module gate that owns it.
    """
    await _enable_module(db_session)
    await _enable_module(db_session, "governance.approvals")
    block = await _block(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    _, admin_token = await _user(db_session, name="admin", superadmin=True)

    out = await _submit_subnet_request(client, req_token, block)
    portal_id = out["body"]["id"]

    # Now turn the portal module OFF — the row still exists.
    await _enable_module(db_session, enabled=False)

    for verb in ("approve", "reject", "cancel"):
        resp = await client.post(
            f"/api/v1/change-requests/{portal_id}/{verb}",
            headers=_auth(admin_token),
            json={},
        )
        assert resp.status_code == 404, (verb, resp.status_code, resp.text)

    # And nothing was provisioned by any of those attempts.
    assert not (await db_session.execute(select(Subnet))).scalars().all()


@pytest.mark.asyncio
async def test_admin_grant_confers_submit(client: AsyncClient, db_session: AsyncSession) -> None:
    """``admin,provisioning_request`` must confer submit.

    The portal gates on ``write``, which ``_ADMIN_IMPLIES`` covers. A bespoke
    ``create`` verb would not be implied, so an operator granting admin on the
    type would get a surprising 403.
    """
    await _enable_module(db_session)
    block = await _block(db_session)
    _, token = await _user(
        db_session,
        name="adm",
        permissions=[
            {"action": "admin", "resource_type": "provisioning_request"},
            {"action": "read", "resource_type": "ip_block"},
        ],
    )
    out = await _submit_subnet_request(client, token, block)
    assert out["status"] == 201, out


@pytest.mark.asyncio
async def test_resource_display_is_the_preview_not_a_sentinel(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every catalog operation's preview returns ``detail="ready"``, so using
    detail as the headline made every row read "ready" in the queue, the audit
    log and the MCP results."""
    await _enable_module(db_session)
    block = await _block(db_session)
    _, token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    out = await _submit_subnet_request(client, token, block)
    display = out["body"]["resource_display"]
    assert display and display != "ready", display


@pytest.mark.asyncio
async def test_unrelated_carve_does_not_block_approval(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A provisioning request must survive unrelated activity in its block.

    ``allocate_subnet``'s preview embeds the CIDR it would pick right now, so
    the #62 byte-for-byte scope-drift guard would make the request permanently
    un-approvable as soon as anyone else carves from the same block — with a
    14-day TTL, the common case rather than an edge case.
    """
    await _enable_module(db_session)
    block = await _block(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    _, appr_token = await _user(db_session, name="appr", permissions=APPROVER_PERMS)

    out = await _submit_subnet_request(client, req_token, block)
    assert out["status"] == 201

    # Someone else carves from the same block in the meantime, moving the
    # allocator's next free answer.
    db_session.add(
        Subnet(
            space_id=block.space_id,
            block_id=block.id,
            network="10.20.0.0/26",
            name="unrelated",
        )
    )
    await db_session.flush()

    resp = await client.post(
        f"/api/v1/requests/{out['body']['id']}/approve",
        headers=_auth(appr_token),
        json={},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed"


# ── Approving a request whose apply() refuses it (#2911) ─────────────────────
#
# The spine rolls the session back when apply() raises, which expires the
# approver's User; the failure stamp then read ``approver.id`` on it and
# raised MissingGreenlet — a bare 500, request still pending. Every case goes
# through the real approve route.


async def _pending_ip_request(
    client: AsyncClient, db: AsyncSession, *, address: str = "10.77.0.10"
) -> tuple[str, str, Subnet, User]:
    await _enable_module(db)
    block = await _block(db, "10.77.0.0/16")
    subnet = Subnet(space_id=block.space_id, block_id=block.id, network="10.77.0.0/24", name="s")
    db.add(subnet)
    await db.flush()
    _, req_token = await _user(
        db,
        name="req",
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "subnet"}],
    )
    appr, appr_token = await _user(
        db,
        name="appr",
        permissions=APPROVER_PERMS + [{"action": "write", "resource_type": "ip_address"}],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={
            "kind": "ip_address",
            "args": {"subnet_id": str(subnet.id), "address": address},
            "justification": "Printer for the imaging lab.",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"], appr_token, subnet, appr


async def _assert_failed_with(
    client: AsyncClient, db: AsyncSession, req_id: str, token: str, appr: User, reason: str
) -> None:
    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers=_auth(token),
        json={"decision_note": "go"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "failed"
    assert reason in body["error"]
    assert body["decided_by_user_id"] == str(appr.id)
    assert body["decided_at"] is not None
    assert body["decision_note"] == "go"
    # The requester sees the same terminal row.
    from app.models.audit import AuditLog

    actions = (
        (
            await db.execute(
                select(AuditLog.action).where(
                    AuditLog.resource_type == "change_request",
                    AuditLog.resource_id == req_id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert any("approve" in a for a in actions), actions
    assert any("fail" in a for a in actions), actions


@pytest.mark.asyncio
async def test_ip_request_approver_needs_write_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3074: an address is written through the subnet that owns it (#3058),
    so ``create_ip_address`` names ``write subnet``. An approver holding only
    ``write ip_address`` is refused up front (403, still pending, so another
    approver can take it) instead of approving a request whose apply then
    fails on the subnet check."""
    from app.models.ipam import IPAddress

    req_id, _, _, _ = await _pending_ip_request(client, db_session)
    _, addr_token = await _user(
        db_session,
        name="addr-only",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "read", "resource_type": "subnet"},
            {"action": "write", "resource_type": "ip_address"},
        ],
    )
    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve", headers=_auth(addr_token), json={}
    )
    assert resp.status_code == 403, resp.text
    row = (await client.get(f"/api/v1/requests/{req_id}", headers=_auth(addr_token))).json()
    assert row["state"] == "pending"
    assert not (await db_session.execute(select(IPAddress))).scalars().all()


@pytest.mark.asyncio
async def test_approve_when_the_address_was_taken_meanwhile_records_failed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.ipam import IPAddress

    req_id, token, subnet, appr = await _pending_ip_request(client, db_session)
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.77.0.10", status="allocated"))
    await db_session.flush()
    await _assert_failed_with(client, db_session, req_id, token, appr, "already allocated")


@pytest.mark.asyncio
async def test_approve_of_a_pre_2910_multicast_request_records_failed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    req_id, token, subnet, appr = await _pending_ip_request(client, db_session)
    # A request queued before the multicast refusal existed.
    subnet.kind = "multicast"
    await db_session.flush()
    await _assert_failed_with(client, db_session, req_id, token, appr, "multicast")


def _patched_apply(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    import dataclasses

    from app.services.ai import operations

    async def boom(db, user, args):  # noqa: ANN001
        raise exc

    op = operations._OPERATIONS["create_ip_address"]
    monkeypatch.setitem(
        operations._OPERATIONS, "create_ip_address", dataclasses.replace(op, apply=boom)
    )


@pytest.mark.asyncio
async def test_approve_when_apply_raises_value_error_records_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    req_id, token, _, appr = await _pending_ip_request(client, db_session)
    _patched_apply(monkeypatch, ValueError("address went away"))
    await _assert_failed_with(client, db_session, req_id, token, appr, "address went away")


@pytest.mark.asyncio
async def test_approve_when_apply_raises_generic_exception_records_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    req_id, token, _, appr = await _pending_ip_request(client, db_session)
    _patched_apply(monkeypatch, RuntimeError("driver exploded"))
    await _assert_failed_with(client, db_session, req_id, token, appr, "driver exploded")


@pytest.mark.asyncio
async def test_approve_when_apply_raises_a_5xx_records_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi import HTTPException

    req_id, token, _, appr = await _pending_ip_request(client, db_session)
    _patched_apply(monkeypatch, HTTPException(status_code=502, detail="upstream down"))
    await _assert_failed_with(client, db_session, req_id, token, appr, "upstream down")


@pytest.mark.asyncio
async def test_approve_when_apply_raises_a_4xx_records_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 4xx refusal from apply() is recorded like any other (#2911): the
    request ends ``failed`` with the detail the requester can read. It used to
    stay pending (#11), telling nobody why."""
    from fastapi import HTTPException

    req_id, token, _, appr = await _pending_ip_request(client, db_session)
    _patched_apply(monkeypatch, HTTPException(status_code=409, detail="raced"))
    await _assert_failed_with(client, db_session, req_id, token, appr, "raced")


@pytest.mark.asyncio
async def test_approve_when_apply_raises_permission_error_is_403_and_pending(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.ai.operations import OperationPermissionError

    req_id, token, _, _ = await _pending_ip_request(client, db_session)
    _patched_apply(monkeypatch, OperationPermissionError("write", "ip_address"))
    resp = await client.post(f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={})
    assert resp.status_code == 403, resp.text
    row = (await client.get(f"/api/v1/requests/{req_id}", headers=_auth(token))).json()
    assert row["state"] == "pending"
