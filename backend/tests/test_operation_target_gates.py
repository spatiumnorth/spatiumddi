"""Operation paths enforce the per-resource gate of their REST twin, and do not
name resources the caller cannot read.

Two halves:

* **Apply.** ``create_ip_address`` (an applied Copilot proposal, an approved
  portal request) needs what ``POST /subnets/{id}/addresses`` needs: write on
  that subnet, or write on an address set covering the address. Like the
  REST route's gate (#3058), the operation admits a ``write subnet`` grant
  scoped to one subnet, or an address-set delegate, and then holds it to that
  subnet or set, with or without a hostname.
* **Preview / submit.** A subnet, block, zone or scope the caller cannot read
  is answered exactly like an id that does not exist: by the request portal's
  submit, and by the previews the Copilot shows.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException, Request
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai.proposals import apply_proposal
from app.models.address_set import AddressSet
from app.models.ai import AIOperationProposal
from app.models.change_request import ChangeRequest
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ai import operations
from app.services.ai.operations import (
    TARGET_NOT_FOUND,
    AllocateSubnetArgs,
    CreateDHCPStaticArgs,
    CreateDNSRecordArgs,
    CreateIPAddressArgs,
    OperationPermissionError,
    get_operation,
    resource_reference_fields,
)
from app.services.requests.catalog import REQUEST_KINDS
from tests.test_self_service_requests import (
    BARE_REQUESTER_PERMS,
    MODULE,
    _auth,
    _enable_module,
    _user,
)

SUBNET_NAME = "finance-private-lan"
SUBNET_CIDR = "10.77.5.0/24"
BLOCK_NAME = "finance-private-block"
ZONE_NAME = "finance-private.example."
SCOPE_NAME = "finance-private-scope"

APPROVE = [
    {"action": "approve", "resource_type": "change_request"},
    {"action": "read", "resource_type": "change_request"},
]


def _fake_request() -> Request:
    return Request(
        {"type": "http", "method": "POST", "path": "/api/v1/ai/proposals/apply", "headers": []}
    )


class _Estate:
    block: IPBlock
    subnet: Subnet
    subnet_id: uuid.UUID
    zone: DNSZone
    scope: DHCPScope


async def _estate(db: AsyncSession) -> _Estate:
    env = _Estate()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    env.block = IPBlock(space_id=space.id, network="10.77.0.0/16", name=BLOCK_NAME)
    db.add(env.block)
    await db.flush()
    env.subnet = Subnet(
        space_id=space.id, block_id=env.block.id, network=SUBNET_CIDR, name=SUBNET_NAME
    )
    db.add(env.subnet)
    await db.flush()
    env.subnet_id = env.subnet.id
    dns_group = DNSServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
    dhcp_group = DHCPServerGroup(name=f"hg-{uuid.uuid4().hex[:6]}")
    db.add_all([dns_group, dhcp_group])
    await db.flush()
    env.zone = DNSZone(
        group_id=dns_group.id,
        name=ZONE_NAME,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(env.zone)
    db.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=dhcp_group.id,
        )
    )
    await db.flush()
    env.scope = DHCPScope(
        group_id=dhcp_group.id, subnet_id=env.subnet.id, name=SCOPE_NAME, address_family="ipv4"
    )
    db.add(env.scope)
    await db.flush()
    return env


async def _addresses(db: AsyncSession, subnet_id: uuid.UUID) -> list[str]:
    # Takes the id, not the row: a refused apply rolls back, expiring the row.
    rows = (
        (await db.execute(select(IPAddress.address).where(IPAddress.subnet_id == subnet_id)))
        .scalars()
        .all()
    )
    return [str(a) for a in rows]


def _ip_args(subnet: Subnet, address: str, *, hostname: str | None = None) -> dict:
    return CreateIPAddressArgs(
        subnet_id=str(subnet.id), address=address, hostname=hostname
    ).model_dump(mode="json")


async def _proposal(db: AsyncSession, user_id: uuid.UUID, args: dict) -> AIOperationProposal:
    row = AIOperationProposal(
        session_id=None,
        user_id=user_id,
        operation="create_ip_address",
        args=args,
        preview_text="preview",
        expires_at=operations.expires_at_default(),
    )
    db.add(row)
    await db.flush()
    return row


def _ip_writer_reading(subnet: Subnet) -> list[dict]:
    """``write`` on some OTHER subnet; ``read`` on this one, no write on it.

    The scoped grant passes the operation's type-level check exactly as it
    passes the REST route's gate (#3058), so what refuses is the per-resource
    gate. (``write ip_address`` no longer opens the REST address create at all
    since #3058, so it would be refused before reaching that gate.)
    """
    return [
        {"action": "write", "resource_type": "subnet", "resource_id": str(uuid.uuid4())},
        {"action": "read", "resource_type": "subnet", "resource_id": str(subnet.id)},
    ]


# ── Apply: create_ip_address needs write on the subnet ─────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("hostname", [None, "app01"])
async def test_copilot_apply_refuses_without_subnet_write(
    db_session: AsyncSession, hostname: str | None
) -> None:
    env = await _estate(db_session)
    user, _ = await _user(db_session, name="ipw", permissions=_ip_writer_reading(env.subnet))
    prop = await _proposal(
        db_session, user.id, _ip_args(env.subnet, "10.77.5.10", hostname=hostname)
    )

    with pytest.raises(HTTPException) as ei:
        await apply_proposal(prop.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403
    assert "No write permission on subnet" in str(ei.value.detail)
    assert await _addresses(db_session, env.subnet_id) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("hostname", [None, "app02"])
async def test_portal_approve_refuses_without_subnet_write(
    client: AsyncClient, db_session: AsyncSession, hostname: str | None
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    _, req_token = await _user(
        db_session,
        name="req",
        permissions=[*BARE_REQUESTER_PERMS, {"action": "read", "resource_type": "subnet"}],
    )
    _, appr_token = await _user(
        db_session, name="apv", permissions=[*APPROVE, *_ip_writer_reading(env.subnet)]
    )
    args = {"subnet_id": str(env.subnet.id), "address": "10.77.5.11"}
    if hostname:
        args["hostname"] = hostname
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={"kind": "ip_address", "args": args, "justification": "need one"},
    )
    assert resp.status_code == 201, resp.text
    rid = resp.json()["id"]

    resp = await client.post(f"/api/v1/requests/{rid}/approve", headers=_auth(appr_token), json={})
    assert resp.status_code == 403, resp.text
    cr = await db_session.get(ChangeRequest, uuid.UUID(rid))
    await db_session.refresh(cr)
    assert cr.state == "pending"
    assert await _addresses(db_session, env.subnet_id) == []


async def _submit_ip_request(
    client: AsyncClient, db: AsyncSession, subnet_id: uuid.UUID, address: str
) -> str:
    _, req_token = await _user(
        db,
        name="req",
        permissions=[*BARE_REQUESTER_PERMS, {"action": "read", "resource_type": "subnet"}],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={
            "kind": "ip_address",
            "args": {"subnet_id": str(subnet_id), "address": address},
            "justification": "need one",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _cr_state(db: AsyncSession, rid: str) -> ChangeRequest:
    cr = await db.get(ChangeRequest, uuid.UUID(rid))
    assert cr is not None
    await db.refresh(cr)
    return cr


@pytest.mark.asyncio
async def test_approver_who_cannot_read_the_subnet_is_refused_and_request_stays_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The approve re-preview hides a subnet the approver can neither read nor
    write. That is about the approver, not the subnet: 403 with the REST
    create's permission detail, and the request stays pending for an approver
    who can reach it — not ``failed`` with "Subnet not found" (#2934)."""
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    rid = await _submit_ip_request(client, db_session, env.subnet_id, "10.77.5.16")
    # Write on some other subnet only: no read on this one.
    _, blind_token = await _user(
        db_session,
        name="blind",
        permissions=[
            *APPROVE,
            {"action": "write", "resource_type": "subnet", "resource_id": str(uuid.uuid4())},
        ],
    )
    await db_session.commit()  # a wrongly-failed request rolls back first
    resp = await client.post(
        f"/api/v1/requests/{rid}/approve", headers=_auth(blind_token), json={}
    )
    assert resp.status_code == 403, resp.text
    assert "No write permission on subnet" in resp.json()["detail"]
    assert "not found" not in resp.json()["detail"]
    cr = await _cr_state(db_session, rid)
    assert cr.state == "pending" and cr.error is None
    assert await _addresses(db_session, env.subnet_id) == []

    # Another approver who can reach the subnet still takes it.
    _, ok_token = await _user(
        db_session,
        name="able",
        permissions=[
            *APPROVE,
            {"action": "write", "resource_type": "subnet", "resource_id": str(env.subnet_id)},
        ],
    )
    resp = await client.post(f"/api/v1/requests/{rid}/approve", headers=_auth(ok_token), json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed", resp.text
    assert await _addresses(db_session, env.subnet_id) == ["10.77.5.16"]


@pytest.mark.asyncio
async def test_address_set_approver_outside_the_set_without_read_stays_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    aset = AddressSet(
        name="desk",
        subnet_id=env.subnet.id,
        range_kind="contiguous",
        start_address="10.77.5.100",
        end_address="10.77.5.110",
    )
    db_session.add(aset)
    await db_session.flush()
    rid = await _submit_ip_request(client, db_session, env.subnet_id, "10.77.5.60")
    _, set_token = await _user(
        db_session,
        name="setw",
        permissions=[
            *APPROVE,
            {"action": "write", "resource_type": "address_set", "resource_id": str(aset.id)},
        ],
    )
    await db_session.commit()  # a wrongly-failed request rolls back first
    resp = await client.post(f"/api/v1/requests/{rid}/approve", headers=_auth(set_token), json={})
    assert resp.status_code == 403, resp.text
    assert "No write permission on subnet" in resp.json()["detail"]
    cr = await _cr_state(db_session, rid)
    assert cr.state == "pending" and cr.error is None
    assert await _addresses(db_session, env.subnet_id) == []


@pytest.mark.asyncio
async def test_deleted_subnet_still_fails_the_request(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A subnet that is genuinely gone is a stale request, whoever approves."""
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    gone = Subnet(
        space_id=env.subnet.space_id, block_id=env.block.id, network="10.77.9.0/24", name="gone"
    )
    db_session.add(gone)
    await db_session.flush()
    gone_id = gone.id
    rid = await _submit_ip_request(client, db_session, gone_id, "10.77.9.5")
    await db_session.delete(gone)
    await db_session.flush()

    # An approver with no read on it: still a failed request, not a 403.
    _, blind_token = await _user(
        db_session,
        name="blind",
        permissions=[
            *APPROVE,
            {"action": "write", "resource_type": "subnet", "resource_id": str(uuid.uuid4())},
        ],
    )
    # The failed path rolls back before stamping; keep the delete and the
    # approver row through that rollback.
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/requests/{rid}/approve", headers=_auth(blind_token), json={}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "failed"
    cr = await _cr_state(db_session, rid)
    assert cr.state == "failed"
    assert cr.error == TARGET_NOT_FOUND["subnet"].format(id=gone_id)


@pytest.mark.asyncio
async def test_apply_function_itself_refuses_without_subnet_write(db_session: AsyncSession) -> None:
    """The gate lives in the operation's own apply, so it holds for any caller."""
    env = await _estate(db_session)
    user, _ = await _user(db_session, name="ipw", permissions=_ip_writer_reading(env.subnet))
    op = get_operation("create_ip_address")
    assert op is not None
    with pytest.raises(OperationPermissionError):
        await op.apply(
            db_session,
            user,
            CreateIPAddressArgs(subnet_id=str(env.subnet.id), address="10.77.5.12"),
        )
    assert await _addresses(db_session, env.subnet_id) == []


@pytest.mark.asyncio
async def test_ip_address_write_alone_is_refused_like_the_rest_route(
    db_session: AsyncSession,
) -> None:
    """``write ip_address`` does not open ``POST /subnets/{id}/addresses``
    since #3058, so it does not reach the operation either."""
    env = await _estate(db_session)
    user, _ = await _user(
        db_session,
        name="ipw",
        permissions=[
            {"action": "write", "resource_type": "ip_address"},
            {"action": "read", "resource_type": "subnet", "resource_id": str(env.subnet.id)},
        ],
    )
    prop = await _proposal(db_session, user.id, _ip_args(env.subnet, "10.77.5.15"))
    with pytest.raises(HTTPException) as ei:
        await apply_proposal(prop.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403
    assert "need 'write' on 'subnet'" in str(ei.value.detail)
    assert await _addresses(db_session, env.subnet_id) == []


@pytest.mark.asyncio
async def test_copilot_apply_with_subnet_write_lands(db_session: AsyncSession) -> None:
    env = await _estate(db_session)
    user, _ = await _user(
        db_session,
        name="ipw",
        permissions=[
            {"action": "write", "resource_type": "subnet", "resource_id": str(env.subnet.id)},
        ],
    )
    prop = await _proposal(db_session, user.id, _ip_args(env.subnet, "10.77.5.13"))
    resp = await apply_proposal(prop.id, user, db_session, _fake_request())
    assert resp.ok is True, resp.detail
    assert await _addresses(db_session, env.subnet_id) == ["10.77.5.13"]


@pytest.mark.asyncio
async def test_address_set_writer_may_create_inside_the_set_only(db_session: AsyncSession) -> None:
    env = await _estate(db_session)
    aset = AddressSet(
        name="desk",
        subnet_id=env.subnet.id,
        range_kind="contiguous",
        start_address="10.77.5.100",
        end_address="10.77.5.110",
    )
    db_session.add(aset)
    await db_session.flush()
    user, _ = await _user(
        db_session,
        name="setw",
        permissions=[
            {"action": "write", "resource_type": "address_set", "resource_id": str(aset.id)},
        ],
    )
    inside = await _proposal(db_session, user.id, _ip_args(env.subnet, "10.77.5.105"))
    resp = await apply_proposal(inside.id, user, db_session, _fake_request())
    assert resp.ok is True, resp.detail

    outside = await _proposal(db_session, user.id, _ip_args(env.subnet, "10.77.5.50"))
    with pytest.raises(HTTPException) as ei:
        await apply_proposal(outside.id, user, db_session, _fake_request())
    assert ei.value.status_code == 403
    assert await _addresses(db_session, env.subnet_id) == ["10.77.5.105"]


@pytest.mark.asyncio
async def test_superadmin_apply_unaffected(db_session: AsyncSession) -> None:
    env = await _estate(db_session)
    admin, _ = await _user(db_session, name="sa", superadmin=True)
    prop = await _proposal(db_session, admin.id, _ip_args(env.subnet, "10.77.5.14"))
    resp = await apply_proposal(prop.id, admin, db_session, _fake_request())
    assert resp.ok is True, resp.detail


# ── Submit: a target the requester cannot read reads as unknown ────────────


def _kind_args(env: _Estate, kind: str, target: str) -> dict:
    if kind == "ip_address":
        return {"subnet_id": target, "address": "10.77.5.20"}
    if kind == "subnet":
        return {"block_id": target, "prefix_len": 26}
    if kind == "dns_record":
        return {"zone_id": target, "name": "web", "record_type": "A", "value": "10.77.5.21"}
    return {"scope_id": target, "ip_address": "10.77.5.22", "mac_address": "aa:bb:cc:00:11:22"}


def _target(env: _Estate, kind: str) -> tuple[str, str]:
    return {
        "ip_address": ("subnet", str(env.subnet.id)),
        "subnet": ("ip_block", str(env.block.id)),
        "dns_record": ("dns_zone", str(env.zone.id)),
        "dhcp_reservation": ("dhcp_scope", str(env.scope.id)),
    }[kind]


_SECRETS = (SUBNET_NAME, SUBNET_CIDR, BLOCK_NAME, ZONE_NAME.rstrip("."), SCOPE_NAME, "10.77.0.0")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["ip_address", "subnet", "dns_record", "dhcp_reservation"])
async def test_submit_unreadable_target_answers_like_unknown(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    _, token = await _user(db_session, name="req", permissions=BARE_REQUESTER_PERMS)
    rtype, real_id = _target(env, kind)
    unknown_id = str(uuid.uuid4())

    async def submit(target: str):
        return await client.post(
            "/api/v1/requests",
            headers=_auth(token),
            json={"kind": kind, "args": _kind_args(env, kind, target), "justification": "x"},
        )

    real = await submit(real_id)
    missing = await submit(unknown_id)
    assert real.status_code == missing.status_code == 400, (real.text, missing.text)
    assert real.json()["detail"] == TARGET_NOT_FOUND[rtype].format(id=real_id)
    assert missing.json()["detail"] == TARGET_NOT_FOUND[rtype].format(id=unknown_id)
    for secret in _SECRETS:
        assert secret not in real.text
    assert await db_session.scalar(select(func.count()).select_from(ChangeRequest)) == 0


@pytest.mark.asyncio
async def test_submit_with_read_on_another_subnet_only_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    other = Subnet(
        space_id=env.subnet.space_id, block_id=env.block.id, network="10.77.6.0/24", name="o"
    )
    db_session.add(other)
    await db_session.flush()
    _, token = await _user(
        db_session,
        name="req",
        permissions=[
            *BARE_REQUESTER_PERMS,
            {"action": "read", "resource_type": "subnet", "resource_id": str(other.id)},
        ],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={"kind": "ip_address", "args": _kind_args(env, "ip_address", str(env.subnet.id))},
    )
    assert resp.status_code == 400
    assert SUBNET_NAME not in resp.text and SUBNET_CIDR not in resp.text

    ok = await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={
            "kind": "ip_address",
            "args": {"subnet_id": str(other.id), "address": "10.77.6.9"},
        },
    )
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_submit_with_read_on_the_target_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    _, token = await _user(
        db_session,
        name="req",
        permissions=[
            *BARE_REQUESTER_PERMS,
            {"action": "read", "resource_type": "subnet", "resource_id": str(env.subnet.id)},
        ],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={"kind": "ip_address", "args": _kind_args(env, "ip_address", str(env.subnet.id))},
    )
    assert resp.status_code == 201, resp.text
    assert SUBNET_CIDR in resp.json()["preview_text"]


def test_every_catalog_reference_has_an_unknown_id_answer() -> None:
    """Submit and the previews word an unreadable target from one table."""
    for entry in REQUEST_KINDS:
        op = get_operation(entry.operation)
        assert op is not None
        fields = resource_reference_fields(op.args_model)
        assert fields, f"{entry.kind}: names no x-resource target"
        for _, rtype in fields:
            assert rtype in TARGET_NOT_FOUND, rtype


# ── Copilot preview: no names of resources the caller cannot read ──────────


@pytest.mark.asyncio
async def test_previews_answer_an_unreadable_target_like_an_unknown_one(
    db_session: AsyncSession,
) -> None:
    env = await _estate(db_session)
    # Write grants on unrelated types only: no read on any target, and none of
    # the grants the previews accept in place of read.
    user, _ = await _user(
        db_session,
        name="cp",
        permissions=[{"action": "write", "resource_type": "ip_address"}],
    )
    cases = [
        ("create_ip_address", CreateIPAddressArgs(subnet_id=str(env.subnet.id), address="10.77.5.30"), "subnet", env.subnet.id),
        ("allocate_subnet", AllocateSubnetArgs(block_id=str(env.block.id), prefix_len=26), "ip_block", env.block.id),
        ("create_dns_record", CreateDNSRecordArgs(zone_id=str(env.zone.id), name="w", record_type="A", value="10.77.5.31"), "dns_zone", env.zone.id),
        ("create_dhcp_static", CreateDHCPStaticArgs(scope_id=str(env.scope.id), ip_address="10.77.5.32", mac_address="aa:bb:cc:00:11:33"), "dhcp_scope", env.scope.id),
    ]  # fmt: skip
    for name, args, rtype, rid in cases:
        op = get_operation(name)
        assert op is not None
        res = await op.preview(db_session, user, args)
        assert res.ok is False, name
        assert res.detail == TARGET_NOT_FOUND[rtype].format(id=rid), (name, res.detail)
        # The approve spine reads this as "refuse the caller", not "gone".
        assert res.forbidden_detail is not None, name
        assert "Permission denied" in res.forbidden_detail or "No write" in res.forbidden_detail
        for secret in _SECRETS:
            assert secret not in res.detail and secret not in res.preview_text, (name, secret)
            assert secret not in res.forbidden_detail, (name, secret)
        # An id that does not exist is plain not-found: nothing to refuse.
        missing = args.model_copy(update={_id_field(args): str(uuid.uuid4())})
        gone = await op.preview(db_session, user, missing)
        assert gone.ok is False and gone.forbidden_detail is None, name


def _id_field(args: object) -> str:
    for f in ("subnet_id", "block_id", "zone_id", "scope_id"):
        if hasattr(args, f):
            return f
    raise AssertionError(args)


@pytest.mark.asyncio
async def test_previews_name_a_readable_target(db_session: AsyncSession) -> None:
    env = await _estate(db_session)
    user, _ = await _user(
        db_session,
        name="cp",
        permissions=[
            {"action": "read", "resource_type": "subnet"},
            {"action": "read", "resource_type": "ip_block"},
            {"action": "read", "resource_type": "dns_zone"},
            {"action": "read", "resource_type": "dhcp_scope"},
        ],
    )
    ip = await get_operation("create_ip_address").preview(  # type: ignore[union-attr]
        db_session, user, CreateIPAddressArgs(subnet_id=str(env.subnet.id), address="10.77.5.40")
    )
    assert ip.ok and SUBNET_CIDR in ip.preview_text
    rec = await get_operation("create_dns_record").preview(  # type: ignore[union-attr]
        db_session,
        user,
        CreateDNSRecordArgs(
            zone_id=str(env.zone.id), name="w", record_type="A", value="10.77.5.41"
        ),
    )
    assert rec.ok and ZONE_NAME in rec.preview_text
    st = await get_operation("create_dhcp_static").preview(  # type: ignore[union-attr]
        db_session,
        user,
        CreateDHCPStaticArgs(
            scope_id=str(env.scope.id), ip_address="10.77.5.42", mac_address="aa:bb:cc:00:11:44"
        ),
    )
    assert st.ok and SCOPE_NAME in st.preview_text
    blk = await get_operation("allocate_subnet").preview(  # type: ignore[union-attr]
        db_session, user, AllocateSubnetArgs(block_id=str(env.block.id), prefix_len=26)
    )
    assert blk.ok and "10.77.0.0/16" in blk.preview_text


@pytest.mark.asyncio
async def test_copilot_propose_tool_does_not_name_an_unreadable_subnet(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.tools.proposals import propose_create_ip_address

    env = await _estate(db_session)
    user, _ = await _user(
        db_session,
        name="cp",
        permissions=[{"action": "write", "resource_type": "ip_address"}],
    )
    out = await propose_create_ip_address(
        db_session, user, CreateIPAddressArgs(subnet_id=str(env.subnet.id), address="10.77.5.50")
    )
    assert out["kind"] == "proposal_rejected"
    assert out["detail"] == TARGET_NOT_FOUND["subnet"].format(id=env.subnet.id)
    assert SUBNET_CIDR not in str(out) and SUBNET_NAME not in str(out)
    assert await db_session.scalar(select(func.count()).select_from(AIOperationProposal)) == 0


# ── DNS record apply: an API token bound to another zone is refused ───────


@pytest.mark.asyncio
async def test_dns_record_apply_refuses_a_token_bound_to_another_zone(
    db_session: AsyncSession,
) -> None:
    env = await _estate(db_session)
    user, _ = await _user(
        db_session,
        name="dnsw",
        permissions=[
            {"action": "write", "resource_type": "dns_record"},
            {"action": "read", "resource_type": "dns_zone"},
        ],
    )
    other_zone = str(uuid.uuid4())
    user._api_token_resource_grants = [  # type: ignore[attr-defined]
        {"action": "write", "resource_type": "dns_record", "resource_id": None},
        {"action": "write", "resource_type": "dns_zone", "resource_id": other_zone},
    ]
    op = get_operation("create_dns_record")
    assert op is not None
    with pytest.raises(OperationPermissionError):
        await op.apply(
            db_session,
            user,
            CreateDNSRecordArgs(
                zone_id=str(env.zone.id), name="w", record_type="A", value="10.77.5.60"
            ),
        )
