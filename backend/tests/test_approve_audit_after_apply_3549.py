"""An approval is audited AFTER the operation it approves (#3549).

``approve_change_request`` used to write the approval's audit row before
``apply()``, so it took the audit-chain advisory lock before apply()'s
``dns_zone`` / ``subnet`` row locks: the reverse of every other path (#3501,
#3503), and a deadlock waiting for its interleaving. ``tests/_audit_lock_order_guard.py``
now enforces this path (its ``KNOWN_UNFIXED`` entry is gone); this drives a real
approval of an operation that writes a zone.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSRecord
from tests.conftest import _TestSessionLocal
from tests.test_dns_dynamic_update_acl import _bind9_group_zone_key
from tests.test_self_service_requests import (
    APPROVER_PERMS,
    REQUESTER_PERMS,
    _auth,
    _block,
    _enable_module,
    _user,
)


async def _named_ip_request(client: AsyncClient, db: AsyncSession) -> tuple[str, str, str]:
    from app.models.ipam import Subnet

    await _enable_module(db)
    group, zone, _ = await _bind9_group_zone_key(db)
    block = await _block(db, "10.78.0.0/16")
    subnet = Subnet(
        space_id=block.space_id,
        block_id=block.id,
        network="10.78.0.0/24",
        name="s",
        dns_group_ids=[str(group.id)],
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    _, req_token = await _user(
        db,
        name="req",
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "subnet"}],
    )
    _, appr_token = await _user(
        db,
        name="appr",
        permissions=APPROVER_PERMS + [{"action": "write", "resource_type": "ip_address"}],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={
            "kind": "ip_address",
            "args": {
                "subnet_id": str(subnet.id),
                "address": "10.78.0.10",
                "hostname": "printer",
            },
            "justification": "Printer for the imaging lab.",
        },
    )
    assert resp.status_code == 201, resp.text
    await db.commit()
    return resp.json()["id"], appr_token, str(zone.id)


@pytest.mark.asyncio
async def test_approval_of_a_zone_writing_operation_respects_the_lock_order(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from tests import _audit_lock_order_guard as guard

    assert "approve_change_request" not in guard.KNOWN_UNFIXED
    req_id, token, zone_id = await _named_ip_request(client, db_session)

    guard.violations.clear()
    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={"decision_note": "ok"}
    )
    found = list(guard.violations)
    guard.violations.clear()
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed", resp.text
    assert found == []
    async with _TestSessionLocal() as check:
        names = (
            (await check.execute(select(DNSRecord.name).where(DNSRecord.zone_id == zone_id)))
            .scalars()
            .all()
        )
    assert "printer" in names


@pytest.mark.asyncio
async def test_audit_order_is_the_change_then_the_approval_then_execution(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    req_id, token, _ = await _named_ip_request(client, db_session)
    resp = await client.post(f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["decided_by_user_id"] is not None

    rows = (
        await db_session.execute(
            select(AuditLog.resource_type, AuditLog.action).order_by(AuditLog.seq)
        )
    ).all()
    seq = [(t, a) for t, a in rows]
    cr = [i for i, (t, _) in enumerate(seq) if t == "change_request"]
    actions = [seq[i][1] for i in cr]
    assert actions == ["requested", "approved", "executed"], seq
    change = [i for i, (t, _) in enumerate(seq) if t not in ("change_request",) and i > cr[0]]
    assert change, seq
    assert max(change) < cr[1], seq  # the change precedes the approval row


@pytest.mark.asyncio
async def test_the_approval_audit_commits_with_the_change(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """apply() commits the change and the ``approved`` stamp; the approval's
    audit row must be in that commit, not in a later one. Here the spine fails
    after apply() returns (its own commit, or the process, could): the change
    and the ``approved`` row are durable, so the approval must be too."""
    from app.services.approvals import service
    from tests.test_approve_apply_failure_2911 import _audit_actions

    req_id, token, zone_id = await _named_ip_request(client, db_session)

    async def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("spine died after apply() committed")

    monkeypatch.setattr(service, "mark_executed", boom)
    with pytest.raises(RuntimeError, match="spine died"):
        await client.post(f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={})

    async with _TestSessionLocal() as check:
        names = (
            (await check.execute(select(DNSRecord.name).where(DNSRecord.zone_id == zone_id)))
            .scalars()
            .all()
        )
        assert "printer" in names
        assert await _audit_actions(check, req_id) == ["requested", "approved"]


@pytest.mark.asyncio
async def test_an_apply_that_does_not_commit_is_audited_once(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An apply() that leaves the commit to the spine still gets exactly one
    approval row, before the execution row."""
    from tests.test_approve_apply_failure_2911 import _audit_actions, _patch_apply

    req_id, token, _ = await _named_ip_request(client, db_session)

    async def no_commit(db: AsyncSession, user: object, args: object) -> dict[str, bool]:
        return {"ok": True}

    _patch_apply(monkeypatch, "create_ip_address", no_commit)
    resp = await client.post(f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={})
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed"
    async with _TestSessionLocal() as check:
        assert await _audit_actions(check, req_id) == ["requested", "approved", "executed"]
