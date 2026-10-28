"""An approve whose ``apply()`` fails ends ``failed`` on every entry point (#2911).

``tests/test_self_service_requests.py`` drives the failure cases through the
portal's ``/requests/{id}/approve``. The same spine
(``services/approvals/service.approve_change_request``) also backs the #62
gate router's ``/change-requests/{id}/approve`` and the Copilot's
``approve_change_request`` operation, each of which serialises the returned
row after the spine's rollback has expired every object in the session. This
file covers those two callers, plus the edges of the failure stamp itself:

* an ``apply()`` that committed (persisting the ``approved`` stamp with it)
  before raising — the row is no longer ``pending``, so the stamp must not
  read that as "changed by somebody else" and strand it ``approved``, a
  state the expiry sweep never touches and nobody can decide;
* a concurrent rejection that lands between the rollback and the re-lock —
  ``failed`` must never overwrite it.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Any

import pytest
from fastapi import HTTPException, Request
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIOperationProposal
from app.models.audit import AuditLog
from app.models.change_request import ChangeRequest
from app.services.ai import operations
from tests.test_approval_workflows import (
    _enable_delete_subnet_policy,
    _subnet,
)
from tests.test_approval_workflows import (
    _enable_module as _enable_approvals,
)
from tests.test_approval_workflows import (
    _user as _gate_user,
)
from tests.test_self_service_requests import (
    _auth,
    _pending_ip_request,
)


def _patch_apply(monkeypatch: pytest.MonkeyPatch, name: str, apply: Any) -> None:
    op = operations._OPERATIONS[name]
    monkeypatch.setitem(operations._OPERATIONS, name, dataclasses.replace(op, apply=apply))


def _raising(exc: Exception) -> Any:
    async def boom(db, user, args):  # noqa: ANN001
        raise exc

    return boom


def _commit_then_raising(exc: Exception) -> Any:
    """An apply() that commits its own transaction (as nearly every operation
    does) and then fails — e.g. a post-commit driver push. The commit also
    persists the spine's ``approved`` stamp."""

    async def boom(db, user, args):  # noqa: ANN001
        await db.commit()
        raise exc

    return boom


async def _audit_actions(db: AsyncSession, cr_id: str) -> list[str]:
    rows = (
        await db.execute(
            select(AuditLog.action)
            .where(
                AuditLog.resource_type == "change_request",
                AuditLog.resource_id == cr_id,
            )
            .order_by(AuditLog.seq)
        )
    ).scalars()
    return list(rows)


async def _state(db: AsyncSession, cr_id: str) -> ChangeRequest:
    db.expire_all()
    cr = await db.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None
    return cr


# ── /change-requests (#62 gate rows) ──────────────────────────────────────────


async def _pending_gate_request(client: AsyncClient, db: AsyncSession) -> tuple[str, str, Any]:
    await _enable_approvals(db)
    await _enable_delete_subnet_policy(db)
    subnet = await _subnet(db)
    _, rtoken = await _gate_user(
        db, name="requester", permissions=[{"action": "delete", "resource_type": "subnet"}]
    )
    approver, atoken = await _gate_user(
        db,
        name="approver",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "delete", "resource_type": "subnet"},
        ],
    )
    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(rtoken))
    assert r.status_code == 202, r.text
    return r.json()["change_request_id"], atoken, approver


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [RuntimeError("driver exploded"), HTTPException(status_code=502, detail="driver exploded")],
)
async def test_change_requests_approve_records_failed(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    exc: Exception,
) -> None:
    cr_id, atoken, approver = await _pending_gate_request(client, db_session)
    _patch_apply(monkeypatch, "delete_subnet", _raising(exc))

    r = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve",
        headers=_auth(atoken),
        json={"decision_note": "go"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "failed"
    assert "driver exploded" in body["error"]
    assert body["decided_by_user_id"] == str(approver.id)
    assert body["decision_note"] == "go"
    assert body["modified_at"] is not None
    # Approved before failed, nothing lost to the rollback.
    assert await _audit_actions(db_session, cr_id) == ["requested", "approved", "failed"]


@pytest.mark.asyncio
async def test_change_requests_approve_4xx_stays_pending(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#11's contract on the gate router too: a raced precondition 4xx keeps
    its status and leaves the request pending, with no decision audited."""
    cr_id, atoken, _ = await _pending_gate_request(client, db_session)
    _patch_apply(
        monkeypatch, "delete_subnet", _raising(HTTPException(status_code=409, detail="raced"))
    )
    r = await client.post(f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atoken))
    assert r.status_code == 409, r.text
    assert (await _state(db_session, cr_id)).state == "pending"
    assert await _audit_actions(db_session, cr_id) == ["requested"]


# ── The Copilot's approve_change_request operation ───────────────────────────


def _fake_request() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/api/v1/ai/proposals/x/apply"})


@pytest.mark.asyncio
async def test_copilot_approve_records_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.ai.proposals import apply_proposal

    cr_id, _, approver = await _pending_gate_request(client, db_session)
    approver_id = approver.id
    _patch_apply(monkeypatch, "delete_subnet", _raising(RuntimeError("driver exploded")))

    proposal = AIOperationProposal(
        session_id=None,
        user_id=approver.id,
        operation="approve_change_request",
        args={"change_request_id": cr_id, "note": "via copilot"},
        preview_text="preview",
        expires_at=operations.expires_at_default(),
    )
    db_session.add(proposal)
    await db_session.commit()
    await db_session.refresh(proposal)

    resp = await apply_proposal(proposal.id, approver, db_session, _fake_request())
    assert resp.result is not None, resp
    assert resp.result["state"] == "failed"
    assert "driver exploded" in resp.result["error"]
    cr = await _state(db_session, cr_id)
    assert cr.state == "failed"
    assert cr.decided_by_user_id == approver_id
    assert cr.decision_note == "via copilot"
    assert await _audit_actions(db_session, cr_id) == ["requested", "approved", "failed"]


# ── apply() committed before it raised ────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("post-commit push failed"),
        HTTPException(status_code=502, detail="post-commit push failed"),
        HTTPException(status_code=409, detail="post-commit push failed"),
    ],
)
async def test_apply_that_committed_then_raised_does_not_strand_approved(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    exc: Exception,
) -> None:
    """The commit inside apply() persisted the ``approved`` stamp, so the row
    is not ``pending`` when the spine re-locks it. That is still this
    approval's own failure: it ends ``failed`` with the reason, rather than a
    bare error that leaves it ``approved`` forever (never expired, never
    decidable). Holds for a 4xx too — a request that is no longer pending
    cannot be "left pending"."""
    req_id, token, _, appr = await _pending_ip_request(client, db_session)
    _patch_apply(monkeypatch, "create_ip_address", _commit_then_raising(exc))

    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={"decision_note": "go"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "failed"
    assert "post-commit push failed" in body["error"]
    assert body["decided_by_user_id"] == str(appr.id)
    # One approved row (committed by apply), one failed row — no duplicate.
    assert await _audit_actions(db_session, req_id) == ["requested", "approved", "failed"]


# ── A rejection that lands between the rollback and the re-lock ──────────────


@pytest.mark.asyncio
async def test_concurrent_reject_is_not_overwritten_by_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.approvals import service
    from tests.conftest import _TestSessionLocal
    from tests.test_self_service_requests import APPROVER_PERMS
    from tests.test_self_service_requests import _user as _portal_user

    req_id, token, _, _ = await _pending_ip_request(client, db_session)
    other, _ = await _portal_user(db_session, name="other", permissions=APPROVER_PERMS)
    await db_session.commit()
    other_id = other.id
    _patch_apply(monkeypatch, "create_ip_address", _raising(RuntimeError("driver exploded")))

    real_rollback = service._safe_rollback

    async def rollback_then_reject(db: AsyncSession) -> None:
        await real_rollback(db)
        # The approver's row lock went with the rollback; a second approver
        # gets in before the spine re-locks.
        from app.models.auth import User

        async with _TestSessionLocal() as s2:
            rejecter = await s2.get(User, other_id)
            cr = await service.get_change_request(s2, uuid.UUID(req_id), for_update=True)
            assert cr is not None and rejecter is not None
            await service.mark_rejected(s2, cr, approver=rejecter, request=None, note="no")
            await s2.commit()

    monkeypatch.setattr(service, "_safe_rollback", rollback_then_reject)

    resp = await client.post(f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={})
    assert resp.status_code == 409, resp.text
    cr = await _state(db_session, req_id)
    assert cr.state == "rejected"
    assert cr.error is None
    assert cr.decided_by_user_id == other_id
    assert await _audit_actions(db_session, req_id) == ["requested", "rejected"]
