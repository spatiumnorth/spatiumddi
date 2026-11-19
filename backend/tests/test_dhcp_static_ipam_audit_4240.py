"""A reservation's IPAM mirror writes the ``ip_address`` audit row (#4240).

The mirror used to change IPAM with no audit row, so a ``compliance_change``
rule on a PCI subnet never saw the address and no ``ip.created`` fired for it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import User
from app.services import alerts
from app.services.event_publisher import _audit_to_event_type
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_self_service_requests import (
    MODULE,
    REQUESTER_PERMS,
    _auth,
    _enable_module,
    _user,
)

IP = "10.60.0.77"
MAC = "aa:bb:cc:dd:ee:77"


async def _ip_audits(db: AsyncSession, address: str) -> list[AuditLog]:
    db.expire_all()
    rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.resource_type == "ip_address", AuditLog.resource_display == address)
            .order_by(AuditLog.timestamp, AuditLog.id)
        )
    ).scalars()
    return list(rows)


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user, ["groups"])
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_rest_reservation_audits_its_address_and_raises_compliance(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    scope, subnet, _block = await _estate(db_session)
    subnet.pci_scope = True
    user, headers = await _admin(db_session)
    rule = AlertRule(
        name=f"r-{uuid.uuid4().hex[:6]}",
        description="",
        rule_type=alerts.RULE_TYPE_COMPLIANCE_CHANGE,
        severity="warning",
        enabled=True,
        classification="pci_scope",
        last_scanned_audit_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    db_session.add(rule)
    await db_session.flush()
    scope_id, user_id, rule_id = scope.id, user.id, rule.id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": IP, "mac_address": MAC},
    )
    assert resp.status_code == 201, resp.text

    rows = await _ip_audits(db_session, IP)
    assert [r.action for r in rows] == ["create"]
    assert rows[0].user_id == user_id
    assert rows[0].new_value["status"] == "static_dhcp"
    assert _audit_to_event_type(rows[0].action, rows[0].resource_type) == "ip.created"

    rule = await db_session.get(AlertRule, rule_id)
    assert rule is not None
    await alerts._evaluate_compliance_change_rule(db_session, rule, datetime.now(UTC))
    events = (
        (await db_session.execute(select(AlertEvent).where(AlertEvent.rule_id == rule_id)))
        .scalars()
        .all()
    )
    assert any(IP in (e.subject_display or "") for e in events), [e.subject_display for e in events]


@pytest.mark.asyncio
async def test_rest_edit_and_delete_audit_the_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    scope, _subnet, _block = await _estate(db_session)
    _user_row, headers = await _admin(db_session)
    scope_id = scope.id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": IP, "mac_address": MAC, "hostname": "a"},
    )
    static_id = resp.json()["id"]
    resp = await client.put(
        f"/api/v1/dhcp/statics/{static_id}", headers=headers, json={"hostname": "b"}
    )
    assert resp.status_code == 200, resp.text
    rows = await _ip_audits(db_session, IP)
    assert [r.action for r in rows] == ["create", "update"]
    assert rows[1].changed_fields == ["hostname"]

    resp = await client.delete(f"/api/v1/dhcp/statics/{static_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    rows = await _ip_audits(db_session, IP)
    assert [r.action for r in rows] == ["create", "update", "update"]
    assert rows[2].new_value["status"] == "available"


@pytest.mark.asyncio
async def test_re_address_audits_the_moved_row_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    scope, _subnet, _block = await _estate(db_session)
    _u, headers = await _admin(db_session)
    scope_id = scope.id
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": IP, "mac_address": MAC},
    )
    static_id = resp.json()["id"]
    resp = await client.put(
        f"/api/v1/dhcp/statics/{static_id}", headers=headers, json={"ip_address": "10.60.0.78"}
    )
    assert resp.status_code == 200, resp.text
    assert [r.action for r in await _ip_audits(db_session, IP)] == ["create", "delete"]
    assert [r.action for r in await _ip_audits(db_session, "10.60.0.78")] == ["create"]


@pytest.mark.asyncio
async def test_approved_portal_reservation_audits_its_address_to_the_approver(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    scope, _subnet, _block = await _estate(db_session)
    _, req_token = await _user(db_session, name="req", permissions=REQUESTER_PERMS)
    approver, appr_token = await _user(
        db_session,
        name="appr",
        permissions=[
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
            {"action": "write", "resource_type": "dhcp_static"},
            {"action": "read", "resource_type": "dhcp_static"},
        ],
    )
    approver_id = approver.id
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(req_token),
        json={
            "kind": "dhcp_reservation",
            "args": {"scope_id": str(scope.id), "ip_address": IP, "mac_address": MAC},
            "justification": "Printer needs a fixed address.",
        },
    )
    assert resp.status_code == 201, resp.text
    resp = await client.post(
        f"/api/v1/requests/{resp.json()['id']}/approve",
        headers=_auth(appr_token),
        json={"decision_note": "ok"},
    )
    assert resp.json()["state"] == "executed", resp.text
    rows = await _ip_audits(db_session, IP)
    assert [r.action for r in rows] == ["create"]
    assert rows[0].user_id == approver_id


@pytest.mark.asyncio
async def test_machine_sync_with_unchanged_mirror_writes_no_audit(
    db_session: AsyncSession,
) -> None:
    from app.models.dhcp import DHCPStaticAssignment
    from app.services.dhcp.static_ipam import upsert_ipam_for_static

    scope, _subnet, _block = await _estate(db_session)
    st = DHCPStaticAssignment(scope_id=scope.id, ip_address=IP, mac_address=MAC, hostname="h")
    db_session.add(st)
    await db_session.flush()
    await upsert_ipam_for_static(db_session, scope, st)
    await upsert_ipam_for_static(db_session, scope, st, action="update")
    rows = await _ip_audits(db_session, IP)
    assert [(r.action, r.user_display_name) for r in rows] == [("create", "system")]
