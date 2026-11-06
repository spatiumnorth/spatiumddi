"""#3647 — an address request whose host name holds a CNAME is refused.

The address sync skips an A beside a CNAME (#1441), so a request promising
"publishes A <name>" promised a record the approval would never write. The
preview now refuses, at submit and again at approve (a CNAME may appear
between the two).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress
from tests.test_operation_create_ip_dns_2900 import _subnet_with_zone, _user
from tests.test_self_service_requests import _enable_module

MODULE = "governance.requests"


async def _cname(db: AsyncSession, zone_id: uuid.UUID, name: str) -> None:
    db.add(
        DNSRecord(
            zone_id=zone_id,
            name=name,
            fqdn=f"{name}.x.",
            record_type="CNAME",
            value="target.example.org.",
        )
    )
    await db.flush()


async def _requester_hdr(db: AsyncSession) -> dict[str, str]:
    from app.core.security import create_access_token
    from app.models.auth import Group, Role

    await _enable_module(db, MODULE)
    u = await _user(db, "req", superadmin=False)
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        permissions=[
            {"action": "write", "resource_type": "provisioning_request"},
            {"action": "read", "resource_type": "provisioning_request"},
            {"action": "read", "resource_type": "subnet"},
        ],
    )
    grp = Group(name=f"g-{uuid.uuid4().hex[:6]}")
    grp.roles = [role]
    db.add_all([role, grp])
    u.groups = [grp]
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _body(sid: str, address: str, host: str) -> dict:
    return {
        "kind": "ip_address",
        "args": {"subnet_id": sid, "address": address, "hostname": host},
        "justification": "need it",
    }


@pytest.mark.asyncio
async def test_submit_refused_when_name_holds_a_cname(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    await _cname(db_session, zone.id, "web")
    hdr = await _requester_hdr(db_session)
    resp = await client.post("/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.30", "web"))
    assert resp.status_code == 400, resp.text
    assert "is a CNAME" in resp.text and "can hold no A record" in resp.text
    assert await db_session.scalar(select(func.count()).select_from(ChangeRequest)) == 0
    # A fresh name is still accepted and promises its record.
    ok = await client.post("/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.31", "fresh"))
    assert ok.status_code == 201, ok.text
    assert "publishes A fresh." in ok.text


@pytest.mark.asyncio
async def test_approve_refused_when_cname_appeared_after_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.core.security import create_access_token

    admin = await _user(db_session, "admin")
    sid, zone, appr_hdr = await _subnet_with_zone(db_session, client, admin)
    hdr = await _requester_hdr(db_session)
    resp = await client.post("/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.40", "late"))
    assert resp.status_code == 201, resp.text
    rid = resp.json()["id"]
    await _cname(db_session, zone.id, "late")
    appr = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    resp = await client.post(
        f"/api/v1/requests/{rid}/approve", headers=appr, json={"decision_note": "ok"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "failed"
    assert "is a CNAME" in resp.json()["error"]
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.address == "10.98.5.40"
            )
        )
    ).scalar_one_or_none()
    assert ip is None
