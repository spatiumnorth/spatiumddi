"""vSphere target REST API (#4740): permissions, validation, 404/409, audit,
secret handling, delete hand-back, module gate, connection test."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.vsphere import VSphereTarget
from app.services import feature_modules
from app.services.vsphere import client as vclient
from tests.test_vsphere_mirror_4740 import FakeVCenter

pytestmark = pytest.mark.asyncio

BASE = "/api/v1/vsphere/targets"


async def _user(db: AsyncSession, *, superadmin: bool) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


def _body(space: IPSpace, **kw: Any) -> dict[str, Any]:
    return {
        "name": f"vc-{uuid.uuid4().hex[:6]}",
        "host": "vc.example.test",
        "username": "svc@vsphere.local",
        "password": "pw-1",
        "ipam_space_id": str(space.id),
        **kw,
    }


async def test_permission_refused_never_500(client: AsyncClient, db_session: AsyncSession) -> None:
    space = await _space(db_session)
    plain = await _user(db_session, superadmin=False)
    admin = await _user(db_session, superadmin=True)
    await db_session.commit()
    for method, url, kw in (
        ("get", BASE, {}),
        ("post", BASE, {"json": _body(space)}),
        ("put", f"{BASE}/{uuid.uuid4()}", {"json": {"name": "x"}}),
        ("delete", f"{BASE}/{uuid.uuid4()}", {}),
        ("post", f"{BASE}/{uuid.uuid4()}/sync", {}),
        ("post", f"{BASE}/test", {"json": {"host": "h", "username": "u", "password": "p"}}),
    ):
        r = await getattr(client, method)(url, headers=plain, **kw)
        assert r.status_code == 403, (method, url, r.status_code, r.text)
    r = await getattr(client, "get")(BASE, headers=admin)
    assert r.status_code == 200 and r.json() == []
    r = await client.get(BASE)
    assert r.status_code in (401, 403)


async def test_module_off_is_404(client: AsyncClient, db_session: AsyncSession) -> None:
    admin = await _user(db_session, superadmin=True)
    db_session.add(FeatureModule(id="integrations.vsphere", enabled=False))
    await db_session.commit()
    feature_modules.invalidate_cache()
    assert (await client.get(BASE, headers=admin)).status_code == 404


async def test_create_validation_and_conflicts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space = await _space(db_session)
    h = await _user(db_session, superadmin=True)
    await db_session.commit()

    for bad in (
        {"port": 0},
        {"port": 70000},
        {"sync_interval_seconds": 5},
        {"username": "  "},
        {"password": ""},
        {"host": " "},
    ):
        r = await client.post(BASE, headers=h, json=_body(space, **bad))
        assert r.status_code == 422, (bad, r.text)
    r = await client.post(BASE, headers=h, json={"name": "x"})
    assert r.status_code == 422  # required fields named by the validator
    r = await client.post(
        BASE, headers=h, json={**_body(space), "ipam_space_id": str(uuid.uuid4())}
    )
    assert r.status_code == 422 and "ipam_space_id" in r.json()["detail"]

    body = _body(space, host="https://vc.example.test/ui")
    r = await client.post(BASE, headers=h, json=body)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["host"] == "vc.example.test"  # scheme + path stripped
    assert out["verify_tls"] is True and out["port"] == 443 and out["enabled"] is True
    assert "password" not in out and out["password_present"] is True
    r = await client.post(BASE, headers=h, json={**_body(space), "name": body["name"]})
    assert r.status_code == 409


async def test_update_delete_sync_404_and_audit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space = await _space(db_session)
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    ghost = uuid.uuid4()
    assert (await client.put(f"{BASE}/{ghost}", headers=h, json={"name": "n"})).status_code == 404
    assert (await client.delete(f"{BASE}/{ghost}", headers=h)).status_code == 404
    assert (await client.post(f"{BASE}/{ghost}/sync", headers=h)).status_code == 404
    r = await client.post(f"{BASE}/test", headers=h, json={"target_id": str(ghost), "host": "h"})
    assert r.status_code == 404

    created = (await client.post(BASE, headers=h, json=_body(space))).json()
    tid = created["id"]
    other = (await client.post(BASE, headers=h, json=_body(space))).json()
    r = await client.put(f"{BASE}/{tid}", headers=h, json={"name": other["name"]})
    assert r.status_code == 409
    r = await client.put(f"{BASE}/{tid}", headers=h, json={"port": 0})
    assert r.status_code == 422
    r = await client.put(f"{BASE}/{tid}", headers=h, json={"ipam_space_id": str(uuid.uuid4())})
    assert r.status_code == 422
    r = await client.put(
        f"{BASE}/{tid}", headers=h, json={"password": "rotated", "mirror_hosts": False}
    )
    assert r.status_code == 200 and r.json()["mirror_hosts"] is False
    row = await db_session.get(VSphereTarget, uuid.UUID(tid))
    await db_session.refresh(row)
    assert decrypt_str(row.password_encrypted) == "rotated"
    # A blank password keeps the stored one.
    assert (await client.put(f"{BASE}/{tid}", headers=h, json={"password": ""})).status_code == 200
    await db_session.refresh(row)
    assert decrypt_str(row.password_encrypted) == "rotated"

    with patch("app.core.celery_dispatch.dispatch") as _d:
        _d.side_effect = RuntimeError("no broker")
        r = await client.post(f"{BASE}/{tid}/sync", headers=h)
    assert r.status_code == 202

    # list: filter-free but ordered; no secret anywhere in the wire format.
    listing = (await client.get(BASE, headers=h)).json()
    assert [t["name"] for t in listing] == sorted(t["name"] for t in listing)
    assert "rotated" not in str(listing)

    assert (await client.delete(f"{BASE}/{tid}", headers=h)).status_code == 204
    actions = [
        a.action
        for a in (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "vsphere_target", AuditLog.resource_id == tid
                )
            )
        )
        .scalars()
        .all()
    ]
    assert {"create", "update", "sync", "delete"} <= set(actions)
    audit_text = str(
        [
            a.new_value
            for a in (await db_session.execute(select(AuditLog))).scalars().all()
            if a.resource_type == "vsphere_target"
        ]
    )
    assert "rotated" not in audit_text and "pw-1" not in audit_text


async def test_delete_hands_back_operator_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space = await _space(db_session)
    h = await _user(db_session, superadmin=True)
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    sn = Subnet(space_id=space.id, block_id=block.id, network="10.20.1.0/24", name="s")
    db_session.add(sn)
    await db_session.commit()
    tid = (await client.post(BASE, headers=h, json=_body(space))).json()["id"]
    mirrored = IPAddress(
        subnet_id=sn.id, address="10.20.1.5", status="vsphere-vm", vsphere_target_id=uuid.UUID(tid)
    )
    edited = IPAddress(
        subnet_id=sn.id,
        address="10.20.1.6",
        status="allocated",
        hostname="operator-edit",
        vsphere_target_id=uuid.UUID(tid),
    )
    from datetime import UTC, datetime

    edited.user_modified_at = datetime.now(UTC)
    db_session.add_all([mirrored, edited])
    await db_session.commit()
    assert (await client.delete(f"{BASE}/{tid}", headers=h)).status_code == 204
    left = (await db_session.execute(select(IPAddress.address, IPAddress.vsphere_target_id))).all()
    assert [(str(a), t) for a, t in left] == [("10.20.1.6", None)]


async def test_connection_test_reports_and_closes_session(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space = await _space(db_session)
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    created = (await client.post(BASE, headers=h, json=_body(space))).json()
    fake = FakeVCenter()
    real = httpx.AsyncClient

    def factory(**kw: Any) -> httpx.AsyncClient:
        return real(transport=httpx.MockTransport(fake.handler), **kw)

    with patch.object(vclient.httpx, "AsyncClient", factory):
        r = await client.post(f"{BASE}/test", headers=h, json={"target_id": created["id"]})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["ok"] is True and out["vcenter_version"] == "8.0.2"
        assert (out["host_count"], out["vm_count"]) == (2, 4)
        assert fake.calls[-1] == ("DELETE", "/api/session")
        # Unreachable / rejected credentials are a result, never a 500.
        fake.overrides["/api/session"] = (401, {})
        r = await client.post(
            f"{BASE}/test",
            headers=h,
            json={"host": "vc2.example.test", "username": "u", "password": "p"},
        )
        assert r.status_code == 200 and r.json()["ok"] is False
        assert "rejected" in r.json()["message"]
    # Missing pieces: 422 naming them.
    r = await client.post(f"{BASE}/test", headers=h, json={"host": "h"})
    assert r.status_code == 422
    stored = await db_session.get(VSphereTarget, uuid.UUID(created["id"]))
    await db_session.refresh(stored)
    assert stored.vcenter_version == "8.0.2"
