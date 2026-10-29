"""#3011 — the local reboot is node-local, so a multi-node control plane refuses it.

``POST /appliance/system/reboot`` writes its trigger into the responding pod's
own node-local release-state hostPath; behind the api Service that is whichever
node the load balancer picked. Same shape as ``slot apply`` (refused by the
shared ``reject_if_clustered``); the operator is pointed at Fleet's
per-appliance reboot, and ``/system/info`` says so for the UI.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import system as system_api
from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.auth import User


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-slot"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _approve(db: AsyncSession, hostname: str, cluster_role: str | None = None) -> Appliance:
    """An approved appliance. `cluster_role` None models a data-plane
    appliance or an unpromoted single node — approved, but NOT part of the
    control plane, and therefore not a source of node ambiguity."""
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        state=APPLIANCE_STATE_APPROVED,
        cluster_role=cluster_role,
        public_key_der=b"fake-key",
        public_key_fingerprint=uuid.uuid4().hex * 2,
        cert_serial="0000",
        deployment_kind="appliance",
    )
    db.add(row)
    await db.flush()
    return row


async def _cluster(db: AsyncSession, n: int) -> None:
    for i in range(n):
        await _approve(db, f"cp-{i}", CLUSTER_ROLE_PRIMARY if i == 0 else CLUSTER_ROLE_MEMBER)
    await db.commit()


@pytest.mark.asyncio
async def test_reboot_refused_with_two_control_plane_nodes(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _superadmin(db_session)
    await _cluster(db_session, 2)
    fired: list[str] = []
    monkeypatch.setattr(system_api, "request_reboot", lambda **k: fired.append("reboot"))
    r = await client.post("/api/v1/appliance/system/reboot", headers=headers)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert "2 control-plane nodes" in detail
    assert "Fleet" in detail and "appliances/{appliance_id}/reboot" in detail
    assert fired == []


@pytest.mark.asyncio
async def test_reboot_allowed_with_one_control_plane_node(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _superadmin(db_session)
    await _cluster(db_session, 1)
    fired: list[str] = []
    monkeypatch.setattr(system_api, "request_reboot", lambda **k: fired.append("reboot"))
    r = await client.post("/api/v1/appliance/system/reboot", headers=headers)
    assert r.status_code == 202
    assert fired == ["reboot"]


@pytest.mark.asyncio
async def test_info_reports_reboot_availability(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    r = await client.get("/api/v1/appliance/system/info", headers=headers)
    assert r.json()["reboot_available"] is True
    assert r.json()["reboot_unavailable_reason"] is None
    await _cluster(db_session, 3)
    r = await client.get("/api/v1/appliance/system/info", headers=headers)
    body = r.json()
    assert body["reboot_available"] is False
    assert "Fleet" in body["reboot_unavailable_reason"]
