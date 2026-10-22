"""Operator-triggered background work records the operator (#2303).

Upgrade start, block-sync force reconcile and integration ``…/sync`` enqueue a
Celery task whose own audit rows say ``system``. The request writes its own row
attributed to the caller, committed before the response returns.
"""

from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.models.ipam import IPSpace
from app.models.meraki import MerakiOrg
from app.models.opnsense import OPNsenseRouter
from app.models.system_upgrade import SystemUpgradeRun
from app.services import feature_modules

bs_router = importlib.import_module("app.api.v1.block_sync.router")

pytestmark = pytest.mark.asyncio

MODULES = ["security.block_sync", "integrations.opnsense", "integrations.meraki"]


@pytest_asyncio.fixture(autouse=True)
async def _modules(db_session: AsyncSession):
    feature_modules.invalidate_cache()
    for m in MODULES:
        await db_session.merge(FeatureModule(id=m, enabled=True))
    await db_session.flush()
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"op-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Opal Operator",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _rows(db: AsyncSession, **kw) -> list[AuditLog]:
    q = select(AuditLog)
    for k, v in kw.items():
        q = q.where(getattr(AuditLog, k) == v)
    return list((await db.execute(q)).scalars().all())


async def test_upgrade_start_audits_the_operator(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    from app.tasks import upgrade_orchestrator

    calls: list[str] = []
    monkeypatch.setattr(
        upgrade_orchestrator,
        "drive_upgrade_run",
        SimpleNamespace(delay=lambda rid: calls.append(rid)),
    )
    user, hdr = await _admin(db_session)
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="planned",
        target_version="2026.10.20-1",
        source_versions={},
        plan={"node_order": ["node-a"], "slot_image_url": "http://x"},
        progress={"per_node": {}, "events": []},
        started_at=datetime.now(UTC),
    )
    db_session.add(run)
    await db_session.flush()

    r = await client.post(f"/api/v1/upgrades/{run.id}/start", headers=hdr)
    assert r.status_code == 200, r.text
    assert calls == [str(run.id)]
    rows = await _rows(db_session, resource_type="system_upgrade_run", resource_id=str(run.id))
    assert len(rows) == 1
    assert rows[0].user_id == user.id
    assert rows[0].user_display_name == "Opal Operator"
    assert rows[0].action == "upgrade.start_requested"


async def test_block_sync_reconcile_audits_the_operator(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    enq: list = []
    monkeypatch.setattr(bs_router, "_enqueue_reconcile", lambda t: enq.append(t))
    user, hdr = await _admin(db_session)
    s = IPSpace(name=f"bs-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(s)
    await db_session.flush()
    org = MerakiOrg(
        name="org1",
        org_id="123456",
        api_key_encrypted=encrypt_str("K"),
        ipam_space_id=s.id,
        block_sync_enabled=True,
        block_sync_api_key_encrypted=encrypt_str("W"),
    )
    db_session.add(org)
    await db_session.flush()

    r = await client.post(f"/api/v1/block-sync/targets/meraki/{org.id}/reconcile", headers=hdr)
    assert r.status_code == 200, r.text
    assert enq, "reconcile should have been enqueued"
    rows = await _rows(db_session, resource_type="network_block_target", action="reconcile")
    assert len(rows) == 1
    assert rows[0].user_id == user.id
    assert rows[0].resource_id == str(org.id)
    assert rows[0].resource_display == "meraki:org1"


async def test_block_sync_preview_does_not_audit_a_trigger(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    monkeypatch.setattr(bs_router, "_enqueue_reconcile", lambda t: None)
    _, hdr = await _admin(db_session)
    s = IPSpace(name=f"bs-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(s)
    await db_session.flush()
    org = MerakiOrg(
        name="org2",
        org_id="123456",
        api_key_encrypted=encrypt_str("K"),
        ipam_space_id=s.id,
        block_sync_enabled=True,
        block_sync_api_key_encrypted=encrypt_str("W"),
    )
    db_session.add(org)
    await db_session.flush()
    r = await client.post(
        f"/api/v1/block-sync/targets/meraki/{org.id}/reconcile?preview=true", headers=hdr
    )
    assert r.status_code == 200, r.text
    assert await _rows(db_session, action="reconcile") == []


async def test_integration_sync_audits_the_operator(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
):
    from app.tasks import opnsense_sync

    calls: list[str] = []
    monkeypatch.setattr(
        opnsense_sync,
        "sync_router_now",
        SimpleNamespace(delay=lambda i: calls.append(i) or SimpleNamespace(id="t1")),
    )
    user, hdr = await _admin(db_session)
    s = IPSpace(name=f"bs-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(s)
    await db_session.flush()
    rt = OPNsenseRouter(
        name="fw1",
        host="10.0.0.1",
        api_key="ro",
        api_secret_encrypted=encrypt_str("s"),
        ipam_space_id=s.id,
    )
    db_session.add(rt)
    await db_session.flush()

    r = await client.post(f"/api/v1/opnsense/routers/{rt.id}/sync", headers=hdr)
    assert r.status_code == 202, r.text
    rows = await _rows(db_session, resource_type="opnsense_router", action="sync")
    assert len(rows) == 1
    assert rows[0].user_id == user.id
    assert rows[0].user_display_name == "Opal Operator"
    assert rows[0].resource_display == "fw1"
