"""Pod actions on Cluster -> Pods (#4232).

Stop / Start answered 500 (an unhandled ValueError) and Restart deleted any pod
in the namespace, including one no controller would recreate.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.appliance import k8s

_CFG = SimpleNamespace(namespace="spatium")


def _pod(name: str, *, controlled: bool) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name, "uid": "u" * 12}
    if controlled:
        meta["ownerReferences"] = [{"kind": "ReplicaSet", "name": "rs", "controller": True}]
    return {"metadata": meta, "spec": {}, "status": {"phase": "Running"}}


async def _token(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.fixture
def kube():
    pods = [_pod("api-1", controlled=True), _pod("bare", controlled=False)]
    with (
        patch.object(k8s, "get_config", return_value=_CFG),
        patch.object(k8s, "list_pods", return_value=pods),
        patch.object(k8s, "delete_pod", return_value=(True, None)) as delete,
    ):
        yield delete


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["stop", "start"])
async def test_stop_start_answer_409_not_500(
    client: AsyncClient, db_session: AsyncSession, kube, action: str
) -> None:
    h = await _token(db_session)
    r = await client.post(f"/api/v1/appliance/containers/api-1/{action}", headers=h)
    assert r.status_code == 409
    assert "scaled" in r.json()["detail"]
    kube.assert_not_called()
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == f"container_{action}")))
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.asyncio
async def test_restart_deletes_a_controlled_pod_and_audits(
    client: AsyncClient, db_session: AsyncSession, kube
) -> None:
    h = await _token(db_session)
    r = await client.post("/api/v1/appliance/containers/api-1/restart", headers=h)
    assert r.status_code == 202
    kube.assert_called_once_with("api-1")
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "container_restart")))
        .scalars()
        .all()
    )
    assert [a.resource_display for a in rows] == ["api-1"]


@pytest.mark.asyncio
async def test_restart_refuses_a_pod_with_no_controller(
    client: AsyncClient, db_session: AsyncSession, kube
) -> None:
    h = await _token(db_session)
    r = await client.post("/api/v1/appliance/containers/bare/restart", headers=h)
    assert r.status_code == 409
    assert "no owning controller" in r.json()["detail"]
    kube.assert_not_called()


@pytest.mark.asyncio
async def test_restart_unknown_pod_is_404(
    client: AsyncClient, db_session: AsyncSession, kube
) -> None:
    h = await _token(db_session)
    r = await client.post("/api/v1/appliance/containers/nope/restart", headers=h)
    assert r.status_code == 404
    kube.assert_not_called()
