"""Platform Insights > Containers on Kubernetes (#3761).

The Containers tab used to read Docker only. It now reports each backend and,
on a Kubernetes install, lists the release's pods and tails their logs through
the support-bundle redactor. The pod inventory is the allowlist.
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

from app.api.v1.admin import containers as admin_containers
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.appliance import containers as svc
from app.services.appliance import k8s

_CFG = SimpleNamespace(namespace="spatium")


def _pod(name: str, component: str, *, instance: str = "rel", ours: bool = True) -> dict[str, Any]:
    labels = {"app.kubernetes.io/component": component, "app.kubernetes.io/instance": instance}
    if ours:
        labels["app.kubernetes.io/name"] = "spatiumddi"
    return {
        "metadata": {"name": name, "uid": "u" * 12, "labels": labels},
        "spec": {"containers": [{"name": component, "image": "ghcr.io/x:1"}]},
        "status": {"phase": "Running", "containerStatuses": [{"ready": True}]},
    }


_PODS = [
    _pod("rel-api-1", "api"),
    _pod("rel-dns-bind9-ns1-0", "dns-bind9"),
    _pod("other-api-1", "api", instance="other"),
    _pod("stranger", "x", ours=False),
]


@pytest.fixture
def kube_ok(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOSTNAME", "rel-api-1")
    with (
        patch.object(k8s, "get_config", return_value=_CFG),
        patch.object(k8s, "list_pods", return_value=list(_PODS)),
    ):
        yield


async def _token(db: AsyncSession, *, superadmin: bool = True) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def test_release_pods_scoped_to_own_release_and_labels(kube_ok) -> None:
    names = {p["metadata"]["name"] for p in svc.release_pods()}
    assert names == {"rel-api-1", "rel-dns-bind9-ns1-0"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("docker", "kube", "kube_expected"),
    [(True, False, False), (False, True, True), (True, True, True), (False, False, False)],
)
async def test_backend_matrix(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    docker: bool,
    kube: bool,
    kube_expected: bool,
) -> None:
    h = await _token(db_session)
    monkeypatch.setattr(admin_containers, "_socket_available", lambda: docker)
    monkeypatch.setenv("HOSTNAME", "rel-api-1")
    with (
        patch.object(k8s, "get_config", return_value=_CFG if kube else None),
        patch.object(k8s, "list_pods", return_value=list(_PODS)),
    ):
        r = await client.get("/api/v1/admin/containers/backends", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["docker"]["available"] is docker
    assert body["kubernetes"]["available"] is kube_expected
    if not kube:
        assert "api.serviceAccount.enabled" in body["kubernetes"]["reason"]
    if not docker:
        assert "docker.sock" in body["docker"]["reason"]


@pytest.mark.asyncio
async def test_forbidden_pod_list_names_the_toggle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _token(db_session)
    with (
        patch.object(k8s, "get_config", return_value=_CFG),
        patch.object(
            k8s, "list_pods", side_effect=k8s.KubeapiUnavailableError("list pods status 403")
        ),
        patch.object(admin_containers, "_socket_available", lambda: False),
    ):
        r = await client.get("/api/v1/admin/containers/backends", headers=h)
    kube = r.json()["kubernetes"]
    assert kube["available"] is False
    assert "api.serviceAccount.enabled" in kube["reason"]


@pytest.mark.asyncio
async def test_pod_list_works_off_appliance(
    client: AsyncClient, db_session: AsyncSession, kube_ok, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc.settings, "appliance_mode", False)
    r = await client.get("/api/v1/admin/containers/pods", headers=await _token(db_session))
    assert r.status_code == 200
    assert [p["name"] for p in r.json()["rows"]] == ["rel-api-1", "rel-dns-bind9-ns1-0"]


@pytest.mark.asyncio
async def test_unlisted_pod_is_404_and_never_reaches_kubeapi(
    client: AsyncClient, db_session: AsyncSession, kube_ok
) -> None:
    h = await _token(db_session)
    with patch.object(k8s, "get_pod_logs") as logs:
        for bad in ("other-api-1", "stranger", "kube-system-thing"):
            r = await client.get(f"/api/v1/admin/containers/pods/{bad}/logs", headers=h)
            assert r.status_code == 404
            r = await client.get(f"/api/v1/admin/containers/pods/{bad}/logs/stream", headers=h)
            assert r.status_code == 404
    logs.assert_not_called()


@pytest.mark.asyncio
async def test_logs_are_redacted_and_audited(
    client: AsyncClient, db_session: AsyncSession, kube_ok
) -> None:
    h = await _token(db_session)
    secret = "postgresql://spatium:hunter2supersecret@db:5432/spatium"
    with patch.object(k8s, "get_pod_logs", return_value=f"start\nconnecting {secret}\nok\n"):
        r = await client.get("/api/v1/admin/containers/pods/rel-api-1/logs?tail=50", headers=h)
    assert r.status_code == 200
    assert "hunter2supersecret" not in r.json()["tail"]
    assert "connecting" in r.json()["tail"]
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "container_logs_read")))
        .scalars()
        .all()
    )
    assert [a.resource_id for a in rows] == ["pod/rel-api-1"]


@pytest.mark.asyncio
async def test_non_superadmin_forbidden(client: AsyncClient, db_session: AsyncSession, kube_ok):
    h = await _token(db_session, superadmin=False)
    for path in (
        "/backends",
        "/pods",
        "/pods/rel-api-1/logs",
        "/pods/rel-api-1/logs/stream",
    ):
        r = await client.get(f"/api/v1/admin/containers{path}", headers=h)
        assert r.status_code == 403, path


def test_appliance_listing_still_gated_on_appliance_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc.settings, "appliance_mode", False)
    with patch.object(k8s, "list_pods", return_value=list(_PODS)):
        assert svc.list_containers() == []
    monkeypatch.setattr(svc.settings, "appliance_mode", True)
    with patch.object(k8s, "list_pods", return_value=list(_PODS)):
        assert len(svc.list_containers()) == 4
