"""#3618 — the control-plane half of the kubeapi proxy, hardened alongside
turning the supervisor's proxy on by default.

* A reply is accepted only from the appliance the request was queued for, so
  one approved appliance cannot answer another's pod list or log request.
* Operator-supplied kubeapi identifiers must be DNS-1123 names before they are
  spliced into a proxied path, so ``?`` / ``&`` cannot widen the request.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.services.appliance import k8s_proxy


async def _answer(appliance_id: uuid.UUID, *, replying_as: uuid.UUID) -> tuple[bool, bool]:
    """Queue a request for ``appliance_id``, reply as ``replying_as``; return
    (delivered, the operator's call was answered)."""
    task = asyncio.create_task(
        k8s_proxy.k8s_call(appliance_id, "GET", "/api/v1/namespaces/spatium/pods", timeout=0.5)
    )
    queued = await k8s_proxy.pop_request(appliance_id, timeout=1.0)
    assert queued is not None
    delivered = await k8s_proxy.deliver_response(
        k8s_proxy.K8sProxyResponse(request_id=queued.request_id, status=200, body_b64=""),
        appliance_id=replying_as,
    )
    try:
        await task
    except TimeoutError:
        return delivered, False
    return delivered, True


@pytest.mark.asyncio
async def test_a_reply_from_another_appliance_is_not_delivered() -> None:
    target, other = uuid.uuid4(), uuid.uuid4()
    delivered, answered = await _answer(target, replying_as=other)
    assert delivered is False
    assert answered is False


@pytest.mark.asyncio
async def test_the_queued_appliance_can_reply() -> None:
    target = uuid.uuid4()
    delivered, answered = await _answer(target, replying_as=target)
    assert delivered is True
    assert answered is True


async def _setup(db: AsyncSession) -> tuple[dict[str, str], Appliance]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-3618"),
        is_superadmin=True,
    )
    db.add(user)
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:8]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ab" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
    )
    db.add(appliance)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, appliance


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route", "params"),
    [
        ("pods", {"namespace": "spatium/secrets?x="}),
        ("pods", {"namespace": "kube-system/../spatium"}),
        ("logs", {"pod": "x?follow=true", "namespace": "spatium"}),
        ("logs", {"pod": "x", "namespace": "spatium", "container": "c&follow=true"}),
        ("logs", {"pod": "..", "namespace": "spatium"}),
        ("workloads", {"namespace": "spatium?watch=1"}),
    ],
    ids=[
        "pods-ns-query",
        "pods-ns-traversal",
        "logs-pod-query",
        "logs-container-query",
        "logs-pod-dotdot",
        "workloads-ns-query",
    ],
)
async def test_injected_identifiers_are_422_and_never_proxied(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
    params: dict[str, str],
) -> None:
    headers, appliance = await _setup(db_session)
    called: list[str] = []

    async def _never(_aid: uuid.UUID, _m: str, path: str, **_k: object) -> tuple[int, bytes]:
        called.append(path)
        return 200, b'{"items": []}'

    monkeypatch.setattr(k8s_proxy, "k8s_call", _never)
    resp = await client.get(
        f"/api/v1/appliance/appliances/{appliance.id}/k8s/{route}",
        params=params,
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert called == []


@pytest.mark.asyncio
async def test_restart_refuses_an_injected_name(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers, appliance = await _setup(db_session)
    called: list[str] = []

    async def _never(_aid: uuid.UUID, _m: str, path: str, **_k: object) -> tuple[int, bytes]:
        called.append(path)
        return 200, b"{}"

    monkeypatch.setattr(k8s_proxy, "k8s_call", _never)
    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/k8s/restart",
        json={"kind": "Deployment", "name": "api/status", "namespace": "spatium"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert called == []


@pytest.mark.asyncio
async def test_valid_identifiers_still_reach_the_proxy(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers, appliance = await _setup(db_session)
    called: list[str] = []

    async def _ok(_aid: uuid.UUID, _m: str, path: str, **_k: object) -> tuple[int, bytes]:
        called.append(path)
        return 200, b"line\n"

    monkeypatch.setattr(k8s_proxy, "k8s_call", _ok)
    resp = await client.get(
        f"/api/v1/appliance/appliances/{appliance.id}/k8s/logs",
        params={"pod": "dns-bind9-7c9f.x", "namespace": "spatium", "container": "agent"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert len(called) == 1
    assert called[0].startswith("/api/v1/namespaces/spatium/pods/dns-bind9-7c9f.x/log?tailLines=")
    assert called[0].endswith("&container=agent")
