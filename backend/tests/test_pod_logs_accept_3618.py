"""#3618 — the pod-logs route asks kubeapi for ``*/*``.

kubeapi answers a pod log with 406 to ``Accept: text/plain`` (it lists only
json / yaml / protobuf), and the supervisor forwards the header since #3618.
"""

from __future__ import annotations

import types
import uuid
from typing import Any

import pytest

from app.api.v1.appliance import supervisor as sup
from app.services.appliance import k8s_proxy


class _DB:
    async def get(self, _model: Any, ident: Any) -> Any:
        return types.SimpleNamespace(id=ident, state=sup.APPLIANCE_STATE_APPROVED)


@pytest.mark.asyncio
async def test_logs_route_queues_any_media_type(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    async def _k8s_call(row_id: Any, method: str, path: str, **kw: Any) -> tuple[int, bytes]:
        seen.update(method=method, path=path, **kw)
        return 200, b"hello\n"

    monkeypatch.setattr(k8s_proxy, "k8s_call", _k8s_call)
    handler = sup.k8s_get_pod_logs
    handler = getattr(handler, "__wrapped__", handler)
    resp = await handler(
        appliance_id=uuid.uuid4(),
        pod="dns-bind9-abc12",
        current_user=None,
        db=_DB(),
        namespace="spatium",
        container="agent",
        tail_lines=10,
    )
    assert seen["accept"] == "*/*"
    assert "container=agent" in seen["path"]
    assert resp.body == b"hello\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("upstream,expected", [(400, 422), (404, 404), (500, 502)])
async def test_logs_route_client_errors_are_not_502(
    monkeypatch: pytest.MonkeyPatch, upstream: int, expected: int
) -> None:
    """#3628: a container not in the pod (kubeapi 400) is the caller's error."""
    from fastapi import HTTPException

    async def _k8s_call(*_a: Any, **_kw: Any) -> tuple[int, bytes]:
        return upstream, b"container x is not valid for pod y"

    monkeypatch.setattr(k8s_proxy, "k8s_call", _k8s_call)
    handler = getattr(sup.k8s_get_pod_logs, "__wrapped__", sup.k8s_get_pod_logs)
    with pytest.raises(HTTPException) as ei:
        await handler(
            appliance_id=uuid.uuid4(),
            pod="dns-bind9-abc12",
            current_user=None,
            db=_DB(),
            namespace="spatium",
            container="agent",
            tail_lines=10,
        )
    assert ei.value.status_code == expected
