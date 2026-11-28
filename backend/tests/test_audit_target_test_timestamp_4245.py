"""#4245 — the Test's synthetic event carries a valid RFC 3339 timestamp.

An aware time's ``isoformat()`` already ends in ``+00:00``; appending ``Z`` gave
``...+00:00Z``, which no strict syslog receiver or SIEM accepts.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import audit_forward as svc

from .test_forward_target_secrets_at_rest import _TARGETS, _admin, _webhook_body

pytestmark = pytest.mark.asyncio

_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def _timestamps(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "timestamp" and isinstance(v, str):
                found.append(v)
            found.extend(_timestamps(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            found.extend(_timestamps(v))
    return found


async def test_test_event_timestamp_is_rfc3339(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    created = (await client.post(_TARGETS, headers=h, json=_webhook_body())).json()
    sent = AsyncMock(return_value=None)
    with patch.object(svc, "_send_webhook", new=sent):
        resp = await client.post(f"{_TARGETS}/{created['id']}/test", headers=h)
    assert resp.status_code == 200, resp.text
    # Creating the target forwards its own audit event too; pick the Test's.
    payloads = [
        a
        for call in sent.await_args_list
        for a in list(call.args) + list(call.kwargs.values())
        if isinstance(a, dict) and a.get("action") == "test_forward"
    ]
    assert len(payloads) == 1, sent.await_args_list
    stamps = _timestamps(payloads)
    assert stamps, "the synthetic event carried no timestamp"
    for ts in stamps:
        assert "+00:00Z" not in ts, ts
        assert _RFC3339.match(ts), ts
        assert datetime.fromisoformat(ts).utcoffset() is not None
