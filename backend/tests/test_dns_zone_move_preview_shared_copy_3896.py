"""Zone move preview: a shared provider copy the commit keeps (#3896)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSZone
from tests.test_dns_zone_group_move import _preview, _superadmin
from tests.test_dns_zone_move_same_provider_3805 import (
    _FakeProvider,
    _server,
    provider,  # noqa: F401  (fixture)
)
from tests.test_dns_zone_move_same_provider_3805 import (
    _group as _g2,
)

_A = {"access_key_id": "AKIA-ONE", "secret_access_key": "s"}
_B = {"access_key_id": "AKIA-TWO", "secret_access_key": "s"}


@pytest.mark.asyncio
async def test_preview_does_not_promise_delete_the_commit_will_skip(
    client: AsyncClient,
    db_session: AsyncSession,
    provider: _FakeProvider,  # noqa: F811
) -> None:
    token = await _superadmin(db_session, "root3896")
    a = await _g2(db_session, f"a-{uuid.uuid4().hex[:6]}")
    b = await _g2(db_session, f"b-{uuid.uuid4().hex[:6]}")
    c = await _g2(db_session, f"c-{uuid.uuid4().hex[:6]}")
    await _server(db_session, a, "ns-a", _A)
    await _server(db_session, b, "ns-b", _A)  # same provider as A
    await _server(db_session, c, "ns-c", _B)
    zone = DNSZone(group_id=a.id, name="example.com.", zone_type="primary")
    other = DNSZone(group_id=b.id, name="example.com.", zone_type="primary")
    db_session.add_all([zone, other])
    await db_session.flush()

    body = (await _preview(client, token, zone, c)).json()
    warnings = body["warnings"]
    assert not any("Source copy on 'ns-a' is deleted" in w for w in warnings)
    assert any("Provider copy kept on 'ns-a'" in w for w in warnings)
