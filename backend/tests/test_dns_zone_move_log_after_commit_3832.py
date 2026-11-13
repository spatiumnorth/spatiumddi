"""#3832 — a zone move rolled back at the provider must not log that it moved.

``dns_zone_moved_group`` was logged inside ``commit_zone_move``, before the
endpoint pushed the zone to the target group's agentless servers. A failed
push answers 502 and rolls everything back, but the line had been written.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import router as dns_router
from app.services.dns import zone_move
from tests.test_dns_zone_move_same_provider_3805 import (
    _A,
    _B,
    _FakeProvider,
    _move,
    _setup,
    _token,
)


class _Failing(_FakeProvider):
    async def apply_zone_change(self, server: Any, zone: Any, op: str, **_: Any) -> bool:
        raise RuntimeError("provider unreachable")


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    events: list[str] = []
    for mod in (dns_router, zone_move):
        for level in ("info", "warning"):
            monkeypatch.setattr(
                mod.logger, level, lambda event, _e=events, **kw: _e.append(event), raising=False
            )
    return events


@pytest.mark.asyncio
async def test_failed_provider_push_logs_rollback_not_move(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: _Failing())
    events = _capture(monkeypatch)
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 502, resp.text
    assert "dns_zone_moved_group" not in events
    assert "dns_zone_move_rolled_back" in events


@pytest.mark.asyncio
async def test_successful_move_logs_once(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: _FakeProvider())
    events = _capture(monkeypatch)
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert events.count("dns_zone_moved_group") == 1
    assert "dns_zone_move_rolled_back" not in events
