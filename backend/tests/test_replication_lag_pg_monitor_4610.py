"""#4610 — the app's DB role is granted ``pg_monitor`` so the rolling-upgrade
preflight can read replica state, and says plainly when it could not."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.services.upgrades import preflight

_REPO = Path(__file__).resolve().parents[2]
_CNPG = _REPO / "charts" / "spatiumddi" / "templates" / "cnpg-cluster.yaml"


def test_chart_grants_app_role_pg_monitor_via_managed_roles() -> None:
    tpl = _CNPG.read_text()
    # managed.roles (not postInit SQL) so existing clusters reconcile it.
    assert "inRoles:" in tpl and "- pg_monitor" in tpl
    assert "postInitApplicationSQL" not in tpl
    # The managed block must render when only the monitor grant is wanted.
    assert (
        "or .Values.postgresql.cnpg.appRoleCreateDb .Values.postgresql.cnpg.appRoleMonitor" in tpl
    )
    # The default (on) is asserted on the rendered chart by charts-render-check.sh.


def _patch_rows(monkeypatch: pytest.MonkeyPatch, rows: list[Any]) -> None:
    class _Result:
        def all(self) -> list[Any]:
            return rows

    class _Session:
        async def execute(self, *_a: Any, **_k: Any) -> _Result:
            return _Result()

    @asynccontextmanager
    async def _factory():  # type: ignore[no-untyped-def]
        yield _Session()

    monkeypatch.setattr(preflight, "AsyncSessionLocal", _factory)


def _row(state: str | None, lag: int | None) -> SimpleNamespace:
    return SimpleNamespace(application_name="pg-2", state=state, lag_bytes=lag)


@pytest.mark.asyncio
async def test_hidden_state_warns_with_remedy_not_measured(monkeypatch) -> None:
    _patch_rows(monkeypatch, [_row(None, None)])
    r = await preflight.check_replication_lag()
    assert r.level == "warn"
    assert r.detail["unverified"] is True
    assert "could not verify" in r.message
    assert "pg_monitor" in r.message and "appRoleMonitor" in r.message


@pytest.mark.asyncio
async def test_visible_state_is_measured(monkeypatch) -> None:
    _patch_rows(monkeypatch, [_row("streaming", 0)])
    r = await preflight.check_replication_lag()
    assert r.level == "ok"
    assert "unverified" not in r.detail
