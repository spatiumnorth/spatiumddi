"""A disabled target's old sync error is history, not a red count (#2221)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dashboards.integrations import _build_panel

from .test_tailscale_token_expiry_2138 import _db_tenant, _headers, _space

NOW = datetime(2026, 10, 20, tzinfo=UTC)


def _t(i: str, *, enabled: bool, error: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        id=i,
        name=f"t-{i}",
        enabled=enabled,
        last_synced_at=NOW - timedelta(seconds=10),
        sync_interval_seconds=60,
        last_sync_error=error,
        last_sync_warning=None,
    )


def test_disabled_target_with_an_old_error_is_not_a_problem() -> None:
    panel = _build_panel(
        kind="docker",
        label="Docker",
        enabled=True,
        targets=[
            _t("off", enabled=False, error="connection refused"),
            _t("live", enabled=True, error="connection refused"),
            _t("ok", enabled=True, error=None),
        ],
        display_attr="name",
        now=NOW,
    )
    assert panel.error_count == 1  # only the enabled one
    assert panel.problem_count == 1
    assert panel.disabled_count == 1
    assert panel.healthy_count == 1
    assert panel.target_count == 3
    off = next(r for r in panel.targets if r.id == "off")
    assert off.enabled is False and off.last_sync_error  # greyed history is kept
    # Problem rows sort first; the disabled one is not among them.
    assert panel.targets[0].id == "live"


def test_only_disabled_targets_means_no_red() -> None:
    panel = _build_panel(
        kind="docker",
        label="Docker",
        enabled=True,
        targets=[_t("off", enabled=False, error="boom")],
        display_attr="name",
        now=NOW,
    )
    assert (panel.error_count, panel.problem_count, panel.stale_count) == (0, 0, 0)
    assert panel.disabled_count == 1


@pytest.mark.asyncio
async def test_summary_endpoint_does_not_count_a_disabled_tenants_error(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    off = await _db_tenant(db_session, space, error="old failure", enabled=False)
    await db_session.commit()

    r = await client.get("/api/v1/dashboards/integrations/summary", headers=h)
    panel = next(p for p in r.json()["panels"] if p["kind"] == "tailscale")
    assert panel["error_count"] == 0
    assert panel["problem_count"] == 0
    assert panel["disabled_count"] == 1
    row = next(x for x in panel["targets"] if x["id"] == str(off.id))
    assert row["enabled"] is False
    assert row["last_sync_error"] == "old failure"
