"""A disabled Tailscale tenant is not 'Token rejected' anywhere (#2191), and a
capped dashboard card never hides a problem tenant (#2192)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.dashboards.integrations as integrations_dash
from app.services.integration_credentials import credential_status
from app.services.tailscale.client import AUTH_REJECTED_PREFIX

from .test_tailscale_token_expiry_2138 import _db_tenant, _headers, _space

REJECTED = f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked. Generate …"


def test_disabled_beats_rejected_and_expired_in_the_shared_rule() -> None:
    now = datetime(2026, 10, 18, tzinfo=UTC)
    past = now - timedelta(days=3)
    s = credential_status(expires_at=past, rejected=True, now=now, enabled=False)
    assert s.state == "disabled"
    assert s.expires_at == past  # kept as history
    assert credential_status(expires_at=past, rejected=True, now=now).state == "rejected"


@pytest.mark.asyncio
async def test_page_api_dashboard_and_mcp_agree_on_a_disabled_rejected_tenant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ai.tools.integrations import (  # noqa: PLC0415
        ListTailscaleTargetsArgs,
        list_tailscale_targets,
    )

    h = await _headers(db_session)
    space = await _space(db_session)
    t = await _db_tenant(db_session, space, error=REJECTED, enabled=False)
    live = await _db_tenant(db_session, space, error=REJECTED, enabled=True)
    await db_session.commit()

    r = await client.get("/api/v1/tailscale/tenants", headers=h)
    by_id = {x["id"]: x for x in r.json()}
    assert by_id[str(t.id)]["credential_state"] == "disabled"
    assert by_id[str(t.id)]["last_sync_error"]  # history is kept
    assert by_id[str(live.id)]["credential_state"] == "rejected"

    d = await client.get("/api/v1/dashboards/integrations/summary", headers=h)
    panel = next(p for p in d.json()["panels"] if p["kind"] == "tailscale")
    rows = {x["id"]: x for x in panel["targets"]}
    assert rows[str(t.id)]["credential_state"] == "disabled"
    assert rows[str(live.id)]["credential_state"] == "rejected"

    mcp = await list_tailscale_targets(
        db_session, None, ListTailscaleTargetsArgs()  # type: ignore[arg-type]
    )
    states = {m["id"]: m["credential_state"] for m in mcp}
    assert states[str(t.id)] == "disabled"
    assert states[str(live.id)] == "rejected"


def _row(
    i: int, state: str | None = None, err: str | None = None
) -> integrations_dash.IntegrationTargetRow:
    return integrations_dash.IntegrationTargetRow(
        id=str(i),
        display=f"t{i}",
        sync_interval_seconds=60,
        last_synced_at=None,
        last_sync_error=err,
        last_sync_warning=None,
        is_stale=False,
        credential_state=state,
    )


def test_cap_names_problem_rows_first_even_past_the_cap(monkeypatch) -> None:
    mod = integrations_dash

    monkeypatch.setattr(mod, "_TARGET_LIMIT", 3)
    rows = [_row(i, "ok") for i in range(4)] + [
        _row(10, "rejected"),
        _row(11, "expiring"),
        _row(12, "disabled"),
        _row(13, None, err="boom"),
        _row(14, "expired"),
    ]
    out = [r.id for r in integrations_dash._cap_rows(rows)]
    assert out == ["10", "11", "13", "14"]  # all problems, none healthy, no disabled
    assert [r.id for r in integrations_dash._cap_rows(rows[:4] + [_row(10, "rejected")])] == [
        "10",
        "0",
        "1",
    ]


def test_problem_rows_are_hard_capped_and_counted_in_full(monkeypatch) -> None:
    """200 failing targets must not become a 200-row card (#2192): the rows
    stop at ``_PROBLEM_TARGET_LIMIT`` and the panel counts carry the truth."""
    mod = integrations_dash

    now = datetime(2026, 10, 18, tzinfo=UTC)

    class _T:
        def __init__(self, i: int, err: str | None) -> None:
            self.id = i
            self.name = f"n{i}"
            self.last_synced_at = now
            self.sync_interval_seconds = 60
            self.last_sync_error = err
            self.enabled = True
            self.api_key_expires_at = None

    targets = [_T(i, "boom") for i in range(200)] + [_T(1000 + i, None) for i in range(5)]
    panel = mod._build_panel(
        kind="proxmox",
        label="Proxmox VE",
        enabled=True,
        targets=targets,
        display_attr="name",
        now=now,
    )
    assert len(panel.targets) == mod._PROBLEM_TARGET_LIMIT
    assert all(r.last_sync_error for r in panel.targets)
    assert panel.problem_count == 200
    assert panel.error_count == 200

    rejected = [_T(i, REJECTED) for i in range(60)]
    ts = mod._build_panel(
        kind="tailscale",
        label="Tailscale",
        enabled=True,
        targets=rejected,
        display_attr="name",
        now=now,
        credential=mod._tailscale_credential(now),
    )
    assert len(ts.targets) == mod._PROBLEM_TARGET_LIMIT
    assert ts.credential_dead_count == 60  # not 50: counted before the cap
    assert ts.problem_count == 60
