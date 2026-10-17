"""The rolling-upgrade health gate reads the supervisor's #2007 settle.

Once a node is back on its committed new slot the supervisor settles the
host's stale ``done``/``reboot-pending`` to ``ready``; the gate only knew
``done``, so a settle that landed before the gate's first look timed the
step out on a node that upgraded perfectly. A node that came back on the
slot it did not stage is reported ``failed`` + ``reverted``, which the gate
names as the auto-revert it is.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.upgrades import alerts, per_node

TARGET = "2026.10.03-1"
OLD = "2026.10.02-1"


class _Node:
    def __init__(self, **kw: Any) -> None:
        self.installed_appliance_version: str | None = TARGET
        self.last_upgrade_state: str | None = "ready"
        self.last_upgrade_state_at: datetime | None = datetime.now(UTC)
        self.last_upgrade_progress: dict[str, Any] | None = None
        for k, v in kw.items():
            setattr(self, k, v)


def _db() -> Any:
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_a_settled_ready_on_the_target_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    node = _Node()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_health_gate(
            _db(),
            "node-1",
            TARGET,
            stamped_at=datetime.now(UTC) - timedelta(minutes=5),
            timeout_s=0.5,
        )
    assert step.ok is True, step.error


@pytest.mark.asyncio
async def test_a_reverted_node_is_reported_as_an_auto_revert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    stamped = datetime.now(UTC) - timedelta(minutes=10)
    node = _Node(
        installed_appliance_version=OLD,
        last_upgrade_state="failed",
        last_upgrade_state_at=datetime.now(UTC),
        last_upgrade_progress={"step": "failed", "reverted": True},
    )
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_health_gate(
            _db(), "node-1", TARGET, stamped_at=stamped, timeout_s=0.5
        )
    assert step.ok is False
    assert (
        alerts.classify_per_node_failure(failed_at="health_gate", error=step.error)
        == alerts.CATEGORY_AUTO_REVERTED
    )


@pytest.mark.asyncio
async def test_a_ready_on_the_old_version_does_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    node = _Node(installed_appliance_version=OLD)
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=node)):
        step = await per_node._step_health_gate(
            _db(), "node-1", TARGET, stamped_at=None, timeout_s=0.2
        )
    assert step.ok is False
    assert "timed out" in (step.error or "")
