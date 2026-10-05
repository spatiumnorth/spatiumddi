"""Rolling-upgrade alert wiring tests (#296 Phase F).

Covers:

* ``classify_per_node_failure`` — every Phase C step name maps to a
  category, with the multi-branch health_gate split (supervisor-
  failed vs timeout vs auto-revert vs other).
* ``operator_hint`` — every category gets a non-empty actionable
  string; unknown category falls through to a generic hint.
* ``emit_upgrade_failed_alert`` — happy path (rule present + enabled
  → AlertEvent added with structured detail), refusals (no rule, rule
  disabled).
* Orchestrator failure paths fire the alert (integration with
  ``_drive_loop``'s node-failed + chart_bump-failed branches).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.upgrades import alerts as upgrade_alerts

# ── classify_per_node_failure ────────────────────────────────────────


def test_classify_preflight() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(failed_at="preflight", error="x")
        == upgrade_alerts.CATEGORY_PREFLIGHT
    )


def test_classify_cordon() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(failed_at="cordon", error="kubeapi status 403")
        == upgrade_alerts.CATEGORY_CORDON_FAIL
    )


def test_classify_drain() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="drain", error="drain timed out after 120s — 1 pod(s) still present"
        )
        == upgrade_alerts.CATEGORY_DRAIN_STUCK
    )


def test_classify_verify_primary_moved() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="verify_primary_moved", error="primary still on node-1"
        )
        == upgrade_alerts.CATEGORY_PRIMARY_NOT_MOVED
    )


def test_classify_health_gate_supervisor_failed() -> None:
    """Phase C's explicit ``last_upgrade_state == 'failed'`` branch."""
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="health_gate", error="supervisor reported upgrade failed"
        )
        == upgrade_alerts.CATEGORY_SUPERVISOR_FAILED
    )


def test_classify_health_gate_timeout() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="health_gate", error="health gate timed out after 1800s"
        )
        == upgrade_alerts.CATEGORY_HEALTH_GATE_TIMEOUT
    )


def test_classify_health_gate_auto_reverted() -> None:
    """Reserved category for the explicit auto-revert signal — Phase F
    follow-up will plumb it through the per_node step's error text;
    today nothing fires it, but the classifier handles it when the
    string is present."""
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="health_gate", error="node auto_reverted to old slot"
        )
        == upgrade_alerts.CATEGORY_AUTO_REVERTED
    )


def test_classify_convergence_timeout() -> None:
    """Failure-mode #21 in the issue — node Ready but DS pods didn't
    come up. Category hints at dead-node replacement."""
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="convergence", error="convergence timed out after 900s"
        )
        == upgrade_alerts.CATEGORY_CONVERGENCE_TIMEOUT
    )


def test_classify_uncordon() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="uncordon",
            error="uncordon ok, maintenance-window clear failed: rbac",
        )
        == upgrade_alerts.CATEGORY_UNCORDON_FAIL
    )


def test_classify_chart_bump() -> None:
    """Phase E's post-loop failure path."""
    assert (
        upgrade_alerts.classify_per_node_failure(
            failed_at="chart_bump", error="HelmChartConfig PATCH 403"
        )
        == upgrade_alerts.CATEGORY_CHART_BUMP
    )


def test_classify_unknown_step_falls_to_other() -> None:
    """Unrecognised failed_at falls through to ``other`` so the operator
    looks at the raw message rather than trusting a misleading hint."""
    assert (
        upgrade_alerts.classify_per_node_failure(failed_at="future_new_step", error="something")
        == upgrade_alerts.CATEGORY_OTHER
    )


def test_classify_none_failed_at() -> None:
    assert (
        upgrade_alerts.classify_per_node_failure(failed_at=None, error=None)
        == upgrade_alerts.CATEGORY_OTHER
    )


# ── operator_hint — every category has a hint ────────────────────────


@pytest.mark.parametrize(
    "category",
    [
        upgrade_alerts.CATEGORY_PREFLIGHT,
        upgrade_alerts.CATEGORY_DRAIN_STUCK,
        upgrade_alerts.CATEGORY_CORDON_FAIL,
        upgrade_alerts.CATEGORY_PRIMARY_NOT_MOVED,
        upgrade_alerts.CATEGORY_AUTO_REVERTED,
        upgrade_alerts.CATEGORY_HEALTH_GATE_TIMEOUT,
        upgrade_alerts.CATEGORY_SUPERVISOR_FAILED,
        upgrade_alerts.CATEGORY_CONVERGENCE_TIMEOUT,
        upgrade_alerts.CATEGORY_CHART_BUMP,
        upgrade_alerts.CATEGORY_UNCORDON_FAIL,
        upgrade_alerts.CATEGORY_OTHER,
    ],
)
def test_operator_hint_non_empty(category: str) -> None:
    """Every category must return a non-empty actionable string —
    blank hints get displayed in the alert body + operator UI."""
    hint = upgrade_alerts.operator_hint(category)
    assert hint
    assert len(hint) > 20  # not just a placeholder


def test_operator_hint_unknown_category_falls_to_generic() -> None:
    hint = upgrade_alerts.operator_hint("totally_made_up")
    assert hint
    # Generic hint points at progress.per_node[<node>].error.
    assert "progress" in hint or "per_node" in hint or "Ph9" in hint


def test_operator_hint_dead_node_categories_mention_evict() -> None:
    """The convergence-timeout + health-gate-timeout hints should
    surface the dead-node-replacement flow (#272 Ph9) since that's
    the operator's likely next action."""
    for cat in (
        upgrade_alerts.CATEGORY_CONVERGENCE_TIMEOUT,
        upgrade_alerts.CATEGORY_HEALTH_GATE_TIMEOUT,
    ):
        hint = upgrade_alerts.operator_hint(cat)
        assert "Ph9" in hint or "evict" in hint.lower() or "dead-node" in hint.lower()


# ── emit_upgrade_failed_alert ────────────────────────────────────────


class _FakeRule:
    def __init__(self, *, enabled: bool = True) -> None:
        self.id = uuid.uuid4()
        self.severity = "critical"
        self.enabled = enabled


class _FakeRun:
    def __init__(self) -> None:
        self.id = uuid.uuid4()
        self.target_version = "2026.06.01-1"
        self.last_error = "node node-a failed at step drain: timed out"


@pytest.mark.asyncio
async def test_emit_alert_happy_path() -> None:
    """Rule present + enabled → AlertEvent added with structured
    detail (run_id, category, hint, failed_node, failed_at_step)."""
    rule = _FakeRule()
    run = _FakeRun()
    db = MagicMock()
    db.scalar = AsyncMock(return_value=rule)
    db.add = MagicMock()

    evt = await upgrade_alerts.emit_upgrade_failed_alert(
        db,
        run,  # type: ignore[arg-type]
        failed_node="node-a",
        failed_at_step="drain",
        category=upgrade_alerts.CATEGORY_DRAIN_STUCK,
    )

    assert evt is not None
    db.add.assert_called_once()
    added = db.add.call_args.args[0]
    assert added.rule_id == rule.id
    assert added.subject_type == "system_upgrade_run"
    assert added.subject_id == str(run.id)
    assert added.severity == "critical"
    # Detail blob carries every Phase G surface needs.
    assert added.last_observed_value["category"] == upgrade_alerts.CATEGORY_DRAIN_STUCK
    assert added.last_observed_value["failed_node"] == "node-a"
    assert added.last_observed_value["failed_at_step"] == "drain"
    assert added.last_observed_value["target_version"] == "2026.06.01-1"
    assert "hint" in added.last_observed_value


@pytest.mark.asyncio
async def test_emit_alert_no_rule_returns_none() -> None:
    """A fresh install whose startup hook hasn't fired yet → emit
    returns None instead of crashing the orchestrator's failure
    transition."""
    db = MagicMock()
    db.scalar = AsyncMock(return_value=None)
    db.add = MagicMock()

    out = await upgrade_alerts.emit_upgrade_failed_alert(
        db,
        _FakeRun(),  # type: ignore[arg-type]
        failed_node="node-a",
        failed_at_step="drain",
        category=upgrade_alerts.CATEGORY_DRAIN_STUCK,
    )
    assert out is None
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_emit_alert_disabled_rule_returns_none() -> None:
    """Operator explicitly disabled the rule → respect that, don't
    re-emit + don't try to re-enable it."""
    rule = _FakeRule(enabled=False)
    db = MagicMock()
    db.scalar = AsyncMock(return_value=rule)
    db.add = MagicMock()

    out = await upgrade_alerts.emit_upgrade_failed_alert(
        db,
        _FakeRun(),  # type: ignore[arg-type]
        failed_node="node-a",
        failed_at_step="drain",
        category=upgrade_alerts.CATEGORY_DRAIN_STUCK,
    )
    assert out is None
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_emit_alert_chart_bump_no_node() -> None:
    """Chart-bump failures don't have a failed_node — message + detail
    should reflect that without erroring."""
    rule = _FakeRule()
    db = MagicMock()
    db.scalar = AsyncMock(return_value=rule)
    db.add = MagicMock()

    evt = await upgrade_alerts.emit_upgrade_failed_alert(
        db,
        _FakeRun(),  # type: ignore[arg-type]
        failed_node=None,
        failed_at_step="chart_bump",
        category=upgrade_alerts.CATEGORY_CHART_BUMP,
    )
    assert evt is not None
    added = db.add.call_args.args[0]
    assert added.last_observed_value["failed_node"] is None
    assert added.last_observed_value["failed_at_step"] == "chart_bump"


# ── Orchestrator integration — node + chart_bump failure paths ───────


@pytest.mark.asyncio
async def test_orchestrator_fires_alert_on_node_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When _drive_loop flips state=failed, emit_upgrade_failed_alert
    fires with the categorised failure."""
    import asyncio  # noqa: PLC0415

    from app.services.upgrades import orchestrator, per_node  # noqa: PLC0415

    class _Run:
        def __init__(self) -> None:
            self.id = uuid.uuid4()
            self.state = "running"
            self.target_version = "2026.06.01-1"
            self.last_error: str | None = None
            self.lease_holder = "api-test"
            self.lease_acquired_at = datetime.now(UTC)
            self.started_at = datetime.now(UTC)
            self.finished_at: Any = None
            self.plan: dict[str, Any] = {
                "node_order": ["node-a"],
                "slot_image_url": "x",
            }
            self.progress: dict[str, Any] = {"events": [], "per_node": {}}

    run = _Run()
    db = MagicMock()
    db.get = AsyncMock(return_value=run)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    async def _fail(*args: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        return per_node.SingleNodeResult(
            node_name=kwargs["node_name"],
            target_version="2026.06.01-1",
            ok=False,
            failed_at="drain",
            steps=[],
            error="drain timed out after 120s — 2 pod(s) still present",
        )

    emit_spy = AsyncMock(return_value=None)
    monkeypatch.setattr(per_node, "single_node_upgrade", _fail)
    monkeypatch.setattr(orchestrator.upgrade_alerts, "emit_upgrade_failed_alert", emit_spy)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))

    stop = asyncio.Event()
    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]

    assert run.state == "failed"
    # Classified as drain-stuck + alert emitted with that category.
    emit_spy.assert_awaited_once()
    call_kwargs = emit_spy.call_args.kwargs
    assert call_kwargs["failed_node"] == "node-a"
    assert call_kwargs["failed_at_step"] == "drain"
    assert call_kwargs["category"] == upgrade_alerts.CATEGORY_DRAIN_STUCK
    # Progress per_node entry carries the category for the Fleet UI.
    assert run.progress["per_node"]["node-a"]["failure_category"] == (
        upgrade_alerts.CATEGORY_DRAIN_STUCK
    )


@pytest.mark.asyncio
async def test_orchestrator_fires_alert_on_chart_bump_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chart-bump failure path also fires the alert with chart_bump
    category."""
    import asyncio  # noqa: PLC0415

    from app.services.upgrades import chart_bump, orchestrator  # noqa: PLC0415

    class _Run:
        def __init__(self) -> None:
            self.id = uuid.uuid4()
            self.state = "running"
            self.target_version = "2026.06.01-1"
            self.last_error: str | None = None
            self.lease_holder = "api-test"
            self.lease_acquired_at = datetime.now(UTC)
            self.started_at = datetime.now(UTC)
            self.finished_at: Any = None
            self.plan: dict[str, Any] = {
                "node_order": ["node-a"],
                "slot_image_url": "x",
            }
            # All nodes already complete → loop runs chart_bump branch.
            self.progress: dict[str, Any] = {
                "events": [],
                "per_node": {"node-a": {"ok": True, "failed_at": None, "steps": []}},
            }

    run = _Run()
    db = MagicMock()
    db.get = AsyncMock(return_value=run)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    async def _bad_bump(*args: Any, **kwargs: Any) -> chart_bump.ChartBumpResult:
        return chart_bump.ChartBumpResult(
            ok=False,
            new_tag=args[0],
            chart_name="spatium-control",
            namespace="kube-system",
            started_at="t",
            finished_at="t",
            error="HelmChartConfig PATCH 403",
        )

    emit_spy = AsyncMock(return_value=None)
    monkeypatch.setattr(chart_bump, "bump_chart_image_tag", _bad_bump)
    monkeypatch.setattr(orchestrator.upgrade_alerts, "emit_upgrade_failed_alert", emit_spy)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))

    stop = asyncio.Event()
    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]

    assert run.state == "failed"
    emit_spy.assert_awaited_once()
    call_kwargs = emit_spy.call_args.kwargs
    assert call_kwargs["failed_at_step"] == "chart_bump"
    assert call_kwargs["category"] == upgrade_alerts.CATEGORY_CHART_BUMP
    assert call_kwargs["failed_node"] is None


# ── seed_cluster_upgrade_failed_alert_rule idempotency ───────────────


@pytest.mark.asyncio
async def test_seed_alert_rule_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Second call doesn't re-add the rule (key on name)."""
    from app.models.alerts import AlertRule  # noqa: PLC0415

    class _Session:
        def __init__(self, existing: AlertRule | None) -> None:
            self._existing = existing
            self.added: list[Any] = []
            self.committed = False

        async def scalar(self, *args: Any, **kwargs: Any) -> Any:
            return self._existing

        def add(self, obj: Any) -> None:
            self.added.append(obj)

        async def commit(self) -> None:
            self.committed = True

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

    # First call — no existing rule → adds + commits.
    session1 = _Session(existing=None)
    monkeypatch.setattr(
        "app.db.AsyncSessionLocal",
        lambda: session1,
    )
    await upgrade_alerts.seed_cluster_upgrade_failed_alert_rule()
    assert len(session1.added) == 1
    assert session1.committed is True

    # Second call — rule already exists → no-op.
    existing = MagicMock()
    session2 = _Session(existing=existing)
    monkeypatch.setattr(
        "app.db.AsyncSessionLocal",
        lambda: session2,
    )
    await upgrade_alerts.seed_cluster_upgrade_failed_alert_rule()
    assert session2.added == []
    assert session2.committed is False


@pytest.mark.asyncio
async def test_emit_alert_delivers_to_forward_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1576 — the upgrade-failed event must reach forward targets,
    not just the in-app alerts page."""
    from app.services import alerts as alert_service
    from app.services import audit_forward

    rule = _FakeRule()
    rule.notify_syslog = True  # type: ignore[attr-defined]
    rule.notify_webhook = True  # type: ignore[attr-defined]
    rule.notify_smtp = True  # type: ignore[attr-defined]
    run = _FakeRun()
    db = MagicMock()
    db.scalar = AsyncMock(return_value=rule)
    db.add = MagicMock()
    db.flush = AsyncMock()

    async def _fake_load() -> list[dict]:
        return [{"name": "stub", "kind": "syslog"}]

    seen: dict[str, Any] = {}

    async def _fake_deliver(r: object, event: object, targets: list) -> tuple[bool, bool, bool]:
        seen["targets"] = targets
        return True, False, False

    monkeypatch.setattr(audit_forward, "_load_targets", _fake_load)
    monkeypatch.setattr(alert_service, "_deliver", _fake_deliver)

    evt = await upgrade_alerts.emit_upgrade_failed_alert(
        db,
        run,  # type: ignore[arg-type]
        failed_node="node-a",
        failed_at_step="drain",
        category=upgrade_alerts.CATEGORY_DRAIN_STUCK,
    )
    assert evt is not None
    assert seen["targets"] == [{"name": "stub", "kind": "syslog"}]
    assert evt.delivered_syslog is True
    assert evt.delivered_webhook is False
