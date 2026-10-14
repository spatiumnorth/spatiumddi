"""Post-rolling-upgrade chart bump tests (#296 Phase E).

Covers:

* ``_patch_image_tag`` parse-modify-dump: preserves unrelated keys,
  handles missing ``image`` block, handles malformed YAML, handles
  empty valuesContent.
* ``bump_chart_image_tag`` end-to-end: no-k3s skip, HelmChartConfig
  POST (creates fresh CR), HelmChartConfig PATCH (existing CR with
  preserved supervisor overrides), Deployment rollout poll happy
  path, Deployment rollout timeout, migrate Job success / failure /
  absent.
* ``_wait_for_deployments_rolled`` / ``_wait_for_migrate_job`` edge
  cases.

Orchestrator integration (the post-loop chart_bump call in
``_drive_loop``) is exercised in test_upgrades_orchestrator.py — kept
separate here to keep this file focused on the chart-bump module.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from app.services.upgrades import chart_bump

# ── _patch_image_tag ─────────────────────────────────────────────────


def test_patch_image_tag_empty_values() -> None:
    """An empty HelmChartConfig.valuesContent + a new tag → a single-
    key YAML document with just image.tag."""
    out = chart_bump._patch_image_tag("", "2026.06.01-1")
    doc = yaml.safe_load(out)
    assert doc == {"image": {"tag": "2026.06.01-1"}}


def test_patch_image_tag_preserves_other_keys() -> None:
    """The supervisor's cp-size / VIP overrides must survive the patch.

    The chart_bump module owns only ``image.tag`` — everything else
    in the YAML belongs to the supervisor."""
    existing = "api:\n  replicas: 3\nfrontend:\n  controlPlaneVIP: 192.168.1.10\n"
    out = chart_bump._patch_image_tag(existing, "2026.06.01-1")
    doc = yaml.safe_load(out)
    assert doc["api"] == {"replicas": 3}
    assert doc["frontend"] == {"controlPlaneVIP": "192.168.1.10"}
    assert doc["image"] == {"tag": "2026.06.01-1"}


def test_patch_image_tag_overwrites_existing_tag() -> None:
    """An existing image.tag gets overwritten."""
    existing = "image:\n  tag: 2026.05.22-2\n  registry: ghcr.io\n"
    out = chart_bump._patch_image_tag(existing, "2026.06.01-1")
    doc = yaml.safe_load(out)
    assert doc["image"]["tag"] == "2026.06.01-1"
    # Sibling keys on the image block survive.
    assert doc["image"]["registry"] == "ghcr.io"


def test_patch_image_tag_malformed_yaml_recovers() -> None:
    """A previous operator's hand-edit that left malformed YAML
    shouldn't block the chart bump. We fall back to writing a fresh
    minimal document."""
    out = chart_bump._patch_image_tag("not: valid: yaml: at: all\n  - x", "2026.06.01-1")
    doc = yaml.safe_load(out)
    # Either the parse recovered + image.tag got stamped, or we wrote
    # a fresh document — both shapes have image.tag set.
    assert doc["image"]["tag"] == "2026.06.01-1"


def test_patch_image_tag_image_block_is_not_a_dict() -> None:
    """``image: ghcr.io/foo:bar`` (string scalar instead of mapping)
    is malformed but recoverable — overwrite with a fresh dict."""
    existing = "image: ghcr.io/foo:bar\napi:\n  replicas: 1\n"
    out = chart_bump._patch_image_tag(existing, "2026.06.01-1")
    doc = yaml.safe_load(out)
    assert doc["image"] == {"tag": "2026.06.01-1"}
    # Other keys still preserved.
    assert doc["api"] == {"replicas": 1}


# ── bump_chart_image_tag — top-level branches ────────────────────────


@pytest.mark.asyncio
async def test_bump_skips_on_no_k8s_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ServiceAccount mounted (docker-compose / non-k3s) → skipped
    short-circuit with reason captured + ok=True."""
    monkeypatch.setattr(chart_bump.k8s, "get_config", lambda: None)
    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is True
    assert result.skipped is True
    assert "ServiceAccount" in (result.skip_reason or "")


@pytest.mark.asyncio
async def test_bump_creates_helmchartconfig_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """404 on the GET → upsert creates the CR with the new image.tag."""
    monkeypatch.setattr(chart_bump.k8s, "get_config", MagicMock)
    monkeypatch.setattr(
        chart_bump.k8s, "get_helmchartconfig", lambda _name, namespace="kube-system": (404, None)
    )
    upsert_called = MagicMock(return_value=(True, None))
    monkeypatch.setattr(chart_bump.k8s, "upsert_helmchartconfig", upsert_called)

    # Make the rollout poll succeed immediately.
    async def _ok_deploys(*args: Any, **kwargs: Any) -> Any:
        return True, ["api"], None

    async def _ok_job(*args: Any, **kwargs: Any) -> Any:
        return True, "succeeded", None

    monkeypatch.setattr(chart_bump, "_wait_for_deployments_rolled", _ok_deploys)
    monkeypatch.setattr(chart_bump, "_wait_for_migrate_job", _ok_job)

    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is True
    upsert_called.assert_called_once()
    # The new valuesContent carries image.tag — the supervisor's
    # parse-modify path inside _patch_image_tag was exercised.
    _name, values, *_ = upsert_called.call_args.args
    assert "tag: 2026.06.01-1" in values


@pytest.mark.asyncio
async def test_bump_patches_existing_helmchartconfig(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """200 on GET with existing valuesContent → patch preserves other
    keys + stamps image.tag."""
    monkeypatch.setattr(chart_bump.k8s, "get_config", MagicMock)
    existing_body = {
        "spec": {"valuesContent": "api:\n  replicas: 3\nimage:\n  tag: 2026.05.22-2\n"}
    }
    monkeypatch.setattr(
        chart_bump.k8s,
        "get_helmchartconfig",
        lambda _name, namespace="kube-system": (200, existing_body),
    )
    upsert_called = MagicMock(return_value=(True, None))
    monkeypatch.setattr(chart_bump.k8s, "upsert_helmchartconfig", upsert_called)

    async def _ok_deploys(*args: Any, **kwargs: Any) -> Any:
        return True, ["api"], None

    async def _ok_job(*args: Any, **kwargs: Any) -> Any:
        return True, "succeeded", None

    monkeypatch.setattr(chart_bump, "_wait_for_deployments_rolled", _ok_deploys)
    monkeypatch.setattr(chart_bump, "_wait_for_migrate_job", _ok_job)

    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is True
    _name, new_values, *_ = upsert_called.call_args.args
    doc = yaml.safe_load(new_values)
    assert doc["image"]["tag"] == "2026.06.01-1"
    assert doc["api"] == {"replicas": 3}


@pytest.mark.asyncio
async def test_bump_fails_on_upsert_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chart_bump.k8s, "get_config", MagicMock)
    monkeypatch.setattr(
        chart_bump.k8s, "get_helmchartconfig", lambda _name, namespace="kube-system": (404, None)
    )
    monkeypatch.setattr(
        chart_bump.k8s,
        "upsert_helmchartconfig",
        MagicMock(return_value=(False, "rbac forbidden")),
    )
    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is False
    assert "rbac forbidden" in (result.error or "")


@pytest.mark.asyncio
async def test_bump_fails_on_deployment_rollout_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(chart_bump.k8s, "get_config", MagicMock)
    monkeypatch.setattr(
        chart_bump.k8s, "get_helmchartconfig", lambda _name, namespace="kube-system": (404, None)
    )
    monkeypatch.setattr(
        chart_bump.k8s, "upsert_helmchartconfig", MagicMock(return_value=(True, None))
    )

    async def _stuck(*args: Any, **kwargs: Any) -> Any:
        return False, [], "timed out waiting for: api, worker"

    monkeypatch.setattr(chart_bump, "_wait_for_deployments_rolled", _stuck)
    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is False
    assert "timed out" in (result.error or "")


@pytest.mark.asyncio
async def test_bump_fails_on_migrate_job_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deployments rolled fine but migrate Job exited non-zero → fail."""
    monkeypatch.setattr(chart_bump.k8s, "get_config", MagicMock)
    monkeypatch.setattr(
        chart_bump.k8s, "get_helmchartconfig", lambda _name, namespace="kube-system": (404, None)
    )
    monkeypatch.setattr(
        chart_bump.k8s, "upsert_helmchartconfig", MagicMock(return_value=(True, None))
    )

    async def _ok_deploys(*args: Any, **kwargs: Any) -> Any:
        return True, ["api", "worker"], None

    async def _failed_job(*args: Any, **kwargs: Any) -> Any:
        return False, "failed", "migrate Job failed"

    monkeypatch.setattr(chart_bump, "_wait_for_deployments_rolled", _ok_deploys)
    monkeypatch.setattr(chart_bump, "_wait_for_migrate_job", _failed_job)
    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is False
    assert result.migrate_job_state == "failed"
    assert "migrate Job failed" in (result.error or "")


@pytest.mark.asyncio
async def test_bump_treats_absent_migrate_job_as_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Helm pre-upgrade hooks GC the Job after success. ``absent`` is
    a clean signal not a failure."""
    monkeypatch.setattr(chart_bump.k8s, "get_config", MagicMock)
    monkeypatch.setattr(
        chart_bump.k8s, "get_helmchartconfig", lambda _name, namespace="kube-system": (404, None)
    )
    monkeypatch.setattr(
        chart_bump.k8s, "upsert_helmchartconfig", MagicMock(return_value=(True, None))
    )

    async def _ok_deploys(*args: Any, **kwargs: Any) -> Any:
        return True, ["api"], None

    async def _absent_job(*args: Any, **kwargs: Any) -> Any:
        return True, "absent", None

    monkeypatch.setattr(chart_bump, "_wait_for_deployments_rolled", _ok_deploys)
    monkeypatch.setattr(chart_bump, "_wait_for_migrate_job", _absent_job)
    result = await chart_bump.bump_chart_image_tag("2026.06.01-1")
    assert result.ok is True
    assert result.migrate_job_state == "absent"


# ── _wait_for_deployments_rolled edge cases ──────────────────────────


@pytest.mark.asyncio
async def test_wait_deployments_404_treated_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Deployment that doesn't exist (operator customised chart to
    drop it) drops out of the remaining-set rather than tripping
    the timeout."""
    monkeypatch.setattr(chart_bump.k8s, "get_deployment", lambda _name, namespace=None: (404, None))
    monkeypatch.setattr(chart_bump, "_POLL_INTERVAL_S", 0.0)
    ok, rolled, err = await chart_bump._wait_for_deployments_rolled(
        ["api", "worker"],
        "spatium",
        new_tag="2026.06.01-1",
        stop_after_monotonic=time.monotonic() + 5.0,
    )
    assert ok is True
    assert rolled == []
    assert err is None


@pytest.mark.asyncio
async def test_wait_deployments_polls_until_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two polls: first NotReady, second Ready → exits cleanly with
    the name in ``rolled``. Both read the new template (#1829: only a
    template on the new tag counts)."""

    template = {"spec": {"containers": [{"image": "ghcr.io/x/spatiumddi-api:2026.06.01-1"}]}}
    poll_count = 0

    def _get_dep(_name: str, namespace: str | None = None) -> Any:
        nonlocal poll_count
        poll_count += 1
        if poll_count == 1:
            return (
                200,
                {
                    "metadata": {"generation": 5},
                    "spec": {"replicas": 2, "template": template},
                    "status": {
                        "observedGeneration": 4,
                        "updatedReplicas": 1,
                        "availableReplicas": 1,
                    },
                },
            )
        return (
            200,
            {
                "metadata": {"generation": 5},
                "spec": {"replicas": 2, "template": template},
                "status": {
                    "observedGeneration": 5,
                    "updatedReplicas": 2,
                    "availableReplicas": 2,
                },
            },
        )

    monkeypatch.setattr(chart_bump.k8s, "get_deployment", _get_dep)
    monkeypatch.setattr(chart_bump, "_POLL_INTERVAL_S", 0.0)
    ok, rolled, err = await chart_bump._wait_for_deployments_rolled(
        ["api"],
        "spatium",
        new_tag="2026.06.01-1",
        stop_after_monotonic=time.monotonic() + 5.0,
    )
    assert ok is True
    assert rolled == ["api"]
    assert err is None


# ── _wait_for_migrate_job edge cases ─────────────────────────────────


@pytest.mark.asyncio
async def test_wait_migrate_job_404_is_absent_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chart_bump.k8s, "get_job", lambda _name, namespace=None: (404, None))
    ok, state, err = await chart_bump._wait_for_migrate_job(
        "migrate-job", "spatium", stop_after_monotonic=time.monotonic() + 5.0
    )
    assert ok is True
    assert state == "absent"


@pytest.mark.asyncio
async def test_wait_migrate_job_succeeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        chart_bump.k8s,
        "get_job",
        lambda _name, namespace=None: (
            200,
            {"status": {"succeeded": 1}},
        ),
    )
    monkeypatch.setattr(chart_bump, "_POLL_INTERVAL_S", 0.0)
    ok, state, err = await chart_bump._wait_for_migrate_job(
        "migrate-job", "spatium", stop_after_monotonic=time.monotonic() + 5.0
    )
    assert ok is True
    assert state == "succeeded"


@pytest.mark.asyncio
async def test_wait_migrate_job_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        chart_bump.k8s,
        "get_job",
        lambda _name, namespace=None: (
            200,
            {"status": {"failed": 1}},
        ),
    )
    monkeypatch.setattr(chart_bump, "_POLL_INTERVAL_S", 0.0)
    ok, state, err = await chart_bump._wait_for_migrate_job(
        "migrate-job", "spatium", stop_after_monotonic=time.monotonic() + 5.0
    )
    assert ok is False
    assert state == "failed"


# ── result_to_dict ───────────────────────────────────────────────────


def test_result_to_dict_includes_every_field() -> None:
    """The orchestrator stamps this dict into ``run.progress.chart_bump``.
    Pin the shape so a Fleet UI consumer (Phase G) sees stable keys."""
    r = chart_bump.ChartBumpResult(
        ok=False,
        new_tag="2026.06.01-1",
        chart_name="spatium-control",
        namespace="kube-system",
        started_at="2026-05-23T12:00:00Z",
        finished_at="2026-05-23T12:30:00Z",
        rolled_deployments=["api"],
        migrate_job_state="failed",
        error="migrate Job failed",
    )
    d = chart_bump.result_to_dict(r)
    assert set(d) == {
        "ok",
        "new_tag",
        "chart_name",
        "namespace",
        "started_at",
        "finished_at",
        "rolled_deployments",
        "migrate_job_state",
        "error",
        "skipped",
        "skip_reason",
    }
    assert d["ok"] is False
    assert d["migrate_job_state"] == "failed"


# ── Orchestrator integration — post-loop chart_bump branches ─────────


@pytest.mark.asyncio
async def test_orchestrator_calls_chart_bump_after_all_nodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The post-loop branch in ``_drive_loop`` runs chart_bump when
    every node is complete + flips state to succeeded on success."""
    import asyncio  # noqa: PLC0415
    import uuid  # noqa: PLC0415
    from datetime import UTC, datetime  # noqa: PLC0415

    from app.services.upgrades import orchestrator  # noqa: PLC0415

    class _FakeRun:
        def __init__(self) -> None:
            self.id = uuid.uuid4()
            self.state = "running"
            self.target_version = "2026.06.01-1"
            self.last_error: str | None = None
            self.lease_holder: str | None = None
            self.lease_acquired_at: Any = None
            self.started_at = datetime.now(UTC)
            self.finished_at: Any = None
            self.plan: dict[str, Any] = {
                # All nodes already in completed_nodes → loop goes to
                # the chart-bump branch immediately.
                "node_order": ["node-a"],
                "slot_image_url": "http://mirror/x",
            }
            self.progress: dict[str, Any] = {
                "events": [],
                "per_node": {"node-a": {"ok": True, "failed_at": None, "steps": []}},
            }

    run = _FakeRun()
    db = MagicMock()
    db.get = AsyncMock(return_value=run)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    async def _ok_bump(*args: Any, **kwargs: Any) -> chart_bump.ChartBumpResult:
        return chart_bump.ChartBumpResult(
            ok=True,
            new_tag=args[0],
            chart_name="spatium-control",
            namespace="kube-system",
            started_at="t",
            finished_at="t",
            rolled_deployments=["api"],
            migrate_job_state="succeeded",
        )

    monkeypatch.setattr(orchestrator.chart_bump, "bump_chart_image_tag", _ok_bump)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))

    stop = asyncio.Event()
    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    assert run.state == "succeeded"
    assert run.progress["chart_bump"]["ok"] is True
    assert run.progress["chart_bump"]["rolled_deployments"] == ["api"]


@pytest.mark.asyncio
async def test_orchestrator_flips_to_failed_on_chart_bump_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """chart_bump returns ok=False → orchestrator state=failed +
    last_error set."""
    import asyncio  # noqa: PLC0415
    import uuid  # noqa: PLC0415
    from datetime import UTC, datetime  # noqa: PLC0415

    from app.services.upgrades import orchestrator  # noqa: PLC0415

    class _FakeRun:
        def __init__(self) -> None:
            self.id = uuid.uuid4()
            self.state = "running"
            self.target_version = "2026.06.01-1"
            self.last_error: str | None = None
            self.lease_holder: str | None = None
            self.lease_acquired_at: Any = None
            self.started_at = datetime.now(UTC)
            self.finished_at: Any = None
            self.plan: dict[str, Any] = {"node_order": ["node-a"], "slot_image_url": "x"}
            self.progress: dict[str, Any] = {
                "events": [],
                "per_node": {"node-a": {"ok": True, "failed_at": None, "steps": []}},
            }

    run = _FakeRun()
    db = MagicMock()
    db.get = AsyncMock(return_value=run)
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    async def _failed_bump(*args: Any, **kwargs: Any) -> chart_bump.ChartBumpResult:
        return chart_bump.ChartBumpResult(
            ok=False,
            new_tag=args[0],
            chart_name="spatium-control",
            namespace="kube-system",
            started_at="t",
            finished_at="t",
            error="HelmChartConfig PATCH 403",
        )

    monkeypatch.setattr(orchestrator.chart_bump, "bump_chart_image_tag", _failed_bump)
    monkeypatch.setattr(orchestrator.mutex, "release", lambda **_kw: (True, None))
    # Phase F — short-circuit the alert emit path (its async db.scalar
    # call doesn't have an AsyncMock fake here; the alert wiring has
    # its own dedicated tests in test_upgrades_alerts.py).
    monkeypatch.setattr(
        orchestrator.upgrade_alerts,
        "emit_upgrade_failed_alert",
        AsyncMock(return_value=None),
    )

    stop = asyncio.Event()
    await orchestrator._drive_loop(db, run, stop)  # type: ignore[arg-type]
    assert run.state == "failed"
    assert "chart bump" in (run.last_error or "")
    assert run.progress["chart_bump"]["ok"] is False
