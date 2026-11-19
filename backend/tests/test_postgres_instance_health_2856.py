"""#2856 — a PostgreSQL standby that is not streaming reads healthy.

In a three-node failover drill a standby was not Ready for 12 minutes and
standbys looped on removed WAL for more than 10, while CNPG reported
"Cluster in healthy state" 3/3 (its readiness probe passes for a standby
that is up but not replicating). The Cluster → Overview database row read
healthy throughout and no alert fired.

Now the row carries one entry per instance and reads degraded when an
instance is not Ready, a standby has no streaming WAL sender on the primary
(``pg_stat_replication``), or a supervisor reports it looping / stuck; and
the ``postgres_instance_unhealthy`` rule opens after 5 minutes, escalates at
15 and resolves on recovery.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.services import alerts as alerts_svc
from app.services.appliance import cluster_health
from app.services.appliance import postgres_instances as pgi

CLUSTER = "spatium-control-spatiumddi-postgresql"
PG1, PG2, PG3 = (f"{CLUSTER}-{i}" for i in (1, 2, 3))


# ── kube-shaped fixtures ────────────────────────────────────────────────────


def _node(name: str) -> dict[str, Any]:
    return {
        "metadata": {"name": name, "labels": {"node-role.kubernetes.io/control-plane": "true"}},
        "spec": {},
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "nodeInfo": {},
            "capacity": {"cpu": "4", "memory": "8Gi", "pods": "110"},
        },
    }


def _pg_pod(
    name: str,
    node: str,
    *,
    ready: bool = True,
    role: str = "replica",
    ready_since: str = "2026-10-26T21:00:00Z",
) -> dict[str, Any]:
    return {
        "metadata": {
            "name": name,
            "namespace": "spatium",
            "labels": {
                "app.kubernetes.io/component": "database",
                "cnpg.io/cluster": CLUSTER,
                "cnpg.io/instanceRole": role,
            },
            "ownerReferences": [{"kind": "Cluster"}],
        },
        "spec": {"nodeName": node},
        "status": {
            "phase": "Running",
            "conditions": [
                {
                    "type": "Ready",
                    "status": "True" if ready else "False",
                    "lastTransitionTime": ready_since,
                }
            ],
            "containerStatuses": [{"ready": ready, "restartCount": 0, "state": {"running": {}}}],
        },
    }


def _patch_kube(
    monkeypatch: pytest.MonkeyPatch,
    pods: list[dict[str, Any]],
    *,
    wanted: int,
    ready: int,
    primary: str = PG1,
    target: str | None = None,
) -> None:
    nodes = sorted({p["spec"]["nodeName"] for p in pods}) or ["d2-cp1"]
    monkeypatch.setattr(
        "app.services.appliance.k8s.list_nodes",
        lambda label_selector=None: (200, [_node(n) for n in nodes]),
    )
    monkeypatch.setattr("app.services.appliance.k8s.list_all_pods", lambda: (200, pods))
    monkeypatch.setattr(
        "app.services.appliance.k8s.get_node_stats_summary",
        lambda name, node_ip=None: (403, None, "direct"),
    )
    body = {
        "spec": {"instances": wanted},
        "status": {
            "readyInstances": ready,
            "currentPrimary": primary,
            "targetPrimary": target or primary,
        },
    }
    monkeypatch.setattr(
        "app.services.appliance.k8s.get_cnpg_cluster",
        lambda name, namespace=None: (200, body),
    )


def _three(**ready: bool) -> list[dict[str, Any]]:
    return [
        _pg_pod(PG1, "d2-cp1", role="primary", ready=ready.get("pg1", True)),
        _pg_pod(PG2, "d2-cp2", ready=ready.get("pg2", True)),
        _pg_pod(PG3, "d2-cp3", ready=ready.get("pg3", True)),
    ]


def _db_row(snap: dict[str, Any]) -> dict[str, Any]:
    return next(w for w in snap["workloads"] if w["component"] == "database")


def _all_streaming() -> dict[str, str | None]:
    return {PG2: "streaming", PG3: "streaming"}


# ── cluster health: the database row ───────────────────────────────────────


def test_healthy_three_node_cluster_reads_healthy(monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    row = _db_row(cluster_health.get_cluster_health())
    pgi.apply(row, _all_streaming())
    assert row["status"] == "healthy"
    assert row["findings"] == []
    assert [(i["name"], i["role"], i["node"]) for i in row["instances"]] == [
        (PG1, "primary", "d2-cp1"),
        (PG2, "standby", "d2-cp2"),
        (PG3, "standby", "d2-cp3"),
    ]
    assert [i["streaming"] for i in row["instances"]] == [None, True, True]


def test_ready_standby_with_no_wal_sender_reads_degraded(monkeypatch) -> None:
    """The #2856 case: CNPG says 3/3 ready, the standby is looping on removed
    WAL, so the primary has no WAL sender for it."""
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    row = _db_row(cluster_health.get_cluster_health())
    assert row["status"] == "healthy"  # kube alone cannot see it
    pgi.apply(row, {PG3: "streaming"})
    assert row["status"] == "degraded"
    assert [(f["instance"], f["node"], f["kind"]) for f in row["findings"]] == [
        (PG2, "d2-cp2", pgi.KIND_NOT_STREAMING)
    ]
    assert PG1 in row["findings"][0]["detail"]


def test_not_ready_instance_reads_degraded_from_kube_alone(monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(pg2=False), wanted=3, ready=2)
    row = _db_row(cluster_health.get_cluster_health())
    assert row["status"] == "degraded"
    assert [(f["instance"], f["kind"], f["since"]) for f in row["findings"]] == [
        (PG2, pgi.KIND_NOT_READY, "2026-10-26T21:00:00Z")
    ]


def test_visible_non_streaming_state_is_degraded_hidden_state_is_not(monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    row = _db_row(cluster_health.get_cluster_health())
    pgi.apply(row, {PG2: "catchup", PG3: None})
    assert [(f["instance"], f["kind"]) for f in row["findings"]] == [(PG2, pgi.KIND_NOT_STREAMING)]
    assert "catchup" in row["findings"][0]["detail"]
    # Connected, but state hidden from the app's role: unverified, not broken.
    pg3 = next(i for i in row["instances"] if i["name"] == PG3)
    assert pg3["streaming"] is None


def test_supervisor_verdict_degrades_the_row(monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    row = _db_row(cluster_health.get_cluster_health())
    pgi.apply(row, _all_streaming(), {PG3: {"verdict": "stuck", "detail": None, "since": None}})
    assert row["status"] == "degraded"
    assert [(f["instance"], f["kind"]) for f in row["findings"]] == [(PG3, pgi.KIND_SUPERVISOR)]


def test_unknown_replication_is_not_a_finding(monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    row = _db_row(cluster_health.get_cluster_health())
    pgi.apply(row, None)
    assert row["status"] == "healthy" and row["findings"] == []
    assert row["replication_checked"] is False


def test_no_streaming_verdict_mid_switchover(monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3, target=PG2)
    row = _db_row(cluster_health.get_cluster_health())
    pgi.apply(row, {})
    assert row["findings"] == []


def test_single_node_reads_healthy(monkeypatch) -> None:
    _patch_kube(monkeypatch, [_pg_pod(PG1, "d2-cp1", role="primary")], wanted=1, ready=1)
    row = _db_row(cluster_health.get_cluster_health())
    pgi.apply(row, {})
    assert row["status"] == "healthy" and row["findings"] == []


async def test_endpoint_reads_degraded_for_a_standby_not_streaming(
    db_session: AsyncSession, monkeypatch
) -> None:
    from app.api.v1.appliance import cluster as cluster_router

    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)

    async def _walsenders(db):  # type: ignore[no-untyped-def]
        return {PG2: None}

    monkeypatch.setattr(pgi, "read_walsenders", _walsenders)
    out = await cluster_router.cluster_health(db=db_session)
    db = next(w for w in out.workloads if w.component == "database")
    assert db.status == "degraded"
    assert db.findings is not None
    assert [(f.instance, f.node, f.kind) for f in db.findings] == [
        (PG3, "d2-cp3", pgi.KIND_NOT_STREAMING)
    ]
    assert db.replication_checked is True


async def test_read_walsenders_on_a_primary_without_standbys(db_session: AsyncSession) -> None:
    """The real query: the test database is a primary with no standbys."""
    assert await pgi.read_walsenders(db_session) == {}


# ── the alert ──────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.data: dict[str, datetime] = {}

    async def load(self) -> dict[str, datetime]:
        return dict(self.data)

    async def save(self, clocks: dict[str, datetime]) -> None:
        self.data = dict(clocks)


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


def _alert_env(
    monkeypatch: pytest.MonkeyPatch, walsenders: dict[str, Any], clock: _Clock
) -> dict[str, Any]:
    state: dict[str, Any] = {"walsenders": walsenders}

    async def _snapshot() -> dict[str, Any]:
        return cluster_health.get_cluster_health()

    async def _ws(db):  # type: ignore[no-untyped-def]
        return state["walsenders"]

    monkeypatch.setattr(alerts_svc, "_cluster_health_snapshot", _snapshot)
    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    monkeypatch.setattr(pgi, "read_walsenders", _ws)
    monkeypatch.setattr(pgi, "load_unhealthy_since", clock.load)
    monkeypatch.setattr(pgi, "save_unhealthy_since", clock.save)
    return state


def _rule() -> AlertRule:
    return AlertRule(
        name="PostgreSQL instance (test)",
        rule_type=alerts_svc.RULE_TYPE_POSTGRES_INSTANCE_UNHEALTHY,
        severity="warning",
        enabled=True,
    )


async def _events(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


async def test_alert_opens_after_threshold_escalates_and_resolves(
    db_session: AsyncSession, monkeypatch
) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    clock = _Clock()
    env = _alert_env(monkeypatch, {PG3: "streaming"}, clock)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()

    # Just started: under the 5-minute threshold, nothing opens, the clock starts.
    await alerts_svc.evaluate_all(db_session)
    assert await _events(db_session, rule) == []
    assert set(clock.data) == {PG2}

    # Held 6 minutes → warning, naming the instance and its node.
    clock.data[PG2] = datetime.now(UTC) - timedelta(minutes=6)
    await alerts_svc.evaluate_all(db_session)
    events = await _events(db_session, rule)
    assert [(e.subject_type, e.subject_id, e.severity) for e in events] == [
        ("postgres_instance", PG2, "warning")
    ]
    assert PG2 in events[0].message and "d2-cp2" in events[0].message

    # Held 16 minutes → critical.
    clock.data[PG2] = datetime.now(UTC) - timedelta(minutes=16)
    await alerts_svc.evaluate_all(db_session)
    events = await _events(db_session, rule)
    assert len(events) == 1 and events[0].severity == "critical"

    # Streams again → resolves, and the clock is dropped.
    env["walsenders"] = _all_streaming()
    await alerts_svc.evaluate_all(db_session)
    assert await _events(db_session, rule) == []
    assert clock.data == {}


async def test_not_ready_uses_the_pods_own_transition_time(
    db_session: AsyncSession, monkeypatch
) -> None:
    long_ago = (datetime.now(UTC) - timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    pods = _three()
    pods[1] = _pg_pod(PG2, "d2-cp2", ready=False, ready_since=long_ago)
    _patch_kube(monkeypatch, pods, wanted=3, ready=2)
    _alert_env(monkeypatch, {PG3: "streaming"}, _Clock())
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()

    await alerts_svc.evaluate_all(db_session)
    events = await _events(db_session, rule)
    assert [(e.subject_id, e.severity) for e in events] == [(PG2, "warning")]
    assert "not Ready" in events[0].message


async def test_healthy_cluster_fires_nothing(db_session: AsyncSession, monkeypatch) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    clock = _Clock()
    _alert_env(monkeypatch, _all_streaming(), clock)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert await _events(db_session, rule) == []
    assert clock.data == {}


async def test_single_node_appliance_fires_nothing(db_session: AsyncSession, monkeypatch) -> None:
    _patch_kube(monkeypatch, [_pg_pod(PG1, "d2-cp1", role="primary")], wanted=1, ready=1)
    clock = _Clock()
    # No standbys: the primary's view is empty, which must not read as a fault.
    _alert_env(monkeypatch, {}, clock)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert await _events(db_session, rule) == []


async def test_unreadable_replication_holds_an_open_event(
    db_session: AsyncSession, monkeypatch
) -> None:
    _patch_kube(monkeypatch, _three(), wanted=3, ready=3)
    clock = _Clock()
    clock.data[PG2] = datetime.now(UTC) - timedelta(minutes=6)
    env = _alert_env(monkeypatch, {PG3: "streaming"}, clock)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    await alerts_svc.evaluate_all(db_session)
    assert len(await _events(db_session, rule)) == 1

    env["walsenders"] = None  # the primary could not be queried
    await alerts_svc.evaluate_all(db_session)
    assert len(await _events(db_session, rule)) == 1


async def test_off_appliance_the_rule_is_inert(db_session: AsyncSession, monkeypatch) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "appliance_mode", False)
    rule = _rule()
    db_session.add(rule)
    await db_session.commit()
    assert (
        await alerts_svc._matching_postgres_instance_subjects(  # noqa: SLF001
            db_session, rule, datetime.now(UTC)
        )
        == []
    )


async def test_seed_creates_one_enabled_rule(db_session: AsyncSession) -> None:
    await alerts_svc.seed_postgres_instance_alert_rule()
    await alerts_svc.seed_postgres_instance_alert_rule()  # idempotent
    rules = (
        (
            await db_session.execute(
                select(AlertRule).where(
                    AlertRule.rule_type == alerts_svc.RULE_TYPE_POSTGRES_INSTANCE_UNHEALTHY
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rules) == 1 and rules[0].enabled is True
