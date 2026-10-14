"""#1710, #1427 — during a rolling upgrade, a node already on the target leaves
the shared role chart alone until every node runs it.

The ``spatiumddi-appliance`` HelmChart is one chart for the whole cluster, and
the image tag it carries is the writer's own slot's. Every agent pod is
``imagePullPolicy: Never``. On ddi-pg's three-node roll, member-1's supervisor
wrote the chart from its new slot the moment it came back: dhcp-kea and
dns-bind9 rolled onto the target on the seed and member-2 too, which did not
have its images (ErrImageNeverPull), and served no DNS or DHCP until each of
them was upgraded in turn.

The contract: while the control plane says a rolling upgrade holds the shared
charts (the heartbeat's ``shared_chart_hold``, kept beside the role env), a
node whose installed version is already the target writes nothing; the nodes
still on the old slot write the chart as before, with the old tag. Once the
hold ends, the upgraded node writes it, with the new tag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state, service_lifecycle

from .test_role_chart_keeps_other_nodes_agents import (
    MEMBER_1,
    NO_ROLES,
    SEED_ROLES,
    Cluster,
    _apply,
    _member,
    _seed,
)

FROM = "2026.10.13-1"
TO = "2026.10.14-1"
HOLD = {"run_id": "6f1c6c1e-0000-4000-8000-000000000001", "from_tag": FROM, "target_version": TO}


def _installed(monkeypatch: pytest.MonkeyPatch, version: str) -> None:
    """The host's installed version (/etc/spatiumddi-host/appliance-release)."""
    monkeypatch.setattr(appliance_state, "read_installed_version", lambda: version)


def _hold_file(tmp_path: Path) -> Path:
    return tmp_path / "shared-chart-hold"


def test_under_a_hold_only_the_nodes_still_on_the_old_slot_write_the_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cluster = Cluster()
    _seed(monkeypatch, cluster, release=FROM)
    _installed(monkeypatch, FROM)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    assert cluster.chart()["global"]["imageTag"] == FROM
    _hold_file(tmp_path).write_text(json.dumps(HOLD))

    # member-1 has booted the target slot: its first heartbeat must not move
    # the agents of every node onto images only it has.
    _member(monkeypatch, cluster, name=MEMBER_1, release=TO)
    _installed(monkeypatch, TO)
    writes = len(cluster.writes)
    result = _apply(tmp_path, NO_ROLES)
    assert len(cluster.writes) == writes
    assert cluster.chart()["global"]["imageTag"] == FROM
    assert result.deferred
    assert result.state != "failed"

    # The seed, still on the old slot, keeps writing (and healing) the chart,
    # with the old tag.
    _seed(monkeypatch, cluster, release=FROM)
    _installed(monkeypatch, FROM)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    assert len(cluster.writes) == writes + 1
    assert cluster.chart()["global"]["imageTag"] == FROM


def test_once_the_hold_ends_the_upgraded_node_writes_the_new_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cluster = Cluster()
    _seed(monkeypatch, cluster, release=FROM)
    _installed(monkeypatch, FROM)
    _apply(tmp_path, SEED_ROLES)
    _hold_file(tmp_path).write_text(json.dumps(HOLD))
    _member(monkeypatch, cluster, name=MEMBER_1, release=TO)
    _installed(monkeypatch, TO)
    assert _apply(tmp_path, NO_ROLES).deferred

    # The run's flip: the next heartbeat carries no hold.
    service_lifecycle.record_shared_chart_hold(tmp_path / "role-compose.env", None)

    result = _apply(tmp_path, NO_ROLES)
    assert result.state == "ready"
    assert not result.deferred
    assert cluster.chart()["global"]["imageTag"] == TO


def test_a_hold_for_another_target_does_not_stop_a_node(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Only a node on the hold's target is held back: a node that is not (an
    old hold record, a node rolled back) writes as before."""
    cluster = Cluster()
    _seed(monkeypatch, cluster, release=FROM)
    _installed(monkeypatch, FROM)
    _hold_file(tmp_path).write_text(json.dumps({**HOLD, "target_version": "2026.10.15-1"}))
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    assert cluster.chart()["global"]["imageTag"] == FROM


def test_the_heartbeats_hold_is_kept_and_cleared_beside_the_role_env(tmp_path: Path) -> None:
    env_file = tmp_path / "role-compose.env"

    service_lifecycle.record_shared_chart_hold(env_file, HOLD)
    assert json.loads(_hold_file(tmp_path).read_text()) == HOLD
    assert service_lifecycle.read_shared_chart_hold(env_file) == HOLD

    # A control plane from before the hold sends nothing: no hold.
    service_lifecycle.record_shared_chart_hold(env_file, None)
    assert not _hold_file(tmp_path).exists()
    assert service_lifecycle.read_shared_chart_hold(env_file) is None
    # Nor is a malformed one a hold.
    service_lifecycle.record_shared_chart_hold(env_file, {"from_tag": FROM})
    assert service_lifecycle.read_shared_chart_hold(env_file) is None
