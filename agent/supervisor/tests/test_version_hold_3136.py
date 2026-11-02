"""#3136 — a hold with no Rolling Upgrade behind it: a cluster upgraded node by
node from Fleet, its members on different versions.

The control plane names, for each node, the version it runs (or, before its
reboot, the one Fleet scheduled it onto), and the supervisor's rule is the
rolling upgrade's: a node already on the hold's target writes nothing to the
shared role chart. The hold is kept beside the role env, so it already stops
the first pass on the new slot, before any heartbeat has been answered there.
What changes is what the node says: no run holds the chart, so the reason must
not send the operator looking for one.
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

FROM = "2026.10.30-1"
TO = "2026.10.31-1"
HOLD = {"run_id": "", "from_tag": FROM, "target_version": TO}


def _installed(monkeypatch: pytest.MonkeyPatch, version: str) -> None:
    """The host's installed version (/etc/spatiumddi-host/appliance-release)."""
    monkeypatch.setattr(appliance_state, "read_installed_version", lambda: version)


def test_a_node_on_a_newer_version_than_the_others_defers_and_says_why(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cluster = Cluster()
    _seed(monkeypatch, cluster, release=FROM)
    _installed(monkeypatch, FROM)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    service_lifecycle.record_shared_chart_hold(tmp_path / "role-compose.env", HOLD)

    _member(monkeypatch, cluster, name=MEMBER_1, release=TO)
    _installed(monkeypatch, TO)
    writes = len(cluster.writes)
    result = _apply(tmp_path, NO_ROLES)

    assert result.deferred
    assert len(cluster.writes) == writes
    assert cluster.chart()["global"]["imageTag"] == FROM
    reason = result.reason or ""
    assert "rolling upgrade" not in reason
    assert TO in reason and FROM in reason


def test_the_hold_kept_before_the_reboot_stops_the_first_pass_on_the_new_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fleet scheduled member-1 onto TO: the heartbeat that fired the upgrade
    carried the hold, and the node kept it. Its first pass after booting TO
    comes before any reply there, and must already leave the chart alone."""
    cluster = Cluster()
    _seed(monkeypatch, cluster, release=FROM)
    _installed(monkeypatch, FROM)
    _apply(tmp_path, SEED_ROLES)
    service_lifecycle.record_shared_chart_hold(tmp_path / "role-compose.env", HOLD)
    assert json.loads((tmp_path / "shared-chart-hold").read_text()) == HOLD

    # Before the reboot the node still runs FROM: the hold stops nothing.
    _member(monkeypatch, cluster, name=MEMBER_1, release=FROM)
    assert service_lifecycle.shared_chart_hold_refusal(HOLD) is None

    # The reboot onto TO.
    _member(monkeypatch, cluster, name=MEMBER_1, release=TO)
    _installed(monkeypatch, TO)
    result = _apply(tmp_path, NO_ROLES)
    assert result.deferred
    assert cluster.chart()["global"]["imageTag"] == FROM

    # Every node runs TO: the next reply carries no hold, and the node writes.
    service_lifecycle.record_shared_chart_hold(tmp_path / "role-compose.env", None)
    result = _apply(tmp_path, NO_ROLES)
    assert result.state == "ready"
    assert cluster.chart()["global"]["imageTag"] == TO
