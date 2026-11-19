"""Only a control-plane member writes the role chart a cluster shares (#1750).

A formed cluster has ONE ``spatiumddi-appliance`` HelmChart, and every node's
supervisor applies it whole. On a promoted appliance, membership is its join
state reading ``ready`` (``appliance_state.is_control_plane_member``), and the
values it renders follow it (#1281): a non-member renders its agents off unless
it holds their keys, points them at the external URL, and keeps nothing for the
other nodes (#1439's keep runs on members only).

So once a member's leave began (``leaving``), its supervisor rendered a
non-member's chart and applied it to the cluster's shared HelmChart. On a
three-node rig a 3 -> 1 demote got ``dnsBind9.enabled: false``,
``dhcpKea.enabled: false``, empty server groups and the seed's external URL,
and helm-controller deleted dns-bind9 and dhcp-kea on every node: DNS failed
249 s of probes, until the seed's watchdog wrote the chart again. The same
render ran in every other in-flight state too: a join before the runner
reports ``ready``, a refused leave (``failed``, still a member), and a verdict
the control plane consumed (the sidecar reads as nothing at all).

The contract, through ``apply_role_assignment`` against the fake kubeapi of
``test_role_chart_keeps_other_nodes_agents``: a member always writes; a
non-member writes only when it is alone in its k3s (its chart is its own);
a non-member sharing a cluster, or one that cannot tell, writes nothing and
the heartbeat does not count that as an apply.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state, heartbeat, service_lifecycle

from .test_role_chart_keeps_other_nodes_agents import (
    MEMBER_1,
    MEMBER_2,
    NO_ROLES,
    SEED,
    SEED_ROLES,
    Cluster,
    _apply,
    _as,
    _member,
    _seed,
)

# Every join state a promoted appliance's sidecar can read that is not ``ready``.
# ``None`` is the sidecar missing, or a ``failed`` verdict already consumed.
NOT_READY = ("joining", "leaving", "failed", "left", None)


def _three_nodes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Cluster:
    """The rig: the seed serves dhcp + dns-bind9 and wrote the chart; two
    members joined with no role, each writing the seed's chart unchanged."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    for name in (MEMBER_1, MEMBER_2):
        _member(monkeypatch, cluster, name=name)
        assert _apply(tmp_path, NO_ROLES).state == "ready"
    return cluster


@pytest.mark.parametrize("join_state", NOT_READY)
def test_a_member_whose_join_state_is_not_ready_never_writes_the_shared_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, join_state: str | None
) -> None:
    """REGRESSION (#1750): a demoted member's leave writes ``leaving``, and its
    next apply (its role apply key moved with its membership) used to write a
    non-member's chart over the seed's. Every in-flight state is the same: the
    apply writes nothing, is deferred, and the seed's agents stay on."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    seed_chart = cluster.values_content
    writes = len(cluster.writes)
    _member(monkeypatch, cluster, name=MEMBER_1, join_state=join_state)
    result = _apply(tmp_path, NO_ROLES)
    assert len(cluster.writes) == writes
    assert cluster.values_content == seed_chart
    assert result.state == "idle" and result.deferred is True
    assert "only a member writes the chart the cluster shares" in (result.reason or "")
    assert cluster.agent_blocks()["dnsBind9"] and cluster.agent_blocks()["dhcpKea"]


def test_both_members_leaving_a_3_to_1_demote_leave_the_seeds_chart_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The walk's C1: both members demoted at once, each applying (its role
    apply key moved) and its watchdog re-firing the apply. Not one write."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    seed_chart = cluster.values_content
    writes = len(cluster.writes)
    for name in (MEMBER_1, MEMBER_2):
        _member(monkeypatch, cluster, name=name, join_state="leaving")
        _apply(tmp_path, NO_ROLES)
        # The watchdog's heal is the same apply with the node's own profiles.
        _apply(tmp_path, SEED_ROLES)
    assert len(cluster.writes) == writes
    assert cluster.values_content == seed_chart


def test_a_ready_member_still_writes_and_carries_on_when_the_seed_is_gone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Failover: the gate is membership, not "the seed". With the seed's Node
    gone, a ready member still applies the chart, and keeps the agents the
    remaining nodes serve."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    cluster.labels.pop(SEED)
    cluster.labels[MEMBER_2]["spatium.io/role-dhcp"] = "true"
    cluster.labels[MEMBER_2]["spatium.io/role-dns-bind9"] = "true"
    writes = len(cluster.writes)
    _member(monkeypatch, cluster, name=MEMBER_1, join_state="ready")
    result = _apply(tmp_path, NO_ROLES)
    assert result.state == "ready" and not getattr(result, "deferred", False)
    assert len(cluster.writes) == writes + 1
    assert cluster.agent_blocks()["dnsBind9"] and cluster.agent_blocks()["dhcpKea"]
    assert "nodes" not in cluster.reads[-2:]


def test_the_seed_writes_in_a_formed_cluster(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The seed is a member by its variant, whatever its sidecar reads."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    writes = len(cluster.writes)
    _seed(monkeypatch, cluster)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    assert len(cluster.writes) == writes + 1


def test_a_single_node_install_writes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A single-node control plane, the default install: unchanged."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    result = _apply(tmp_path, SEED_ROLES)
    assert result.state == "ready" and not getattr(result, "deferred", False)
    assert cluster.agent_blocks()["dnsBind9"] and cluster.agent_blocks()["dhcpKea"]
    assert "nodes" not in cluster.reads


@pytest.mark.parametrize("join_state", NOT_READY)
def test_a_non_member_alone_in_its_k3s_writes_its_own_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, join_state: str | None
) -> None:
    """Alone in its k3s, a non-member's chart is its own: an application
    appliance never promoted (no sidecar), a demoted node on its fresh
    standalone cluster (``left``, or ``leaving`` once the wipe brought k3s back
    up), a node a failed join rolled back (``failed``), or a joiner before its
    k3s restarts into the seed's cluster (``joining``). Each writes its own
    roles, with its own configured URL."""
    cluster = Cluster()
    _member(monkeypatch, cluster, name=MEMBER_1, join_state=join_state)
    result = _apply(tmp_path, SEED_ROLES)
    assert result.state == "ready" and not getattr(result, "deferred", False)
    assert cluster.agent_blocks()["dnsBind9"] and cluster.agent_blocks()["dhcpKea"]
    assert cluster.chart()["dnsBind9"]["controlPlaneUrl"] == "https://192.0.2.10/"


def test_a_non_member_that_cannot_list_the_nodes_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Not knowing whether another node is there is never "alone": a leaving
    member whose kubeapi read fails writes nothing."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    seed_chart = cluster.values_content
    cluster.nodes_readable = False
    _member(monkeypatch, cluster, name=MEMBER_1, join_state="leaving")
    result = _apply(tmp_path, NO_ROLES)
    assert cluster.values_content == seed_chart
    assert result.deferred and "could not tell" in (result.reason or "")


def test_a_leave_that_starts_mid_render_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The gate reads ``ready``, then the runner writes ``leaving`` before the
    render reads it: the values are a non-member's, so the apply defers instead
    of shipping them under a member's gate."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    seed_chart = cluster.values_content
    _member(monkeypatch, cluster, name=MEMBER_1, join_state="ready")
    states = iter(["ready"])
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (next(states, "leaving"), None)
    )
    result = _apply(tmp_path, NO_ROLES)
    assert cluster.values_content == seed_chart
    assert result.deferred and "membership changed" in (result.reason or "")


def test_a_revoked_node_sharing_a_cluster_keeps_the_chart_and_clears_its_labels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Revocation tears the role release down. Deleting the shared chart would
    uninstall every node's agents, so a node sharing a cluster only clears its
    own role labels, which takes its own agents away."""
    cluster = _three_nodes(monkeypatch, tmp_path)
    cluster.labels[MEMBER_1]["spatium.io/role-dhcp"] = "true"
    seed_chart = cluster.values_content
    _as(monkeypatch, cluster, name=MEMBER_1, variant="appliance", join_state="ready")
    monkeypatch.setenv("NODE_NAME", MEMBER_1)
    service_lifecycle.tear_down_supervised_services()
    assert cluster.deleted is False and cluster.values_content == seed_chart
    assert cluster.labels[MEMBER_1] == {}


def test_a_revoked_node_alone_deletes_its_own_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cluster = Cluster()
    _member(monkeypatch, cluster, name=MEMBER_1, join_state=None)
    _apply(tmp_path, SEED_ROLES)
    monkeypatch.setenv("NODE_NAME", MEMBER_1)
    service_lifecycle.tear_down_supervised_services()
    assert cluster.deleted is True


def test_the_heartbeat_stamps_no_apply_key_on_a_deferred_apply() -> None:
    """A deferred apply wrote nothing, so the heartbeat must not count it: a
    demoted node renders the same apply key on its fresh standalone cluster
    (``left``) as it did ``leaving``, and a stamped key would skip the apply
    that gives that cluster its role chart."""
    result = service_lifecycle.LifecycleResult
    assert heartbeat._apply_settled(result(state="ready")) is True
    assert heartbeat._apply_settled(result(state="idle")) is True
    assert heartbeat._apply_settled(result(state="failed")) is False
    assert heartbeat._apply_settled(result(state="idle", deferred=True)) is False
    source = inspect.getsource(heartbeat._run_role_lifecycle)
    assert "if _apply_settled(lifecycle):\n" in source
    assert source.count("_write_last_apply_hash(") == 1
