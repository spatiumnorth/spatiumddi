"""The cluster's role chart renders the same whichever node applies it (#1137).

A formed cluster has ONE ``spatiumddi-appliance`` HelmChart, and every node's
supervisor server-side-applies it whole (``apply_role_assignment`` ->
``k8s_api.apply_helmchart``, one ``valuesContent`` string) from its own inputs.
So a value two nodes render differently is a chart upgrade each time the
other one applies. When that value reaches an agent DaemonSet's pod template,
the RollingUpdate replaces that DaemonSet's pod on EVERY node. The seed's pod
goes too, although only one node's roles changed.

That is #1137. The seed is installed with no ``CONTROL_PLANE_URL``, so its
agents get the chart's in-cluster api Service. A member keeps the seed's
external URL it was paired with, and rendered it into its agents'
``controlPlaneUrl``. A member's first role apply therefore moved
``CONTROL_PLANE_URL`` / ``SPATIUM_API_URL`` in every agent DaemonSet to the
external URL (and added the TLS skip the chart keeps for off-cluster
appliances). kea and named were restarted on each node in turn. The next
apply by the seed moved it back and restarted them all again.

A promoted member is in the cluster. Its own heartbeat already goes to the
in-cluster Service (``heartbeat._effective_control_plane_url``), and since
#1350 (for #1281) its agents go there too: on a control-plane member the role
chart gets the seed's value, which is none, so the same roles render the same
chart on every node. These tests hold that property for #1137.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state, heartbeat, k8s_api, service_lifecycle
from spatium_supervisor.role_orchestrator import compute_target_env, render_env_file

SEED_URL = "https://192.0.2.10/"  # what a member was paired with (TEST-NET-1)
AGENT_BLOCKS = ("dnsBind9", "dnsPowerdns", "dnsTechnitium", "dhcpKea", "lookingGlass")
# The role assignment the control plane ships to each node holding these roles
# (``backend/app/api/v1/appliance/supervisor.py``): the same groups and keys.
ASSIGNMENT = {
    "roles": ["dhcp", "dns-bind9"],
    "dns_group_name": "default",
    "dhcp_group_name": "default-dhcp",
    "dns_agent_key": "a" * 48,
    "dhcp_agent_key": "b" * 48,
}


def _as(
    monkeypatch: pytest.MonkeyPatch,
    *,
    variant: str | None,
    join_state: str | None,
    configured_url: str,
) -> None:
    """Make this process the supervisor of one node: its install variant, its
    cluster-join sidecar, and the ``CONTROL_PLANE_URL`` its entrypoint exports
    from the host ``.env`` (the role env never carries it)."""
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: variant)
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (join_state, None)
    )
    monkeypatch.setenv("CONTROL_PLANE_URL", configured_url)


def _seed(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(monkeypatch, variant="control-plane", join_state=None, configured_url="")


def _member(monkeypatch: pytest.MonkeyPatch, join_state: str = "ready") -> None:
    _as(monkeypatch, variant="appliance", join_state=join_state, configured_url=SEED_URL)


def _applied_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict:
    """What this node's ``apply_role_assignment`` writes into the shared
    HelmChart for ``ASSIGNMENT``: the role env the heartbeat renders, then the
    apply itself, with the kubeapi calls captured."""
    env_file = tmp_path / "role-compose.env"
    target = compute_target_env(ASSIGNMENT)
    env_file.write_text(render_env_file(target), encoding="utf-8")
    written: list[dict] = []

    def capture(name: str, *, values: dict, **_: object) -> tuple[bool, None]:
        assert name == "spatiumddi-appliance"
        written.append(values)
        return True, None

    monkeypatch.setattr(
        service_lifecycle,
        "k3s_available",
        lambda: service_lifecycle.K3sEnvironment(available=True),
    )
    monkeypatch.setattr(service_lifecycle, "_read_chart_tarball", lambda: b"chart")
    monkeypatch.setattr(service_lifecycle, "_resolve_node_name", lambda: "")
    monkeypatch.setattr(k8s_api, "apply_helmchart", capture)
    result = service_lifecycle.apply_role_assignment(target.profiles, env_file)
    assert result.state == "ready"
    assert len(written) == 1
    return written[0]


def test_the_seed_and_a_member_with_the_same_roles_write_the_same_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The issue's exact sequence: the seed serves dhcp + dns-bind9, then a
    member is given the same roles and groups. If the member's apply wrote
    anything the seed's did not, helm would re-template the agent DaemonSets
    and replace the seed's kea and named. The seed's next apply would then
    write its own values back and replace them again."""
    _seed(monkeypatch)
    seed_values = _applied_values(monkeypatch, tmp_path)
    _member(monkeypatch)
    member_values = _applied_values(monkeypatch, tmp_path)
    assert member_values == seed_values


def test_a_member_gives_its_agents_the_in_cluster_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """None, like the seed's, so the chart falls through to the in-cluster api
    Service: the path the member's own heartbeat already takes."""
    _member(monkeypatch)
    values = _applied_values(monkeypatch, tmp_path)
    assert {values[b]["controlPlaneUrl"] for b in AGENT_BLOCKS} == {""}


def test_an_off_cluster_appliance_keeps_its_configured_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A paired appliance that was never promoted runs its own k3s and its own
    role chart. It has no in-cluster api Service to reach, so its agents still
    get the URL it was paired with."""
    _as(monkeypatch, variant="appliance", join_state=None, configured_url=SEED_URL)
    values = _applied_values(monkeypatch, tmp_path)
    assert {values[b]["controlPlaneUrl"] for b in AGENT_BLOCKS} == {SEED_URL}


def test_a_member_whose_join_is_not_ready_keeps_its_configured_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Until the host runner reports the join ready, the node's heartbeat still
    goes to the configured URL, and its agents follow the same rule."""
    _member(monkeypatch, join_state="joining")
    values = _applied_values(monkeypatch, tmp_path)
    assert {values[b]["controlPlaneUrl"] for b in AGENT_BLOCKS} == {SEED_URL}


@pytest.mark.parametrize(
    ("variant", "join_state", "member"),
    [
        ("control-plane", None, True),
        ("appliance", "ready", True),
        ("appliance", "joining", False),
        ("appliance", "failed", False),
        ("appliance", None, False),
        (None, None, False),
    ],
)
def test_the_agents_and_the_heartbeat_agree_on_membership(
    monkeypatch: pytest.MonkeyPatch,
    variant: str | None,
    join_state: str | None,
    member: bool,
) -> None:
    """One definition of membership: the heartbeat's switch to the in-cluster
    Service and the agents' cannot disagree about a node."""
    _as(monkeypatch, variant=variant, join_state=join_state, configured_url=SEED_URL)
    assert appliance_state.is_control_plane_member() is member
    assert heartbeat._is_control_plane_member() is member
    assert service_lifecycle.role_control_plane_url({}) == ("" if member else SEED_URL)
