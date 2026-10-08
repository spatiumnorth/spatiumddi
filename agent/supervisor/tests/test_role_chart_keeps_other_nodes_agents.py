"""A node's role apply keeps the agents other nodes serve (#1439, #1427).

A formed cluster has ONE ``spatiumddi-appliance`` HelmChart, and every node's
supervisor server-side-applies it whole from its own role env
(``apply_role_assignment`` -> ``k8s_api.apply_helmchart``). A node renders an
agent block only when its own env carries that role's key (#1062), and the
control plane ships a key only to a node that holds the role.

Since #1350 a member's promotion changes its role apply key (the agents'
control-plane URL, #1281), so the member's first heartbeat after the join
re-applies the chart with the roles it holds at that moment: none. Every agent
block went out disabled, and the helm upgrade deleted every agent DaemonSet on
every node, the seed's included, until a node holding the roles wrote the chart
again (the seed's watchdog, every 300 s). On a three-node rig of main the seed
served no DHCP and no DNS for 3 min 49 s of a formation; a Replace did the same.
The same mechanism without the trigger is #1427's: a member given some of the
roles, or a node a role is taken back from, rendered that role off, and Kea was
killed on every node still assigned DHCP until a watchdog wrote the chart again.

The contract these tests hold, through ``apply_role_assignment`` against a fake
kubeapi that keeps the shared chart as the ``valuesContent`` string the apply
writes and each node's role labels: whether an agent family is written on is
decided by the cluster's role labels, not by the roles of the node writing; the
values only a holder is given (its key, its server group, its DHCP network mode)
come from the live chart a holder wrote; everything else is the writer's own.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import yaml

from spatium_supervisor import appliance_state, k8s_api, service_lifecycle
from spatium_supervisor.role_orchestrator import compute_target_env, render_env_file

DNS_KEY = "a" * 48
DHCP_KEY = "b" * 48
SEED_ROLES = {
    "roles": ["dhcp", "dns-bind9"],
    "dns_group_name": "default",
    "dhcp_group_name": "default-dhcp",
    "dns_agent_key": DNS_KEY,
    "dhcp_agent_key": DHCP_KEY,
}
NO_ROLES: dict = {"roles": []}
AGENT_BLOCKS = ("dnsBind9", "dnsPowerdns", "dnsTechnitium", "dhcpKea", "lookingGlass")
SEED, MEMBER_1, MEMBER_2 = "ddipg-seed", "ddipg-member-1", "ddipg-member-2"
RELEASE = "2026.10.06-1"


class Cluster:
    """The kubeapi as the role apply sees it: the one shared HelmChart, kept as
    the ``valuesContent`` string ``apply_helmchart`` renders (``None`` before
    any node wrote it) with the chart tarball it carries, and each node's
    ``spatium.io/role-*`` labels."""

    def __init__(self) -> None:
        self.values_content: str | None = None
        self.chart_content: bytes | None = None
        self.labels: dict[str, dict[str, str]] = {}
        self.writes: list[str] = []
        self.reads: list[str] = []
        self.chart_readable = True
        self.labels_readable = True

    def helmchart_values(self, name: str, *, namespace: str = "kube-system") -> dict | None:
        assert (name, namespace) == ("spatiumddi-appliance", "kube-system")
        self.reads.append("chart")
        if not self.chart_readable:
            return None
        if self.values_content is None:
            return {}
        return yaml.safe_load(self.values_content)

    def node_role_labels(self, exclude: str = "", timeout: float = 5.0):
        self.reads.append(f"labels-but-{exclude}")
        if not self.labels_readable:
            return None, "kubeapi status 503"
        doc = {
            "items": [
                {"metadata": {"name": node, "labels": dict(labels)}}
                for node, labels in self.labels.items()
            ]
        }
        return k8s_api.role_labels_of(doc, exclude), None

    def apply_helmchart(
        self, name: str, *, values: dict, chart_content_b64: str, **_: object
    ) -> tuple[bool, None]:
        assert name == "spatiumddi-appliance"
        # The same rendering as k8s_api.apply_helmchart's body.
        self.values_content = yaml.safe_dump(values, default_flow_style=False, sort_keys=False)
        self.chart_content = base64.b64decode(chart_content_b64)
        self.writes.append(self.values_content)
        return True, None

    def patch_node_labels(self, node: str, diff: dict[str, str | None]) -> tuple[bool, None]:
        mine = self.labels.setdefault(node, {})
        for key, value in diff.items():
            if value is None:
                mine.pop(key, None)
            else:
                mine[key] = value
        return True, None

    def chart(self) -> dict:
        return yaml.safe_load(self.values_content or "{}") or {}

    def agent_blocks(self) -> dict[str, bool]:
        doc = self.chart()
        return {b: bool((doc.get(b) or {}).get("enabled")) for b in AGENT_BLOCKS}


def _as(
    monkeypatch: pytest.MonkeyPatch,
    cluster: Cluster,
    *,
    name: str,
    variant: str | None,
    join_state: str | None,
    release: str = RELEASE,
) -> None:
    """Make this process the supervisor of one node of ``cluster``, running
    ``release`` (its slot's image tag and baked chart)."""
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: variant)
    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: (join_state, None))
    monkeypatch.setenv(
        "CONTROL_PLANE_URL", "" if variant == "control-plane" else "https://192.0.2.10/"
    )
    monkeypatch.setenv("SPATIUMDDI_VERSION", release)
    monkeypatch.setattr(service_lifecycle, "_resolve_node_name", lambda: name)
    monkeypatch.setattr(
        service_lifecycle,
        "k3s_available",
        lambda: service_lifecycle.K3sEnvironment(available=True),
    )
    chart = f"chart of {release}".encode()
    monkeypatch.setattr(service_lifecycle, "_read_chart_tarball", lambda: chart)
    monkeypatch.setattr(k8s_api, "_helmchart_values", cluster.helmchart_values)
    # raising=False: a build without the read still runs these tests, and fails
    # them on what it writes, not on the stub.
    monkeypatch.setattr(k8s_api, "node_role_labels", cluster.node_role_labels, raising=False)
    monkeypatch.setattr(k8s_api, "apply_helmchart", cluster.apply_helmchart)
    monkeypatch.setattr(k8s_api, "patch_node_labels", cluster.patch_node_labels)


def _seed(monkeypatch: pytest.MonkeyPatch, cluster: Cluster, release: str = RELEASE) -> None:
    _as(monkeypatch, cluster, name=SEED, variant="control-plane", join_state=None, release=release)


def _member(
    monkeypatch: pytest.MonkeyPatch,
    cluster: Cluster,
    name: str = MEMBER_1,
    join_state: str | None = "ready",
    release: str = RELEASE,
) -> None:
    _as(
        monkeypatch, cluster, name=name, variant="appliance", join_state=join_state, release=release
    )


def _apply(tmp_path: Path, assignment: dict) -> service_lifecycle.LifecycleResult:
    """This node's heartbeat: the role env it renders, then the apply."""
    env_file = tmp_path / "role-compose.env"
    target = compute_target_env(assignment)
    env_file.write_text(render_env_file(target), encoding="utf-8")
    return service_lifecycle.apply_role_assignment(target.profiles, env_file)


def test_a_member_promoted_with_no_role_writes_the_chart_the_seed_wrote(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#1439's formation: the seed serves dhcp + dns-bind9; a member joins and
    is promoted with no role. Its first apply after the join must write the
    very ``valuesContent`` the seed wrote, so helm has nothing to upgrade and
    the seed's kea and named keep running. It used to write every agent off."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    seed_chart = cluster.values_content
    assert cluster.agent_blocks() == {
        "dnsBind9": True,
        "dnsPowerdns": True,
        "dnsTechnitium": True,
        "dhcpKea": True,
        "lookingGlass": False,
    }
    _member(monkeypatch, cluster)
    result = _apply(tmp_path, NO_ROLES)
    assert result.state == "ready"
    assert cluster.writes[-1] == seed_chart
    assert cluster.reads[-2:] == [f"labels-but-{MEMBER_1}", "chart"]
    # The member's own labels still say it holds nothing but the control plane:
    # no agent pod schedules onto it.
    assert cluster.labels[MEMBER_1] == {"spatium.io/role-control-plane": "true"}


def test_a_second_member_and_a_replacement_keep_it_too(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Every join is the same apply: the second member, and the node a Replace
    installs, each promoted with no role, write the seed's chart unchanged."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, SEED_ROLES)
    seed_chart = cluster.values_content
    for name in (MEMBER_1, MEMBER_2, "ddipg-member-3"):
        _member(monkeypatch, cluster, name=name)
        assert _apply(tmp_path, NO_ROLES).state == "ready"
        assert cluster.writes[-1] == seed_chart


def test_a_member_on_another_release_keeps_the_agents_and_writes_its_own_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An upgrade leg: the seed still runs 2026.10.02-1 and wrote the chart with
    its image tag and its baked chart; a member already on the next release is
    promoted with no role (a join, or a Replace, mid-roll). The member keeps the
    seed's agents on, with the seed's key and groups, and everything it renders
    itself is its own: the agents' image tag and the chart it ships. A kept
    agent never carries another node's release."""
    cluster = Cluster()
    _seed(monkeypatch, cluster, release="2026.10.02-1")
    _apply(tmp_path, SEED_ROLES)
    seed = cluster.chart()
    assert seed["global"]["imageTag"] == "2026.10.02-1"

    _member(monkeypatch, cluster, release=RELEASE)
    assert _apply(tmp_path, NO_ROLES).state == "ready"
    member = cluster.chart()
    assert member["global"]["imageTag"] == RELEASE
    assert cluster.chart_content == f"chart of {RELEASE}".encode()
    for block in ("dnsBind9", "dnsPowerdns", "dnsTechnitium", "dhcpKea"):
        assert member[block] == seed[block], block
    assert member["dnsBind9"]["agentKey"] == DNS_KEY
    assert member["dnsBind9"]["serverGroupName"] == "default"
    assert member["dhcpKea"]["agentKey"] == DHCP_KEY
    assert member["dhcpKea"]["serverGroupName"] == "default-dhcp"
    assert member["lookingGlass"]["enabled"] is False


def test_a_kept_agent_takes_only_the_holders_values_from_the_live_chart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PURE: of a kept block, only what a holder alone is given (its key, its
    server group, its DHCP network mode) comes from the live chart; the writer
    renders the rest. Here the live chart carries a value no supervisor of this
    release writes into an agent block (as a block another release rendered
    could), and a control-plane URL other than the writer's: neither is copied."""
    monkeypatch.setattr(appliance_state, "is_control_plane_member", lambda: False)
    monkeypatch.delenv("CONTROL_PLANE_URL", raising=False)
    values = service_lifecycle._build_values([], {})
    live = service_lifecycle._build_values(
        ["dhcp"],
        {
            "DHCP_AGENT_KEY": DHCP_KEY,
            "DHCP_AGENT_GROUP": "site-a",
            "DHCP_NETWORK_MODE": "bridge",
            "CONTROL_PLANE_URL": "https://198.51.100.7/",
        },
    )
    live["dhcpKea"]["image"] = {"tag": "2026.10.02-1"}
    out, kept = service_lifecycle.keep_other_nodes_agents(values, live, {"dhcp"})
    assert kept == ["dhcpKea"]
    assert out["dhcpKea"] == {
        **values["dhcpKea"],
        "enabled": True,
        "agentKey": DHCP_KEY,
        "serverGroupName": "site-a",
        "networkMode": "bridge",
    }
    assert out["global"] == values["global"]


def test_an_agent_no_other_node_serves_is_still_written_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The live chart renders the agents, but no other node carries their
    role labels any more: there is no one to keep them for, and the member's
    apply writes them off, which takes the DaemonSets away as it always did."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, SEED_ROLES)
    cluster.labels[SEED] = {"spatium.io/role-control-plane": "true"}
    _member(monkeypatch, cluster)
    assert _apply(tmp_path, NO_ROLES).state == "ready"
    assert not any(cluster.agent_blocks().values())


def test_the_last_node_holding_a_role_still_removes_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A single node dropping its roles: its own labels are not "another
    node", so the release drops the agents' DaemonSets as before, and with no
    other node serving anything it has no need to read the chart."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, SEED_ROLES)
    cluster.reads.clear()
    assert _apply(tmp_path, NO_ROLES).state == "ready"
    assert not any(cluster.agent_blocks().values())
    assert cluster.reads == [f"labels-but-{SEED}"]


def test_an_appliance_off_the_cluster_reads_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A paired appliance never promoted runs its own k3s and its own chart:
    nothing it writes is another node's, so it reads nothing and renders its
    own roles alone."""
    cluster = Cluster()
    _member(monkeypatch, cluster, join_state=None)
    assert _apply(tmp_path, NO_ROLES).state == "ready"
    assert cluster.reads == []
    assert not any(cluster.agent_blocks().values())


def test_unreadable_node_labels_fail_the_apply_and_write_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Not knowing what the other nodes serve is never taken as "nothing":
    the apply fails (so the heartbeat stamps no key and retries) and the
    shared chart is left as it is."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, SEED_ROLES)
    seed_chart = cluster.values_content
    cluster.labels_readable = False
    _member(monkeypatch, cluster)
    result = _apply(tmp_path, NO_ROLES)
    assert result.state == "failed"
    assert result.reason == "the cluster's node role labels could not be read: kubeapi status 503"
    assert cluster.values_content == seed_chart and len(cluster.writes) == 1


def test_an_unreadable_live_chart_fails_the_apply_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Another node serves the agents, and their key is only in the live
    chart: unread, the apply cannot write them, so it writes nothing."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, SEED_ROLES)
    seed_chart = cluster.values_content
    cluster.chart_readable = False
    _member(monkeypatch, cluster)
    result = _apply(tmp_path, NO_ROLES)
    assert result.state == "failed"
    assert result.reason == "the live role chart could not be read; not writing it blind"
    assert cluster.values_content == seed_chart and len(cluster.writes) == 1


def test_role_labels_of_reads_the_other_nodes_true_role_labels() -> None:
    doc = {
        "items": [
            {
                "metadata": {
                    "name": SEED,
                    "labels": {
                        "spatium.io/role-dhcp": "true",
                        "spatium.io/role-dns-bind9": "true",
                        "spatium.io/role-control-plane": "true",
                        "kubernetes.io/hostname": SEED,
                    },
                }
            },
            {
                "metadata": {
                    "name": MEMBER_1,
                    "labels": {
                        "spatium.io/role-looking-glass": "true",
                        "spatium.io/role-dns-powerdns": "false",
                    },
                }
            },
            {"metadata": {"name": MEMBER_2}},
        ]
    }
    assert k8s_api.role_labels_of(doc, exclude=MEMBER_1) == {"dhcp", "dns-bind9", "control-plane"}
    assert k8s_api.role_labels_of(doc, exclude=SEED) == {"looking-glass"}
    assert k8s_api.role_labels_of(doc) == {
        "dhcp",
        "dns-bind9",
        "control-plane",
        "looking-glass",
    }
    assert k8s_api.role_labels_of({}) == set()


# ---- #1427: a node given some of the roles keeps the others' agents ---------------

DNS_ONLY = {
    "roles": ["dns-bind9"],
    "dns_group_name": "default",
    "dns_agent_key": DNS_KEY,
}
DHCP_ONLY = {
    "roles": ["dhcp"],
    "dhcp_group_name": "default-dhcp",
    "dhcp_agent_key": DHCP_KEY,
}


def test_a_member_given_a_subset_keeps_the_roles_it_was_not_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#1427's 21:48Z case: all three nodes hold dhcp + dns-bind9, then
    member-2 is given dns-bind9 alone. Its apply used to write ``dhcpKea`` off,
    and the upgrade deleted the dhcp-kea DaemonSet on the seed and member-1,
    whose roles never changed. It now writes the seed's chart unchanged, and
    only its own label moves: member-2's kea is unscheduled, no other node's."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, SEED_ROLES)
    seed_chart = cluster.values_content
    for name in (MEMBER_1, MEMBER_2):
        _member(monkeypatch, cluster, name=name)
        _apply(tmp_path, SEED_ROLES)
        assert cluster.writes[-1] == seed_chart
    result = _apply(tmp_path, DNS_ONLY)
    assert result.state == "ready"
    assert cluster.writes[-1] == seed_chart
    assert cluster.labels[MEMBER_2] == {
        "spatium.io/role-dns-bind9": "true",
        "spatium.io/role-control-plane": "true",
    }
    assert "spatium.io/role-dhcp" in cluster.labels[SEED]
    assert "spatium.io/role-dhcp" in cluster.labels[MEMBER_1]


TECHNITIUM = {
    "roles": ["dns-technitium"],
    "dns_group_name": "default",
    "dns_agent_key": DNS_KEY,
}
TECHNITIUM_DHCP = {
    "roles": ["dns-technitium", "dhcp"],
    "dns_group_name": "default",
    "dhcp_group_name": "vlan-30",
    "dns_agent_key": DNS_KEY,
    "dhcp_agent_key": DHCP_KEY,
}


def test_taking_a_role_back_from_one_node_keeps_it_on_the_node_still_assigned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The field report on #1427: ddi03 holds dns-technitium + dhcp and serves
    DHCP; ddi02 holds dns-technitium. ddi02 is given dhcp for a few minutes,
    then its roles are put back. Putting them back made ddi02 write ``dhcpKea``
    off, and the dhcp-kea DaemonSet, ddi03's Kea with it, was deleted: no DHCP
    anywhere until ddi03's roles were re-sent. Taking a role from one node now
    moves only that node's label."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, NO_ROLES)
    _member(monkeypatch, cluster, name="ddi03")
    _apply(tmp_path, TECHNITIUM_DHCP)
    ddi03_chart = cluster.values_content
    assert cluster.agent_blocks()["dhcpKea"] is True
    _member(monkeypatch, cluster, name="ddi02")
    _apply(tmp_path, TECHNITIUM)
    assert cluster.writes[-1] == ddi03_chart
    assert _apply(tmp_path, TECHNITIUM_DHCP).state == "ready"
    assert "spatium.io/role-dhcp" in cluster.labels["ddi02"]
    assert _apply(tmp_path, TECHNITIUM).state == "ready"
    assert cluster.writes[-1] == ddi03_chart
    assert "spatium.io/role-dhcp" not in cluster.labels["ddi02"]
    assert cluster.labels["ddi03"]["spatium.io/role-dhcp"] == "true"


def test_two_nodes_with_different_roles_write_one_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The seed serves DNS, member-1 DHCP. Each apply keeps the other's agent,
    so either node writing again (a role toggle, a watchdog heal) leaves the
    chart as it is instead of flipping the other's DaemonSet off and on."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, DNS_ONLY)
    _member(monkeypatch, cluster)
    assert _apply(tmp_path, DHCP_ONLY).state == "ready"
    both = cluster.values_content
    assert cluster.agent_blocks() == {
        "dnsBind9": True,
        "dnsPowerdns": True,
        "dnsTechnitium": True,
        "dhcpKea": True,
        "lookingGlass": False,
    }
    _seed(monkeypatch, cluster)
    assert _apply(tmp_path, DNS_ONLY).state == "ready"
    assert cluster.writes[-1] == both


def test_dropping_a_role_no_other_node_serves_still_removes_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """member-1 alone held DHCP; it drops it. No other node is labelled for
    DHCP, so ``dhcpKea`` goes off, while the seed's DNS stays as it was."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    _apply(tmp_path, DNS_ONLY)
    _member(monkeypatch, cluster)
    _apply(tmp_path, DHCP_ONLY)
    assert _apply(tmp_path, NO_ROLES).state == "ready"
    assert cluster.agent_blocks() == {
        "dnsBind9": True,
        "dnsPowerdns": True,
        "dnsTechnitium": True,
        "dhcpKea": False,
        "lookingGlass": False,
    }


def test_a_node_rendering_every_agent_reads_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Nothing it writes can be another node's loss: no read, no keep."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    everything = dict(SEED_ROLES, roles=["dhcp", "dns-bind9", "looking-glass"])
    everything["lg_agent_key"] = "c" * 48
    assert _apply(tmp_path, everything).state == "ready"
    assert cluster.reads == []
    assert all(cluster.agent_blocks().values())
