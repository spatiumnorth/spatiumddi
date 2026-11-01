"""A node's DHCP group never reaches the shared role chart (#3202).

A formed cluster has ONE ``spatiumddi-appliance`` HelmChart and ONE dhcp-kea
DaemonSet for every node, and every node's supervisor writes that chart whole
from its own role env. Its dhcpKea block carried the writer's own DHCP group
(``serverGroupName``, from ``DHCP_AGENT_GROUP``), which the template rendered as
the pod template's ``AGENT_GROUP``. So when Fleet moved ONE node's DHCP to
another group, that node's supervisor wrote the chart with its new group name,
helm-controller made a new release, the DaemonSet's template changed in that one
env line, and Kubernetes replaced the Kea pod on every node, one at a time: on a
three-node rig a working hot-standby pair stopped answering for 15 to 25 s, and
every standalone Kea restarted too.

The agent used ``AGENT_GROUP`` only to pick the group of the server row its
registration creates, and the control plane now places that row by the
appliance's own assignment (``test_dhcp_agent_register_follows_appliance_3202``
in the backend). So the chart carries no DHCP group at all: nodes holding the
same roles in different DHCP groups write the very same values, and a group move
leaves the chart, and every Kea pod, alone.

These tests drive the real ``apply_role_assignment`` against the fake kubeapi of
``test_role_chart_keeps_other_nodes_agents`` (the one shared chart, kept as the
``valuesContent`` string each apply writes).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from spatium_supervisor import k8s_api, service_lifecycle
from tests.test_role_chart_keeps_other_nodes_agents import (
    DHCP_KEY,
    DNS_KEY,
    MEMBER_1,
    MEMBER_2,
    Cluster,
    _apply,
    _member,
    _seed,
)

REPO = Path(__file__).resolve().parents[3]
TEMPLATES = REPO / "charts" / "spatiumddi-appliance" / "templates"
DHCP_KEA_TEMPLATE = TEMPLATES / "dhcp-kea.yaml"


def _roles(dhcp_group: str, *, dns: bool) -> dict:
    """A node's role assignment as the heartbeat carries it: dhcp in
    ``dhcp_group`` (plus dns-bind9 in ``default`` when ``dns``)."""
    out: dict = {
        "roles": ["dhcp", "dns-bind9"] if dns else ["dhcp"],
        "dhcp_group_name": dhcp_group,
        "dhcp_agent_key": DHCP_KEY,
    }
    if dns:
        out.update({"dns_group_name": "default", "dns_agent_key": DNS_KEY})
    return out


def test_nodes_in_different_dhcp_groups_write_the_same_chart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """THE ISSUE'S STEPS, as the supervisors see them. The seed serves DHCP in
    its own group; Fleet gives member-1 the dhcp role in ``pair``, then member-2
    the same; then the seed's DHCP moves into ``pair`` and back. Every one of
    those writes must leave the shared chart's values exactly as the seed first
    wrote them, so helm-controller has nothing to upgrade and no Kea pod is
    replaced. Before the fix each write carried the writer's group."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    assert _apply(tmp_path, _roles("meridian-dhcp", dns=True)).state == "ready"
    first = cluster.values_content
    assert first is not None
    assert cluster.chart()["dhcpKea"]["enabled"] is True

    _member(monkeypatch, cluster, name=MEMBER_1)
    assert _apply(tmp_path, _roles("pair", dns=False)).state == "ready"
    assert cluster.values_content == first, "member-1 given dhcp in another group"

    _member(monkeypatch, cluster, name=MEMBER_2)
    assert _apply(tmp_path, _roles("pair", dns=False)).state == "ready"
    assert cluster.values_content == first, "member-2 joining that group"

    for group in ("pair", "meridian-dhcp"):
        _seed(monkeypatch, cluster)
        assert _apply(tmp_path, _roles(group, dns=True)).state == "ready"
        assert cluster.values_content == first, f"the seed moved to {group}"

    _member(monkeypatch, cluster, name=MEMBER_1)
    assert _apply(tmp_path, _roles("a-third-group", dns=False)).state == "ready"
    assert cluster.values_content == first, "member-1 moved to a third group"


def test_the_dhcp_block_carries_no_group_from_any_writer(monkeypatch: pytest.MonkeyPatch) -> None:
    """PURE: a holder renders no DHCP group, and a node that keeps dhcpKea on
    for the holders (#1439) copies none from the live chart, even one an older
    build wrote there. Its key and network mode are still the holder's."""
    holder = service_lifecycle._build_values(
        ["dhcp"], {"DHCP_AGENT_KEY": DHCP_KEY, "DHCP_AGENT_GROUP": "site-a"}
    )
    assert "serverGroupName" not in holder["dhcpKea"]  # type: ignore[operator]

    live = service_lifecycle._build_values(
        ["dhcp"], {"DHCP_AGENT_KEY": DHCP_KEY, "DHCP_NETWORK_MODE": "bridged"}
    )
    live["dhcpKea"]["serverGroupName"] = "written-by-an-older-build"  # type: ignore[index]
    values = service_lifecycle._build_values([], {})
    out, kept = service_lifecycle.keep_other_nodes_agents(values, live, {"dhcp"})
    assert kept == ["dhcpKea"]
    assert out["dhcpKea"]["agentKey"] == DHCP_KEY  # type: ignore[index]
    assert out["dhcpKea"]["networkMode"] == "bridged"  # type: ignore[index]
    assert "serverGroupName" not in out["dhcpKea"]  # type: ignore[operator]


def test_dns_groups_still_reach_the_chart() -> None:
    """PURE: only DHCP changes. The DNS blocks keep their group (one DNS group
    per cluster is enforced by the control plane, #1427)."""
    values = service_lifecycle._build_values(
        ["dns-bind9"], {"DNS_AGENT_KEY": DNS_KEY, "AGENT_GROUP": "dns-a"}
    )
    for block in ("dnsBind9", "dnsPowerdns", "dnsTechnitium"):
        assert values[block]["serverGroupName"] == "dns-a", block  # type: ignore[index]


def test_the_dhcp_kea_template_names_no_group() -> None:
    """The pod template of the one dhcp-kea DaemonSet holds nothing that varies
    by a node's DHCP group: no ``AGENT_GROUP`` env and no ``serverGroupName``
    (comments aside)."""
    lines = [
        line
        for line in DHCP_KEA_TEMPLATE.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#") and "{{- /*" not in line
    ]
    body = "\n".join(lines)
    assert not re.search(r"name:\s*AGENT_GROUP\b", body)
    assert "serverGroupName" not in body


def test_the_dhcp_label_is_never_held_for_a_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """#2190's gate holds a role label until the DaemonSet's template carries
    the node's group. The dhcp-kea template carries none any more, so a dhcp
    label must go through whatever the template's env says, or every node
    given the dhcp role would wait out the gate's 300 s."""
    assert "dhcp" not in service_lifecycle._ROLE_AGENT_GROUP
    monkeypatch.setattr(
        k8s_api,
        "daemonset_template_env",
        lambda name, *, env_name, **_k: (True, "another-nodes-group", None),
    )
    diff = {"spatium.io/role-dhcp": "true"}
    out, held = service_lifecycle.hold_stale_role_labels(diff, {"DHCP_AGENT_GROUP": "pair"})
    assert held == []
    assert out == diff


def test_a_standalone_and_a_hot_standby_group_render_the_same_kea_pods(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Two DHCP groups of different kinds, a standalone one on the host network
    and a hot-standby pair in bridged mode with its HA listener: the chart's
    values then differ only in what a group's network mode writes, and no
    template reads that, so helm renders the very same dhcp-kea DaemonSet (and
    the very same release). No template hashes values into an annotation
    either, which would roll every pod on any change of values."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    standalone = {**_roles("site-a", dns=True), "dhcp_network_mode": "host"}
    assert _apply(tmp_path, standalone).state == "ready"
    seed = cluster.chart()

    _member(monkeypatch, cluster, name=MEMBER_1)
    pair = {
        **_roles("pair", dns=False),
        "dhcp_network_mode": "bridged",
        "dhcp_ha_port": 8000,
        "dhcp_ha_peer_cidrs": ["192.0.2.12/32"],
    }
    assert _apply(tmp_path, pair).state == "ready"
    member = cluster.chart()

    kea_seed, kea_member = seed.pop("dhcpKea"), member.pop("dhcpKea")
    assert seed == member
    differ = {k for k in kea_seed.keys() | kea_member.keys() if kea_seed.get(k) != kea_member.get(k)}
    assert "networkMode" in differ, "the two groups' modes never reached the values"
    templates = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(TEMPLATES.rglob("*")) if p.is_file()
    )
    for key in sorted(differ):
        assert not re.search(rf"dhcpKea\.{key}\b", templates), f"a template renders dhcpKea.{key}"
    assert not re.search(r"\b(sha256sum|sha1sum|adler32sum)\b", templates)
