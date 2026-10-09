"""spatium-cluster-join leave removes the old cluster's pod routes (#1682).

Flannel runs host-gw, so a member holds a kernel route to every other node's
pod subnet, `<subnet> via <that node>`, and nothing removes those routes when
k3s stops. The node then restarts as a fresh single-node cluster that takes
the first subnet of the pod network for itself, the seed's, so the stale route
via the seed shadows the node's own cni0 route and its pods never reach their
own API. The leave must remove every gateway route into the pod network while
k3s is stopped, and before the identity wipe removes flannel's subnet.env,
which names that network.

The real script is sourced as a library and ``do_leave`` runs with stubbed
``systemctl``, ``ip``, runtime cleanup and etcd runner; the identity wipe is
the real one, against a synthetic tree.

    python3 -m pytest appliance/tests/test_cluster_leave_clears_pod_routes.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-cluster-join"
)
LEAVE_CONFIRM = "SPATIUMDDI-CLUSTER-LEAVE-CONFIRM-V1"

# What `ip -4 route show root <pod network>` answers on a member of a
# three-node host-gw cluster: its own cni0 subnet, and one route per peer.
V4_ROUTES = (
    "10.52.0.0/24 via 192.0.2.10 dev ens18 \n"
    "10.52.1.0/24 dev cni0 proto kernel scope link src 10.52.1.1 \n"
    "10.52.2.0/24 via 192.0.2.12 dev ens18 \n"
)
V6_ROUTES = (
    "fd52:0:0:1::/64 dev cni0 proto kernel metric 256 pref medium\n"
    "fd52::/64 via 2001:db8::10 dev ens18 metric 1024 pref medium\n"
)


def _leave(
    tmp_path: Path,
    *,
    subnet_env: str | None,
    cidr_dropin: str | None = None,
) -> tuple[int, list[str], str]:
    rs = tmp_path / "release-state"
    rs.mkdir()
    (rs / "cluster-leave-pending").write_text(f"{LEAVE_CONFIRM}\n")
    k3s_config = tmp_path / "config.yaml"
    k3s_config.write_text("cluster-init: true\n")
    dropin = tmp_path / "dropin"
    dropin.mkdir()
    (dropin / "spatium-cluster.yaml").write_text("server: https://192.0.2.10:6443\n")
    if cidr_dropin is not None:
        (dropin / "spatium-cidrs.yaml").write_text(f"cluster-cidr: {cidr_dropin}\n")
    flannel = tmp_path / "flannel" / "subnet.env"
    if subnet_env is not None:
        flannel.parent.mkdir()
        flannel.write_text(subnet_env)
    calls = tmp_path / "calls"
    evict = tmp_path / "evict"
    evict.write_text(f'#!/bin/sh\necho "evict $*" >> "{calls}"\nexit 0\n')
    evict.chmod(0o755)
    driver = f"""
        source "{SCRIPT}"
        systemctl() {{ echo "systemctl $*" >> "{calls}"; }}
        clean_k3s_runtime() {{ :; }}
        wait_ready() {{ return 0; }}
        ip() {{
            echo "ip $*" >> "{calls}"
            case "$*" in
                "-4 route show root 10.52.0.0/16") printf '%s' "{V4_ROUTES}" ;;
                "-6 route show root fd52::/56") printf '%s' "{V6_ROUTES}" ;;
            esac
        }}
        do_leave
    """
    env = {
        **os.environ,
        "SPATIUM_CLUSTER_JOIN_LIB": "1",
        "SPATIUM_RELEASE_STATE": str(rs),
        "SPATIUM_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_K3S_CONFIG": str(k3s_config),
        "SPATIUM_K3S_DROPIN_DIR": str(dropin),
        "SPATIUM_K3S_SERVER_DIR": str(tmp_path / "k3s-server"),
        "SPATIUM_K3S_AGENT_DIR": str(tmp_path / "k3s-agent"),
        "SPATIUM_K3S_NODE_PASSWORD": str(tmp_path / "node" / "password"),
        "SPATIUM_K3S_KUBECONFIG": str(tmp_path / "k3s.yaml"),
        "SPATIUM_FLANNEL_SUBNET_ENV": str(flannel),
        "SPATIUM_CNI_NETWORKS_DIR": str(tmp_path / "cni" / "networks"),
        "SPATIUM_ETCD_EVICT": str(evict),
    }
    r = subprocess.run(["bash", "-c", driver], env=env, capture_output=True, text=True, check=False)
    state = (rs / "cluster-join.state").read_text() if (rs / "cluster-join.state").exists() else ""
    return r.returncode, calls.read_text().splitlines() if calls.exists() else [], state


def test_every_route_through_an_old_peer_is_removed_and_cni0_is_kept(tmp_path: Path) -> None:
    rc, calls, state = _leave(
        tmp_path, subnet_env="FLANNEL_NETWORK=10.52.0.0/16\nFLANNEL_SUBNET=10.52.1.1/24\n"
    )
    assert rc == 0, calls
    assert state.startswith("left")
    deleted = [c for c in calls if " route del " in c]
    assert deleted == [
        "ip -4 route del 10.52.0.0/24 via 192.0.2.10",
        "ip -4 route del 10.52.2.0/24 via 192.0.2.12",
    ], calls


def test_routes_go_while_k3s_is_stopped_and_before_the_wipe_takes_subnet_env(
    tmp_path: Path,
) -> None:
    """The network is read from subnet.env, which the wipe removes. A pod
    network other than k3s's default proves the read came first: a clear after
    the wipe would have fallen back to 10.42.0.0/16 and removed nothing."""
    rc, calls, _ = _leave(
        tmp_path, subnet_env="FLANNEL_NETWORK=10.52.0.0/16\nFLANNEL_SUBNET=10.52.1.1/24\n"
    )
    assert rc == 0, calls
    first_del = next(i for i, c in enumerate(calls) if " route del " in c)
    assert calls.index("systemctl stop k3s") < first_del < calls.index("systemctl start k3s")
    assert not (tmp_path / "flannel" / "subnet.env").exists(), "the wipe still clears subnet.env"


def test_without_subnet_env_the_configured_cluster_cidr_is_used(tmp_path: Path) -> None:
    rc, calls, _ = _leave(tmp_path, subnet_env=None, cidr_dropin='"10.52.0.0/16"')
    assert rc == 0, calls
    assert "ip -4 route show root 10.52.0.0/16" in calls
    assert "ip -4 route del 10.52.0.0/24 via 192.0.2.10" in calls


def test_without_either_the_k3s_default_network_is_cleared(tmp_path: Path) -> None:
    rc, calls, _ = _leave(tmp_path, subnet_env=None)
    assert rc == 0, calls
    assert "ip -4 route show root 10.42.0.0/16" in calls


def test_a_dual_stack_pod_network_loses_its_v6_peer_routes_too(tmp_path: Path) -> None:
    rc, calls, _ = _leave(
        tmp_path,
        subnet_env=(
            "FLANNEL_NETWORK=10.52.0.0/16\nFLANNEL_SUBNET=10.52.1.1/24\n"
            "FLANNEL_IPV6_NETWORK=fd52::/56\nFLANNEL_IPV6_SUBNET=fd52:0:0:1::1/64\n"
        ),
    )
    assert rc == 0, calls
    assert "ip -6 route del fd52::/64 via 2001:db8::10" in calls
    assert not any(c.startswith("ip -6 route del fd52:0:0:1::") for c in calls), calls


def test_a_dual_stack_cluster_cidr_is_split_when_subnet_env_is_gone(tmp_path: Path) -> None:
    rc, calls, _ = _leave(tmp_path, subnet_env=None, cidr_dropin="10.52.0.0/16,fd52::/56")
    assert rc == 0, calls
    assert "ip -4 route show root 10.52.0.0/16" in calls
    assert "ip -6 route show root fd52::/56" in calls
