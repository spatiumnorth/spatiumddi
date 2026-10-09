"""spatium-cluster-join leave puts the 6443 bootstrap sentinel back (#1682).

A member's supervisor renders `# spatium-bootstrap: retire` (a multi-node
control plane), so spatium-firewall-reload moves the baked
00-spatium-k3s-bootstrap.nft aside, and the rendered `kubeapi` rule admits 6443
from the peers only. After the leave resets the node to a fresh single-node
cluster, its pods reach their own API through the service-IP DNAT to its own
:6443, from the pod's address, and the input chain (policy drop) drops them, so
no supervisor ever starts to render the single-node `keep` that restores the
sentinel. The leave restores it before k3s starts, validating the merged
config first, as the reload runner's `keep` does.

The real script is sourced as a library and ``do_leave`` runs with stubbed
``systemctl``, ``nft``, ``ip``, runtime cleanup, identity wipe and etcd runner.

    python3 -m pytest appliance/tests/test_cluster_leave_restores_bootstrap_sentinel.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-cluster-join"
)
LEAVE_CONFIRM = "SPATIUMDDI-CLUSTER-LEAVE-CONFIRM-V1"
SENTINEL = "00-spatium-k3s-bootstrap.nft"


def _leave(
    tmp_path: Path, *, sentinel: str | None, check_rc: int = 0
) -> tuple[int, list[str], Path]:
    rs = tmp_path / "release-state"
    rs.mkdir()
    (rs / "cluster-leave-pending").write_text(f"{LEAVE_CONFIRM}\n")
    k3s_config = tmp_path / "config.yaml"
    k3s_config.write_text("cluster-init: true\n")
    nft_dir = tmp_path / "nftables.d"
    nft_dir.mkdir()
    if sentinel == "retired":
        (nft_dir / f"{SENTINEL}.retired").write_text('tcp dport 6443 accept comment "k3s-bootstrap"\n')
    elif sentinel == "present":
        (nft_dir / SENTINEL).write_text('tcp dport 6443 accept comment "k3s-bootstrap"\n')
    calls = tmp_path / "calls"
    evict = tmp_path / "evict"
    evict.write_text(f'#!/bin/sh\necho "evict $*" >> "{calls}"\nexit 0\n')
    evict.chmod(0o755)
    driver = f"""
        source "{SCRIPT}"
        systemctl() {{ echo "systemctl $*" >> "{calls}"; }}
        clean_k3s_runtime() {{ :; }}
        backup_and_wipe_identity() {{ echo "wipe" >> "{calls}"; }}
        clear_stale_pod_routes() {{ :; }}
        wait_ready() {{ return 0; }}
        nft() {{
            echo "nft $* sentinel=$(ls "{nft_dir}" | tr '\\n' ' ')" >> "{calls}"
            case "$1" in -c) return {check_rc} ;; esac
            return 0
        }}
        do_leave
    """
    env = {
        **os.environ,
        "SPATIUM_CLUSTER_JOIN_LIB": "1",
        "SPATIUM_RELEASE_STATE": str(rs),
        "SPATIUM_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_K3S_CONFIG": str(k3s_config),
        "SPATIUM_K3S_DROPIN_DIR": str(tmp_path / "dropin"),
        "SPATIUM_K3S_SERVER_DIR": str(tmp_path / "k3s-server"),
        "SPATIUM_ETCD_EVICT": str(evict),
        "SPATIUM_NFT_DIR": str(nft_dir),
        "SPATIUM_NFT_MAIN": str(tmp_path / "nftables.conf"),
    }
    r = subprocess.run(["bash", "-c", driver], env=env, capture_output=True, text=True, check=False)
    return r.returncode, calls.read_text().splitlines() if calls.exists() else [], nft_dir


def test_a_retired_sentinel_is_restored_and_applied_before_k3s_starts(tmp_path: Path) -> None:
    rc, calls, nft_dir = _leave(tmp_path, sentinel="retired")
    assert rc == 0, calls
    assert (nft_dir / SENTINEL).is_file()
    assert not (nft_dir / f"{SENTINEL}.retired").exists()
    nft = [c for c in calls if c.startswith("nft ")]
    assert [c.split(" sentinel=")[0] for c in nft] == [
        f"nft -c -f {tmp_path / 'nftables.conf'}",
        f"nft -f {tmp_path / 'nftables.conf'}",
    ]
    # validated with the sentinel already in place, so the check covers it
    assert all(f"sentinel={SENTINEL} " in c for c in nft), nft
    applied = calls.index(nft[-1])
    assert calls.index("wipe") < applied < calls.index("systemctl start k3s")


def test_a_sentinel_already_in_place_is_left_alone(tmp_path: Path) -> None:
    rc, calls, nft_dir = _leave(tmp_path, sentinel="present")
    assert rc == 0, calls
    assert (nft_dir / SENTINEL).is_file()
    assert not any(c.startswith("nft ") for c in calls), calls


def test_a_merged_config_that_does_not_validate_keeps_it_retired(tmp_path: Path) -> None:
    rc, calls, nft_dir = _leave(tmp_path, sentinel="retired", check_rc=1)
    assert rc == 0, calls
    assert (nft_dir / f"{SENTINEL}.retired").is_file()
    assert not (nft_dir / SENTINEL).exists()
    assert not any(c.startswith("nft -f") for c in calls), calls


def test_no_sentinel_at_all_is_a_no_op(tmp_path: Path) -> None:
    rc, calls, nft_dir = _leave(tmp_path, sentinel=None)
    assert rc == 0, calls
    assert list(nft_dir.iterdir()) == []
    assert not any(c.startswith("nft ") for c in calls), calls
