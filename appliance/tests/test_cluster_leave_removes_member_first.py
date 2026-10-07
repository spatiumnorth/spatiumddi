"""spatium-cluster-join leave removes this node's etcd member before it wipes,
and never wipes when the removal is not confirmed (#1541).

The real script is sourced as a library and ``do_leave`` runs with stubbed
``systemctl``, identity wipe and etcd runner, so the order of what it does is
what is asserted.

    python3 -m pytest appliance/tests/test_cluster_leave_removes_member_first.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-cluster-join"
)
LEAVE_CONFIRM = "SPATIUMDDI-CLUSTER-LEAVE-CONFIRM-V1"


def _leave(tmp_path: Path, evict_rc: int) -> tuple[int, list[str], str]:
    rs = tmp_path / "release-state"
    rs.mkdir()
    (rs / "cluster-leave-pending").write_text(f"{LEAVE_CONFIRM}\n")
    k3s_config = tmp_path / "config.yaml"
    k3s_config.write_text("cluster-init: true\n")
    calls = tmp_path / "calls"
    evict = tmp_path / "evict"
    evict.write_text(f'#!/bin/sh\necho "evict $*" >> "{calls}"\nexit {evict_rc}\n')
    evict.chmod(0o755)
    driver = f"""
        source "{SCRIPT}"
        systemctl() {{ echo "systemctl $*" >> "{calls}"; }}
        clean_k3s_runtime() {{ :; }}
        backup_and_wipe_identity() {{ echo "wipe" >> "{calls}"; }}
        wait_ready() {{ return 0; }}
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
    }
    r = subprocess.run(["bash", "-c", driver], env=env, capture_output=True, text=True, check=False)
    state = (rs / "cluster-join.state").read_text() if (rs / "cluster-join.state").exists() else ""
    return r.returncode, calls.read_text().splitlines() if calls.exists() else [], state


def test_member_is_removed_before_k3s_stops_and_the_wipe(tmp_path: Path) -> None:
    rc, calls, state = _leave(tmp_path, evict_rc=0)
    assert rc == 0, calls
    assert calls[0] == "evict --leave-self"
    assert calls.index("evict --leave-self") < calls.index("systemctl stop k3s")
    assert "wipe" in calls
    assert state.startswith("left")


def test_unconfirmed_removal_restarts_k3s_and_never_wipes(tmp_path: Path) -> None:
    rc, calls, state = _leave(tmp_path, evict_rc=1)
    assert rc == 1
    assert "wipe" not in calls
    assert "systemctl start k3s" in calls
    assert state.startswith("failed")
    assert not (tmp_path / "release-state" / "cluster-leave-pending").exists()


def test_a_node_that_joined_nobody_still_leaves(tmp_path: Path) -> None:
    rc, calls, state = _leave(tmp_path, evict_rc=2)
    assert rc == 0, calls
    assert "wipe" in calls
    assert state.startswith("left")
