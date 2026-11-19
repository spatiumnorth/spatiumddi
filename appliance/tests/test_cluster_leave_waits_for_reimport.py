"""#1859 — a leave waits for its fresh k3s past READY_TIMEOUT.

The leave wipes containerd's image store and its import cache with the
node's cluster identity (#1085), so the fresh single-node k3s imports every
airgap image again before its kubelet reports Ready. On the demote drill's
nested rigs that took longer than READY_TIMEOUT (180 s): the runner wrote
`failed`, the row stayed `failed`, and k3s came up anyway a little later.
The node is already wiped by then, so failing early recovers nothing. The
leave now waits LEAVE_READY_TIMEOUT (600 s) more, the budget #1052 gives a
join that registered with the seed's etcd, before it calls the leave
failed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-cluster-join"
)


def _leave_wait(first: int, second: int, env: dict[str, str] | None = None):
    """Run leave_wait_ready with wait_ready stubbed: its first call returns
    ``first``, any later one ``second``. Returns (rc, stdout lines)."""
    script = f"""
source "{SCRIPT}"
log() {{ echo "LOG: $*"; }}
n=0
wait_ready() {{
    n=$((n + 1))
    echo "WAIT ${{1:-READY_TIMEOUT}}"
    if [ "$n" -eq 1 ]; then return {first}; fi
    return {second}
}}
leave_wait_ready
"""
    proc = subprocess.run(
        ["bash", "-c", script],
        env={**os.environ, "SPATIUM_CLUSTER_JOIN_LIB": "1", **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout.splitlines()


def test_a_k3s_ready_in_time_is_waited_for_once() -> None:
    rc, out = _leave_wait(0, 1)
    assert rc == 0
    assert out == ["WAIT READY_TIMEOUT"]


def test_a_slow_k3s_gets_the_leave_budget_more() -> None:
    rc, out = _leave_wait(1, 0)
    assert rc == 0
    assert out[0] == "WAIT READY_TIMEOUT"
    assert out[1].startswith("LOG: LEAVE: k3s not Ready within 180s")
    assert "waiting up to 600s more (#1859)" in out[1]
    assert out[2] == "WAIT 600"


def test_the_leave_budget_can_be_set() -> None:
    rc, out = _leave_wait(1, 0, {"SPATIUM_LEAVE_READY_TIMEOUT": "900"})
    assert rc == 0
    assert out[-1] == "WAIT 900"


def test_a_k3s_never_ready_still_fails_the_leave() -> None:
    rc, out = _leave_wait(1, 1)
    assert rc == 1
    assert out[-1] == "WAIT 600"


def _do_leave() -> str:
    text = SCRIPT.read_text()
    start = text.index("do_leave() {")
    return text[start : text.index("\n}\n", start)]


def test_the_leave_waits_with_the_leave_budget() -> None:
    dl = _do_leave()
    assert "systemctl start k3s && leave_wait_ready; then" in dl
    assert "systemctl start k3s && wait_ready; then" not in dl
    # The failure names the whole budget it waited.
    assert "did not come Ready within $((READY_TIMEOUT + LEAVE_READY_TIMEOUT))s" in dl
    # The reason the row carries is unchanged.
    assert 'write_state failed "leave failed; k3s not Ready"' in dl
