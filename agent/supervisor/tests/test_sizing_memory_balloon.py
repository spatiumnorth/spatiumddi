"""The control plane is sized from the largest MemTotal seen this boot (#1585).

A virtio balloon changes the guest's MemTotal while it runs, and the sizing is
linear at MiB resolution, so before #1585 every balloon step re-rendered
spatium-control (new api rollout + migrate Job, and on a bigger seed a CNPG
rolling restart). A balloon only takes memory away from what the node booted
with, so ``sizing_memory_mib`` keeps the largest value seen since this boot,
per ``boot_id`` in the state dir.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import heartbeat, k8s_api

BOOT_A = "11111111-1111-1111-1111-111111111111"
BOOT_B = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def node(tmp_path, monkeypatch):
    """A node whose MemTotal and boot_id the test sets."""
    state = {"mem": 4923, "boot": BOOT_A}
    boot_file = tmp_path / "boot_id"

    def mem() -> int | None:
        return state["mem"]

    monkeypatch.setattr(k8s_api, "node_memory_mib", mem)

    class _Boot:
        def read_text(self, encoding: str = "utf-8") -> str:
            boot_file.write_text(state["boot"] + "\n", encoding=encoding)
            return boot_file.read_text(encoding=encoding)

    monkeypatch.setattr(k8s_api, "_BOOT_ID_PATH", _Boot())
    sd = tmp_path / "state"
    sd.mkdir()
    return state, sd


def test_a_balloon_step_down_keeps_the_size(node) -> None:
    state, sd = node
    assert k8s_api.sizing_memory_mib(sd) == 4923
    # The issue's steps: 4923 → 4703 → 4503 → 4303 MiB.
    for ballooned in (4703, 4503, 4303):
        state["mem"] = ballooned
        assert k8s_api.sizing_memory_mib(sd) == 4923
    # Deflated again: still the same size, so nothing re-renders.
    state["mem"] = 4923
    assert k8s_api.sizing_memory_mib(sd) == 4923


def test_the_sizing_does_not_move_while_the_balloon_does(node) -> None:
    state, sd = node
    seen = set()
    for ballooned in (4923, 4703, 4503, 4303, 4923):
        state["mem"] = ballooned
        seen.add(json.dumps(k8s_api.control_plane_resources(k8s_api.sizing_memory_mib(sd))))
    assert len(seen) == 1


def test_more_memory_is_taken_at_once(node) -> None:
    """A hot-plug (or a deflate past the boot value) raises the size."""
    state, sd = node
    assert k8s_api.sizing_memory_mib(sd) == 4923
    state["mem"] = 7936
    assert k8s_api.sizing_memory_mib(sd) == 7936


def test_a_reboot_with_less_ram_sizes_down(node) -> None:
    """A real downgrade needs a reboot, and a new boot_id starts over."""
    state, sd = node
    state["mem"] = 7936
    assert k8s_api.sizing_memory_mib(sd) == 7936
    state["mem"], state["boot"] = 3840, BOOT_B
    assert k8s_api.sizing_memory_mib(sd) == 3840


def test_a_supervisor_restart_while_ballooned_keeps_the_size(node) -> None:
    """The maximum lives in the state dir, not in the process."""
    state, sd = node
    assert k8s_api.sizing_memory_mib(sd) == 4923
    state["mem"] = 4303
    # A new process reads the same file: nothing in memory carries over.
    assert json.loads((sd / "sizing-memory.json").read_text())["mem_mib"] == 4923
    assert k8s_api.sizing_memory_mib(sd) == 4923


def test_unreadable_memtotal_is_none(node) -> None:
    state, sd = node
    state["mem"] = None
    assert k8s_api.sizing_memory_mib(sd) is None


def test_an_unwritable_state_dir_falls_back_to_memtotal(node, tmp_path) -> None:
    state, _sd = node
    missing = tmp_path / "does-not-exist"
    assert k8s_api.sizing_memory_mib(missing) == 4923
    state["mem"] = 4303
    assert k8s_api.sizing_memory_mib(missing) == 4303


def test_a_corrupt_record_is_replaced(node) -> None:
    _state, sd = node
    (sd / "sizing-memory.json").write_text("{not json", encoding="utf-8")
    assert k8s_api.sizing_memory_mib(sd) == 4923
    assert json.loads((sd / "sizing-memory.json").read_text())["mem_mib"] == 4923


def test_the_heartbeat_sizes_from_the_boot_maximum() -> None:
    src = Path(heartbeat.__file__).read_text(encoding="utf-8")
    assert "mem_total_mib=k8s_api.sizing_memory_mib(cfg.state_dir)" in src
    assert "mem_total_mib=k8s_api.node_memory_mib()" not in src
