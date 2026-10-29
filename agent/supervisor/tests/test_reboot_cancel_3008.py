"""#3008 — a console F9 cancel is reported on the heartbeat and then dropped.

The marker the console writes carries the boot it was made in; the supervisor
reports it (only from that boot), and once the control plane has the heartbeat
drops it together with the once-per-boot fire marker, so a new Fleet request in
the same boot can fire again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture()
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    state: dict[str, object] = {"boot": "boot-a"}
    monkeypatch.setattr(appliance_state, "_REBOOT_TRIGGER_FILE", tmp_path / "reboot-pending-fleet")
    monkeypatch.setattr(
        appliance_state, "_REBOOT_FIRED_BOOT_MARKER", tmp_path / "reboot-fleet-fired-boot"
    )
    monkeypatch.setattr(appliance_state, "_REBOOT_CANCEL_MARKER", tmp_path / "reboot-cancelled")
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_boot_id", lambda: state["boot"])
    state["dir"] = tmp_path
    return state


def test_the_cancel_is_reported_from_its_own_boot_only(host: dict[str, object]) -> None:
    d: Path = host["dir"]  # type: ignore[assignment]
    assert appliance_state.read_reboot_cancel() is None
    (d / "reboot-cancelled").write_text("boot-a\n")
    assert appliance_state.read_reboot_cancel() == "boot-a"
    host["boot"] = "boot-b"
    assert appliance_state.read_reboot_cancel() is None


def test_acking_the_cancel_lets_a_new_request_fire_in_the_same_boot(
    host: dict[str, object],
) -> None:
    d: Path = host["dir"]  # type: ignore[assignment]
    assert appliance_state.maybe_fire_reboot(True) is True
    (d / "reboot-pending-fleet").rename(d / "reboot-pending-fleet.done")  # runner took it
    assert appliance_state.maybe_fire_reboot(True) is False  # once per boot
    (d / "reboot-cancelled").write_text("boot-a\n")  # F9

    appliance_state.ack_reboot_cancel()

    assert not (d / "reboot-cancelled").exists()
    assert appliance_state.maybe_fire_reboot(True) is True


def test_acking_with_no_cancel_keeps_the_fire_marker(host: dict[str, object]) -> None:
    d: Path = host["dir"]  # type: ignore[assignment]
    assert appliance_state.maybe_fire_reboot(True) is True
    appliance_state.ack_reboot_cancel()
    assert (d / "reboot-fleet-fired-boot").exists()
