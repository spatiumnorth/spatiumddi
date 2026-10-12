"""The fleet reboot trigger is written at most once per boot (#1446).

The control plane now keeps sending ``reboot_requested`` until a heartbeat
arrives from a new boot, so every heartbeat between writing the trigger and
the host going down carries it again. Re-writing the trigger each time could
leave one behind the shutdown never consumed, and the old ``exists()`` check
then made the NEXT reboot request a silent no-op.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture()
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    state: dict[str, object] = {"boot": "boot-a"}
    trigger = tmp_path / "reboot-pending-fleet"
    marker = tmp_path / "reboot-fleet-fired-boot"
    monkeypatch.setattr(appliance_state, "_REBOOT_TRIGGER_FILE", trigger)
    monkeypatch.setattr(appliance_state, "_REBOOT_FIRED_BOOT_MARKER", marker)
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_boot_id", lambda: state["boot"])
    state["trigger"] = trigger
    return state


def _runner_consumes(host: dict[str, object]) -> None:
    trigger: Path = host["trigger"]  # type: ignore[assignment]
    trigger.rename(trigger.with_name(trigger.name + ".done"))


def test_fires_once_and_not_again_in_the_same_boot(host: dict[str, object]) -> None:
    assert appliance_state.maybe_fire_reboot(True) is True
    _runner_consumes(host)  # the host runner moves it aside and reboots
    # Heartbeats before the shutdown still carry the request.
    assert appliance_state.maybe_fire_reboot(True) is False
    assert not host["trigger"].exists()  # type: ignore[attr-defined]


def test_a_new_boot_fires_a_new_request(host: dict[str, object]) -> None:
    assert appliance_state.maybe_fire_reboot(True) is True
    _runner_consumes(host)
    host["boot"] = "boot-b"
    assert appliance_state.maybe_fire_reboot(True) is True


def test_a_stale_trigger_from_an_earlier_boot_is_rewritten(host: dict[str, object]) -> None:
    """A trigger the runner never consumed must not swallow the next request."""
    assert appliance_state.maybe_fire_reboot(True) is True  # left unconsumed
    host["boot"] = "boot-b"
    assert appliance_state.maybe_fire_reboot(True) is True


def test_nothing_happens_without_a_request_or_off_appliance(
    host: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert appliance_state.maybe_fire_reboot(False) is False
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "k8s")
    assert appliance_state.maybe_fire_reboot(True) is False
    assert not host["trigger"].exists()  # type: ignore[attr-defined]
