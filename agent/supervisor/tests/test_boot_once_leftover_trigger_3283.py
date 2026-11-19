"""A Boot once trigger left by an earlier boot does not block the next (#3283).

The host runner renames ``slot-set-next-boot-pending`` away only after
``spatium-upgrade-slot set-next-boot`` returns, so a reboot inside that run
leaves the trigger behind, its ``.state`` still reading "in-flight". The path
unit watches with ``PathChanged=``, which does not fire for a file already
there at boot, and the supervisor skipped every write while the file existed,
so every later Boot once on the node answered 200 and never ran.

A trigger written in an earlier boot is now stale: nothing will ever consume
it, so the supervisor writes the request over it (a rename onto the watched
path, which ``PathChanged=`` sees), as it already does for the fleet reboot
trigger (#1446). A trigger written in this boot is still the runner's.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture()
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    state: dict[str, object] = {"boot": "0b0b0b0b-2222-4222-8222-bbbbbbbbbbbb", "dir": tmp_path}
    monkeypatch.setattr(
        appliance_state,
        "_SET_NEXT_BOOT_TRIGGER_FILE",
        tmp_path / "slot-set-next-boot-pending",
    )
    monkeypatch.setattr(
        appliance_state,
        "_SET_NEXT_BOOT_FIRED_MARKER",
        tmp_path / "slot-set-next-boot-fired",
        raising=False,  # absent before #3284
    )
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_boot_id", lambda: state["boot"])
    return state


def _leftover(host: dict[str, object], slot: str, marker: str | None) -> Path:
    """What a reboot in the middle of a run leaves: the trigger (``slot``),
    its ``.state`` "in-flight", and the fire record when there was one."""
    d: Path = host["dir"]  # type: ignore[assignment]
    trigger = d / "slot-set-next-boot-pending"
    trigger.write_text(slot + "\n")
    (d / "slot-set-next-boot-pending.state").write_text(
        "in-flight 2026-11-01T18:01:46+00:00\n"
    )
    if marker is not None:
        (d / "slot-set-next-boot-fired").write_text(marker)
    return trigger


def test_a_trigger_from_before_the_upgrade_does_not_block_the_next_boot_once(
    host: dict[str, object],
) -> None:
    """The node as reported: the trigger written by a supervisor with no fire
    record, then a reboot; a Boot once of slot_a 15 minutes later never ran."""
    trigger = _leftover(host, "slot_b", None)
    assert appliance_state.maybe_fire_set_next_boot("slot_a", "slot_b") is True
    assert trigger.read_text() == "slot_a\n"
    assert appliance_state.read_set_next_boot_ran() == (None, None)  # not run yet


def test_a_run_cut_by_a_reboot_is_run_again_for_the_same_request(
    host: dict[str, object],
) -> None:
    """The request still stands (the row never saw slot_b booted): the run
    the reboot cut short is run again, once."""
    trigger = _leftover(host, "slot_b", "slot_b 0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa\n")
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    assert trigger.read_text() == "slot_b\n"
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is False
    trigger.rename(trigger.with_name(trigger.name + ".done.1793557000"))
    assert appliance_state.read_set_next_boot_ran() == ("slot_b", "0b0b0b0b-2222-4222-8222-bbbbbbbbbbbb")
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is False


def test_a_cut_run_is_not_reported_as_run(host: dict[str, object]) -> None:
    """Else the control plane would retire a request whose run never finished."""
    _leftover(host, "slot_b", "slot_b 0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa\n")
    assert appliance_state.read_set_next_boot_ran() == (None, None)


def test_a_trigger_written_in_this_boot_is_left_to_the_runner(
    host: dict[str, object],
) -> None:
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    d: Path = host["dir"]  # type: ignore[assignment]
    trigger = d / "slot-set-next-boot-pending"
    before = trigger.stat().st_mtime_ns
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is False
    assert trigger.stat().st_mtime_ns == before


def test_without_a_boot_id_a_present_trigger_is_left_alone(
    host: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing tells this boot from the one that wrote it: change nothing."""
    trigger = _leftover(host, "slot_b", None)
    monkeypatch.setattr(appliance_state, "read_boot_id", lambda: None)
    assert appliance_state.maybe_fire_set_next_boot("slot_a", "slot_b") is False
    assert trigger.read_text() == "slot_b\n"
