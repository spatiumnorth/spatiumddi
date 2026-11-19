"""One Fleet Boot once is one set-next-boot run (#3284).

The control plane keeps ``desired_next_boot_slot`` on the heartbeat response
until the node reports that slot as its ``current_slot``, and the host runner
renames its trigger away when it finishes. The supervisor used to fire
whenever no trigger was present, so every heartbeat between the Boot once and
the reboot re-ran ``set-next-boot`` (four runs in 98 s on a test node), and a
trial of that slot that fell back left the request standing, so the node
re-armed the slot that had just failed on every heartbeat.

Now the supervisor records the slot it fired and the boot it fired in, fires
at most once per request, and forgets the record only when a response carries
no request. It reports the run once the runner has taken the trigger, so the
control plane can retire a request that a reboot has spent.
"""

from __future__ import annotations

import json
import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog

from spatium_supervisor import appliance_state
from spatium_supervisor import heartbeat as hb


@pytest.fixture()
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    state: dict[str, object] = {
        "boot": "0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa",
        "dir": tmp_path,
    }
    monkeypatch.setattr(
        appliance_state,
        "_SET_NEXT_BOOT_TRIGGER_FILE",
        tmp_path / "slot-set-next-boot-pending",
    )
    monkeypatch.setattr(
        appliance_state,
        "_SET_NEXT_BOOT_FIRED_MARKER",
        tmp_path / "slot-set-next-boot-fired",
        raising=False,  # absent before #3284: the tests then fail on behaviour
    )
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "read_boot_id", lambda: state["boot"])
    return state


def _trigger(host: dict[str, object]) -> Path:
    d: Path = host["dir"]  # type: ignore[assignment]
    return d / "slot-set-next-boot-pending"


def _runner_consumes(host: dict[str, object], n: int) -> None:
    """The host runner's last act: the trigger renamed to ``.done.<epoch>``."""
    trigger = _trigger(host)
    trigger.rename(trigger.with_name(f"{trigger.name}.done.{1793556000 + n}"))


def test_one_boot_once_is_one_run_however_many_heartbeats_carry_it(
    host: dict[str, object],
) -> None:
    """The reported loop: the request stays on every response until the reboot."""
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    assert _trigger(host).read_text() == "slot_b\n"
    _runner_consumes(host, 0)
    for _ in range(4):  # the heartbeats before the operator reboots
        assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is False
    assert not _trigger(host).exists()


def test_a_trial_that_fell_back_does_not_rearm_the_slot_that_failed(
    host: dict[str, object],
) -> None:
    """The trial of slot_b never heartbeat from slot_b (so the request was
    never cleared) and GRUB fell back to slot_a: a new boot, the same request."""
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    _runner_consumes(host, 0)
    host["boot"] = (
        "0c0c0c0c-3333-4333-8333-cccccccccccc"  # the fallback boot, on slot_a again
    )
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is False
    assert not _trigger(host).exists()


def test_a_new_request_after_the_old_one_was_retired_runs(
    host: dict[str, object],
) -> None:
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    _runner_consumes(host, 0)
    appliance_state.forget_set_next_boot_fire()  # a response carried no request
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    assert _trigger(host).read_text() == "slot_b\n"


def test_a_request_for_the_other_slot_is_a_new_request(host: dict[str, object]) -> None:
    """Running slot_b now (a committed trial), the operator asks for slot_a."""
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    _runner_consumes(host, 0)
    host["boot"] = "0b0b0b0b-2222-4222-8222-bbbbbbbbbbbb"
    assert appliance_state.maybe_fire_set_next_boot("slot_a", "slot_b") is True
    assert _trigger(host).read_text() == "slot_a\n"


def test_the_run_is_reported_once_the_runner_took_the_trigger(
    host: dict[str, object],
) -> None:
    assert appliance_state.read_set_next_boot_ran() == (None, None)
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is True
    # Still the runner's: nothing ran yet.
    assert appliance_state.read_set_next_boot_ran() == (None, None)
    _runner_consumes(host, 0)
    assert appliance_state.read_set_next_boot_ran() == (
        "slot_b",
        "0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa",
    )
    host["boot"] = "0c0c0c0c-3333-4333-8333-cccccccccccc"
    # The boot it ran in, not this one: that is how a reboot shows.
    assert appliance_state.read_set_next_boot_ran() == (
        "slot_b",
        "0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa",
    )
    appliance_state.forget_set_next_boot_fire()
    assert appliance_state.read_set_next_boot_ran() == (None, None)


def test_nothing_fires_for_the_running_slot_or_off_appliance(
    host: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert appliance_state.maybe_fire_set_next_boot("slot_a", "slot_a") is False
    assert appliance_state.maybe_fire_set_next_boot("slot_c", "slot_a") is False
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "k8s")
    assert appliance_state.maybe_fire_set_next_boot("slot_b", "slot_a") is False
    assert appliance_state.read_set_next_boot_ran() == (None, None)
    assert not _trigger(host).exists()


# --- the heartbeat: what it reports, and when the record is forgotten


def _heartbeat_with_response(
    monkeypatch: pytest.MonkeyPatch,
    host: dict[str, object],
    response: dict[str, object],
) -> list[dict[str, object]]:
    """One heartbeat whose response is ``response``. Everything but the
    set-next-boot fire is the quiet docker path; the fire runs as on an
    appliance, from slot_a."""
    d: Path = host["dir"]  # type: ignore[assignment]
    real_ran = appliance_state.read_set_next_boot_ran

    def ran() -> tuple[str | None, str | None]:
        with monkeypatch.context() as m:
            m.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
            return real_ran()

    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(
        appliance_state,
        "collect",
        lambda: {
            "boot_id": host["boot"],
            "current_slot": "slot_a",
            "next_boot_ran_slot": ran()[0],
            "next_boot_ran_boot_id": ran()[1],
        },
    )
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(
        hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid"
    )
    monkeypatch.setattr(hb, "load_cert", lambda d: None)
    real_fire = appliance_state.maybe_fire_set_next_boot

    def fire(desired: str | None, current: str | None) -> bool:
        with monkeypatch.context() as m:
            m.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
            return real_fire(desired, current)

    monkeypatch.setattr(appliance_state, "maybe_fire_set_next_boot", fire)
    sent: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=response)

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=30, state_dir=d / "state")
    (d / "state").mkdir(exist_ok=True)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        hb.heartbeat_once(cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger())  # type: ignore[arg-type]
    return sent


def test_heartbeats_fire_once_and_report_the_run(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, object]
) -> None:
    request = {"desired_next_boot_slot": "slot_b"}
    _heartbeat_with_response(monkeypatch, host, request)
    assert _trigger(host).read_text() == "slot_b\n"
    _runner_consumes(host, 0)
    sent = _heartbeat_with_response(monkeypatch, host, request)
    sent += _heartbeat_with_response(monkeypatch, host, request)
    assert not _trigger(host).exists()  # no second run
    assert sent[-1]["next_boot_ran_slot"] == "slot_b"
    assert sent[-1]["next_boot_ran_boot_id"] == "0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa"


def test_a_response_without_a_request_forgets_the_run(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, object]
) -> None:
    d: Path = host["dir"]  # type: ignore[assignment]
    _heartbeat_with_response(monkeypatch, host, {"desired_next_boot_slot": "slot_b"})
    _runner_consumes(host, 0)
    _heartbeat_with_response(monkeypatch, host, {"desired_next_boot_slot": "slot_b"})
    assert (d / "slot-set-next-boot-fired").exists()
    # The control plane retired the request: the next Boot once is a new one.
    _heartbeat_with_response(monkeypatch, host, {"desired_next_boot_slot": None})
    assert not (d / "slot-set-next-boot-fired").exists()
    sent = _heartbeat_with_response(
        monkeypatch, host, {"desired_next_boot_slot": "slot_b"}
    )
    assert sent[-1]["next_boot_ran_slot"] is None
    assert _trigger(host).read_text() == "slot_b\n"


def test_a_damaged_record_never_reaches_the_heartbeat(host: dict[str, object]) -> None:
    """A power cut can leave NUL bytes in a file (#1747): the record's boot id
    is then read as none, and a heartbeat never carries the bytes (the
    control plane would refuse every heartbeat over a value that long)."""
    d: Path = host["dir"]  # type: ignore[assignment]
    (d / "slot-set-next-boot-fired").write_bytes(b"slot_b " + b"\x00" * 300 + b"\n")
    assert appliance_state.read_set_next_boot_ran() == ("slot_b", None)
    (d / "slot-set-next-boot-fired").write_bytes(b"\x00" * 64)
    assert appliance_state.read_set_next_boot_ran() == (None, None)
    (d / "slot-set-next-boot-fired").write_bytes(b"slot_b \xff\xfe\n")
    assert appliance_state.read_set_next_boot_ran() == ("slot_b", None)
