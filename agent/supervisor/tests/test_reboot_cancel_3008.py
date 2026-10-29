"""#3008 — a console F9 cancel is reported on the heartbeat and then dropped.

The marker the console writes carries the boot it was made in; the supervisor
reports it (only from that boot), and once a response proves the control plane
retired the request (``reboot_requested`` false) it empties it and drops the
once-per-boot fire marker, so a new Fleet request in the same boot can fire.
Any other response keeps both, or the request still on the row would reboot
the node the operator just cancelled.
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

    appliance_state.ack_reboot_cancel("boot-a", False)  # the api retired it

    assert appliance_state.read_reboot_cancel() is None
    assert appliance_state.maybe_fire_reboot(True) is True


def test_acking_with_no_cancel_keeps_the_fire_marker(host: dict[str, object]) -> None:
    d: Path = host["dir"]  # type: ignore[assignment]
    assert appliance_state.maybe_fire_reboot(True) is True
    appliance_state.ack_reboot_cancel(None, False)
    assert (d / "reboot-fleet-fired-boot").exists()


# --- the heartbeat: the fire marker goes only on proof the request was retired


def _heartbeat_with_response(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, object], response: dict[str, object]
) -> list[dict[str, object]]:
    """One heartbeat whose response is ``response``. Everything but the reboot
    fire is the quiet docker path; the fire itself runs as on an appliance."""
    d: Path = host["dir"]  # type: ignore[assignment]
    real_read_cancel = appliance_state.read_reboot_cancel
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(
        appliance_state,
        "collect",
        lambda: {"boot_id": host["boot"], "reboot_cancelled_boot_id": real_read_cancel()},
    )
    monkeypatch.setattr(appliance_state, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(hb, "load_cert", lambda d: None)
    real_fire = appliance_state.maybe_fire_reboot

    def fire(requested: bool) -> bool:
        with monkeypatch.context() as m:
            m.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
            return real_fire(requested)

    monkeypatch.setattr(appliance_state, "maybe_fire_reboot", fire)
    sent: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=response)

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=30, state_dir=d / "state")
    (d / "state").mkdir(exist_ok=True)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        hb.heartbeat_once(cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger())  # type: ignore[arg-type]
    return sent


def _fired_then_cancelled(host: dict[str, object]) -> Path:
    d: Path = host["dir"]  # type: ignore[assignment]
    with pytest.MonkeyPatch.context() as m:
        m.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
        assert appliance_state.maybe_fire_reboot(True) is True
    (d / "reboot-pending-fleet").unlink()  # F9 removed the trigger
    (d / "reboot-cancelled").write_text("boot-a\n")  # and recorded the cancel
    return d


@pytest.mark.parametrize(
    "response",
    [
        # An older api ignores the report and still holds the request, as does
        # a newer one whose boot ids did not match.
        {"reboot_requested": True},
        # No answer about the request at all is not proof it was retired.
        {},
    ],
)
def test_a_cancel_the_control_plane_did_not_retire_does_not_reboot_the_node(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, object], response: dict[str, object]
) -> None:
    """REGRESSION: the fire marker was dropped on ANY response, so the same
    heartbeat that carried the still-set request re-fired the reboot the
    operator had just cancelled."""
    d = _fired_then_cancelled(host)
    sent = _heartbeat_with_response(monkeypatch, host, response)
    assert sent and sent[0]["reboot_cancelled_boot_id"] == "boot-a"
    assert not (d / "reboot-pending-fleet").exists()
    assert (d / "reboot-fleet-fired-boot").read_text().strip() == "boot-a"
    # Still reported, so a newer api can still retire it.
    assert appliance_state.read_reboot_cancel() == "boot-a"


def test_a_retired_request_drops_both_markers(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, object]
) -> None:
    d = _fired_then_cancelled(host)
    _heartbeat_with_response(monkeypatch, host, {"reboot_requested": False})
    assert not (d / "reboot-pending-fleet").exists()
    assert not (d / "reboot-fleet-fired-boot").exists()
    assert appliance_state.read_reboot_cancel() is None


def test_a_cancel_made_after_the_heartbeat_was_built_is_kept(
    monkeypatch: pytest.MonkeyPatch, host: dict[str, object]
) -> None:
    """REGRESSION: the ack read the marker AFTER the response, so a cancel
    written while the heartbeat was in flight was dropped (and the fire marker
    with it) though the control plane had never been told of it."""
    d: Path = host["dir"]  # type: ignore[assignment]
    with pytest.MonkeyPatch.context() as m:
        m.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
        assert appliance_state.maybe_fire_reboot(True) is True
    (d / "reboot-pending-fleet").unlink()
    real_post = httpx.Client.post

    def post_then_cancel(self: httpx.Client, *a: object, **k: object) -> httpx.Response:
        (d / "reboot-cancelled").write_text("boot-a\n")  # F9 while in flight
        return real_post(self, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx.Client, "post", post_then_cancel)
    sent = _heartbeat_with_response(monkeypatch, host, {"reboot_requested": True})
    assert sent[0]["reboot_cancelled_boot_id"] is None
    assert not (d / "reboot-pending-fleet").exists()
    assert (d / "reboot-fleet-fired-boot").exists()
    assert appliance_state.read_reboot_cancel() == "boot-a"


def test_a_new_fire_supersedes_an_earlier_cancel(host: dict[str, object]) -> None:
    """A reboot fired after a cancel is not that cancel: reporting it on would
    have the control plane retire the new request as if it had been
    cancelled too."""
    d: Path = host["dir"]  # type: ignore[assignment]
    (d / "reboot-cancelled").write_text("boot-a\n")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
        assert appliance_state.maybe_fire_reboot(True) is True
    assert appliance_state.read_reboot_cancel() is None
