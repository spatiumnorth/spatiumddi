"""#1747 — a power loss right after a slot apply leaves NUL bytes in the
host's slot-upgrade files. Postgres refuses U+0000, so a NUL in the
heartbeat's ``last_upgrade_log_tail`` made the api 422 every heartbeat.
The readers must scrub / treat such a file as unknown."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st


def test_log_tail_never_carries_nul(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = tmp_path / "slot-upgrade.log"
    log.write_bytes(
        b"line one\napply succeeded - calling set-next-boot\n" + b"\x00" * 410
    )
    monkeypatch.setattr(st, "_SLOT_UPGRADE_LOG", log)
    tail = st._read_slot_upgrade_log_tail()
    assert "\x00" not in tail
    assert "apply succeeded" in tail


def test_log_tail_keeps_newline_and_tab(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = tmp_path / "slot-upgrade.log"
    log.write_bytes(b"a\tb\x01\x1b[0m\nc\x00\n")
    monkeypatch.setattr(st, "_SLOT_UPGRADE_LOG", log)
    assert st._read_slot_upgrade_log_tail() == "a\tb[0m\nc"


def test_all_nul_state_file_reads_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "slot-upgrade-pending.state"
    f.write_bytes(b"\x00" * 64)
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", f)
    assert st._last_upgrade_state_from_sidecar() == (None, None)


def test_state_with_nul_tail_still_parses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "slot-upgrade-pending.state"
    f.write_bytes(b"done 2026-10-11T16:01:54+00:00\n\x00\x00\x00")
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", f)
    state, stamp = st._last_upgrade_state_from_sidecar()
    assert state == "done" and stamp is not None


@pytest.mark.parametrize("raw", [b"\x00" * 50, b'{"step":"arming","de\x00\x00'])
def test_nul_or_truncated_progress_is_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: bytes
) -> None:
    f = tmp_path / "slot-upgrade.progress"
    f.write_bytes(raw)
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", f)
    assert st._read_slot_upgrade_progress() is None


def test_progress_strings_are_scrubbed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "slot-upgrade.progress"
    f.write_text(json.dumps({"step": "writing", "detail": "a\u0000b", "pct": 3}))
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", f)
    assert st._read_slot_upgrade_progress() == {
        "step": "writing",
        "detail": "ab",
        "pct": 3,
    }


# --- an unparseable state is healed by the clear paths ----------------------


@pytest.fixture
def appliance_state_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "appliance")
    paths = {
        "state": tmp_path / "slot-upgrade-pending.state",
        "trigger": tmp_path / "slot-upgrade-pending",
        "marker": tmp_path / "slot-upgrade-fired-url",
        "progress": tmp_path / "slot-upgrade.progress",
    }
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", paths["state"])
    monkeypatch.setattr(st, "_TRIGGER_FILE", paths["trigger"])
    monkeypatch.setattr(st, "_FIRED_URL_MARKER", paths["marker"])
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", paths["progress"])
    return paths


@pytest.mark.parametrize("raw", [b"\x00" * 64, b"", b"garbage"])
def test_clear_command_heals_an_unparseable_state(appliance_state_files, raw: bytes) -> None:
    """A NUL-filled state is not ``in-flight``, so no crash detector keys on
    it; left alone, the operator's clear could never be acknowledged."""
    appliance_state_files["state"].write_bytes(raw)
    assert st.apply_clear_upgrade_command() is True
    assert st._last_upgrade_state_from_sidecar()[0] == "ready"


def test_clear_command_still_leaves_a_live_inflight_alone(appliance_state_files) -> None:
    appliance_state_files["state"].write_text("in-flight 2026-10-11T16:01:54+00:00\n")
    st.apply_clear_upgrade_command()
    assert st._last_upgrade_state_from_sidecar()[0] == "in-flight"


def test_passive_heal_resets_an_unparseable_state(appliance_state_files) -> None:
    appliance_state_files["state"].write_bytes(b"\x00" * 64)
    st.clear_fleet_upgrade_marker()
    assert st._last_upgrade_state_from_sidecar()[0] == "ready"


def test_passive_heal_leaves_done_alone(appliance_state_files) -> None:
    appliance_state_files["state"].write_text("done 2026-10-11T16:01:54+00:00\n")
    st.clear_fleet_upgrade_marker()
    assert st._last_upgrade_state_from_sidecar()[0] == "done"


# --- the heartbeat body never carries a NUL, whatever field it came from ------


def test_heartbeat_body_is_sent_without_nul(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import types
    import uuid

    import httpx
    import structlog

    from spatium_supervisor import heartbeat as hb

    monkeypatch.setattr(
        st,
        "collect",
        lambda: {"some_host_field": "ok\x00\x00", "nested": {"k": ["a\x00b"]}},
    )
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(st, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(hb, "load_cert", lambda d: None)

    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content)
        raise httpx.ConnectError("stop here", request=request)

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=0, state_dir=tmp_path)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        hb.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    assert len(sent) == 1
    body = json.loads(sent[0])
    assert "\\u0000" not in sent[0].decode() and "\x00" not in sent[0].decode()
    assert body["some_host_field"] == "ok"
    assert body["nested"] == {"k": ["ab"]}
