"""Additional network interfaces, supervisor side (#4428).

The supervisor has three jobs on this plane: fire the host runner's trigger
when the control plane's desired set changes, CONFIRM an apply once a
heartbeat has round-tripped (the proof the node still reaches the control
plane, which is what stops the host's rollback), and report the node's
inventory and the runner's verdict back.

The confirm is the safety-critical one, so its refusals are the point: it
must not be written without a live revert window, nor for a config other
than the one the runner settled — and on a node that cannot heartbeat it is
never reached at all, which is the whole rollback.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st

H1 = "a" * 64
H2 = "b" * 64


@pytest.fixture
def host(tmp_path, monkeypatch):
    state = tmp_path / "release-state"
    state.mkdir()
    for attr, name in (
        ("_NETIF_TRIGGER_FILE", "netif-config-pending"),
        ("_NETIF_HASH_SIDECAR", "netif-config-hash"),
        ("_NETIF_STATUS_SIDECAR", "netif-status.json"),
        ("_NETIF_INVENTORY_SIDECAR", "netif-inventory.json"),
        ("_NETIF_DEADLINE_FILE", "netif-revert-deadline"),
        ("_NETIF_CONFIRM_FILE", "netif-confirm"),
    ):
        monkeypatch.setattr(st, attr, state / name)
    # The fire-guard keeps its ledger next to the trigger; keep the planes
    # list pointed at the redirected paths.
    monkeypatch.setattr(
        st,
        "_HOST_CONFIG_PLANES",
        [("netif", state / "netif-config-pending", state / "netif-config-hash")],
    )
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "appliance")
    return state


def block(interfaces, config_hash=H1, revert_seconds=180):
    return {
        "enabled": bool(interfaces),
        "config_hash": config_hash,
        "interfaces": interfaces,
        "revert_seconds": revert_seconds,
    }


IFACE = {
    "name": "ens19",
    "kind": "ethernet",
    "parent": None,
    "vlan_id": None,
    "addresses": ["10.9.0.2/24"],
    "mtu": None,
    "up": True,
    "routes": [],
}


# ── firing ───────────────────────────────────────────────────────────


def test_a_new_desired_set_writes_the_trigger_in_the_runners_format(host):
    assert st.maybe_fire_netif_reload(block([IFACE])) is True
    lines = (host / "netif-config-pending").read_text().splitlines()
    assert lines[0] == "enabled"
    assert lines[1] == H1
    body = json.loads(lines[2])
    assert body == {"interfaces": [IFACE], "revert_seconds": 180}
    # Owner-only, like every trigger: it can carry config an operator typed.
    assert (host / "netif-config-pending").stat().st_mode & 0o077 == 0


def test_an_empty_set_is_the_disable_marker_not_a_skip(host):
    """Removal is an ordinary operator action on this plane."""
    assert st.maybe_fire_netif_reload(block([], config_hash=H2)) is True
    assert (host / "netif-config-pending").read_text().splitlines()[0] == "disabled"


def test_no_instruction_means_do_nothing_never_teardown(host):
    # The control plane ships interfaces=None when the stored set stops
    # validating, and an empty list is this plane's teardown command.
    assert st.maybe_fire_netif_reload(block(None)) is False
    assert st.maybe_fire_netif_reload(block([IFACE], config_hash="")) is False
    assert st.maybe_fire_netif_reload({"config_hash": H1}) is False
    assert st.maybe_fire_netif_reload(None) is False
    assert st.maybe_fire_netif_reload("x") is False
    assert not (host / "netif-config-pending").exists()


def test_an_already_settled_hash_is_idempotent(host):
    (host / "netif-config-hash").write_text(H1 + "\n")
    assert st.maybe_fire_netif_reload(block([IFACE])) is False
    assert not (host / "netif-config-pending").exists()


def test_an_unconsumed_trigger_is_not_stacked(host):
    assert st.maybe_fire_netif_reload(block([IFACE])) is True
    first = (host / "netif-config-pending").read_text()
    assert st.maybe_fire_netif_reload(block([IFACE], config_hash=H2)) is False
    assert (host / "netif-config-pending").read_text() == first


def test_a_garbage_revert_window_falls_back_to_the_default(host):
    st.maybe_fire_netif_reload(block([IFACE], revert_seconds="soon"))
    body = json.loads((host / "netif-config-pending").read_text().splitlines()[2])
    assert body["revert_seconds"] == 180


def test_it_only_acts_on_an_appliance(host, monkeypatch):
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    assert st.maybe_fire_netif_reload(block([IFACE])) is False
    assert st.maybe_confirm_netif(block([IFACE]), sent_after()) is False
    assert not list(host.iterdir())


def test_the_plane_is_registered_with_the_stuck_apply_reporter():
    assert "netif" in [p[0] for p in st._HOST_CONFIG_PLANES]


# ── confirming ───────────────────────────────────────────────────────


def sent_after():
    """A request sent after the runner armed its deadline."""
    return time.time() + 1


def arm(host, settled=H1):
    (host / "netif-revert-deadline").write_text(f"{int(time.time()) + 100}\n")
    (host / "netif-config-hash").write_text(settled + "\n")


def test_a_heartbeat_that_round_tripped_confirms_the_applied_config(host):
    arm(host)
    assert st.maybe_confirm_netif(block([IFACE]), sent_after()) is True
    assert (host / "netif-confirm").read_text().strip() == H1


def test_a_heartbeat_sent_before_the_deadline_was_armed_confirms_nothing(host):
    """The long-poll answering right after an apply was sent BEFORE it, over
    the old network: its response proves nothing about the new one (#4428)."""
    sent = time.time() - 5
    arm(host)
    assert st.maybe_confirm_netif(block([IFACE]), sent) is False
    assert st.maybe_confirm_netif(block([IFACE]), None) is False
    assert not (host / "netif-confirm").exists()


def test_nothing_is_confirmed_without_a_live_revert_window(host):
    (host / "netif-config-hash").write_text(H1 + "\n")
    assert st.maybe_confirm_netif(block([IFACE]), sent_after()) is False
    assert not (host / "netif-confirm").exists()


def test_a_config_the_runner_did_not_settle_is_never_confirmed(host):
    """The operator replaced the config while one was in flight: confirming
    the NEW hash would keep a change nobody reviewed on the node."""
    arm(host, settled=H1)
    assert st.maybe_confirm_netif(block([IFACE], config_hash=H2), sent_after()) is False
    assert not (host / "netif-confirm").exists()


def test_confirm_is_not_rewritten_while_one_is_pending(host):
    arm(host)
    assert st.maybe_confirm_netif(block([IFACE]), sent_after()) is True
    assert st.maybe_confirm_netif(block([IFACE]), sent_after()) is False


def test_a_block_with_no_hash_confirms_nothing(host):
    arm(host)
    assert st.maybe_confirm_netif(block([IFACE], config_hash=""), sent_after()) is False
    assert st.maybe_confirm_netif({}, sent_after()) is False


# ── reporting ────────────────────────────────────────────────────────


def test_nothing_reported_is_none_not_an_empty_block(host):
    assert st.read_netif_state() is None


def test_a_fresh_inventory_and_the_runner_verdict_are_reported(host):
    inv = {"at_epoch": int(time.time()), "interfaces": [{"name": "ens19"}], "routes": []}
    (host / "netif-inventory.json").write_text(json.dumps(inv))
    (host / "netif-status.json").write_text(
        json.dumps({"state": "reverted", "hash": H1, "error": "lost contact"})
    )
    out = st.read_netif_state()
    assert out["inventory"] == inv
    assert out["apply_status"]["state"] == "reverted"


def test_a_stale_inventory_is_withheld_not_reported_as_current(host):
    """A dead timer must read as UNKNOWN: validating a change against a
    network picture from an hour ago is how a node gets cut off."""
    old = {"at_epoch": int(time.time()) - 3600, "interfaces": [], "routes": []}
    (host / "netif-inventory.json").write_text(json.dumps(old))
    assert st.read_netif_state() is None
    (host / "netif-status.json").write_text(json.dumps({"state": "applied", "hash": H1}))
    out = st.read_netif_state()
    assert "inventory" not in out and out["apply_status"]["state"] == "applied"


def test_corrupt_sidecars_read_as_absent(host):
    (host / "netif-inventory.json").write_text("{not json")
    (host / "netif-status.json").write_text("[1, 2]")
    assert st.read_netif_state() is None


def test_the_heartbeat_wires_fire_then_confirm_from_the_response_block():
    src = (Path(st.__file__).parent / "heartbeat.py").read_text()
    fire = src.index('maybe_fire_netif_reload(body_out.get("netif_settings"))')
    confirm = src.index('maybe_confirm_netif(\n        body_out.get("netif_settings"), request_sent_at')
    assert fire < confirm
    # Folded into cluster_health so the control plane stores it verbatim.
    assert '_extra["netif"] = _netif' in Path(st.__file__).read_text()
