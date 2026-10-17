"""Bounded-retry fire-guard for hash-keyed host-config runners (#387).

Before #387 each host-config runner (snmp / ntp / lldp / syslog / ssh /
resolver / firewall / timezone) re-fired its trigger every heartbeat
whenever ``config_hash != applied_hash`` — and since the runner only
writes the applied-hash sidecar on SUCCESS, a persistently-failing apply
(e.g. the bad ``chronyd -t -f`` validate flag) looped forever, flooding
thousands of ``.failed.<ts>`` sidecars and surfacing nothing. These
tests cover the guard that caps the re-fire RATE per distinct
config_hash with exponential backoff, the per-plane health reader that
surfaces a stuck apply, and the generalised sidecar prune.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state

# ── _hostcfg_should_fire: backoff logic (pure, time-injected) ─────────


def _fire_state(tmp_path: Path) -> Path:
    return tmp_path / "ntp-config-pending.fire-state"


def test_fresh_hash_fires_immediately(tmp_path: Path) -> None:
    # No fire-state yet → fire now, recorded as attempt 1.
    should, attempt = appliance_state._hostcfg_should_fire(
        _fire_state(tmp_path), "hashA", now=datetime.now(UTC)
    )
    assert should is True
    assert attempt == 1


def test_same_hash_backs_off_then_retries(tmp_path: Path) -> None:
    fs = _fire_state(tmp_path)
    t0 = datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC)
    appliance_state._write_fire_state(fs, "hashA", 1, t0)
    # Within the 60 s backoff window for attempt 1 → no re-fire.
    should, attempt = appliance_state._hostcfg_should_fire(
        fs, "hashA", now=t0 + timedelta(seconds=30)
    )
    assert should is False
    assert attempt == 1
    # Past the window → re-fire, attempt advances to 2.
    should, attempt = appliance_state._hostcfg_should_fire(
        fs, "hashA", now=t0 + timedelta(seconds=61)
    )
    assert should is True
    assert attempt == 2


def test_backoff_grows_exponentially(tmp_path: Path) -> None:
    fs = _fire_state(tmp_path)
    t0 = datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC)
    # 3 prior attempts → backoff = 60 * 2**2 = 240 s.
    appliance_state._write_fire_state(fs, "hashA", 3, t0)
    assert (
        appliance_state._hostcfg_should_fire(
            fs, "hashA", now=t0 + timedelta(seconds=239)
        )[0]
        is False
    )
    assert (
        appliance_state._hostcfg_should_fire(
            fs, "hashA", now=t0 + timedelta(seconds=241)
        )[0]
        is True
    )


def test_backoff_capped_at_ceiling(tmp_path: Path) -> None:
    fs = _fire_state(tmp_path)
    t0 = datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC)
    # A huge attempt count must not push the interval past the 15-min
    # ceiling — a stuck apply still retries (never permanently gives up),
    # so a fixed runner auto-recovers.
    appliance_state._write_fire_state(fs, "hashA", 50, t0)
    assert (
        appliance_state._hostcfg_should_fire(
            fs, "hashA", now=t0 + timedelta(seconds=899)
        )[0]
        is False
    )
    assert (
        appliance_state._hostcfg_should_fire(
            fs, "hashA", now=t0 + timedelta(seconds=901)
        )[0]
        is True
    )


def test_new_hash_resets_budget(tmp_path: Path) -> None:
    fs = _fire_state(tmp_path)
    t0 = datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC)
    appliance_state._write_fire_state(fs, "hashA", 9, t0)
    # Operator pushed a fresh config (new hash) → fire immediately,
    # attempt counter reset to 1, regardless of hashA's backoff.
    should, attempt = appliance_state._hostcfg_should_fire(
        fs, "hashB", now=t0 + timedelta(seconds=1)
    )
    assert should is True
    assert attempt == 1


def test_read_fire_state_tolerates_garbage(tmp_path: Path) -> None:
    fs = tmp_path / "fs"
    assert appliance_state._read_fire_state(fs) == ("", 0, None)  # missing
    fs.write_text("hashA\tnotanint\tnotadate\n")
    h, attempts, when = appliance_state._read_fire_state(fs)
    assert h == "hashA"
    assert attempts == 0
    assert when is None


# ── _fire_host_config: write path + short-circuits ────────────────────


def test_fire_writes_trigger_and_fire_state(tmp_path: Path) -> None:
    trigger = tmp_path / "ntp-config-pending"
    applied = tmp_path / "ntp-config-hash"
    fired = appliance_state._fire_host_config(trigger, applied, "h1", "payload\n")
    assert fired is True
    assert trigger.read_text() == "payload\n"
    fs = appliance_state._fire_state_path(trigger)
    assert fs.exists()
    assert appliance_state._read_fire_state(fs)[0] == "h1"


def test_fire_short_circuits_when_applied(tmp_path: Path) -> None:
    trigger = tmp_path / "ntp-config-pending"
    applied = tmp_path / "ntp-config-hash"
    applied.write_text("h1\n")
    # Desired hash already applied → no trigger, no fire.
    assert appliance_state._fire_host_config(trigger, applied, "h1", "x\n") is False
    assert not trigger.exists()


def test_fire_does_not_stack_on_pending_trigger(tmp_path: Path) -> None:
    trigger = tmp_path / "ntp-config-pending"
    applied = tmp_path / "ntp-config-hash"
    trigger.write_text("old\n")  # path unit hasn't consumed it yet
    assert appliance_state._fire_host_config(trigger, applied, "h2", "new\n") is False
    assert trigger.read_text() == "old\n"


# ── read_host_config_health: honest surfacing ─────────────────────────


def test_health_reports_stuck_and_clears_on_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trigger = tmp_path / "ntp-config-pending"
    applied = tmp_path / "ntp-config-hash"
    monkeypatch.setattr(
        appliance_state, "_HOST_CONFIG_PLANES", [("ntp", trigger, applied)]
    )
    # Never fired → nothing to report.
    assert appliance_state.read_host_config_health() == {}

    # Fired once, not yet applied → "retrying".
    appliance_state._write_fire_state(
        appliance_state._fire_state_path(trigger), "h1", 1, datetime.now(UTC)
    )
    health = appliance_state.read_host_config_health()
    assert health["ntp"]["state"] == "retrying"
    assert health["ntp"]["attempts"] == 1

    # Many failed attempts → "failing".
    appliance_state._write_fire_state(
        appliance_state._fire_state_path(trigger), "h1", 4, datetime.now(UTC)
    )
    assert appliance_state.read_host_config_health()["ntp"]["state"] == "failing"

    # Runner finally applied h1 → plane omitted (healthy).
    applied.write_text("h1\n")
    assert appliance_state.read_host_config_health() == {}


# ── prune ─────────────────────────────────────────────────────────────


def test_prune_keeps_newest_n(tmp_path: Path) -> None:
    trigger = tmp_path / "ntp-config-pending"
    for ts in range(1000, 1012):  # 12 stale .failed sidecars
        (tmp_path / f"ntp-config-pending.failed.{ts}").write_text("x")
    appliance_state._prune_host_config_sidecars(trigger, keep=5)
    remaining = sorted(p.name for p in tmp_path.glob("ntp-config-pending.failed.*"))
    assert len(remaining) == 5
    # Newest (highest timestamps) survive.
    assert remaining == [f"ntp-config-pending.failed.{ts}" for ts in range(1007, 1012)]


def test_prune_all_sweeps_every_family(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ntp = tmp_path / "ntp-config-pending"
    setnext = tmp_path / "slot-set-next-boot-pending"
    monkeypatch.setattr(appliance_state, "_PRUNABLE_TRIGGERS", [ntp, setnext])
    for ts in range(2000, 2010):
        (tmp_path / f"ntp-config-pending.failed.{ts}").write_text("x")
        (tmp_path / f"slot-set-next-boot-pending.done.{ts}").write_text("x")
    appliance_state.prune_all_trigger_sidecars(keep=3)
    assert len(list(tmp_path.glob("ntp-config-pending.failed.*"))) == 3
    assert len(list(tmp_path.glob("slot-set-next-boot-pending.done.*"))) == 3


# ── #2053: an EMPTY config hash (a plane turned off) ──────────────────


def test_empty_hash_fire_state_round_trips(tmp_path: Path) -> None:
    fs = tmp_path / "fs"
    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    appliance_state._write_fire_state(fs, "", 1, t0)
    # The leading tab must survive: fields must not shift left.
    assert appliance_state._read_fire_state(fs) == ("", 1, t0)


def _one_plane(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    trigger = tmp_path / "ssh-config-pending"
    applied = tmp_path / "ssh-config-hash"
    monkeypatch.setattr(
        appliance_state, "_HOST_CONFIG_PLANES", [("ssh", trigger, applied)]
    )
    return trigger, applied


def test_managed_then_off_reads_applied_not_retrying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trigger, applied = _one_plane(monkeypatch, tmp_path)
    appliance_state._write_fire_state(
        appliance_state._fire_state_path(trigger),
        "",
        1,
        datetime.now(UTC),
    )
    applied.write_text("\n")  # the runner applied 'off': empty hash sidecar
    assert appliance_state.read_host_config_health() == {}


def test_empty_hash_unapplied_is_still_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trigger, applied = _one_plane(monkeypatch, tmp_path)
    appliance_state._write_fire_state(
        appliance_state._fire_state_path(trigger), "", 2, datetime.now(UTC)
    )
    applied.write_text("oldhash\n")
    health = appliance_state.read_host_config_health()
    assert health["ssh"]["state"] == "retrying"
    assert health["ssh"]["attempts"] == 2


def test_never_fired_plane_is_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _trigger, applied = _one_plane(monkeypatch, tmp_path)
    applied.write_text("oldhash\n")
    assert appliance_state.read_host_config_health() == {}
