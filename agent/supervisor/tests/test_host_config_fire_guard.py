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


# ── #2053 validation: every on-disk shape, every off-capable plane ────


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # What _write_fire_state has always written (since #387) — a line
        # left on disk by an older supervisor is this exact format.
        ("abc\t2\t2026-10-01T00:00:00+00:00\n", ("abc", 2, True)),
        ("\t1\t2026-10-01T00:00:00+00:00\n", ("", 1, True)),
        # CRLF from a hand edit on another OS.
        ("\t1\t2026-10-01T00:00:00+00:00\r\n", ("", 1, True)),
        ("abc\t2\t2026-10-01T00:00:00+00:00\r\n", ("abc", 2, True)),
        # Trailing / stray whitespace from a hand edit.
        ("abc \t2 \t2026-10-01T00:00:00+00:00  \n", ("abc", 2, True)),
        ("\t1\t2026-10-01T00:00:00+00:00   \n", ("", 1, True)),
        # Missing time field, or attempts only.
        ("abc\t3\n", ("abc", 3, False)),
        ("\t3\n", ("", 3, False)),
        ("abc\n", ("abc", 0, False)),
        # Unparseable fields degrade, never raise.
        ("abc\tx\tnot-a-time\n", ("abc", 0, False)),
        # Empty / whitespace-only / no fields → never fired.
        ("", ("", 0, False)),
        ("\n", ("", 0, False)),
        ("   \n", ("", 0, False)),
        ("\t\t\n", ("", 0, False)),
    ],
)
def test_fire_state_reader_shapes(
    tmp_path: Path, body: str, expected: tuple[str, int, bool]
) -> None:
    fs = tmp_path / "x.fire-state"
    fs.write_bytes(body.encode())
    fhash, attempts, when = appliance_state._read_fire_state(fs)
    assert (fhash, attempts, when is not None) == expected


# The runners differ in HOW they record an applied 'off': ssh / snmp /
# lldp / syslog truncate the sidecar (``: >``), while apt / chrony /
# resolved ``echo "$HASH"``, which writes a bare newline for an empty hash.
@pytest.mark.parametrize("plane", ["ssh", "snmp", "lldp", "syslog", "apt", "ntp", "resolver"])
@pytest.mark.parametrize("off_sidecar", ["", "\n"])
def test_plane_turned_off_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plane: str, off_sidecar: str
) -> None:
    trigger = tmp_path / f"{plane}-config-pending"
    applied = tmp_path / f"{plane}-config-hash"
    monkeypatch.setattr(
        appliance_state, "_HOST_CONFIG_PLANES", [(plane, trigger, applied)]
    )
    applied.write_text("hashA\n")  # was managed, applied
    # Operator turns it off → the bundle's config_hash goes empty.
    assert appliance_state._fire_host_config(trigger, applied, "", "disabled\n\n")
    assert trigger.exists()
    # Before the runner has consumed it: the plane is honestly pending.
    assert appliance_state.read_host_config_health()[plane]["state"] == "retrying"
    # The runner applies 'off' and consumes the trigger.
    trigger.unlink()
    applied.write_text(off_sidecar)
    assert appliance_state.read_host_config_health() == {}
    # And the steady state is a no-op, not a re-fire.
    assert not appliance_state._fire_host_config(trigger, applied, "", "disabled\n\n")
    assert not trigger.exists()
    assert appliance_state.read_host_config_health() == {}


def test_off_that_fails_backs_off_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fixed reader also makes the #387 backoff apply to an empty hash:
    # before, the ledger's hash read back as "1", so every tick looked like
    # a fresh config and re-fired without backoff.
    trigger, applied = _one_plane(monkeypatch, tmp_path)
    applied.write_text("hashA\n")
    assert appliance_state._fire_host_config(trigger, applied, "", "disabled\n\n")
    trigger.unlink()  # runner failed: renamed to .failed, sidecar untouched
    assert not appliance_state._fire_host_config(trigger, applied, "", "disabled\n\n")
    health = appliance_state.read_host_config_health()
    assert health["ssh"]["state"] == "retrying"
    assert health["ssh"]["attempts"] == 1


def test_reverting_to_the_applied_config_clears_a_failed_fire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # hashB fails to apply; the operator reverts to hashA, which the host
    # already runs. Nothing will fire for hashB again, so its ledger must not
    # keep the plane 'retrying' until some unrelated save.
    trigger, applied = _one_plane(monkeypatch, tmp_path)
    applied.write_text("hashA\n")
    assert appliance_state._fire_host_config(trigger, applied, "hashB", "x")
    trigger.unlink()  # runner failed
    assert appliance_state.read_host_config_health()["ssh"]["state"] == "retrying"
    assert not appliance_state._fire_host_config(trigger, applied, "hashA", "x")
    assert appliance_state.read_host_config_health() == {}
    # Same for turning the plane off when 'off' is what is applied.
    applied.write_text("")
    assert appliance_state._fire_host_config(trigger, applied, "hashC", "x")
    trigger.unlink()
    assert not appliance_state._fire_host_config(trigger, applied, "", "x")
    assert appliance_state.read_host_config_health() == {}


def test_converged_ledger_is_kept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    trigger, applied = _one_plane(monkeypatch, tmp_path)
    applied.write_text("hashA\n")
    fs = appliance_state._fire_state_path(trigger)
    appliance_state._write_fire_state(fs, "hashA", 1, datetime.now(UTC))
    assert not appliance_state._fire_host_config(trigger, applied, "hashA", "x")
    assert fs.exists()


def test_timezone_cleared_forgets_a_failed_fire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trigger = tmp_path / "tz-pending"
    applied = tmp_path / "tz-hash"
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(appliance_state, "_TZ_TRIGGER_FILE", trigger)
    monkeypatch.setattr(appliance_state, "_TZ_APPLIED_HASH_FILE", applied)
    monkeypatch.setattr(
        appliance_state, "_HOST_CONFIG_PLANES", [("timezone", trigger, applied)]
    )
    applied.write_text("UTC\n")
    assert appliance_state.maybe_fire_timezone("Not/AZone")
    trigger.unlink()  # timedatectl refused it
    assert appliance_state.read_host_config_health()["timezone"]["state"] == "retrying"
    assert not appliance_state.maybe_fire_timezone(None)
    assert appliance_state.read_host_config_health() == {}


@pytest.mark.parametrize("fingerprint", ["leave", "0123456789abcdef"])
def test_cluster_transition_ledger_counts_survive_the_reader(
    tmp_path: Path, fingerprint: str
) -> None:
    # The other two _read_fire_state callers key on a 16-hex digest or the
    # literal "leave" — never empty — and must keep counting.
    trigger = tmp_path / "cluster-join-pending"
    for _ in range(3):
        appliance_state._record_cluster_transition_fire(trigger, fingerprint)
    fhash, attempts, when = appliance_state._read_fire_state(
        appliance_state._fire_state_path(trigger)
    )
    assert (fhash, attempts) == (fingerprint, 3)
    assert when is not None
    assert not appliance_state._cluster_transition_should_fire(
        trigger, fingerprint, max_attempts=3
    )
    assert appliance_state._cluster_transition_should_fire(
        trigger, "other", max_attempts=3
    )
