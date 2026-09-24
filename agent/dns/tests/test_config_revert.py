"""Last-known-good revert + poison-pill quarantine (issue #882).

Before this, ``previous.json`` was written on every fetch and read by
nothing, so a bundle that rendered config ``named`` rejects overwrote the
only copy of the config that worked and then re-applied itself on every
poll. These tests pin the three properties that fixes:

* ``previous`` tracks the last bundle that APPLIED, not the last one fetched;
* a failed bundle is not retried until the backoff expires;
* the daemon is only re-rendered when the failure actually disturbed it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.cache import (
    commit_config,
    ensure_layout,
    load_config,
    load_previous_config,
    save_config,
)
from spatium_dns_agent.config_apply import (
    PHASE_RELOAD,
    PHASE_VALIDATE,
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    ApplyStatus,
    ConfigApplyError,
    Quarantine,
    truncate_error,
)
from spatium_dns_agent.drivers.base import DriverBase
from spatium_dns_agent.sync import SyncLoop


# ── cache: previous == last GOOD, not last fetched ────────────────────────


def _bundle(tag: str) -> dict[str, Any]:
    return {"etag": tag, "structural_etag": f"s-{tag}", "zones": []}


def test_save_config_does_not_rotate_previous(tmp_path: Path) -> None:
    """The regression that destroyed the fallback.

    Pre-#882 ``save_config`` rotated current→previous on every FETCH. A bad
    bundle left ``_current_etag`` unadvanced, so the next poll re-fetched the
    same bundle and rotated the bad config into ``previous`` — after two
    cycles there was no good config left anywhere on disk.
    """
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")

    # Two fetches of the same bad bundle, as the old retry loop produced.
    save_config(tmp_path, _bundle("bad"), "bad")
    save_config(tmp_path, _bundle("bad"), "bad")

    prev, prev_etag = load_previous_config(tmp_path)
    assert prev_etag == "good"
    assert prev == _bundle("good")


def test_commit_config_promotes_current(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("one"), "one")
    commit_config(tmp_path, "one")
    save_config(tmp_path, _bundle("two"), "two")
    commit_config(tmp_path, "two")

    assert load_previous_config(tmp_path) == (_bundle("two"), "two")
    assert load_config(tmp_path) == (_bundle("two"), "two")


def test_no_previous_when_nothing_ever_applied(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("first"), "first")
    assert load_previous_config(tmp_path) == (None, None)


def test_previous_without_etag_is_still_usable(tmp_path: Path) -> None:
    """A field agent upgraded across #882 has a ``previous.json`` written by
    the old rotating save_config, and no ``previous.etag`` beside it. The
    bundle is still a valid fallback."""
    ensure_layout(tmp_path)
    (tmp_path / "config" / "previous.json").write_text(json.dumps(_bundle("legacy")))
    bundle, etag = load_previous_config(tmp_path)
    assert bundle == _bundle("legacy")
    assert etag is None


# ── quarantine ────────────────────────────────────────────────────────────


def test_quarantine_blocks_then_retries(tmp_path: Path, monkeypatch) -> None:
    ensure_layout(tmp_path)
    now = [1000.0]
    monkeypatch.setattr("spatium_dns_agent.config_apply.time.time", lambda: now[0])

    q = Quarantine(tmp_path)
    q.record("bad", "named-checkconf failed")
    assert q.blocks("bad")
    assert not q.blocks("other")
    assert not q.retry_due()

    now[0] += 61.0
    assert not q.blocks("bad")
    assert q.retry_due()


def test_quarantine_backoff_grows_per_failure(tmp_path: Path, monkeypatch) -> None:
    ensure_layout(tmp_path)
    now = [0.0]
    monkeypatch.setattr("spatium_dns_agent.config_apply.time.time", lambda: now[0])
    q = Quarantine(tmp_path)
    q.record("bad", "x")
    first = q.retry_at
    q.record("bad", "x")
    second = q.retry_at
    q.record("bad", "x")
    third = q.retry_at
    assert first < second < third
    # And it stops growing at the cap rather than running away.
    q.record("bad", "x")
    assert q.retry_at == third


def test_quarantine_resets_ladder_for_a_different_bundle(tmp_path: Path, monkeypatch) -> None:
    ensure_layout(tmp_path)
    now = [0.0]
    monkeypatch.setattr("spatium_dns_agent.config_apply.time.time", lambda: now[0])
    q = Quarantine(tmp_path)
    q.record("bad-1", "x")
    q.record("bad-1", "x")
    q.record("bad-2", "y")
    assert q.failures == 1


def test_quarantine_survives_restart(tmp_path: Path) -> None:
    """Persisted, not in-memory: a crash-looping container must not re-break
    itself with the same bundle on every start."""
    ensure_layout(tmp_path)
    Quarantine(tmp_path).record("bad", "boom")
    reloaded = Quarantine(tmp_path)
    assert reloaded.etag == "bad"
    assert reloaded.blocks("bad")


def test_quarantine_clear_removes_the_file(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    q = Quarantine(tmp_path)
    q.record("bad", "boom")
    q.clear()
    assert not (tmp_path / "config" / "quarantine.json").exists()
    assert not Quarantine(tmp_path).blocks("bad")


def test_corrupt_quarantine_file_does_not_raise(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    (tmp_path / "config" / "quarantine.json").write_text("{not json")
    q = Quarantine(tmp_path)
    assert q.etag is None


def test_truncate_error_marks_the_cut(tmp_path: Path) -> None:
    assert truncate_error("a\n  b   c") == "a b c"
    long = truncate_error("x" * 5000)
    assert len(long) <= 2000
    assert long.endswith("…")


# ── phased apply ──────────────────────────────────────────────────────────


class _Driver(DriverBase):
    """Driver whose phases can be made to fail on demand."""

    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        self.fail_on: str | None = None
        self.applied: list[str] = []

    def render(self, bundle: dict[str, Any]) -> None:
        if self.fail_on == "render":
            raise RuntimeError("render boom")

    def validate(self) -> None:
        if self.fail_on == "validate":
            raise RuntimeError("named-checkconf failed: bad acl")

    def swap_and_reload(self) -> None:
        if self.fail_on == "reload":
            raise RuntimeError("rndc reconfig failed")

    def apply_config(self, bundle: dict[str, Any]) -> None:
        super().apply_config(bundle)
        self.applied.append(str(bundle.get("etag")))

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        return None

    def start_daemon(self) -> None:
        return None

    def daemon_running(self) -> bool:
        return True


def test_apply_config_tags_the_failing_phase(tmp_path: Path) -> None:
    d = _Driver(tmp_path)
    d.fail_on = "validate"
    with pytest.raises(ConfigApplyError) as ei:
        d.apply_config({})
    assert ei.value.phase == PHASE_VALIDATE
    # Validation runs against the staging tree, so the daemon is untouched.
    assert not ei.value.daemon_disturbed


def test_reload_failure_is_daemon_disturbing(tmp_path: Path) -> None:
    d = _Driver(tmp_path)
    d.fail_on = "reload"
    with pytest.raises(ConfigApplyError) as ei:
        d.apply_config({})
    assert ei.value.phase == PHASE_RELOAD
    assert ei.value.daemon_disturbed


# ── SyncLoop revert behaviour ─────────────────────────────────────────────


class _Heartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.failed_ops_count = 0
        self.config_apply = ApplyStatus()


class _Cfg:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.control_plane_url = "http://cp.invalid"
        self.insecure_skip_tls_verify = False
        self.tls_ca_path = None


def _loop(tmp_path: Path, driver: _Driver) -> SyncLoop:
    return SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())


def _assert_echoed(loop: SyncLoop, verdict: str) -> None:
    """The verdict is echoed into the heartbeat's ``daemon`` field too, and
    the control plane parses that reason (#1067): ``daemon_state.
    is_config_apply_verdict`` reads a ``config_apply_`` prefix as a failed
    apply — #882's to report — rather than a daemon that is not serving.
    Reword it and every routine revert pages critical as "not serving"."""
    assert loop.heartbeat.daemon_status["status"] == "degraded"
    assert loop.heartbeat.daemon_status["reason"].startswith(f"config_apply_{verdict}: ")


def test_validate_failure_leaves_daemon_alone(tmp_path: Path) -> None:
    """A staging-tree failure must not bounce a healthy daemon.

    ``named`` renders and validates into ``rendered.new``; a checkconf
    failure never reached it. Re-rendering the previous bundle there would
    reload a daemon to reach the state it is already in.
    """
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    loop = _loop(tmp_path, driver)
    driver.applied.clear()

    driver.fail_on = "validate"
    assert loop._apply_with_revert(_bundle("bad"), "bad") is False

    assert driver.applied == []  # no revert re-render
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.failed_etag == "bad"
    assert loop.apply_status.etag == "good"
    _assert_echoed(loop, STATUS_REVERTED)


def test_reload_failure_re_renders_the_previous_bundle(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    loop = _loop(tmp_path, driver)
    driver.applied.clear()

    calls = {"n": 0}
    original_swap = driver.swap_and_reload

    def swap() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("rndc reconfig failed")
        original_swap()

    driver.swap_and_reload = swap  # type: ignore[method-assign]
    assert loop._apply_with_revert(_bundle("bad"), "bad") is False

    assert driver.applied == ["good"]  # the previous bundle was put back
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.etag == "good"
    _assert_echoed(loop, STATUS_REVERTED)


def test_failure_with_no_previous_is_reported_distinctly(tmp_path: Path) -> None:
    """Nothing to revert TO. The operator has to fix the config — telling
    them 'reverted' would imply a safe state that does not exist."""
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)

    driver.fail_on = "validate"
    assert loop._apply_with_revert(_bundle("bad"), "bad") is False
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    assert loop.apply_status.etag is None
    _assert_echoed(loop, STATUS_NO_PREVIOUS)


def test_revert_failure_is_reported_distinctly(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    loop = _loop(tmp_path, driver)

    driver.fail_on = "reload"  # fails for the bad bundle AND for the revert
    assert loop._apply_with_revert(_bundle("bad"), "bad") is False
    assert loop.apply_status.status == STATUS_REVERT_FAILED
    assert "revert also failed" in (loop.apply_status.error or "")
    _assert_echoed(loop, STATUS_REVERT_FAILED)


def test_success_commits_and_clears_quarantine(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    loop._quarantine.record("bad", "boom")

    save_config(tmp_path, _bundle("new"), "new")
    assert loop._apply_with_revert(_bundle("new"), "new") is True

    assert loop.apply_status.status == STATUS_OK
    assert loop._quarantine.etag is None
    assert load_previous_config(tmp_path) == (_bundle("new"), "new")


def test_bootstrap_skips_a_quarantined_bundle(tmp_path: Path) -> None:
    """A restart must not re-break the daemon with the bundle that broke it."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    save_config(tmp_path, _bundle("bad"), "bad")
    Quarantine(tmp_path).record("bad", "named-checkconf failed")

    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)

    assert driver.applied == ["good"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.failed_etag == "bad"


def test_bootstrap_falls_back_when_cached_bundle_fails(tmp_path: Path) -> None:
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    save_config(tmp_path, _bundle("bad"), "bad")

    driver = _Driver(tmp_path)
    calls = {"n": 0}
    real_validate = driver.validate

    def validate() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("named-checkconf failed")
        real_validate()

    driver.validate = validate  # type: ignore[method-assign]
    loop = _loop(tmp_path, driver)

    assert driver.applied == ["good"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop._current_etag == "good"
    # And the bad bundle is quarantined so the next poll doesn't retry it.
    assert loop._quarantine.blocks("bad")


# ── named-checkconf diagnostics land on stdout ────────────────────────────


def test_bind9_validate_reads_checkconf_stdout(tmp_path: Path, monkeypatch) -> None:
    """``named-checkconf`` writes its diagnostics to STDOUT, not stderr.

    Reading only stderr produced ``"named-checkconf failed: "`` — an empty
    reason. That was survivable while the text went nowhere; #882 makes it
    the operator-facing explanation of why a config did not go live, so an
    empty one defeats the point of reporting at all.
    """
    import subprocess

    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    (tmp_path / "rendered.new").mkdir(parents=True)
    (tmp_path / "rendered.new" / "named.conf").write_text("options {};\n")

    monkeypatch.setattr("spatium_dns_agent.drivers.bind9.shutil.which", lambda _: "/x")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a[0],
            1,
            stdout="named.conf:20: undefined ACL 'trusted'\n",
            stderr="",
        ),
    )
    driver = Bind9Driver(tmp_path)
    with pytest.raises(RuntimeError) as ei:
        driver.validate()
    assert "undefined ACL 'trusted'" in str(ei.value)
    assert "named.conf:20" in str(ei.value)


def test_commit_is_skipped_when_previous_already_matches(tmp_path: Path) -> None:
    """``commit_config`` is called from two points in a successful poll; the
    second must not re-copy a bundle that can be tens of kilobytes."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("one"), "one")
    commit_config(tmp_path, "one")
    first = (tmp_path / "config" / "previous.json").stat().st_mtime_ns
    commit_config(tmp_path, "one")
    assert (tmp_path / "config" / "previous.json").stat().st_mtime_ns == first


def test_commit_refuses_when_current_is_not_what_applied(tmp_path: Path) -> None:
    """The guard that stops a caller stamping the WRONG bundle as
    last-known-good — the one thing this file must never hold."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    save_config(tmp_path, _bundle("bad"), "bad")
    # A caller that applied something other than ``current`` (a revert, say)
    # must not promote ``current``.
    commit_config(tmp_path, "good")
    assert load_previous_config(tmp_path) == (_bundle("good"), "good")
