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
from typing import Any, Self

import httpx
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
    MAX_ERROR_LEN,
    ApplyStatus,
    ConfigApplyError,
    Quarantine,
    truncate_error,
)
from spatium_dns_agent.drivers.base import DriverBase, HeldZone
from spatium_dns_agent.sync import PARTIAL_APPLY_PREFIX, SyncLoop, _partial_apply_error


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
        # What the next validate holds back (#1403), as the BIND9 zone check does.
        self.hold: tuple[HeldZone, ...] = ()
        self.ops: list[str] = []

    def render(self, bundle: dict[str, Any]) -> None:
        if self.fail_on == "render":
            raise RuntimeError("render boom")

    def validate(self) -> None:
        self.held_back = ()
        if self.fail_on == "validate":
            raise RuntimeError("named-checkconf failed: bad acl")
        self.held_back = self.hold

    def swap_and_reload(self) -> None:
        if self.fail_on == "reload":
            raise RuntimeError("rndc reconfig failed")

    def apply_config(self, bundle: dict[str, Any]) -> None:
        super().apply_config(bundle)
        self.applied.append(str(bundle.get("etag")))

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        self.ops.append(str(op["op_id"]))
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


# ── #1403: a zone the zone check refuses holds back only itself ───────────

HELD = HeldZone(
    "bad.test",
    "internal",
    "zone bad.test/IN: NS 'ns9.bad.test' has no address records (A or AAAA)",
    True,
)


def test_a_held_zone_is_reported_not_quarantined(tmp_path: Path) -> None:
    """The rest of the bundle is live, so it is committed and nothing is
    quarantined; the server says which zone is not, the way #882 reports any
    divergence."""
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    driver.hold = (HELD,)

    save_config(tmp_path, _bundle("b1"), "b1")
    assert loop._apply_with_revert(_bundle("b1"), "b1") is True

    assert loop._quarantine.etag is None
    assert load_previous_config(tmp_path) == (_bundle("b1"), "b1")
    status = loop.apply_status
    assert (status.status, status.etag, status.failed_etag, status.phase) == (
        STATUS_REVERTED,
        "b1",
        "b1",
        PHASE_VALIDATE,
    )
    assert "bad.test (view internal): zone bad.test/IN: NS" in (status.error or "")
    assert "still served from its last good copy" in (status.error or "")
    assert loop.heartbeat.config_apply is status
    _assert_echoed(loop, STATUS_REVERTED)


def test_held_back_error_names_every_zone_and_stays_bounded() -> None:
    gone = HeldZone("new.test", None, "zone new.test/IN: bad dotted quad", False)
    text = _partial_apply_error((HELD, gone), ())
    assert text.startswith(
        PARTIAL_APPLY_PREFIX + "named-checkzone refused 2 zone files, held back until"
    )
    assert "bad.test (view internal): zone bad.test/IN" in text
    assert "new.test: zone new.test/IN: bad dotted quad (not served)" in text
    long = HeldZone("x.test", None, "y" * 5000, True)
    assert len(_partial_apply_error((long,), ())) <= MAX_ERROR_LEN


def test_both_kinds_of_unserved_zone_are_named_in_one_verdict() -> None:
    """No driver both holds back and refuses today; if one did, the verdict
    names both rather than dropping one."""
    text = _partial_apply_error((HELD,), ["other.test: HTTP 422 bad rrset"])
    assert text.startswith(PARTIAL_APPLY_PREFIX + "named-checkzone refused a zone file")
    assert "the daemon refused 1 zone(s); every other zone is served: other.test" in text


class _Http:
    """The control plane: one long-poll answer per ``get``, posts recorded."""

    def __init__(self, bundles: list[dict[str, Any]]):
        self.bundles = bundles
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(200, json=self.bundles.pop(0), request=httpx.Request("GET", url))

    def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> httpx.Response:
        self.posts.append((url, json))
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


def _flat(tag: str, structural: str, ops: list[str]) -> dict[str, Any]:
    """A bundle of a group without views: two zones, and a page of record ops."""
    return {
        "etag": tag,
        "structural_etag": structural,
        "zones": [{"name": "bad.test.", "serial": 7}, {"name": "lab.test.", "serial": 9}],
        "pending_record_ops": [{"op_id": op, "op": "create", "zone_name": "lab.test."}
                               for op in ops],
    }


def test_a_poll_applies_the_rest_while_a_zone_is_held(tmp_path: Path, monkeypatch) -> None:
    """Before #1403 a refused zone returned before the ops page: every record
    change on the server stalled behind it. Now the page drains, and the held
    zone is left out of the zone-state report (it is not serving that serial)."""
    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http([_flat("e1", "s1", ["op-1"]), _flat("e2", "s1", [])])
    loop._client = lambda: http  # type: ignore[method-assign]

    driver.hold = (HELD,)
    loop._poll_once()

    assert driver.applied == ["e1"]
    assert driver.ops == ["op-1"]
    assert loop.heartbeat.pending_acks == [{"op_id": "op-1", "result": "ok"}]
    assert loop.apply_status.status == STATUS_REVERTED, "the recovery check must not clear it"
    assert loop._quarantine.etag is None
    assert loop._current_structural_etag is None
    reports = [body for url, body in http.posts if url.endswith("/zone-state")]
    assert reports == [{"zones": [{"zone_name": "lab.test.", "serial": 9}]}]

    # The bad record is deleted: on a group without views a record-only change,
    # so the structural etag does not move. It must still re-render, load the
    # zone, and clear the verdict.
    driver.hold = ()
    loop._poll_once()

    assert driver.applied == ["e1", "e2"]
    assert loop.apply_status.status == STATUS_OK
    assert loop._current_structural_etag == "s1"
    assert loop.heartbeat.daemon_status == {"status": "ok"}


def test_a_change_made_while_a_zone_is_held_still_applies(
    tmp_path: Path, monkeypatch
) -> None:
    """#1403's own scenario: the zone is already held when another zone's
    record changes. The next bundle re-renders, holds the zone again, applies
    the rest, and keeps reporting the hold; nothing is quarantined."""
    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http([_flat("e1", "s1", []), _flat("e2", "s1", ["op-2"])])
    loop._client = lambda: http  # type: ignore[method-assign]
    driver.hold = (HELD,)

    loop._poll_once()
    loop._poll_once()

    assert driver.applied == ["e1", "e2"], "the second bundle re-rendered"
    assert driver.ops == ["op-2"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.etag == "e2"
    assert loop._quarantine.etag is None
    assert loop._current_structural_etag is None
    _assert_echoed(loop, STATUS_REVERTED)


def test_a_held_zone_reads_as_a_partial_apply_and_survives_a_record_only_poll(
    tmp_path: Path, monkeypatch
) -> None:
    """A BIND9 hold is reported with :data:`PARTIAL_APPLY_PREFIX`, so the UI and
    the ``agent_config_rejected`` alert say "nothing rolled back" instead of
    #882's rollback wording (#1280). And a poll that re-renders nothing must
    not read that verdict as stale: the zone is still held."""
    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http([_flat("e1", "s1", []), _flat("e2", "s1", ["op-3"])])
    loop._client = lambda: http  # type: ignore[method-assign]
    driver.hold = (HELD,)

    loop._poll_once()
    error = loop.apply_status.error or ""
    assert loop.apply_status.status == STATUS_REVERTED
    assert error.startswith(PARTIAL_APPLY_PREFIX + "named-checkzone refused a zone file")
    assert "bad.test (view internal)" in error

    # Force the record-only path: the structural etag matches, so nothing
    # re-renders and only the stale-verdict clear stands between the poll and
    # an ``ok`` that would hide the held zone.
    loop._current_structural_etag = "s1"
    loop._poll_once()

    assert driver.applied == ["e1"], "a record-only poll re-renders nothing"
    assert driver.ops == ["op-3"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert (loop.apply_status.error or "").startswith(PARTIAL_APPLY_PREFIX)
    _assert_echoed(loop, STATUS_REVERTED)


def test_bootstrap_reports_zones_held_back(tmp_path: Path) -> None:
    """A restart re-applies the cache; a zone it holds back is reported too,
    and the first bundle after it re-renders."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("cached"), "cached")
    commit_config(tmp_path, "cached")

    class _Holding(_Driver):
        def __init__(self, state_dir: Path):
            super().__init__(state_dir)
            self.hold = (HELD,)

    driver = _Holding(tmp_path)
    loop = _loop(tmp_path, driver)

    assert driver.applied == ["cached"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert "bad.test (view internal)" in (loop.apply_status.error or "")
    assert loop._current_structural_etag is None


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
