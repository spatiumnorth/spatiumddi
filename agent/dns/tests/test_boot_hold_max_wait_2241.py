"""A startup hold does not wait forever on a control plane that answers (#2241).

After a death the #2019 hold asks the control plane for a bundle before it
serves the cache, and serves the cache at once only when the control plane
cannot be reached. In the #2240 scale lab the control plane WAS reachable but
could not render (renders OOM-killed or killed at their time limit), so five
servers holding valid cached bundles stayed dark for about 3.5 h. Past
``BOOT_HOLD_MAX_WAIT_SECONDS`` the control plane now counts as unreachable for
the hold. These tests drive the hold's clock (``sync._hold_clock``) by hand;
nothing sleeps.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import httpx
import pytest
from structlog.testing import capture_logs

from spatium_dns_agent import apply_guard, config_apply, sync
from spatium_dns_agent.config_apply import STATUS_NO_PREVIOUS, STATUS_OK, STATUS_REVERTED

from .test_apply_guard_2019 import _client, _crashed_on_cached_bundle, _die_again_offline
from .test_config_revert import _bundle, _Driver, _loop

MAX_WAIT = sync.BOOT_HOLD_MAX_WAIT_SECONDS
LOG_EVENT = "bootstrap_hold_max_wait_elapsed_applying_cache"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch) -> None:
    monkeypatch.setattr(sync, "push_rendered_config", lambda *a: None)
    monkeypatch.setattr(sync.time, "sleep", lambda s: None)


@pytest.fixture
def clock(monkeypatch) -> list[float]:
    """The hold's clock, moved by the test."""
    now = [5_000.0]
    monkeypatch.setattr(sync, "_hold_clock", lambda: now[0])
    return now


class _Daemon(_Driver):
    """Counts what the apply does to the daemon: a start (the deferred one,
    #1056: nothing was running) or a reload of a running one, as the BIND9
    driver's ``swap_and_reload`` decides."""

    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        self.running = False
        self.starts = 0
        self.reloads = 0

    def swap_and_reload(self) -> None:
        super().swap_and_reload()
        if self.running:
            self.reloads += 1
        else:
            self.running = True
            self.starts += 1

    def daemon_running(self) -> bool:
        return self.running


class _Reachable:
    """A control plane that answers every poll, but with no bundle: the
    long-poll ends in a 304 (nothing rendered), or a bundle once one is
    queued in ``bundles``."""

    def __init__(self, bundles: list[dict[str, Any]] | None = None) -> None:
        self.bundles = list(bundles or [])
        self.calls = 0
        self.inm: list[str | None] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        self.calls += 1
        self.inm.append(headers.get("If-None-Match"))
        req = httpx.Request("GET", url)
        if self.bundles:
            return httpx.Response(200, json=self.bundles.pop(0), request=req)
        return httpx.Response(304, request=req)

    def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


def _held(tmp_path: Path, driver: _Driver, cp: _Reachable):
    loop = _loop(tmp_path, driver)
    assert loop._boot_hold is not None
    loop._client = _client(cp)  # type: ignore[method-assign]
    return loop


def test_no_bundle_within_the_max_wait_serves_the_cache(tmp_path: Path, clock) -> None:
    _crashed_on_cached_bundle(tmp_path)
    driver = _Daemon(tmp_path)
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)
    assert f"sends no bundle within {int(MAX_WAIT)} s" in (loop.apply_status.error or "")

    # Reachable, answering, sending nothing: the hold waits, as #2019 wants.
    for _ in range(5):
        clock[0] += MAX_WAIT / 10
        loop._poll_once()
    assert cp.calls == 5
    assert driver.applied == []
    assert driver.starts == 0
    assert loop.apply_status.status == STATUS_NO_PREVIOUS

    # ... but not forever.
    clock[0] += MAX_WAIT
    with capture_logs() as logs:
        loop._poll_once()
    assert driver.applied == ["big"]
    assert driver.starts == 1
    assert loop._boot_hold is None
    assert not (tmp_path / "rendered.held").exists()
    assert loop.apply_status.status == STATUS_OK
    assert loop.apply_status.etag == "big"
    assert loop.heartbeat.daemon_status == {"status": "ok"}
    events = [e for e in logs if e["event"] == LOG_EVENT]
    assert len(events) == 1
    assert events[0]["etag"] == "big"
    assert events[0]["serving"] == "cache"
    assert events[0]["max_wait_s"] == int(MAX_WAIT)

    # It keeps syncing, now long-polling on the bundle it serves.
    loop._poll_once()
    assert cp.inm[-1] == "big"
    assert driver.applied == ["big"]
    assert driver.starts == 1


def test_a_bundle_inside_the_max_wait_means_no_fallback(tmp_path: Path, clock) -> None:
    _crashed_on_cached_bundle(tmp_path)
    driver = _Daemon(tmp_path)
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)

    clock[0] += MAX_WAIT / 2
    loop._poll_once()
    assert driver.applied == []

    cp.bundles.append(_bundle("fixed"))
    clock[0] += MAX_WAIT / 2 - 1
    loop._poll_once()
    assert driver.applied == ["fixed"]
    assert loop._boot_hold is None

    # Long past the max wait: nothing re-applies the held bundle.
    clock[0] += 10 * MAX_WAIT
    with capture_logs() as logs:
        loop._poll_once()
        loop._poll_once()
    assert driver.applied == ["fixed"]
    assert driver.starts == 1
    assert driver.reloads == 0
    assert loop.apply_status.status == STATUS_OK
    assert loop.apply_status.etag == "fixed"
    assert not [e for e in logs if e["event"] == LOG_EVENT]


def test_after_the_fallback_a_later_bundle_reloads_and_does_not_start_again(
    tmp_path: Path, clock
) -> None:
    _crashed_on_cached_bundle(tmp_path)
    driver = _Daemon(tmp_path)
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)

    clock[0] += MAX_WAIT + 1
    loop._poll_once()
    assert driver.applied == ["big"]
    assert driver.starts == 1

    # The control plane can render again: its bundle goes through the normal
    # path, a reload of the daemon the fallback started.
    cp.bundles.append(_bundle("fixed"))
    loop._poll_once()
    assert driver.applied == ["big", "fixed"]
    assert driver.starts == 1
    assert driver.reloads == 1
    assert loop.apply_status.status == STATUS_OK
    assert loop.apply_status.etag == "fixed"
    assert loop._current_etag == "fixed"


def test_the_same_bundle_after_the_fallback_is_not_reapplied(tmp_path: Path, clock) -> None:
    """The control plane eventually renders exactly what the cache holds: the
    poll carries its etag and nothing is re-rendered."""
    _crashed_on_cached_bundle(tmp_path)
    driver = _Daemon(tmp_path)
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)
    clock[0] += MAX_WAIT + 1
    loop._poll_once()

    cp.bundles.append(_bundle("big"))  # served even though If-None-Match matches
    loop._poll_once()
    assert cp.inm[-1] == "big"
    assert driver.applied == ["big"]
    assert driver.starts == 1
    assert driver.reloads == 0


def test_a_condemned_bundle_is_never_applied_by_the_max_wait(
    tmp_path: Path, clock, monkeypatch
) -> None:
    """Two deaths the agent watched: the timer must not start a crash loop on
    the bundle that caused them, not even once its quarantine backoff is due.
    The control plane is reachable, so the operator's fix can still arrive."""
    now = [1_000_000.0]
    monkeypatch.setattr(config_apply.time, "time", lambda: now[0])
    _crashed_on_cached_bundle(tmp_path, watched=True)
    assert _die_again_offline(tmp_path, watched=True) == ["big"]

    driver = _Daemon(tmp_path)
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)
    assert loop._guard.condemned("big")

    clock[0] += MAX_WAIT + 1
    with capture_logs() as logs:
        loop._poll_once()
    assert driver.applied == []
    events = [e for e in logs if e["event"] == LOG_EVENT]
    assert len(events) == 1
    assert events[0]["serving"].startswith("nothing")

    # The quarantine's backoff is due: still not by this path.
    now[0] += 3600
    clock[0] += 10 * MAX_WAIT
    with capture_logs() as logs:
        for _ in range(3):
            loop._poll_once()
    assert driver.applied == []
    assert driver.starts == 0
    assert loop._boot_hold is not None
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    assert not [e for e in logs if e["event"] == LOG_EVENT]  # announced once

    # The fix arrives and is taken normally.
    cp.bundles.append(_bundle("fixed"))
    loop._poll_once()
    assert driver.applied == ["fixed"]
    assert driver.starts == 1
    assert loop._boot_hold is None


def test_a_condemned_bundle_swaps_to_a_different_last_known_good(tmp_path: Path, clock) -> None:
    _crashed_on_cached_bundle(tmp_path, "big", watched=True)
    _die_again_offline(tmp_path, watched=True)
    (tmp_path / "config" / "previous.json").write_text(
        '{"etag": "small", "structural_etag": "s-small", "zones": []}'
    )
    (tmp_path / "config" / "previous.etag").write_text("small")

    driver = _Daemon(tmp_path)
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)

    clock[0] += MAX_WAIT / 2
    loop._poll_once()
    assert driver.applied == []

    clock[0] += MAX_WAIT
    with capture_logs() as logs:
        loop._poll_once()
    assert driver.applied == ["small"]
    assert driver.starts == 1
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.etag == "small"
    assert loop.apply_status.failed_etag == "big"
    events = [e for e in logs if e["event"] == LOG_EVENT]
    assert [e["serving"] for e in events] == ["last_known_good"]

    # Serving the last-known-good: later polls do not re-apply anything.
    clock[0] += MAX_WAIT
    loop._poll_once()
    assert driver.applied == ["small"]

    # The fix arrives: a reload, and the hold is over.
    cp.bundles.append(_bundle("fixed"))
    loop._current_etag = None
    loop._poll_once()
    assert driver.applied == ["small", "fixed"]
    assert driver.starts == 1
    assert driver.reloads == 1
    assert loop._boot_hold is None
    assert loop.apply_status.status == STATUS_OK


def test_a_condemned_bundle_with_an_unreadable_last_known_good_stays_down(
    tmp_path: Path, clock, monkeypatch
) -> None:
    """``_boot_hold_fallback`` retries the condemned bundle itself when the
    last-known-good cannot be loaded and the backoff is due; the max-wait path
    must not reach that branch."""
    now = [1_000_000.0]
    monkeypatch.setattr(config_apply.time, "time", lambda: now[0])
    _crashed_on_cached_bundle(tmp_path, "big", watched=True)
    _die_again_offline(tmp_path, watched=True)
    (tmp_path / "config" / "previous.json").write_text('{"etag": "small", "zon')
    (tmp_path / "config" / "previous.etag").write_text("small")

    driver = _Daemon(tmp_path)
    loop = _held(tmp_path, driver, _Reachable())
    now[0] += 3600
    clock[0] += MAX_WAIT + 1
    loop._poll_once()
    assert driver.applied == []


@pytest.mark.parametrize("etag_file", [None, "", "  \n"])
def test_a_condemned_bundle_with_a_last_known_good_of_unknown_etag_stays_down(
    tmp_path: Path, clock, monkeypatch, etag_file: str | None
) -> None:
    """A ``previous.json`` with no etag (agents upgraded in the field carry
    one) cannot be told apart from the condemned bundle, and
    ``_boot_hold_fallback`` would not serve it either: it would fall through to
    retrying the condemned bundle on its backoff. So it does not serve."""
    now = [1_000_000.0]
    monkeypatch.setattr(config_apply.time, "time", lambda: now[0])
    _crashed_on_cached_bundle(tmp_path, "big", watched=True)
    _die_again_offline(tmp_path, watched=True)
    etag_path = tmp_path / "config" / "previous.etag"
    if etag_file is None:
        etag_path.unlink()
    else:
        etag_path.write_text(etag_file)

    driver = _Daemon(tmp_path)
    loop = _held(tmp_path, driver, _Reachable())
    assert loop._guard.condemned("big")
    now[0] += 3600
    clock[0] += MAX_WAIT + 1
    with capture_logs() as logs:
        for _ in range(3):
            loop._poll_once()
    assert driver.applied == []
    assert driver.starts == 0
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    events = [e for e in logs if e["event"] == LOG_EVENT]
    assert [e["serving"][:7] for e in events] == ["nothing"]


class _FailsOn(_Daemon):
    """Fails to render one bundle, as a cache that no longer applies does."""

    def __init__(self, state_dir: Path, bad: str) -> None:
        super().__init__(state_dir)
        self.bad = bad

    def render(self, bundle: dict[str, Any]) -> None:
        if bundle.get("etag") == self.bad:
            raise RuntimeError("render boom")
        super().render(bundle)


def test_a_cache_that_fails_to_apply_serves_the_last_known_good_once(tmp_path: Path, clock) -> None:
    """The held cache raises on apply, and ``_bootstrap_fallback`` puts the
    last-known-good live in its place. Later polls must not apply (and reload)
    it again on every pass."""
    _crashed_on_cached_bundle(tmp_path, "big")
    (tmp_path / "config" / "previous.json").write_text(
        '{"etag": "small", "structural_etag": "s-small", "zones": []}'
    )
    (tmp_path / "config" / "previous.etag").write_text("small")
    driver = _FailsOn(tmp_path, "big")
    cp = _Reachable()
    loop = _held(tmp_path, driver, cp)

    clock[0] += MAX_WAIT + 1
    for _ in range(4):
        loop._poll_once()
    assert driver.applied == ["small"]
    assert driver.starts == 1
    assert driver.reloads == 0
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.etag == "small"
    assert loop.apply_status.failed_etag == "big"

    # The control plane's bundle ends the hold, as a reload.
    cp.bundles.append(_bundle("fixed"))
    loop._current_etag = None
    loop._poll_once()
    assert driver.applied == ["small", "fixed"]
    assert driver.starts == 1
    assert driver.reloads == 1
    assert loop._boot_hold is None
    assert loop.apply_status.status == STATUS_OK


def test_an_unreachable_control_plane_still_serves_at_once(tmp_path: Path, clock) -> None:
    """The max wait is a backstop, not a delay added to #2019's offline path."""
    _crashed_on_cached_bundle(tmp_path)
    driver = _Daemon(tmp_path)
    loop = _loop(tmp_path, driver)

    class _Down(_Reachable):
        def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

    loop._client = _client(_Down())  # type: ignore[method-assign]
    loop._poll_once()
    assert driver.applied == ["big"]
    assert driver.starts == 1


def test_no_hold_no_timer(tmp_path: Path, clock) -> None:
    """A clean start applies the cache from the constructor; the timer is
    never armed, and a quiet control plane later changes nothing."""
    from spatium_dns_agent.cache import ensure_layout, save_config

    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    driver = _Daemon(tmp_path)
    loop = _loop(tmp_path, driver)
    assert driver.applied == ["good"]
    assert loop._boot_hold_since is None
    loop._client = _client(_Reachable())  # type: ignore[method-assign]
    clock[0] += 10 * MAX_WAIT
    loop._poll_once()
    assert driver.applied == ["good"]
    assert driver.starts == 1


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, 600.0),
        ("", 600.0),
        ("900", 900.0),
        ("90.5", 90.5),
        ("0", 600.0),
        ("-5", 600.0),
        ("ten minutes", 600.0),
        ("nan", 600.0),
        ("inf", 600.0),
    ],
)
def test_the_max_wait_is_env_configurable(monkeypatch, raw: str | None, expected: float) -> None:
    if raw is None:
        monkeypatch.delenv("AGENT_BOOT_HOLD_MAX_WAIT_S", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOOT_HOLD_MAX_WAIT_S", raw)
    assert apply_guard._boot_hold_max_wait_from_env() == expected
    assert apply_guard.DEFAULT_BOOT_HOLD_MAX_WAIT_SECONDS == 600.0
