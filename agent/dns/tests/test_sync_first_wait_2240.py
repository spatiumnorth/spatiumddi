"""The sync-first hold after a death waits a bounded time for a bundle (#2240).

#2019 holds the cached bundle back at startup after the daemon died on it and
asks the control plane first, serving the cache only when the control plane
cannot be reached. At about 1.1M records in 20,000 zones the control plane was
reachable but could not render a bundle at that size, and the five servers the
OOM kill restarted sat dark for about 3.5 h with valid caches on disk, until the
guard was bypassed by hand. The wait is now bounded: past it the control plane
counts as unreachable whatever it answers, the cache serves, and the sync loop
keeps asking, so a fresh bundle replaces it when one lands. A condemned cache
is still never applied by the wait.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import httpx
import pytest
from structlog.testing import capture_logs

from spatium_dns_agent import config_apply, fetch, sync
from spatium_dns_agent.apply_guard import SYNC_FIRST_FALLBACK_SECONDS
from spatium_dns_agent.cache import load_config
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.config_apply import STATUS_NO_PREVIOUS, STATUS_OK, STATUS_REVERTED

from .test_apply_guard_2019 import _client, _crashed_on_cached_bundle, _die_again_offline
from .test_config_revert import _bundle, _Cfg, _Driver, _Heartbeat, _loop

WAIT = SYNC_FIRST_FALLBACK_SECONDS


@pytest.fixture(autouse=True)
def _quiet(monkeypatch) -> None:
    monkeypatch.setattr(sync, "push_rendered_config", lambda *a: None)
    monkeypatch.setattr(sync.time, "sleep", lambda s: None)


class _Answers:
    """A reachable control plane: one answer per ``get`` (a bundle, or a bare
    status for "nothing to send"), with the If-None-Match of each recorded."""

    def __init__(self, answers: list[dict[str, Any] | int]):
        self.answers = answers
        self.seen: list[str | None] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        self.seen.append(headers.get("If-None-Match"))
        answer = self.answers.pop(0)
        request = httpx.Request("GET", url)
        if isinstance(answer, int):
            return httpx.Response(answer, request=request)
        return httpx.Response(200, json=answer, request=request)

    def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


def _time_passes(loop: sync.SyncLoop, seconds: float) -> None:
    """Move the hold's start back, as if ``seconds`` had gone by since it began."""
    assert loop._hold_since is not None
    loop._hold_since -= seconds


def _events(logs: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    return [e for e in logs if e.get("event") == name]


# ── (a) a bundle inside the wait ───────────────────────────────────────────


def test_a_bundle_that_arrives_inside_the_wait_is_applied_not_the_cache(
    tmp_path: Path,
) -> None:
    _crashed_on_cached_bundle(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    assert loop._hold_wait_s == WAIT

    # Reachable, nothing to send yet: the hold keeps waiting.
    cp = _Answers([304, 304, _bundle("fixed"), 304])
    loop._client = _client(cp)  # type: ignore[method-assign]
    loop._poll_once()
    _time_passes(loop, WAIT - 60)
    loop._poll_once()
    assert driver.applied == []
    assert loop._boot_hold is not None

    # The render lands before the wait is over: it is what serves.
    loop._poll_once()
    assert driver.applied == ["fixed"]
    assert loop._boot_hold is None
    assert loop.apply_status.status == STATUS_OK
    assert load_config(tmp_path)[1] == "fixed"

    # The wait running out later changes nothing: the cache is never applied
    # over the bundle the control plane sent.
    _time_passes(loop, 120)
    with capture_logs() as logs:
        loop._poll_once()
    assert driver.applied == ["fixed"]
    assert cp.seen == [None, None, None, "fixed"]
    assert not _events(logs, "bootstrap_cache_released_after_wait")


# ── (b) no bundle within the wait ──────────────────────────────────────────


@pytest.mark.parametrize(
    "nothing",
    [304, {"pending_approval": True, "etag": None}],
    ids=["not_modified", "pending_approval"],
)
def test_no_bundle_within_the_wait_serves_the_cache_and_keeps_asking(
    tmp_path: Path, nothing: dict[str, Any] | int
) -> None:
    _crashed_on_cached_bundle(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    cp = _Answers([nothing, nothing, 304, _bundle("fixed")])
    loop._client = _client(cp)  # type: ignore[method-assign]

    loop._poll_once()
    assert driver.applied == []

    _time_passes(loop, WAIT + 1)
    with capture_logs() as logs:
        loop._poll_once()

    # The control plane answered and sent nothing for the whole wait: the
    # cache serves as if it were unreachable.
    assert driver.applied == ["big"]
    assert loop._boot_hold is None
    assert loop.apply_status.status == STATUS_OK
    [event] = _events(logs, "bootstrap_cache_released_after_wait")
    assert event["etag"] == "big"
    assert event["deaths"] == 1
    assert event["waited_s"] >= WAIT
    assert event["wait_s"] == WAIT
    # Still a guarded apply: a death on it counts as usual.
    assert loop._guard.armed == "big"

    # ... and the agent keeps asking, now long-polling on the cache's etag,
    # until the control plane's bundle replaces it.
    loop._poll_once()
    loop._poll_once()
    assert cp.seen == [None, None, "big", "big"]
    assert driver.applied == ["big", "fixed"]
    assert loop.apply_status.status == STATUS_OK
    assert load_config(tmp_path)[1] == "fixed"


def test_the_wait_acts_once(tmp_path: Path) -> None:
    """A release whose apply failed is not retried on every poll by the wait:
    the quarantine it recorded decides from then on."""
    _crashed_on_cached_bundle(tmp_path)

    class _CacheFails(_Driver):
        def render(self, bundle: dict[str, Any]) -> None:
            self.fail_on = "reload" if bundle.get("etag") == "big" else None

    driver = _CacheFails(tmp_path)
    loop = _loop(tmp_path, driver)
    loop._client = _client(_Answers([304, 304, 304]))  # type: ignore[method-assign]
    _time_passes(loop, WAIT + 1)
    with capture_logs() as logs:
        loop._poll_once()
        loop._poll_once()
        loop._poll_once()
    assert len(_events(logs, "bootstrap_cache_released_after_wait")) == 1
    assert loop._quarantine.etag == "big"
    assert driver.applied == []


def test_a_bundle_still_streaming_when_the_wait_runs_out_is_abandoned_for_the_cache(
    tmp_path: Path, monkeypatch
) -> None:
    """Reachable but slow counts as unreachable once the wait is over: a read
    timeout bounds one read, so a body that trickles in never trips it."""
    _crashed_on_cached_bundle(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    _time_passes(loop, WAIT - 5)

    # The fetch module's clock, moved with the hold's when the wait runs out.
    later = [0.0]
    real = fetch.time.monotonic
    monkeypatch.setattr(fetch, "time", SimpleNamespace(monotonic=lambda: real() + later[0]))
    body = json.dumps(_bundle("fixed")).encode()

    # Every held fetch gets at least BOOT_FETCH_TIMEOUT, so the gap between
    # the chunks has to outlast that as well as the wait.
    gap = sync.BOOT_FETCH_TIMEOUT + 10.0

    def trickle() -> Iterator[bytes]:
        yield body[:10]
        later[0] = gap
        _time_passes(loop, gap)
        yield body[10:]

    transport = httpx.MockTransport(lambda req: httpx.Response(200, content=trickle()))
    loop._client = lambda **kw: httpx.Client(  # type: ignore[method-assign]
        base_url="http://cp.invalid", transport=transport
    )
    with capture_logs() as logs:
        loop._poll_once()

    assert driver.applied == ["big"]
    assert loop._boot_hold is None
    assert _events(logs, "bootstrap_cache_released_after_wait")
    [error] = _events(logs, "sync_http_error")
    assert "startup wait" in error["error"]
    assert not (tmp_path / "config" / "fetch.json.part").exists()


def test_an_unreachable_control_plane_still_serves_at_once(tmp_path: Path) -> None:
    """The bound is for a control plane that answers; one that cannot be
    reached never had to be waited for (#2019's offline rule is unchanged)."""
    _crashed_on_cached_bundle(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    loop._client = _client(_Answers([503]))  # type: ignore[method-assign]
    with capture_logs() as logs:
        loop._poll_once()
    assert driver.applied == ["big"]
    assert _events(logs, "bootstrap_hold_applying_cache_offline")
    assert not _events(logs, "bootstrap_cache_released_after_wait")


# ── (c) a condemned cache ──────────────────────────────────────────────────


def _condemned(tmp_path: Path, monkeypatch, now: list[float]) -> None:
    """The daemon was SEEN dying on the cached bundle twice: quarantined."""
    monkeypatch.setattr(config_apply.time, "time", lambda: now[0])
    _crashed_on_cached_bundle(tmp_path, watched=True)
    assert _die_again_offline(tmp_path, watched=True) == ["big"]


def test_the_wait_never_applies_a_condemned_cache(tmp_path: Path, monkeypatch) -> None:
    now = [1_000_000.0]
    _condemned(tmp_path, monkeypatch, now)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    assert loop._guard.condemned("big")
    assert loop._quarantine.etag == "big"
    # The cache is not bounded by the wait: the bundle in flight is the only
    # way out, so it is never abandoned for one that would not be applied.
    assert loop._hold_fetch_deadline() is None

    loop._client = _client(_Answers([304, 304]))  # type: ignore[method-assign]
    loop._poll_once()
    # Even with the quarantine's own retry due, the wait does not apply it.
    now[0] += WAIT + 1
    _time_passes(loop, WAIT + 1)
    with capture_logs() as logs:
        loop._poll_once()

    assert driver.applied == []
    assert loop._boot_hold is not None
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    assert not _events(logs, "bootstrap_cache_released_after_wait")
    [event] = _events(logs, "bootstrap_hold_wait_over_cache_not_applied")
    assert event["reason"] == "quarantined"
    assert event["etag"] == "big"


def test_past_the_wait_a_condemned_cache_gives_way_to_the_last_known_good(
    tmp_path: Path, monkeypatch
) -> None:
    """What the wait can serve for a condemned cache is the last-known-good,
    under the usual rules: a different bundle the daemon was not seen dying on."""
    _condemned(tmp_path, monkeypatch, [1_000_000.0])
    (tmp_path / "config" / "previous.json").write_text(
        '{"etag": "small", "structural_etag": "s-small", "zones": []}'
    )
    (tmp_path / "config" / "previous.etag").write_text("small")
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    cp = _Answers([304, 304, _bundle("fixed")])
    loop._client = _client(cp)  # type: ignore[method-assign]

    loop._poll_once()
    assert driver.applied == []
    _time_passes(loop, WAIT + 1)
    loop._poll_once()
    assert driver.applied == ["small"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.etag == "small"
    assert loop.apply_status.failed_etag == "big"

    loop._poll_once()
    assert cp.seen == [None, None, "small"]
    assert driver.applied == ["small", "fixed"]
    assert loop._boot_hold is None


# ── (d) the setting ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected", "warned"),
    [
        (None, WAIT, False),
        ("", WAIT, False),
        ("90", 90.0, False),
        (" 1800 ", 1800.0, False),
        ("0", 0.0, False),
        ("2.5", 2.5, False),
        ("ten minutes", WAIT, True),
        ("-1", WAIT, True),
        ("inf", WAIT, True),
        ("nan", WAIT, True),
    ],
)
def test_the_env_var_sets_the_wait(
    monkeypatch, raw: str | None, expected: float, warned: bool
) -> None:
    """A bad value is logged and the default kept: a typo in a tuning knob
    must not stop a DNS server from starting."""
    monkeypatch.setenv("CONTROL_PLANE_URL", "https://cp")
    monkeypatch.setenv("DNS_AGENT_KEY", "k")
    if raw is None:
        monkeypatch.delenv("SPATIUM_DNS_SYNC_FIRST_FALLBACK_S", raising=False)
    else:
        monkeypatch.setenv("SPATIUM_DNS_SYNC_FIRST_FALLBACK_S", raw)
    with capture_logs() as logs:
        cfg = AgentConfig.from_env()
    assert cfg.sync_first_fallback_seconds == expected
    assert bool(_events(logs, "agent_config_seconds_invalid")) == warned


def test_the_loop_takes_the_wait_from_the_config(tmp_path: Path) -> None:
    """A wait of 0 still asks the control plane once before serving the cache,
    and that one fetch gets its full chance (``BOOT_FETCH_TIMEOUT``)."""
    _crashed_on_cached_bundle(tmp_path)
    cfg = _Cfg(tmp_path)
    cfg.sync_first_fallback_seconds = 0.0  # type: ignore[attr-defined]
    driver = _Driver(tmp_path)
    loop = sync.SyncLoop(cfg, ["tok"], driver, _Heartbeat())  # type: ignore[arg-type]
    assert loop._hold_wait_s == 0.0
    assert driver.applied == []
    assert "sends none within 0 s" in (loop.apply_status.error or "")
    deadline = loop._hold_fetch_deadline()
    assert deadline is not None and deadline >= sync.time.monotonic() + sync.BOOT_FETCH_TIMEOUT - 1

    cp = _Answers([304])
    loop._client = _client(cp)  # type: ignore[method-assign]
    loop._poll_once()
    assert cp.seen == [None]
    assert driver.applied == ["big"]
    assert loop.apply_status.status == STATUS_OK
