"""A bundle the daemon dies on is not re-applied blindly at every start (#2019).

A blocklist set too big for the container's memory limit applies cleanly and
then gets ``named`` OOM-killed while it loads the zones. Nothing is caught, so
#882's quarantine never hears of it, and the restarted agent re-applied the
cached bundle from its constructor, before the sync thread existed: the server
crash-looped on the cache and never fetched the bundle the operator fixed.

A process "dies" in these tests the way it does in the field: it is simply
dropped, with no orderly exit, leaving whatever it had persisted behind. The
next ``SyncLoop`` built on the same state dir is the restarted container.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import httpx
import pytest

from spatium_dns_agent import apply_guard, config_apply, sync
from spatium_dns_agent.cache import commit_config, ensure_layout, load_config, save_config
from spatium_dns_agent.config_apply import (
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERTED,
)

from .test_config_revert import _bundle, _Driver, _Http, _loop
from .test_supervisor_deferred_start import supervised  # noqa: F401 — fixture


@pytest.fixture(autouse=True)
def _quiet(monkeypatch) -> None:
    monkeypatch.setattr(sync, "push_rendered_config", lambda *a: None)
    monkeypatch.setattr(sync.time, "sleep", lambda s: None)


class _Down:
    """The control plane, unreachable."""

    def __init__(self) -> None:
        self.calls = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        self.calls += 1
        raise httpx.ConnectError("connection refused")


def _client(http: Any):
    return lambda **kw: http


def _rendered(state_dir: Path, tag: str) -> None:
    """The live rendered tree a previous run left (``start_daemon`` reads it)."""
    live = state_dir / "rendered"
    live.mkdir(parents=True, exist_ok=True)
    (live / "named.conf").write_text(f"// {tag}\n")


def _crashed_on_cached_bundle(tmp_path: Path, tag: str = "big") -> None:
    """Cache ``tag`` the way #2019's agent had it, and die on it once.

    The bundle applied and was committed (so ``previous`` is that same bundle,
    as on the reproduction rig), then the daemon was killed inside the settle
    window: the process is dropped without an orderly exit."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle(tag), tag)
    commit_config(tmp_path, tag)
    _rendered(tmp_path, tag)
    driver = _Driver(tmp_path)
    _loop(tmp_path, driver)
    assert driver.applied == [tag]


def test_a_death_on_the_cached_bundle_syncs_first_and_takes_the_fixed_one(
    tmp_path: Path,
) -> None:
    _crashed_on_cached_bundle(tmp_path)

    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)

    # Not re-applied before the sync thread exists, and the daemon cannot come
    # up on it either: its rendered tree is set aside, so the start defers.
    assert driver.applied == []
    assert not (tmp_path / "rendered" / "named.conf").exists()
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    assert loop.apply_status.failed_etag == "big"
    assert "died once" in (loop.apply_status.error or "")
    assert loop.heartbeat.daemon_status["reason"].startswith("config_apply_no_previous: ")

    # The first poll asks the control plane, which holds the operator's fix.
    http = _Http([_bundle("fixed")])
    loop._client = _client(http)  # type: ignore[method-assign]
    loop._poll_once()

    assert driver.applied == ["fixed"]
    assert loop.apply_status.status == STATUS_OK
    assert loop._boot_hold is None
    assert not (tmp_path / "rendered.held").exists()
    assert load_config(tmp_path)[1] == "fixed"


def test_a_clean_restart_still_applies_the_cache(tmp_path: Path) -> None:
    """A healthy agent restarted on purpose (a rollout, a SIGTERM) must not
    lose its cache to this guard."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    first = _loop(tmp_path, _Driver(tmp_path))
    first.note_orderly_exit()

    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    assert driver.applied == ["good"]
    assert loop._boot_hold is None
    assert loop.apply_status.status == STATUS_OK


def test_a_death_after_the_bundle_settled_is_not_blamed_on_it(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(apply_guard, "SETTLE_SECONDS", 0.0)
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    first = _loop(tmp_path, _Driver(tmp_path))
    first._maybe_settle()  # the daemon stayed up past the window

    driver = _Driver(tmp_path)  # ... and then the node lost power
    _loop(tmp_path, driver)
    assert driver.applied == ["good"]


def test_an_unreachable_control_plane_still_serves_from_cache(tmp_path: Path) -> None:
    """Non-negotiable #5: one death can be a power cut. With no control plane
    to ask, the cached bundle is what serves."""
    _crashed_on_cached_bundle(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    down = _Down()
    loop._client = _client(down)  # type: ignore[method-assign]

    loop._poll_once()

    assert down.calls == 1
    assert driver.applied == ["big"]
    assert loop._boot_hold is None
    assert loop.apply_status.status == STATUS_OK


def test_a_second_death_quarantines_the_bundle(tmp_path: Path, monkeypatch) -> None:
    now = [1_000_000.0]
    monkeypatch.setattr(config_apply.time, "time", lambda: now[0])
    _crashed_on_cached_bundle(tmp_path)
    # Restart 1: offline, so the cache is applied again, and the daemon dies
    # on it a second time.
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    loop._client = _client(_Down())  # type: ignore[method-assign]
    loop._poll_once()
    assert driver.applied == ["big"]

    # Restart 2: two deaths. The bundle is quarantined, and ``previous`` is
    # that same bundle, so there is nothing safe to serve offline yet.
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    assert loop._quarantine.etag == "big"
    assert "died 2 times" in (loop._quarantine.reason or "")
    loop._client = _client(_Down())  # type: ignore[method-assign]
    loop._poll_once()
    assert driver.applied == []
    assert loop.apply_status.status == STATUS_NO_PREVIOUS

    # ... but not forever: once the quarantine's backoff runs out, the cache is
    # tried again (one crash per interval, not a crash loop).
    now[0] += 61
    loop._poll_once()
    assert driver.applied == ["big"]


def test_quarantined_falls_back_to_previous_when_it_is_a_different_bundle(
    tmp_path: Path,
) -> None:
    """The control plane is up but still serves the bundle the daemon died on
    twice: the last-known-good serves meanwhile, reported as a revert."""
    _crashed_on_cached_bundle(tmp_path, "big")
    # A second death on the cached bundle, with a different bundle committed as
    # last-known-good underneath (an agent that had it from before).
    loop = _loop(tmp_path, _Driver(tmp_path))
    loop._client = _client(_Down())  # type: ignore[method-assign]
    loop._poll_once()
    (tmp_path / "config" / "previous.json").write_text(
        '{"etag": "small", ' '"structural_etag": "s-small", ' '"zones": []}'
    )
    (tmp_path / "config" / "previous.etag").write_text("small")

    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http([_bundle("big"), _bundle("fixed")])
    loop._client = _client(http)  # type: ignore[method-assign]
    loop._poll_once()

    assert driver.applied == ["small"]
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.etag == "small"
    assert loop.apply_status.failed_etag == "big"

    # The operator removes the blocklists: the control plane's new bundle is
    # taken, and the server row clears.
    loop._current_etag = None
    loop._poll_once()
    assert driver.applied == ["small", "fixed"]
    assert loop.apply_status.status == STATUS_OK
    assert loop._boot_hold is None


def test_a_steady_state_apply_is_guarded_too(tmp_path: Path) -> None:
    """The first kill in #2019 came 30 s after a POLL applied the bundle, not
    after a startup apply: that death must count as well."""
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver)
    loop._client = _client(_Http([_bundle("big")]))  # type: ignore[method-assign]
    loop._poll_once()
    assert driver.applied == ["big"]

    driver = _Driver(tmp_path)
    _loop(tmp_path, driver)
    assert driver.applied == []


def test_a_revert_never_goes_back_to_a_bundle_the_daemon_died_on(tmp_path: Path) -> None:
    """``previous`` is committed the moment an apply returns, so it can be the
    bundle that killed the daemon. Reverting to it would kill it again."""
    _crashed_on_cached_bundle(tmp_path, "big")

    class _NextFails(_Driver):
        """Reloads anything but ``next``, so a revert to ``big`` would land."""

        def render(self, bundle: dict[str, Any]) -> None:
            self.fail_on = "reload" if bundle.get("etag") == "next" else None

    driver = _NextFails(tmp_path)
    loop = _loop(tmp_path, driver)
    loop._client = _client(_Http([_bundle("next")]))  # type: ignore[method-assign]
    loop._poll_once()

    assert driver.applied == []  # neither ``next`` nor a revert to ``big`` landed
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    assert loop.apply_status.failed_etag == "next"


# ── the supervisor ─────────────────────────────────────────────────────────


def test_a_sigterm_is_an_orderly_exit(supervised) -> None:  # noqa: F811
    sv = supervised
    rc = sv.run({1: sv.drv.launch, 2: sv.sigterm})
    assert rc == 0
    assert sv.idles[1].orderly_exits == 1  # idles[1] is the sync loop


def test_a_daemon_death_is_not_an_orderly_exit(supervised) -> None:  # noqa: F811
    sv = supervised
    rc = sv.run({1: sv.drv.launch, 3: sv.drv.die})
    assert rc == 2
    assert sv.idles[1].orderly_exits == 0


def test_the_deferred_start_keeps_the_holds_reason(supervised) -> None:  # noqa: F811
    """While the cache is held the daemon start defers (#1056); the heartbeat
    must keep saying why, not "no bundle yet"."""
    sv = supervised
    held = {"status": "degraded", "reason": "config_apply_no_previous: held"}
    seen: list[dict[str, Any]] = []

    def hold() -> None:
        sv.idles[0].daemon_status = dict(held)

    rc = sv.run({1: hold, 3: lambda: seen.append(dict(sv.idles[0].daemon_status)), 4: sv.sigterm})
    assert rc == 0
    assert seen == [held]
