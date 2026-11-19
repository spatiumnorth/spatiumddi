"""A boot hold serves the held cache while a 401/404 re-registers (#2182).

During a #2019 boot hold the cached bundle is held back and the daemon has not
started. Since #2052 a 401/404 re-registers in process, and ``reauthenticate``
can back off for up to 5 minutes before it does; for all of that the server
answered nothing, though it had a perfectly good cached config. Non-negotiable
#5: the held cache serves (under the offline rules) while the agent
re-registers, and the control plane's bundle takes over normally afterwards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import httpx
import pytest

from spatium_dns_agent import bootstrap as bootstrap_mod
from spatium_dns_agent import config_apply
from spatium_dns_agent.cache import ensure_layout, load_config, load_previous_config, save_config
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.config_apply import STATUS_NO_PREVIOUS, STATUS_OK

from .test_apply_guard_2019 import (  # noqa: F401 — _quiet is an autouse fixture
    _crashed_on_cached_bundle,
    _die_again_offline,
    _quiet,
)
from .test_config_revert import _bundle, _Driver, _loop


class _Rejects:
    """The control plane answering ``status`` (401 or 404) to the config poll."""

    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(self.status, request=httpx.Request("GET", url))

    def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


class _Serves:
    """The control plane after re-registration: one bundle per poll, and it
    records the token each poll carried."""

    def __init__(self, bundles: list[dict[str, Any]]) -> None:
        self.bundles = bundles
        self.tokens: list[str] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        self.tokens.append(headers["Authorization"])
        if not self.bundles:
            return httpx.Response(304, request=httpx.Request("GET", url))
        return httpx.Response(200, json=self.bundles.pop(0), request=httpx.Request("GET", url))

    def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


class _Registry:
    """What ``register`` saw: the driver's applied bundles when it ran.

    ``reauthenticate`` calls ``register`` after its backoff, so what it records
    is what the server was answering with for the whole of that wait."""

    def __init__(self) -> None:
        self.seen: list[list[str]] = []
        self.driver: _Driver | None = None


@pytest.fixture
def registering(monkeypatch: pytest.MonkeyPatch) -> _Registry:
    bootstrap_mod._reset_reauth_state()
    reg = _Registry()

    def fake_register(cfg: AgentConfig):  # type: ignore[no-untyped-def]
        assert reg.driver is not None
        reg.seen.append(list(reg.driver.applied))
        return "agent", "new-token", {}

    monkeypatch.setattr(bootstrap_mod, "register", fake_register)
    monkeypatch.setattr(bootstrap_mod, "save_token", lambda *a: None)
    return reg


def _held_loop(tmp_path: Path, reg: _Registry) -> tuple[Any, _Driver]:
    _crashed_on_cached_bundle(tmp_path)
    driver = _Driver(tmp_path)
    reg.driver = driver
    loop = _loop(tmp_path, driver)
    assert loop._boot_hold is not None
    assert driver.applied == []
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    return loop, driver


@pytest.mark.parametrize("status", [401, 404])
def test_the_held_cache_serves_while_the_agent_re_registers(
    tmp_path: Path, registering: _Registry, status: int
) -> None:
    loop, driver = _held_loop(tmp_path, registering)
    loop._client = lambda **kw: _Rejects(status)  # type: ignore[method-assign]

    loop._poll_once()

    # The daemon was started from the held cache BEFORE registration ran, so
    # it served through the whole of reauthenticate's backoff.
    assert registering.seen == [["big"]]
    assert driver.applied == ["big"]
    assert loop._boot_hold is None
    assert not (tmp_path / "rendered.held").exists()
    assert loop.token_ref[0] == "new-token"
    assert loop.apply_status.status == STATUS_OK
    # Nothing was fetched: the cache is still the held bundle, and it is the
    # one committed as last-known-good, as on the offline path.
    assert load_config(tmp_path)[1] == "big"
    assert load_previous_config(tmp_path)[1] == "big"
    # A fresh 200 is forced for the new registration.
    assert loop._current_etag is None


def test_the_next_bundle_applies_normally_after_re_registration(
    tmp_path: Path, registering: _Registry
) -> None:
    loop, driver = _held_loop(tmp_path, registering)
    loop._client = lambda **kw: _Rejects(401)  # type: ignore[method-assign]
    loop._poll_once()
    assert driver.applied == ["big"]

    cp = _Serves([_bundle("fixed")])
    loop._client = lambda **kw: cp  # type: ignore[method-assign]
    loop._poll_once()

    assert cp.tokens == ["Bearer new-token"]
    assert driver.applied == ["big", "fixed"]
    assert loop.apply_status.status == STATUS_OK
    assert loop.apply_status.etag == "fixed"
    assert loop._current_etag == "fixed"
    assert load_config(tmp_path)[1] == "fixed"
    assert load_previous_config(tmp_path)[1] == "fixed"


def test_the_same_bundle_from_the_control_plane_is_not_applied_twice(
    tmp_path: Path, registering: _Registry
) -> None:
    """The fallback put the held bundle live; the control plane serving that
    same bundle after re-registration must not re-render or restart it."""
    loop, driver = _held_loop(tmp_path, registering)
    loop._client = lambda **kw: _Rejects(404)  # type: ignore[method-assign]
    loop._poll_once()

    cp = _Serves([_bundle("big")])
    loop._client = lambda **kw: cp  # type: ignore[method-assign]
    loop._poll_once()

    assert driver.applied == ["big"]
    assert loop._current_etag == "big"
    assert loop.apply_status.status == STATUS_OK


def test_a_condemned_held_bundle_is_not_served_while_re_registering(
    tmp_path: Path, registering: _Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback's rules still decide: a bundle the daemon was WATCHED dying
    on twice, with no different last-known-good, is not re-applied just because
    the control plane answered 401 rather than not at all."""
    now = [1_000_000.0]
    monkeypatch.setattr(config_apply.time, "time", lambda: now[0])
    _crashed_on_cached_bundle(tmp_path, watched=True)
    assert _die_again_offline(tmp_path, watched=True) == ["big"]
    driver = _Driver(tmp_path)
    registering.driver = driver
    loop = _loop(tmp_path, driver)
    assert loop._boot_hold is not None
    assert loop._quarantine.etag == "big"
    loop._client = lambda **kw: _Rejects(401)  # type: ignore[method-assign]

    loop._poll_once()

    assert registering.seen == [[]]
    assert driver.applied == []
    assert loop._boot_hold is not None
    assert loop.token_ref[0] == "new-token"


def test_no_hold_means_no_apply_on_a_401(tmp_path: Path, registering: _Registry) -> None:
    """Outside a hold the daemon is already serving the cache: a 401 only
    re-registers, it does not re-apply anything."""
    ensure_layout(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    driver = _Driver(tmp_path)
    registering.driver = driver
    loop = _loop(tmp_path, driver)
    assert driver.applied == ["good"]
    loop._client = lambda **kw: _Rejects(401)  # type: ignore[method-assign]

    loop._poll_once()

    assert registering.seen == [["good"]]
    assert driver.applied == ["good"]


def test_a_second_401_does_not_apply_the_held_cache_again(
    tmp_path: Path, registering: _Registry
) -> None:
    """The fallback ends the hold once the cache is live, so a further 401 (the
    new token rejected too, or the heartbeat thread's token racing this one)
    finds no hold and leaves the running daemon alone: no second apply."""
    loop, driver = _held_loop(tmp_path, registering)
    loop._client = lambda **kw: _Rejects(401)  # type: ignore[method-assign]
    loop._poll_once()
    bootstrap_mod._reset_reauth_state()
    loop._poll_once()

    assert driver.applied == ["big"]
    assert registering.seen == [["big"], ["big"]]
    assert loop._boot_hold is None
