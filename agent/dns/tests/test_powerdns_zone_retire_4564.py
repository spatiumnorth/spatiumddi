"""A zone the bundle drops leaves PowerDNS (#4564).

``_reconcile_zones`` created and updated zones and never deleted one, and the
driver had no zone DELETE call at all. A zone deleted in SpatiumDDI, moved to
another group, converted to a forward zone, a secondary left without
primaries, a switched-off catalog zone and every zone of the group a moved
server left all kept answering authoritatively from LMDB.

The driver tests run real applies (``render`` then ``swap_and_reload``)
against an in-memory stand-in for the pdns REST API and assert on the zones
it is left holding. The sync-loop tests assert when the driver is told the
control plane vouches for the live bundle, which is the only time it deletes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import commit_config, ensure_layout, save_config
from spatium_dns_agent.config_apply import ApplyStatus
from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.base import DriverBase
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver
from spatium_dns_agent.sync import SyncLoop

_ZONES = "/api/v1/servers/localhost/zones"


class _Pdns:
    """The slice of the pdns REST API the reconcile and the retire use."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *zones: str):
        self.zones: set[str] = set(zones)
        self.list_status = 200
        self.delete_status: int | None = None
        self.deletes: list[str] = []
        real_client = httpx.Client

        def client(*args: Any, **kwargs: Any) -> httpx.Client:
            kwargs.pop("transport", None)
            return real_client(*args, transport=httpx.MockTransport(self._handle), **kwargs)

        monkeypatch.setattr(powerdns.httpx, "Client", client)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == _ZONES:
            if method == "GET":
                if self.list_status != 200:
                    return httpx.Response(self.list_status)
                return httpx.Response(
                    200, json=[{"name": z, "kind": "Master", "masters": []} for z in self.zones]
                )
            self.zones.add(json.loads(request.content)["name"].lower())
            return httpx.Response(201, json={})
        rest = path[len(_ZONES) + 1 :]
        zone = rest.split("/", 1)[0]
        if "/" not in rest and method == "DELETE":
            self.deletes.append(zone)
            if self.delete_status is not None:
                return httpx.Response(self.delete_status, json={"error": "nope"})
            if zone not in self.zones:
                return httpx.Response(404)
            self.zones.discard(zone)
            return httpx.Response(204)
        if method == "GET":
            return httpx.Response(200, json={"name": zone, "rrsets": [], "metadata": []})
        if method == "DELETE":
            return httpx.Response(404)  # metadata already absent: benign
        return httpx.Response(204)


def _zone(name: str, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "type": "primary",
        "records": [{"name": "www", "type": "A", "value": "192.0.2.1", "ttl": 60}],
        **extra,
    }


def _bundle(*zones: Any, **extra: Any) -> dict[str, Any]:
    return {
        "options": {},
        "zones": [_zone(z) if isinstance(z, str) else z for z in zones],
        **extra,
    }


def _driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PowerDNSDriver:
    driver = PowerDNSDriver(state_dir=tmp_path)
    monkeypatch.setattr(driver, "daemon_running", lambda: True)
    return driver


def _apply(driver: PowerDNSDriver, bundle: dict[str, Any]) -> None:
    driver.render(bundle)
    driver.swap_and_reload()


def _ledger(tmp_path: Path) -> set[str]:
    return set(json.loads((tmp_path / powerdns._MANAGED_ZONES_FILE).read_text()))


# ── the driver ────────────────────────────────────────────────────────────────


def test_a_zone_the_bundle_drops_is_deleted(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test", "gone.test"))
    driver.control_plane_confirmed()
    assert pdns.zones == {"keep.test.", "gone.test."}

    _apply(driver, _bundle("keep.test"))
    driver.control_plane_confirmed()

    assert pdns.zones == {"keep.test."}
    assert pdns.deletes == ["gone.test."]
    assert _ledger(tmp_path) == {"keep.test."}


def test_nothing_is_deleted_until_the_control_plane_confirms(tmp_path: Path, monkeypatch) -> None:
    """An apply alone may be the cached bundle with the control plane down."""
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test", "gone.test"))
    _apply(driver, _bundle("keep.test"))
    assert pdns.zones == {"keep.test.", "gone.test."}
    assert pdns.deletes == []


def test_a_confirmed_pass_is_not_repeated(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test", "gone.test"))
    _apply(driver, _bundle("keep.test"))
    driver.control_plane_confirmed()
    pdns.zones.add("gone.test.")  # made by hand afterwards: not ours any more
    driver.control_plane_confirmed()
    assert pdns.deletes == ["gone.test."]
    assert "gone.test." in pdns.zones


def test_a_zone_made_behind_the_agent_is_never_deleted(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test"))
    pdns.zones.add("byhand.test.")

    _apply(driver, _bundle("keep.test", "second.test"))
    driver.control_plane_confirmed()
    _apply(driver, _bundle("keep.test"))
    driver.control_plane_confirmed()

    assert pdns.zones == {"keep.test.", "byhand.test."}
    assert pdns.deletes == ["second.test."]


def test_the_first_run_adopts_the_zones_already_there(tmp_path: Path, monkeypatch) -> None:
    """An agent upgraded from a build with no ledger: the zones orphaned
    before the upgrade are the ones the issue is about."""
    pdns = _Pdns(monkeypatch, "keep.test.", "orphan.test.")
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test"))
    assert pdns.zones == {"keep.test.", "orphan.test."}
    driver.control_plane_confirmed()
    assert pdns.zones == {"keep.test."}


def test_the_ledger_survives_a_restart(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    _apply(_driver(tmp_path, monkeypatch), _bundle("keep.test", "gone.test"))

    restarted = _driver(tmp_path, monkeypatch)
    pdns.zones.add("byhand.test.")
    _apply(restarted, _bundle("keep.test"))
    restarted.control_plane_confirmed()

    assert pdns.zones == {"keep.test.", "byhand.test."}


def test_a_bundle_with_no_zone_list_deletes_nothing(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("a.test", "b.test"))
    for broken in ({"options": {}}, {"options": {}, "zones": None}):
        _apply(driver, broken)
        driver.control_plane_confirmed()
    assert pdns.zones == {"a.test.", "b.test."}
    assert pdns.deletes == []
    assert _ledger(tmp_path) == {"a.test.", "b.test."}


def test_an_empty_zone_list_deletes_every_managed_zone(tmp_path: Path, monkeypatch) -> None:
    """What a group whose last zone was deleted sends, and what a server moved
    to an empty group gets."""
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("a.test", "b.test"))
    _apply(driver, _bundle())
    driver.control_plane_confirmed()
    assert pdns.zones == set()


def test_a_failed_apply_deletes_nothing(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test", "gone.test"))
    pdns.list_status = 500
    with pytest.raises(RuntimeError):
        _apply(driver, _bundle("keep.test"))
    driver.control_plane_confirmed()
    assert pdns.zones == {"keep.test.", "gone.test."}
    assert pdns.deletes == []


def test_a_zone_the_driver_stops_rendering_is_deleted(tmp_path: Path, monkeypatch) -> None:
    """Converted to forward, or a secondary whose primaries were removed:
    still in the bundle, no longer served by PowerDNS, so the old
    authoritative copy must go."""
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(
        driver,
        _bundle(
            "fwd.test", _zone("sec.test", type="secondary", masters=["192.0.2.53"]), "keep.test"
        ),
    )
    assert pdns.zones == {"fwd.test.", "sec.test.", "keep.test."}
    _apply(
        driver,
        _bundle(
            _zone("fwd.test", type="forward"),
            _zone("sec.test", type="secondary", masters=[]),
            "keep.test",
        ),
    )
    driver.control_plane_confirmed()
    assert pdns.zones == {"keep.test."}


def test_a_switched_off_catalog_zone_is_deleted(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    catalog = {"mode": "producer", "zone_name": "catalog.test.", "members": []}
    _apply(driver, _bundle("keep.test", catalog=catalog))
    assert "catalog.test." in pdns.zones
    _apply(driver, _bundle("keep.test"))
    driver.control_plane_confirmed()
    assert pdns.zones == {"keep.test."}


def test_a_delete_pdns_refuses_is_retried(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test", "gone.test"))
    _apply(driver, _bundle("keep.test"))
    pdns.delete_status = 500
    driver.control_plane_confirmed()
    assert "gone.test." in pdns.zones
    assert "gone.test." in _ledger(tmp_path), "still ours to delete"

    pdns.delete_status = None
    driver.control_plane_confirmed()
    assert pdns.zones == {"keep.test."}
    assert _ledger(tmp_path) == {"keep.test."}


def test_a_zone_already_gone_leaves_the_ledger(tmp_path: Path, monkeypatch) -> None:
    pdns = _Pdns(monkeypatch)
    driver = _driver(tmp_path, monkeypatch)
    _apply(driver, _bundle("keep.test", "gone.test"))
    pdns.zones.discard("gone.test.")
    _apply(driver, _bundle("keep.test"))
    driver.control_plane_confirmed()
    assert _ledger(tmp_path) == {"keep.test."}


# ── the sync loop: when the driver is told ───────────────────────────────────


class _Driver(DriverBase):
    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        #: When set, every bundle but this one fails at the reload.
        self.only_applies: str | None = None
        self.applied: list[str] = []
        self.confirmed = 0

    def render(self, bundle: dict[str, Any]) -> None:
        self._etag = str(bundle.get("etag"))

    def validate(self) -> None:
        return None

    def swap_and_reload(self) -> None:
        if self.only_applies not in (None, self._etag):
            raise RuntimeError("cannot list PowerDNS zones: connection refused")
        self.applied.append(self._etag)

    def control_plane_confirmed(self) -> None:
        self.confirmed += 1

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        return None

    def start_daemon(self) -> None:
        return None

    def daemon_running(self) -> bool:
        return True


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


class _Resp:
    def __init__(self, status: int, body: dict[str, Any] | None = None):
        self.status_code = status
        self.headers: dict[str, str] = {}
        self._body = body or {}
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


class _Client:
    def __init__(self, resp: _Resp | Exception):
        self._resp = resp

    def __enter__(self) -> _Client:  # noqa: PYI034 - a test double, never subclassed
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, *args: Any, **kwargs: Any) -> _Resp:
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp

    def post(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp(200)


def _cp_bundle(tag: str, structural: str | None = None) -> dict[str, Any]:
    return {
        "etag": tag,
        "structural_etag": structural or f"s-{tag}",
        "zones": [],
        "pending_record_ops": [],
    }


def _loop(tmp_path: Path, driver: _Driver, monkeypatch: pytest.MonkeyPatch) -> SyncLoop:
    ensure_layout(tmp_path)
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **k: None)
    monkeypatch.setattr(sync_mod.time, "sleep", lambda s: None)
    return SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())


def _poll(loop: SyncLoop, monkeypatch: pytest.MonkeyPatch, resp: _Resp | Exception) -> None:
    monkeypatch.setattr(loop, "_client", lambda **kw: _Client(resp))
    loop._poll_once()


def _cached(tmp_path: Path, tag: str) -> None:
    ensure_layout(tmp_path)
    save_config(tmp_path, _cp_bundle(tag), tag)
    commit_config(tmp_path, tag)


def test_the_cached_bundle_at_startup_is_not_a_confirmation(tmp_path: Path, monkeypatch) -> None:
    _cached(tmp_path, "e1")
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    assert driver.applied == ["e1"]
    assert driver.confirmed == 0

    # The control plane stays unreachable: still nothing.
    _poll(loop, monkeypatch, httpx.ConnectError("down"))
    _poll(loop, monkeypatch, _Resp(503))
    assert driver.confirmed == 0


def test_a_304_for_the_live_bundle_confirms_it(tmp_path: Path, monkeypatch) -> None:
    """An upgraded agent restarts onto its cache and the control plane has
    nothing new: the 304 is what lets the pre-upgrade orphans go."""
    _cached(tmp_path, "e1")
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    _poll(loop, monkeypatch, _Resp(304))
    assert driver.confirmed == 1


def test_a_fetched_bundle_that_applies_confirms_it(tmp_path: Path, monkeypatch) -> None:
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    _poll(loop, monkeypatch, _Resp(200, _cp_bundle("e1")))
    assert driver.applied == ["e1"]
    assert driver.confirmed == 1
    # A record-only change: the same structure is live and vouched for.
    _poll(loop, monkeypatch, _Resp(200, _cp_bundle("e2", structural="s-e1")))
    assert driver.applied == ["e1"]
    assert driver.confirmed == 2


def test_a_bundle_that_fails_to_apply_confirms_nothing(tmp_path: Path, monkeypatch) -> None:
    """The last-known-good is re-applied and serves, and the failed bundle is
    parked on its etag: the 304s that follow are for a bundle that is not the
    live one."""
    _cached(tmp_path, "good")
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)

    driver.only_applies = "good"
    _poll(loop, monkeypatch, _Resp(200, _cp_bundle("bad")))
    assert driver.applied == ["good", "good"], "reverted to the last-known-good"
    _poll(loop, monkeypatch, _Resp(304))
    assert driver.confirmed == 0
