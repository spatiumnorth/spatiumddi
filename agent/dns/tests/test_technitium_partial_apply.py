"""A record Technitium refuses degrades the apply; it does not hold the group
back (#1608, on #1280's partial-apply model).

ddi-pg's gate walk of #1608 on Technitium 15.4: the first cut made a partly
refused structural apply RAISE, so the #882 machinery quarantined the bundle
and retried it at 60 s / 300 s / 900 s. Until the refused record was deleted,
every later change to the group was held back — an A record added to the same
zone sat unacknowledged, a TSIG key never reached the daemon — and the revert
deleted records the failed apply had just added. These drive the real
``SyncLoop`` against the real ``TechnitiumDriver`` with only the HTTP layer
faked, so they pin the loop and the driver together.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import ensure_layout, load_previous_config
from spatium_dns_agent.config_apply import STATUS_OK, STATUS_REVERTED, ApplyStatus
from spatium_dns_agent.drivers.technitium import TechnitiumDriver
from spatium_dns_agent.sync import SyncLoop

REFUSAL = "Index was outside the bounds of the array."


class _FakeResponse:
    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


class _Daemon:
    """The Technitium API, faked at ``_request``. Refuses every SVCB add, and
    can be switched to unreachable or to rejecting the agent's token."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.unreachable = False
        self.reject_token = False

    def request(
        self, _token: str, _method: str, path: str, params: dict[str, Any]
    ) -> _FakeResponse:
        self.calls.append((path, dict(params)))
        if self.unreachable:
            raise httpx.ConnectError("connection refused")
        if self.reject_token:
            return _FakeResponse({"status": "invalid-token"})
        if path == "zones/records/get":
            return _FakeResponse({"status": "ok", "response": {"records": []}})
        if path == "zones/records/add" and params.get("type") == "SVCB":
            return _FakeResponse({"status": "error", "errorMessage": REFUSAL})
        return _FakeResponse({"status": "ok"})

    def added(self, rtype: str) -> list[dict[str, Any]]:
        return [p for path, p in self.calls if path == "zones/records/add" and p["type"] == rtype]


def _driver(tmp_path: Path, daemon: _Daemon) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    d.daemon_running = lambda: True  # type: ignore[method-assign]
    d._wait_for_api_up = lambda **_: None  # type: ignore[method-assign]
    d._get_api_token = lambda: "tok-1"  # type: ignore[method-assign]
    d._reprovision_token = lambda stale: None  # type: ignore[method-assign]
    d._request = daemon.request  # type: ignore[method-assign]
    return d


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

    def httpx_verify(self) -> bool:
        return True


class _Resp:
    def __init__(self, body: dict[str, Any]):
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self._body = body
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


class _Client:
    def __init__(self, body: dict[str, Any]):
        self._body = body

    def __enter__(self) -> _Client:  # noqa: PYI034 - a test double, never subclassed
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp(self._body)

    def post(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp({})


SVCB = {"name": "svc", "type": "SVCB", "value": "1 . alpn=h2 port=8443", "ttl": 300}
WWW = {"name": "www", "type": "A", "value": "10.0.0.1", "ttl": 300}


def _bundle(
    etag: str,
    structural: str,
    records: list[dict[str, Any]],
    ops: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "etag": etag,
        "structural_etag": structural,
        "zones": [{"name": "example.com.", "type": "primary", "ttl": 3600, "records": records}],
        "pending_record_ops": ops or [],
    }


def _op(op_id: str, record: dict[str, Any]) -> dict[str, Any]:
    return {"op_id": op_id, "op": "create", "zone_name": "example.com.", "record": record}


def _loop(tmp_path: Path, driver: TechnitiumDriver, monkeypatch: pytest.MonkeyPatch) -> SyncLoop:
    ensure_layout(tmp_path)
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **k: None)
    return SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())


def _poll(loop: SyncLoop, monkeypatch: pytest.MonkeyPatch, bundle: dict[str, Any]) -> None:
    monkeypatch.setattr(loop, "_client", lambda: _Client(bundle))
    loop._poll_once()


def _acks(loop: SyncLoop) -> dict[str, dict[str, Any]]:
    return {a["op_id"]: a for a in loop.heartbeat.pending_acks}


def test_a_refused_record_does_not_hold_back_the_rest_of_the_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = _Daemon()
    driver = _driver(tmp_path, daemon)
    loop = _loop(tmp_path, driver, monkeypatch)

    # A structural apply carrying the refused SVCB, plus record ops for a
    # DIFFERENT name in the same zone and for the refused record itself.
    new_a = {"name": "new", "type": "A", "value": "10.0.0.9", "ttl": 300}
    _poll(
        loop,
        monkeypatch,
        _bundle("e1", "s1", [WWW, SVCB], ops=[_op("op-new", new_a), _op("op-svc", SVCB)]),
    )

    # Everything the daemon accepts is applied: the zone's other record via
    # the reconcile, and the other name's op.
    assert [p["domain"] for p in daemon.added("A")] == ["www.example.com", "new.example.com"]
    acks = _acks(loop)
    assert acks["op-new"]["result"] == "ok", "a different record in the same zone is acked"
    # The refused record's own op is NOT reported as applied.
    assert acks["op-svc"]["result"] == "error"
    assert REFUSAL in acks["op-svc"]["message"]

    # Reported as #1280's partial apply, naming zone + record + the reason.
    status = loop.apply_status
    assert status.status == STATUS_REVERTED
    error = status.error or ""
    assert error.startswith(sync_mod.PARTIAL_APPLY_PREFIX), error
    assert "example.com: record add svc.example.com SVCB" in error
    assert REFUSAL in error
    assert status.etag == "e1", "the new bundle is what is live — nothing rolled back"

    # No quarantine, no revert: the bundle is committed as last-known-good.
    assert loop._quarantine.etag is None
    assert load_previous_config(tmp_path)[1] == "e1"
    assert (tmp_path / ".ready").exists()

    # A later record-only poll is not held back either, and the verdict
    # stays up (the SVCB is still refused).
    later = {"name": "later", "type": "A", "value": "10.0.0.10", "ttl": 300}
    _poll(loop, monkeypatch, _bundle("e2", "s1", [WWW, SVCB], ops=[_op("op-later", later)]))
    assert _acks(loop)["op-later"]["result"] == "ok"
    assert any(p["domain"] == "later.example.com" for p in daemon.added("A"))
    assert loop.apply_status.status == STATUS_REVERTED


def test_a_clean_structural_apply_clears_the_partial_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = _Daemon()
    driver = _driver(tmp_path, daemon)
    loop = _loop(tmp_path, driver, monkeypatch)

    _poll(loop, monkeypatch, _bundle("e1", "s1", [WWW, SVCB]))
    assert (loop.apply_status.error or "").startswith(sync_mod.PARTIAL_APPLY_PREFIX)
    assert loop._quarantine.etag is None

    # The operator deletes the refused record: the next structural apply
    # lands with nothing refused, and the verdict clears.
    _poll(loop, monkeypatch, _bundle("e2", "s2", [WWW]))
    assert loop.apply_status.status == STATUS_OK
    assert loop.heartbeat.daemon_status.get("status") != "degraded"


@pytest.mark.parametrize("failure", ["unreachable", "reject_token"])
def test_a_daemon_failure_still_fails_the_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """An unreachable daemon or one rejecting our token has refused nothing:
    the apply fails and is quarantined as before, and is never reported as a
    partial apply of refused items."""
    daemon = _Daemon()
    driver = _driver(tmp_path, daemon)
    loop = _loop(tmp_path, driver, monkeypatch)
    setattr(daemon, failure, True)

    _poll(loop, monkeypatch, _bundle("e1", "s1", [WWW], ops=[_op("op-new", WWW)]))

    assert loop._quarantine.etag == "e1"
    error = loop.apply_status.error or ""
    assert not error.startswith(sync_mod.PARTIAL_APPLY_PREFIX)
    assert "connection refused" in error or "auth failure" in error, error
    assert _acks(loop)["op-new"]["result"] == "error"
    assert "not applied" in _acks(loop)["op-new"]["message"]
