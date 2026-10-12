"""#1373 — the zone serial a record change brings is reported once its op applies.

The agent reports each zone's serial (POST /dns/agents/zone-state, the
per-server sync pill) after a structural reload. While a zone's serial was
part of the structural fingerprint every record change triggered one, so the
report followed every record change. With the serial out of the fingerprint
a record-only change in a group without views is applied over RFC 2136 and
never re-renders, so the serial it brings is reported after the op instead:
the ``target_serial`` the op carries, once the op has applied, never for a
zone an op failed for in that pass, and never backwards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.cache import ensure_layout
from spatium_dns_agent.config_apply import ApplyStatus
from spatium_dns_agent.drivers.base import DriverBase
from spatium_dns_agent.sync import SyncLoop

STRUCTURAL = "s-1"


class _Driver(DriverBase):
    """Applies every op except those for a zone named in ``fail_zones``."""

    def __init__(self, state_dir: Path) -> None:
        super().__init__(state_dir)
        self.fail_zones: set[str] = set()
        self.applied: list[str] = []

    def render(self, bundle: dict[str, Any]) -> None:
        raise AssertionError("a record-only bundle must not re-render")

    def validate(self) -> None:
        return None

    def swap_and_reload(self) -> None:
        raise AssertionError("a record-only bundle must not reload")

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        if op["zone_name"] in self.fail_zones:
            raise RuntimeError("nsupdate returned rcode=5")
        self.applied.append(op["op_id"])
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
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.control_plane_url = "http://cp.invalid"
        self.insecure_skip_tls_verify = False
        self.tls_ca_path = None


class _Resp:
    def __init__(self, status: int, body: Any = None) -> None:
        self.status_code, self._body, self.headers, self.text = status, body, {}, ""

    def json(self) -> Any:
        return self._body


class _ControlPlane:
    """Serves one bundle per poll and records every zone-state POST."""

    def __init__(self) -> None:
        self.bundle: dict[str, Any] = {}
        self.zone_state: list[list[dict[str, Any]]] = []

    def __enter__(self) -> _ControlPlane:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, path: str, headers: dict[str, str] | None = None) -> _Resp:
        return _Resp(200, self.bundle)

    def post(self, path: str, headers: Any = None, json: Any = None) -> _Resp:
        if path == "/api/v1/dns/agents/zone-state":
            self.zone_state.append(json["zones"])
        return _Resp(200, {"updated": len(json.get("zones") or [])})


def _op(op_id: str, zone: str, target: int | None) -> dict[str, Any]:
    op: dict[str, Any] = {
        "op_id": op_id,
        "zone_name": zone,
        "op": "create",
        "record": {"name": op_id, "type": "A", "value": "192.0.2.1", "ttl": None},
    }
    if target is not None:
        op["target_serial"] = target
    return op


def _bundle(etag: str, ops: list[dict[str, Any]]) -> dict[str, Any]:
    zones = [
        {"name": "a.test.", "serial": 2026100105, "records": []},
        {"name": "b.test.", "serial": 2026100107, "records": []},
    ]
    return {
        "etag": etag,
        "structural_etag": STRUCTURAL,
        "zones": zones,
        "pending_record_ops": ops,
    }


def _loop(tmp_path: Path) -> tuple[SyncLoop, _Driver, _ControlPlane]:
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    loop = SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())
    loop._current_structural_etag = STRUCTURAL  # the config is already live
    cp = _ControlPlane()
    loop._client = lambda: cp  # type: ignore[method-assign]
    return loop, driver, cp


def test_the_serial_an_applied_op_brings_is_reported(tmp_path: Path) -> None:
    loop, driver, cp = _loop(tmp_path)
    cp.bundle = _bundle("e1", [_op("o1", "a.test.", 2026100104), _op("o2", "a.test.", 2026100105)])

    loop._poll_once()

    assert driver.applied == ["o1", "o2"]
    assert cp.zone_state == [[{"zone_name": "a.test", "serial": 2026100105}]]


def test_a_zone_whose_op_failed_is_not_reported(tmp_path: Path) -> None:
    loop, driver, cp = _loop(tmp_path)
    driver.fail_zones = {"b.test."}
    cp.bundle = _bundle(
        "e1",
        [_op("o1", "a.test.", 2026100105), _op("o2", "b.test.", 2026100106),
         _op("o3", "b.test.", 2026100107)],
    )

    loop._poll_once()

    # b.test. is not at 2026100107 (nor at 2026100106): its change did not
    # land. a.test. is reported on its own.
    assert cp.zone_state == [[{"zone_name": "a.test", "serial": 2026100105}]]
    assert [a["result"] for a in loop.heartbeat.pending_acks] == ["ok", "error", "error"]


def test_a_late_retry_never_reports_a_zone_backwards(tmp_path: Path) -> None:
    loop, _driver, cp = _loop(tmp_path)
    cp.bundle = _bundle("e1", [_op("o2", "a.test.", 2026100105)])
    loop._poll_once()
    # An older op of the same zone (another name) applies late, after a retry.
    cp.bundle = _bundle("e2", [_op("o1", "a.test.", 2026100104)])
    loop._poll_once()

    assert cp.zone_state == [[{"zone_name": "a.test", "serial": 2026100105}]]


def test_an_op_without_a_target_serial_reports_nothing(tmp_path: Path) -> None:
    loop, driver, cp = _loop(tmp_path)
    cp.bundle = _bundle("e1", [_op("o1", "a.test.", None)])

    loop._poll_once()

    assert driver.applied == ["o1"]
    assert cp.zone_state == []
