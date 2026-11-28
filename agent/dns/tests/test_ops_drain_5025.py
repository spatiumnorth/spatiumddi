"""Draining a long record-op queue no longer costs a whole bundle per page (#5025).

Measured at 1M devices: every 5,000-op page re-fetched, re-parsed and re-saved
the 250 MB bundle it already held, applied the ops one UPDATE each, and ran the
20,000-zone served-serial sweep on the sync thread. These pin each part:

* a reply that is only the ops page of the bundle the agent holds (the control
  plane's answer to ``X-Spatium-Ops-Only``), and a full reply that carries the
  ETag already held (an older control plane), neither parse nor re-save it;
* consecutive ops of a zone are one RFC 2136 UPDATE, in order, and a batch that
  fails is applied op by op with the per-op errors it always had;
* the TSIG key is parsed once;
* the served-serial sweep waits while ops are draining and skips the zones the
  ops touched.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Self

import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import httpx
import pytest

from spatium_dns_agent import fetch as fetch_mod
from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import ensure_layout, load_config
from spatium_dns_agent.config_apply import ApplyStatus
from spatium_dns_agent.drivers import bind9 as bind9_mod
from spatium_dns_agent.drivers.base import SERIAL_UNREAD, DriverBase
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.fetch import get_config
from spatium_dns_agent.sync import SyncLoop

STRUCTURAL = "s-1"

# ── get_config: reading only the head of a reply that carries the held ETag ──


class _Resp:
    status_code = 200

    def __init__(self, chunks: list[bytes]) -> None:
        self.headers = httpx.Headers({"ETag": 'W/"e1"'})
        self._chunks = chunks
        self.consumed = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def iter_bytes(self) -> Any:
        for chunk in self._chunks:
            self.consumed += 1
            yield chunk


class _StreamClient:
    def __init__(self, chunks: list[bytes]) -> None:
        self.resp = _Resp(chunks)

    def stream(self, method: str, path: str, headers: Any = None) -> _Resp:
        return self.resp


def _body(etag: str, ops: list[dict[str, Any]], *, zones: int = 50) -> bytes:
    """A reply as the control plane writes it: the head, then the bundle."""
    head = (
        '{"etag":'
        + json.dumps(etag)
        + ',"pending_record_ops":'
        + json.dumps(ops, separators=(",", ":"))
        + ',"pending_ops_remaining":7,'
    )
    rest = json.dumps(
        {
            "structural_etag": STRUCTURAL,
            "zones": [{"name": f"z{i}.test.", "serial": 1, "records": []} for i in range(zones)],
        },
        separators=(",", ":"),
    )
    return (head + rest[1:]).encode()


def _split(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def test_a_reply_with_the_held_etag_is_read_as_far_as_its_head(tmp_path: Path) -> None:
    ops = [{"op_id": "o1", "record": {"name": "é", "value": "10.0.0.1"}}]
    client = _StreamClient(_split(_body("e1", ops, zones=2000), 64))

    resp = get_config(client, {}, tmp_path, hold_etag="e1")

    assert resp.status_code == 200
    assert resp.json() == {
        "etag": "e1",
        "pending_record_ops": ops,
        "pending_ops_remaining": 7,
        "head_only": True,
    }
    # Not the body: a handful of 64-byte chunks of a hundred thousand bytes.
    assert client.resp.consumed < 20
    assert not (tmp_path / fetch_mod.FETCH_SPOOL).exists()


def test_a_value_that_looks_like_the_end_of_the_head_does_not_end_it(tmp_path: Path) -> None:
    ops = [{"op_id": "o1", "record": {"value": 'x","pending_ops_remaining":99,'}}]
    resp = get_config(_StreamClient(_split(_body("e1", ops), 5)), {}, tmp_path, hold_etag="e1")
    assert resp.json()["pending_record_ops"] == ops
    assert resp.json()["pending_ops_remaining"] == 7


@pytest.mark.parametrize("hold", ["e0", None], ids=["another-etag", "nothing-held"])
def test_any_other_reply_is_read_in_full(tmp_path: Path, hold: str | None) -> None:
    ops = [{"op_id": "o1", "record": {"name": "a", "value": "10.0.0.1"}}]
    client = _StreamClient(_split(_body("e1", ops, zones=40), 97))

    resp = get_config(client, {}, tmp_path, hold_etag=hold)

    body = resp.json()
    assert "head_only" not in body
    assert body["etag"] == "e1" and body["pending_record_ops"] == ops
    assert len(body["zones"]) == 40
    assert body["structural_etag"] == STRUCTURAL
    assert not (tmp_path / fetch_mod.FETCH_SPOOL).exists()


def test_a_body_that_does_not_open_like_a_head_is_read_in_full(tmp_path: Path) -> None:
    other = json.dumps({"zones": [], "etag": "e1", "pending_record_ops": []}).encode()
    resp = get_config(_StreamClient(_split(other, 9)), {}, tmp_path, hold_etag="e1")
    body = resp.json()
    assert body["zones"] == [] and "head_only" not in body


# ── the sync loop ─────────────────────────────────────────────────────────


class _Driver(DriverBase):
    def __init__(self, state_dir: Path) -> None:
        super().__init__(state_dir)
        self.applied: list[str] = []
        self.rendered = 0

    def render(self, bundle: dict[str, Any]) -> None:
        self.rendered += 1

    def validate(self) -> None:
        return None

    def swap_and_reload(self) -> None:
        return None

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
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


def _op(op_id: str, zone: str = "a.test.", target: int | None = None) -> dict[str, Any]:
    op: dict[str, Any] = {
        "op_id": op_id,
        "zone_name": zone,
        "op": "create",
        "record": {"name": op_id, "type": "A", "value": "192.0.2.1", "ttl": None},
    }
    if target is not None:
        op["target_serial"] = target
    return op


def _bundle(etag: str, ops: list[dict[str, Any]], remaining: int = 0) -> dict[str, Any]:
    return {
        "etag": etag,
        "structural_etag": STRUCTURAL,
        "zones": [{"name": "a.test.", "serial": 5, "records": [{"name": "h", "type": "A"}]}],
        "pending_record_ops": ops,
        "pending_ops_remaining": remaining,
    }


class _Reply:
    def __init__(self, status: int, body: Any = None) -> None:
        self.status_code, self._body, self.headers, self.text = status, body, {}, ""

    def json(self) -> Any:
        return self._body


class _ControlPlane:
    """Answers each config poll with the next scripted reply; records the
    headers of every poll."""

    def __init__(self) -> None:
        self.replies: list[Any] = []
        self.polls: list[dict[str, str]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, path: str, headers: dict[str, str] | None = None) -> Any:
        if path == fetch_mod.CONFIG_PATH:
            self.polls.append(dict(headers or {}))
            return self.replies.pop(0)
        return _Reply(200, {})

    def post(self, path: str, headers: Any = None, json: Any = None) -> _Reply:
        return _Reply(200, {"updated": 0})


def _loop(tmp_path: Path) -> tuple[SyncLoop, _Driver, _ControlPlane]:
    ensure_layout(tmp_path)
    driver = _Driver(tmp_path)
    loop = SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())
    cp = _ControlPlane()
    loop._client = lambda **kw: cp  # type: ignore[method-assign]
    return loop, driver, cp


def _forbid_resave(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no(*a: Any, **k: Any) -> None:
        raise AssertionError("the bundle was parsed and saved again")

    monkeypatch.setattr(sync_mod, "save_config", _no)


def _current(tmp_path: Path) -> Path:
    return tmp_path / "config" / "current.json"


def test_an_ops_only_reply_applies_the_ops_without_touching_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop, driver, cp = _loop(tmp_path)
    cp.replies = [_Reply(200, _bundle("e1", [_op("o1")], remaining=2))]
    loop._poll_once()  # the first fetch: a full body, saved, applied
    assert driver.rendered == 1 and driver.applied == ["o1"]
    assert "X-Spatium-Ops-Only" not in cp.polls[0]  # nothing held yet
    before = _current(tmp_path).stat()
    cached_before = _current(tmp_path).read_bytes()

    _forbid_resave(monkeypatch)
    cp.replies = [
        _Reply(
            200,
            {
                "etag": "e1",
                "pending_record_ops": [_op("o2"), _op("o3")],
                "pending_ops_remaining": 0,
                "ops_only": True,
            },
        )
    ]
    loop._poll_once()

    assert cp.polls[1]["X-Spatium-Ops-Only"] == "1"
    assert cp.polls[1]["If-None-Match"] == "e1"
    assert driver.applied == ["o1", "o2", "o3"]
    assert driver.rendered == 1  # no structural re-render either
    assert [a["result"] for a in loop.heartbeat.pending_acks] == ["ok", "ok", "ok"]
    # The cache is the file it was: not rewritten, byte for byte.
    after = _current(tmp_path).stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert _current(tmp_path).read_bytes() == cached_before
    # ...and still a cache a restart can serve from (non-negotiable #5).
    cached, etag = load_config(tmp_path)
    assert etag == "e1" and cached is not None and cached["structural_etag"] == STRUCTURAL
    assert cached["zones"][0]["records"] == [{"name": "h", "type": "A"}]


def test_a_full_reply_carrying_the_held_etag_is_not_parsed_or_saved_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A control plane older than #5025 sends the body with every page."""
    loop, driver, _cp = _loop(tmp_path)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            return httpx.Response(200, json={})
        seen.append(request.headers.get("x-spatium-ops-only", ""))
        if len(seen) == 1:
            body = json.dumps(_bundle("e1", [_op("o1")])).encode()
        else:
            body = _body("e1", [_op("o2")], zones=3000)
        return httpx.Response(200, content=body, headers={"ETag": 'W/"e1"'})

    loop._client = lambda **kw: httpx.Client(  # type: ignore[method-assign]
        transport=httpx.MockTransport(handler), base_url="http://cp.invalid"
    )
    loop._poll_once()
    cached_before = _current(tmp_path).read_bytes()

    _forbid_resave(monkeypatch)

    def _no_parse(*a: Any, **k: Any) -> None:
        raise AssertionError("the body was parsed")

    monkeypatch.setattr(fetch_mod, "parse_bundle_file", _no_parse)
    loop._poll_once()

    assert seen == ["", "1"]
    assert driver.applied == ["o1", "o2"] and driver.rendered == 1
    assert _current(tmp_path).read_bytes() == cached_before


def test_a_changed_etag_is_saved_and_applied_as_before(tmp_path: Path) -> None:
    loop, driver, cp = _loop(tmp_path)
    cp.replies = [_Reply(200, _bundle("e1", [])), _Reply(200, _bundle("e2", [_op("o2")]))]
    loop._poll_once()
    loop._poll_once()

    assert cp.polls[1]["X-Spatium-Ops-Only"] == "1"  # it asked, and got a body anyway
    assert load_config(tmp_path)[1] == "e2"
    assert driver.applied == ["o2"]


def test_the_header_is_not_sent_when_the_held_bundle_is_not_the_live_one(tmp_path: Path) -> None:
    loop, _driver, cp = _loop(tmp_path)
    cp.replies = [_Reply(200, _bundle("e1", [])), _Reply(304), _Reply(304), _Reply(304)]
    loop._poll_once()
    loop._poll_once()
    assert "X-Spatium-Ops-Only" in cp.polls[1]

    loop._zones_refused = True  # part of it is not served: read the body in full
    loop._poll_once()
    assert "X-Spatium-Ops-Only" not in cp.polls[2]
    loop._zones_refused = False

    loop._live_etag = None  # a failed apply, a revert
    loop._poll_once()
    assert "X-Spatium-Ops-Only" not in cp.polls[3]


def test_an_ops_only_reply_for_a_bundle_not_held_is_returned_unapplied(tmp_path: Path) -> None:
    loop, driver, cp = _loop(tmp_path)
    cp.replies = [
        _Reply(200, _bundle("e1", [])),
        _Reply(200, {"etag": "other", "pending_record_ops": [_op("o9")], "ops_only": True}),
    ]
    loop._poll_once()
    loop._poll_once()

    assert driver.applied == []
    assert [(a["result"]) for a in loop.heartbeat.pending_acks] == ["error"]
    assert loop._current_etag is None  # the next poll asks for the body


# ── batching ops of one zone into one RFC 2136 UPDATE ────────────────────


def _rrset_op(op_id: str, zone: str, name: str, value: str, target: int | None = None) -> dict:
    op = {
        "op_id": op_id,
        "zone_name": zone,
        "op": "create",
        "record": {
            "name": name,
            "type": "A",
            "value": value,
            "ttl": 300,
            "rrset": {"ttl": 300, "members": [{"value": value}]},
        },
    }
    if target is not None:
        op["target_serial"] = target
    return op


class _Ok:
    def __init__(self, rcode: int = 0) -> None:
        self._rcode = rcode

    def rcode(self) -> int:
        return self._rcode


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """The UPDATE messages handed to ``dns.query.tcp``."""
    sent: list[Any] = []

    def fake_tcp(q: Any, where: str, timeout: float | None = None, **kw: Any) -> _Ok:
        sent.append(q)
        return _Ok(sent_rcode(q))

    def sent_rcode(q: Any) -> int:
        return 5 if getattr(q, "_refuse", False) else 0

    monkeypatch.setattr(dns.query, "tcp", fake_tcp)
    return sent


def _driver(tmp_path: Path) -> Bind9Driver:
    drv = Bind9Driver(state_dir=tmp_path)
    drv._served_soa = lambda zone: (None, 3600, None, False)  # type: ignore[method-assign]
    return drv


def _adds(update: Any) -> list[str]:
    return [rd.to_text() for rrset in update.update if rrset.deleting is None for rd in rrset]


def test_ops_of_one_zone_are_one_update_and_order_is_kept(tmp_path: Path, wire: list[Any]) -> None:
    drv = _driver(tmp_path)
    ops = [
        _rrset_op("1", "a.test.", "h1", "10.0.0.1"),
        _rrset_op("2", "a.test.", "h2", "10.0.0.2"),
        _rrset_op("3", "b.test.", "h1", "10.0.1.1"),
        _rrset_op("4", "a.test.", "h3", "10.0.0.3"),
        _rrset_op("5", "a.test.", "h4", "10.0.0.4"),
    ]
    plan = drv.plan_op_batches(ops)
    assert [[o["op_id"] for o in b] for b in plan] == [["1", "2"], ["3"], ["4", "5"]]

    assert drv.apply_record_op_batch(plan[0]) == [None, None]
    assert len(wire) == 1
    msg = wire[0]
    assert msg.origin.to_text() == "a.test."
    assert _adds(msg) == ["10.0.0.1", "10.0.0.2"]
    # In order, each as the whole-RRset write a single op is (#773).
    kinds = [
        ("delete-rrset" if r.deleting == dns.rdataclass.ANY else "add", r.name.to_text())
        for r in msg.update
    ]
    assert kinds == [
        ("delete-rrset", "h1"),
        ("add", "h1"),
        ("delete-rrset", "h2"),
        ("add", "h2"),
    ]


def test_a_run_never_crosses_an_op_it_cannot_batch(tmp_path: Path) -> None:
    drv = _driver(tmp_path)
    legacy = {
        "op_id": "L",
        "zone_name": "a.test.",
        "op": "create",
        "record": {"name": "old", "type": "A", "value": "10.0.0.9"},
    }
    rollover = {"op_id": "R", "zone_name": "a.test.", "op": "dnssec_rollover", "record": {}}
    ops = [
        _rrset_op("1", "a.test.", "h1", "10.0.0.1"),
        legacy,
        _rrset_op("2", "a.test.", "h2", "10.0.0.2"),
        _rrset_op("3", "a.test.", "h3", "10.0.0.3"),
        rollover,
    ]
    plan = drv.plan_op_batches(ops)
    assert [[o["op_id"] for o in b] for b in plan] == [["1"], ["L"], ["2", "3"], ["R"]]
    assert [o["op_id"] for b in plan for o in b] == [o["op_id"] for o in ops]


def test_an_op_that_can_change_the_apex_is_applied_on_its_own(tmp_path: Path) -> None:
    drv = _driver(tmp_path)
    drv._apex_blob = (  # type: ignore[attr-defined]
        b"\na.test\t"
        + json.dumps({"name": "a.test.", "ns": [], "primary_ns": "ns1.a.test."}).encode()
        + b"\n"
    )
    ns = _rrset_op("n", "a.test.", "@", "ns2.a.test.")
    ns["record"]["type"] = "NS"
    glue = _rrset_op("g", "a.test.", "ns1", "10.0.0.53")
    plain = [
        _rrset_op("1", "a.test.", "h1", "10.0.0.1"),
        _rrset_op("2", "a.test.", "h2", "10.0.0.2"),
    ]
    plan = drv.plan_op_batches([plain[0], ns, glue, plain[1]])
    assert [[o["op_id"] for o in b] for b in plan] == [["1"], ["n"], ["g"], ["2"]]


def test_the_batch_is_bounded(tmp_path: Path) -> None:
    drv = _driver(tmp_path)
    ops = [_rrset_op(str(i), "a.test.", f"h{i}", "10.0.0.1") for i in range(450)]
    plan = drv.plan_op_batches(ops)
    assert [len(b) for b in plan] == [200, 200, 50]
    fat = [_rrset_op(str(i), "a.test.", "h", "x" * 9000) for i in range(6)]
    assert max(len(b) for b in drv.plan_op_batches(fat)) <= 4


def test_a_batch_carries_the_latest_serial_once(tmp_path: Path, wire: list[Any]) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    soa = dns.rdata.from_text("IN", "SOA", "ns1.a.test. h.a.test. 5 3600 600 86400 300")
    drv._served_soa = lambda zone: (soa, 300, 5, False)  # type: ignore[method-assign]
    drv.apply_record_op_batch(
        [
            _rrset_op("1", "a.test.", "h1", "10.0.0.1", target=6),
            _rrset_op("2", "a.test.", "h2", "10.0.0.2", target=8),
            _rrset_op("3", "a.test.", "h3", "10.0.0.3", target=7),
        ]
    )
    soas = [r for r in wire[0].update if r.rdtype == dns.rdatatype.SOA]
    assert len(soas) == 1 and soas[0][0].serial == 8


def test_a_failed_batch_falls_back_to_per_op_with_the_same_errors(
    tmp_path: Path, wire: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """named refuses the whole message; each op is then applied alone, and the
    one that is refused on its own is the one reported."""
    drv = _driver(tmp_path)

    def tcp(q: Any, where: str, timeout: float | None = None, **kw: Any) -> _Ok:
        wire.append(q)
        bad = any(r.name.to_text() == "bad" for r in q.update)
        return _Ok(5 if bad else 0)

    monkeypatch.setattr(dns.query, "tcp", tcp)
    loop, _d, cp = _loop(tmp_path)
    loop.driver = drv
    loop._current_structural_etag = STRUCTURAL  # the config is already live
    ops = [
        _rrset_op("1", "a.test.", "h1", "10.0.0.1"),
        _rrset_op("2", "a.test.", "bad", "10.0.0.2"),
        _rrset_op("3", "a.test.", "h3", "10.0.0.3"),
    ]
    cp.replies = [_Reply(200, _bundle("e1", ops))]
    loop._poll_once()

    acks = loop.heartbeat.pending_acks
    assert [(a["op_id"], a["result"]) for a in acks] == [("1", "ok"), ("2", "error"), ("3", "ok")]
    assert "rcode=5" in acks[1]["message"] and "name=bad" in acks[1]["message"]
    assert loop.heartbeat.failed_ops_count == 1
    # One refused batch, then one message per op.
    assert len(wire) == 4


def test_a_batch_sent_through_the_sync_loop_acks_every_op_in_order(
    tmp_path: Path, wire: list[Any]
) -> None:
    loop, _d, cp = _loop(tmp_path)
    loop.driver = _driver(tmp_path)
    loop._current_structural_etag = STRUCTURAL  # the config is already live
    ops = [_rrset_op(str(i), "a.test.", f"h{i}", "10.0.0.1") for i in range(6)]
    cp.replies = [_Reply(200, _bundle("e1", ops))]
    loop._poll_once()

    assert len(wire) == 1
    assert [a["op_id"] for a in loop.heartbeat.pending_acks] == [str(i) for i in range(6)]
    assert {a["result"] for a in loop.heartbeat.pending_acks} == {"ok"}


def test_a_driver_that_does_not_batch_keeps_the_per_op_path(tmp_path: Path) -> None:
    loop, driver, cp = _loop(tmp_path)
    cp.replies = [_Reply(200, _bundle("e1", [_op("o1"), _op("o2"), _op("o3")]))]
    loop._poll_once()
    assert driver.applied == ["o1", "o2", "o3"]


# ── the TSIG key ─────────────────────────────────────────────────────────


def test_the_tsig_key_is_parsed_once_and_again_when_the_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    key = tmp_path / "tsig" / "ddns.key"
    key.parent.mkdir(parents=True)
    key.write_text('key "k1" { algorithm hmac-sha256; secret "c2VjcmV0MQ=="; };\n')
    parses: list[dict[str, str]] = []
    real = bind9_mod.dns.tsigkeyring.from_text

    def counting(keys: dict[str, str]) -> Any:
        parses.append(keys)
        return real(keys)

    monkeypatch.setattr(bind9_mod.dns.tsigkeyring, "from_text", counting)

    first = drv._ddns_keyring()
    for _ in range(50):
        assert drv._ddns_keyring() is first
    assert len(parses) == 1 and list(parses[0]) == ["k1"]

    key.write_text('key "k2" { algorithm hmac-sha256; secret "c2VjcmV0Mg=="; };\n')
    os.utime(key, ns=(1, 1))  # a changed mtime even on a coarse clock
    assert drv._ddns_keyring() is not first
    assert [list(p) for p in parses] == [["k1"], ["k2"]]


def test_no_key_file_is_no_keyring(tmp_path: Path) -> None:
    assert Bind9Driver(state_dir=tmp_path)._ddns_keyring() is None


# ── the served-serial sweep ──────────────────────────────────────────────


class _SweepDriver(_Driver):
    def __init__(self, state_dir: Path) -> None:
        super().__init__(state_dir)
        self.sweeps: list[Any] = []

    def periodic_served_serials(self, exclude: Any = ()) -> dict[str, int]:
        self.sweeps.append(set(exclude))
        return {}


def test_the_sweep_waits_while_ops_drain_and_skips_the_zones_they_touched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(tmp_path)
    driver = _SweepDriver(tmp_path)
    loop = SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())
    cp = _ControlPlane()
    loop._client = lambda **kw: cp  # type: ignore[method-assign]
    cp.replies = [_Reply(200, _bundle("e1", [_op("o1", "a.test.", target=6)], remaining=5000))]
    loop._poll_once()
    assert loop._draining

    clock = [1000.0]
    monkeypatch.setattr(sync_mod.time, "monotonic", lambda: clock[0])
    loop._report_served_serials()
    clock[0] += 61
    loop._report_served_serials()
    assert driver.sweeps == []  # ops are still draining: no sweep

    clock[0] += sync_mod.SERVED_REPORT_MAX_DEFER_SECONDS
    loop._report_served_serials()
    # The bound passed: it runs, without the zone the ops reported themselves.
    assert driver.sweeps == [{"a.test"}]

    # The queue empties (a 304): the next sweep is a normal one, over every zone.
    cp.replies = [_Reply(304)]
    loop._poll_once()
    assert not loop._draining
    clock[0] += 61
    loop._report_served_serials()
    assert driver.sweeps == [{"a.test"}, set()]


def test_a_zone_whose_serial_the_op_could_not_read_stays_in_the_sweep(tmp_path: Path) -> None:
    class _Unread(_SweepDriver):
        def reached_serial(self, zone_name: str) -> object:
            return SERIAL_UNREAD

    ensure_layout(tmp_path)
    driver = _Unread(tmp_path)
    loop = SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())
    cp = _ControlPlane()
    loop._client = lambda **kw: cp  # type: ignore[method-assign]
    cp.replies = [_Reply(200, _bundle("e1", [_op("o1", "a.test.", target=6)])), _Reply(304)]
    loop._poll_once()
    loop._poll_once()  # the queue is empty: the sweep is no longer deferred
    loop._report_served_serials()
    # Nothing was reported for a.test, so the sweep still reads it.
    assert driver.sweeps == [set()]


def test_bind9_leaves_the_excluded_zones_out_of_the_sweep(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv._rendered_has_views = False  # type: ignore[attr-defined]
    drv._apex_blob = b"a.test\t{}\nb.test\t{}\nc.test\t{}"  # type: ignore[attr-defined]
    drv._rendered_secondaries = ["s.test"]  # type: ignore[attr-defined]
    read: list[str] = []

    def served(zone: str) -> tuple[Any, int, int, bool]:
        read.append(zone)
        return None, 0, 7, False

    drv._served_soa = served  # type: ignore[method-assign]
    assert drv.periodic_served_serials(exclude={"B.test.", "s.test"}) == {
        "a.test": 7,
        "c.test": 7,
    }
    assert sorted(read) == ["a.test.", "c.test."]
