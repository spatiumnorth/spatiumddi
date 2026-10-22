"""Taking a big bundle must not cost the agent several copies of it (#2029).

ddi-pg watched the agent reach 1.70-1.74 GB taking a 147 MB bundle (five
blocklists on two views, ~708k RPZ entries per view). It shares named's 2Gi
container, so the container was OOM-killed before named started. The memory
went to the response body held as bytes beside its decoded text and the
parsed bundle, and to the PREVIOUS bundle, still referenced for the DNSSEC
re-read, during the whole fetch and parse.

These tests drive the real fetch path — a real ``httpx.Client`` over a mock
transport streaming the body in chunks, as a socket would — and the real
BIND9 RPZ render, with an agent that has already applied a bundle of the
same shape from its cache.
"""

from __future__ import annotations

import gc
import json
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import (
    commit_config,
    ensure_layout,
    load_config,
    parse_bundle_file,
    save_config,
)
from spatium_dns_agent.config_apply import ApplyStatus
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.fetch import get_config
from spatium_dns_agent.sync import SyncLoop

VIEWS = ("internal", "guest")
LISTS = 5


def _bundle(tag: str, per_view: int) -> dict[str, Any]:
    """Five lists folded into one RPZ zone per view, as the control plane ships it."""
    blocklists = []
    for view in VIEWS:
        entries = [
            {
                "action": "block",
                "block_mode": "sinkhole" if i % 7 == 0 else "nxdomain",
                "domain": f"ads{i}-tracker.list{i % LISTS}.example-cdn.test",
                "is_wildcard": True,
                "target": None,
            }
            for i in range(per_view)
        ]
        blocklists.append(
            {
                "rpz_zone_name": f"spatium-blocklist-{view}.rpz.",
                "entries": entries,
                "exceptions": ["ok.example.test"],
                "view_name": view,
            }
        )
    return {
        "etag": tag,
        "structural_etag": f"s-{tag}",
        "zones": [{"name": "signed.test.", "type": "primary", "dnssec_enabled": True}],
        "views": [{"name": v, "match_clients": ["any"], "recursion": True} for v in VIEWS],
        "options": {"recursion_enabled": True},
        "blocklists": blocklists,
        "pending_record_ops": [],
    }


class _Driver(Bind9Driver):
    """The real BIND9 render; no named to validate against or reload."""

    def validate(self) -> None:
        self.held_back = ()

    def swap_and_reload(self) -> None:
        return None


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

    def httpx_verify(self) -> bool:
        return True


def _serve(body_path: Path, status: int = 200) -> httpx.MockTransport:
    def chunks() -> Iterator[bytes]:
        with body_path.open("rb") as fh:
            while chunk := fh.read(65536):
                yield chunk

    return httpx.MockTransport(lambda req: httpx.Response(status, content=chunks()))


def _client(transport: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(base_url="http://cp.invalid", transport=transport)


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    per_view = 30_000
    state = tmp_path / "state"
    ensure_layout(state)
    # What the agent applied last time: the same shape, already cached.
    save_config(state, _bundle("old", per_view), "old")
    commit_config(state, "old")
    body = tmp_path / "body.json"
    body.write_bytes(json.dumps(_bundle("new", per_view), separators=(",", ":")).encode())
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **k: None)
    return state, body, per_view


def test_taking_a_bundle_holds_it_about_once(rig, monkeypatch: pytest.MonkeyPatch) -> None:
    state, body, per_view = rig
    size = body.stat().st_size
    assert size > 5_000_000

    gc.collect()
    tracemalloc.start()
    try:
        # Bootstrap from the cache inside the trace, so whatever the agent
        # keeps of the previous bundle counts against the fetch below.
        loop = SyncLoop(_Cfg(state), ["tok"], _Driver(state_dir=state), _Heartbeat())  # type: ignore[arg-type]
        assert loop._current_etag == "old"
        monkeypatch.setattr(loop, "_report_zone_state", lambda *a, **k: None)
        monkeypatch.setattr(loop, "_refresh_dnssec_state", lambda force=False: None)
        monkeypatch.setattr(loop, "_client", lambda *a, **k: _client(_serve(body)))
        gc.collect()
        tracemalloc.reset_peak()

        loop._poll_once()
        gc.collect()
        held_after, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert loop._current_etag == "new"
    # Measured with this shape: main held the previous bundle plus the body as
    # bytes, as text and parsed — ~7.8x the body. Now the text and the parse,
    # ~3.1x. The bound leaves room for interpreter and allocator drift.
    assert peak < 4 * size, f"peak {peak / 1e6:.1f} MB for a {size / 1e6:.1f} MB bundle"
    # And nothing bundle-sized outlives the poll: main kept the whole bundle
    # (for the DNSSEC re-read) until the next structural apply.
    assert held_after < size / 2, f"{held_after / 1e6:.1f} MB still held after the poll"

    # Same behaviour: the bundle cached and the RPZ zones rendered as before.
    assert load_config(state) == (json.loads(body.read_bytes()), "new")
    zone = state / "rendered.new" / "zones" / "guest" / "spatium-blocklist-guest.rpz.db"
    lines = zone.read_text().splitlines()
    assert "ads1-tracker.list1.example-cdn.test CNAME ." in lines
    # A sinkhole answers with A + AAAA local data (#2124), not rpz-drop.
    assert "*.ads7-tracker.list2.example-cdn.test A 0.0.0.0" in lines
    assert "*.ads7-tracker.list2.example-cdn.test AAAA ::" in lines
    assert "ok.example.test CNAME rpz-passthru." in lines
    sinkholes = len(range(0, per_view, 7))
    assert len(lines) == 3 + 2 * per_view + 2 * sinkholes + 2
    # The DNSSEC re-read still sees the signed zone.
    assert loop._dnssec_bundle == {
        "zones": [{"name": "signed.test.", "type": "primary", "dnssec_enabled": True}]
    }
    assert not (state / "config" / "fetch.json.part").exists()


def test_the_body_is_spooled_and_parsed_to_the_same_bundle(tmp_path: Path) -> None:
    state = tmp_path / "state"
    ensure_layout(state)
    body = tmp_path / "body.json"
    bundle = _bundle("x", 50)
    bundle["zones"][0]["records"] = [{"name": "www", "type": "A", "value": "192.0.2.1"}]
    body.write_text(json.dumps(bundle), encoding="utf-8")

    with _client(_serve(body)) as c:
        resp = get_config(c, {}, state)
    spool = state / "config" / "fetch.json.part"
    assert resp.status_code == 200
    assert spool.read_bytes() == body.read_bytes()
    assert resp.json() == bundle
    assert not spool.exists()


def test_a_non_200_reply_spools_nothing(tmp_path: Path) -> None:
    state = tmp_path / "state"
    ensure_layout(state)
    body = tmp_path / "body.json"
    body.write_text("{}")
    for status in (304, 401, 404, 503):
        with _client(_serve(body, status)) as c:
            resp = get_config(c, {"If-None-Match": "e"}, state)
        assert resp.status_code == status
        assert not (state / "config" / "fetch.json.part").exists()


def test_a_body_cut_off_midway_raises_and_leaves_no_spool(tmp_path: Path) -> None:
    state = tmp_path / "state"
    ensure_layout(state)

    def cut() -> Iterator[bytes]:
        yield b'{"etag": "e", "zones": ['
        raise httpx.ReadError("connection reset")

    transport = httpx.MockTransport(lambda req: httpx.Response(200, content=cut()))
    with pytest.raises(httpx.HTTPError), _client(transport) as c:
        get_config(c, {}, state)
    assert not (state / "config" / "fetch.json.part").exists()


def test_a_parse_reads_utf16_like_json_loads(tmp_path: Path) -> None:
    """``json.loads`` on bytes sniffs UTF-16/32; the file parse must too."""
    doc = {"zones": [{"name": "é.test.", "type": "primary"}], "blocklists": []}
    path = tmp_path / "b.json"
    path.write_bytes(json.dumps(doc, ensure_ascii=False).encode("utf-16"))
    assert parse_bundle_file(path) == json.loads(path.read_bytes()) == doc


def test_a_stale_spool_is_removed_at_start_and_the_cache_is_untouched(tmp_path: Path) -> None:
    """An agent killed mid-download leaves the spool; start drops it (#2029)."""
    state = tmp_path / "state"
    ensure_layout(state)
    save_config(state, _bundle("old", 3), "old")
    commit_config(state, "old")
    before = {p.name: p.read_bytes() for p in (state / "config").iterdir()}
    (state / "config" / "fetch.json.part").write_bytes(b'{"etag": "new", "zones": [')

    ensure_layout(state)

    assert not (state / "config" / "fetch.json.part").exists()
    assert {p.name: p.read_bytes() for p in (state / "config").iterdir()} == before
    assert load_config(state)[1] == "old"


def test_a_torn_cache_file_reads_as_no_cache_not_a_crash(tmp_path: Path) -> None:
    """Sniffing the encoding makes a NUL-filled file a DECODE error (UTF-32);
    it must still read as "nothing cached", as the JSON error did (#5)."""
    state = tmp_path / "state"
    ensure_layout(state)
    for name in ("current.json", "previous.json"):
        (state / "config" / name).write_bytes(b"\x00" * 4097)
    from spatium_dns_agent.cache import load_previous_config

    assert load_config(state) == (None, None)
    assert load_previous_config(state) == (None, None)


def test_a_full_disk_while_spooling_fails_the_fetch_and_keeps_the_cache(
    rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, body, _ = rig
    cached = (state / "config" / "current.json").read_bytes()
    loop = SyncLoop(_Cfg(state), ["tok"], _Driver(state_dir=state), _Heartbeat())  # type: ignore[arg-type]
    monkeypatch.setattr(loop, "_client", lambda *a, **k: _client(_serve(body)))
    monkeypatch.setattr(sync_mod.time, "sleep", lambda s: None)

    real_open = Path.open

    class _Full:
        def __init__(self, fh: Any) -> None:
            self._fh = fh

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *exc: object) -> None:
            self._fh.close()

        def write(self, chunk: bytes) -> int:
            self._fh.write(chunk[:10])
            raise OSError(28, "No space left on device")

    def fake_open(self: Path, mode: str = "r", *a: Any, **k: Any) -> Any:
        fh = real_open(self, mode, *a, **k)
        return _Full(fh) if self.name == "fetch.json.part" else fh

    monkeypatch.setattr(Path, "open", fake_open)
    loop._poll_once()  # must not raise: an exception here ends the sync thread

    assert loop._current_etag == "old"
    assert (state / "config" / "current.json").read_bytes() == cached
    assert not (state / "config" / "fetch.json.part").exists()


def test_the_dnssec_copy_drops_only_records_and_collects_the_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The slim ``_dnssec_bundle`` (#2029) must give the BIND9 collector the
    same answer the whole bundle did: it reads name / type / dnssec_enabled."""
    state = tmp_path / "state"
    ensure_layout(state)
    zones = [
        {
            "name": "signed.test.",
            "type": "primary",
            "dnssec_enabled": True,
            "view_name": "internal",
            "records": [{"name": "www", "type": "A", "value": "192.0.2.1"}],
        },
        {"name": "signed.test.", "type": "primary", "dnssec_enabled": True, "view_name": "guest"},
        {"name": "plain.test.", "type": "primary", "dnssec_enabled": False, "records": []},
        {"name": "sec.test.", "type": "secondary", "dnssec_enabled": True},
        {"name": "Master.test", "type": "master", "dnssec_enabled": True},
    ]
    full = {**_bundle("x", 5), "zones": zones}
    loop = SyncLoop(_Cfg(state), ["tok"], _Driver(state_dir=state), _Heartbeat())  # type: ignore[arg-type]
    loop._dnssec_bundle = full

    slim = loop._dnssec_bundle
    assert slim is not None and set(slim) == {"zones"}
    assert slim["zones"] == [{k: v for k, v in z.items() if k != "records"} for z in zones]

    drv = _Driver(state_dir=state)
    monkeypatch.setattr(
        drv,
        "_zone_dnssec_state",
        lambda zone: {"zone_name": zone + ".", "ds_records": [], "keys": [{"key_tag": 1}]},
    )
    assert drv.collect_dnssec_state(slim) == drv.collect_dnssec_state(full)
    assert [s["zone_name"] for s in drv.collect_dnssec_state(slim)] == [
        "signed.test.",
        "Master.test.",
    ]

    loop._dnssec_bundle = None
    assert loop._dnssec_bundle is None
