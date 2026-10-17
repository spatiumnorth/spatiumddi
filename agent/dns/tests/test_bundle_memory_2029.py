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
    assert "*.ads7-tracker.list2.example-cdn.test CNAME rpz-drop." in lines
    assert "ok.example.test CNAME rpz-passthru." in lines
    assert len(lines) == 3 + 2 * per_view + 2
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
