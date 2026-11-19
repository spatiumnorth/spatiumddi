"""A big zone bundle must cost the agent about one parsed copy, briefly (#2223).

ddi-pg's scale lab ran a group of 20,000 zones holding a million records. The
``dns-bind9`` container (agent and named under one 2Gi limit) was OOM-killed on
5 of 7 nodes, with the agent at ~1.1 GB anon. Measured on a synthetic bundle of
that shape (126 MB), the agent was holding the bundle up to three ways:

* the parse held the file's whole text beside the objects it built;
* after a bundle applied, the slim zone list kept for the DNSSEC re-read and
  the per-zone serial map referenced objects the parse had allocated among the
  records, so the freed bundle stayed resident (~370 MB of RSS between polls);
* a startup hold (#2019) kept the cached bundle parsed while the first fetch
  parsed the control plane's, and the ingest thread re-parsed the whole cache,
  records and all, every sweep after it changed — two bundles at once.

These tests drive the real parse, the real sync poll over a streamed body and
the real BIND9 render, on a smaller bundle of the same shape.
"""

from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
import textwrap
import tracemalloc
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent import cache as cache_mod
from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.apply_guard import ApplyGuard
from spatium_dns_agent.cache import (
    HELD_BUNDLE,
    commit_config,
    ensure_layout,
    load_config,
    parse_bundle_file,
    save_config,
)
from spatium_dns_agent.ingest import IngestWorker
from spatium_dns_agent.sync import SyncLoop

from .test_bundle_memory_2029 import _Cfg, _client, _Driver, _Heartbeat, _serve

ZONES = 1_000
PER_ZONE = 50


def _zone(name: str, records: list[dict[str, Any]], tag: str) -> dict[str, Any]:
    """One zone as ``agent_config.py`` ships it (every key, most of them null)."""
    return {
        "id": f"00000000-0000-0000-0000-{abs(hash(name)) % 10**12:012d}",
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 2026101701,
        "forwarders": [],
        "forward_only": True,
        "masters": [],
        "dnssec_enabled": name.startswith("site00000."),
        "dnssec_policy_name": None,
        "dynamic_update_enabled": name.startswith("site00001."),
        "update_acl": [],
        "allow_transfer": None,
        "allow_query": None,
        "also_notify": None,
        "notify_enabled": None,
        "primary_ns": "ns1.example.test.",
        "admin_email": "hostmaster.example.test.",
        "refresh": 86400,
        "retry": 7200,
        "expire": 3600000,
        "minimum": 3600,
        "view_name": None,
        "records": records,
        "tag": tag,
    }


def _zones_bundle(tag: str, sites: int = ZONES // 2, per_zone: int = PER_ZONE) -> dict[str, Any]:
    """``sites`` forward + reverse zone pairs, ``per_zone`` A / PTR records each."""
    zones = []
    for s in range(sites):
        a, b = divmod(s, 250)
        fwd = [
            {
                "name": f"dev{i:05d}",
                "type": "A",
                "ttl": None,
                "value": f"10.{a}.{b}.{i % 254 + 1}",
                "priority": None,
                "weight": None,
                "port": None,
            }
            for i in range(per_zone)
        ]
        rev = [
            {
                "name": f"{i % 254 + 1}.{i // 254}",
                "type": "PTR",
                "ttl": None,
                "value": f"dev{i:05d}.site{s:05d}.example.test.",
                "priority": None,
                "weight": None,
                "port": None,
            }
            for i in range(per_zone)
        ]
        zones.append(_zone(f"site{s:05d}.example.test.", fwd, tag))
        zones.append(_zone(f"{b}.{a}.10.in-addr.arpa.", rev, tag))
    return {
        "etag": tag,
        "structural_etag": f"s-{tag}",
        "options": {"recursion_enabled": True},
        "views": [],
        "blocklists": [],
        "pending_record_ops": [],
        "tsig_keys": [{"name": "spatium-ddns", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"}],
        "zones": zones,
    }


def _write(path: Path, bundle: dict[str, Any]) -> int:
    path.write_bytes(json.dumps(bundle, separators=(",", ":")).encode())
    return path.stat().st_size


def _traced(fn: Any) -> tuple[Any, int, int]:
    """``(result, held after, peak)`` of ``fn`` in traced Python allocations."""
    gc.collect()
    tracemalloc.start()
    try:
        result = fn()
        gc.collect()
        held, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, held, peak


# --- the parse ------------------------------------------------------------


def test_the_parse_never_holds_the_whole_text(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    size = _write(path, _zones_bundle("x"))
    assert size > 5_000_000

    bundle, held, peak = _traced(lambda: parse_bundle_file(path))

    assert bundle == json.loads(path.read_bytes())
    # Reading the file whole put its text (~size) on top of the parsed form;
    # streamed, the parse costs the objects plus a chunk, one zone and the
    # memo of shared values (~size / 4 on Python 3.14).
    assert peak - held < size / 2.5, (
        f"parse peaked {(peak - held) / 1e6:.1f} MB above the parsed bundle "
        f"for a {size / 1e6:.1f} MB file"
    )


def test_keys_and_short_values_are_shared_across_the_whole_bundle(tmp_path: Path) -> None:
    """Decoded a zone at a time, ``json``'s own key memo is per zone; the
    decoder's must span the bundle, or every zone carries its own keys."""
    path = tmp_path / "b.json"
    _write(path, _zones_bundle("x", sites=3, per_zone=2))
    zones = parse_bundle_file(path)["zones"]
    first, last = zones[0], zones[-1]
    for k1, k2 in zip(first, last, strict=True):
        assert k1 is k2
    assert first["type"] is last["type"]
    assert first["records"][0]["type"] is zones[2]["records"][1]["type"]


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"zones": []},
        {"a": 1, "zones": [], "b": [[]], "c": {"d": [1, 2.5, -3e-7, None, True]}},
        {"zones": [{"name": "é.test.", "records": [{"value": "x☃😀"}]}]},
        {"n": 123456789012345678901234567890, "zones": [1, 22, 333, 4444, 55555]},
        {"s": "a" * 5000, "zones": ["b" * 3000, {"k": "c" * 7000}], "t": '"\\/\b\f\n\r\t'},
        {"blocklists": [{"entries": [{"domain": f"d{i}.test"} for i in range(200)]}]},
    ],
)
@pytest.mark.parametrize("chunk", [1, 7, 64, 1 << 20])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-8-sig"])
def test_the_streamed_parse_equals_json_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, doc: Any, chunk: int, encoding: str
) -> None:
    """Every value split across every chunk boundary — a number cut off at
    the end of the buffer must not decode as a shorter one."""
    monkeypatch.setattr(cache_mod, "_PARSE_CHUNK", chunk)
    path = tmp_path / "b.json"
    for text in (json.dumps(doc, ensure_ascii=False), json.dumps(doc, indent=3)):
        path.write_bytes(text.encode(encoding))
        assert parse_bundle_file(path) == json.loads(path.read_bytes()) == doc


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "{",
        '{"zones": [',
        '{"zones": [{"name": "a"}',
        '{"zones": [{"name": "a"},]}',
        '{"a" 1}',
        '{"a": 1,}',
        "{1: 2}",
        '{"a": 1} x',
        '{"a": 1}{}',
        '{"a": tru}',
        "[1, 2",
        "\x00" * 64,
    ],
)
def test_a_document_json_rejects_is_rejected(tmp_path: Path, text: str) -> None:
    path = tmp_path / "b.json"
    path.write_bytes(text.encode("latin-1"))
    with pytest.raises(ValueError):
        json.loads(path.read_bytes())
    with pytest.raises(ValueError):
        parse_bundle_file(path)


def test_a_non_object_document_parses_as_json_does(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    for doc in ([1, {"a": "b"}], "x", 5, None):
        path.write_text(json.dumps(doc))
        assert parse_bundle_file(path) == doc


def test_records_false_leaves_out_records_and_blocklist_entries(tmp_path: Path) -> None:
    bundle = _zones_bundle("x")
    bundle["blocklists"] = [
        {
            "rpz_zone_name": "bl.rpz.",
            "entries": [{"domain": f"ad{i}.test", "action": "block"} for i in range(50_000)],
        }
    ]
    path = tmp_path / "b.json"
    size = _write(path, bundle)

    slim = parse_bundle_file(path, records=False)

    assert slim["zones"] == [
        {k: v for k, v in z.items() if k != "records"} for z in bundle["zones"]
    ]
    assert slim["blocklists"] == [{"rpz_zone_name": "bl.rpz."}]
    assert slim["tsig_keys"] == bundle["tsig_keys"]
    assert slim["options"] == bundle["options"]
    assert size > 0


# --- the ingest thread ----------------------------------------------------


def test_the_ingest_sweep_does_not_parse_the_records(tmp_path: Path, agent_cfg: Any) -> None:
    """The sweep needs the loopback key and the dynamic zones' names. It ran a
    full parse in its own thread every 180 s once the cache changed, which it
    does on every record edit — alongside the sync loop's own parse."""
    state = agent_cfg.state_dir
    ensure_layout(state)
    bundle = _zones_bundle("x", per_zone=200)
    save_config(state, bundle, "x")
    size = (state / "config" / "current.json").stat().st_size

    inputs, _held, peak = _traced(lambda: IngestWorker(agent_cfg, ["tok"])._sweep_inputs())

    assert inputs == [("site00001.example.test", None, bundle["tsig_keys"][0])]
    assert peak < size / 4, f"{peak / 1e6:.1f} MB for a {size / 1e6:.1f} MB cache"


# --- the startup hold -----------------------------------------------------


def test_a_startup_hold_keeps_the_held_bundle_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first fetch after a death must not parse beside a second bundle."""
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **k: None)
    state = tmp_path / "state"
    ensure_layout(state)
    save_config(state, _zones_bundle("old"), "old")
    commit_config(state, "old")
    ApplyGuard(state).arm("old")  # the previous process died applying it
    body = tmp_path / "body.json"
    size = _write(body, _zones_bundle("new"))
    held_path = state / HELD_BUNDLE

    def start_and_poll() -> SyncLoop:
        loop = SyncLoop(_Cfg(state), ["tok"], _Driver(state_dir=state), _Heartbeat())  # type: ignore[arg-type]
        assert loop._boot_hold is not None
        assert loop._boot_hold[0] == held_path
        # A hard link to the cache file, so it costs no disk.
        assert held_path.read_bytes() == (state / "config" / "current.json").read_bytes()
        assert os.path.samefile(held_path, state / "config" / "current.json")
        monkeypatch.setattr(loop, "_report_zone_state", lambda *a, **k: True)
        monkeypatch.setattr(loop, "_refresh_dnssec_state", lambda force=False: None)
        monkeypatch.setattr(loop, "_client", lambda *a, **k: _client(_serve(body)))
        loop._poll_once()
        return loop

    loop, _held, peak = _traced(start_and_poll)

    assert loop._current_etag == "new"
    assert loop._boot_hold is None
    assert not held_path.exists()
    # One parsed bundle (~4x its file with these short records) at a time.
    # Holding the cached one too put the peak near 8x.
    assert peak < 5.5 * size, f"peak {peak / 1e6:.1f} MB for a {size / 1e6:.1f} MB bundle"


def test_the_held_bundle_survives_the_fetch_that_replaces_the_cache(tmp_path: Path) -> None:
    """``save_config`` renames over ``current.json``; the hold's link keeps the
    held bundle, which a failed apply of the new one falls back to."""
    state = tmp_path / "state"
    ensure_layout(state)
    save_config(state, {"zones": [], "etag": "old"}, "old")
    held = cache_mod.hold_bundle(state, "old")
    assert held is not None
    save_config(state, {"zones": [], "etag": "new"}, "new")
    assert cache_mod.load_held_bundle(held) == {"zones": [], "etag": "old"}
    assert load_config(state)[1] == "new"
    # Not for a bundle the cache no longer holds.
    assert cache_mod.hold_bundle(state, "old") is None
    # And a new start never inherits one.
    ensure_layout(state)
    assert not held.exists()


# --- what outlives a poll -------------------------------------------------

_RSS_SCRIPT = textwrap.dedent(
    """
    import gc, json, sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    from tests.test_bundle_memory_2029 import _Cfg, _client, _Driver, _Heartbeat, _serve
    from spatium_dns_agent import sync as sync_mod
    sync_mod.push_rendered_config = lambda *a, **k: None
    state, body = Path(sys.argv[2]), Path(sys.argv[3])

    def rss():
        for line in open("/proc/self/status"):
            if line.startswith("VmRSS"):
                return int(line.split()[1]) * 1024

    gc.collect()
    base = rss()
    loop = sync_mod.SyncLoop(_Cfg(state), ["tok"], _Driver(state_dir=state), _Heartbeat())
    posted = []

    def post(entries):
        # The real bookkeeping, without the network.
        reported = loop._reported_serials
        for e in entries:
            reported[sync_mod._zone_key(e["zone_name"])] = int(e["serial"])
        loop._reported_serials = reported
        posted.append(len(entries))
        return True

    loop._post_zone_state = post
    loop._refresh_dnssec_state = lambda force=False: None
    loop._client = lambda *a, **k: _client(_serve(body))
    loop._poll_once()
    assert loop._current_etag == "new" and posted, (loop._current_etag, posted)
    assert loop._dnssec_bundle["zones"] and loop._reported_serials
    gc.collect()
    print(json.dumps({"base": base, "after": rss()}))
    """
)


@pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="reads VmRSS")
def test_what_outlives_a_poll_does_not_keep_the_bundle_resident(tmp_path: Path) -> None:
    """The bundle is freed when the poll returns; its memory must be too.

    CPython hands memory back to the system an arena at a time, and an arena
    holding one live object stays. The zone list kept for the DNSSEC re-read
    and the per-zone serial map were built from the parsed bundle, so their
    objects sat in nearly every arena the bundle had used: tracemalloc saw a
    few MB live while the process kept ~80% of the bundle resident. Measured
    in a fresh interpreter, since it is the process's RSS that the
    container's memory limit counts.
    """
    state = tmp_path / "state"
    ensure_layout(state)
    save_config(state, _zones_bundle("old", sites=2_500), "old")
    commit_config(state, "old")
    body = tmp_path / "body.json"
    size = _write(body, _zones_bundle("new", sites=2_500))

    out = subprocess.run(
        [
            sys.executable,
            "-c",
            _RSS_SCRIPT,
            str(Path(__file__).parent.parent),
            str(state),
            str(body),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    rss = json.loads(out.stdout.strip().splitlines()[-1])
    kept = rss["after"] - rss["base"]
    # Parsed, this bundle is ~4x its file. Main kept ~3x resident after the
    # poll; what the agent actually keeps (the frozen zone list, the serial
    # map, the driver's bookkeeping) is a small fraction of one.
    assert kept < size, f"{kept / 1e6:.1f} MB kept resident after a {size / 1e6:.1f} MB bundle"
