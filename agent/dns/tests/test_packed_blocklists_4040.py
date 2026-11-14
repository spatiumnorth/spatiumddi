"""Packed blocklist entries on the agent (#4040).

A bundle's ``entries`` may hold gzip + base64 runs of consecutive alike
entries instead of one object each. The rendered RPZ zone must be the one the
per-entry bundle renders — to the byte, SOA serial included — and the cached
bundle must render alone, with the control plane unreachable.
"""

from __future__ import annotations

import base64
import gzip
import json
import tracemalloc
from pathlib import Path
from typing import Any

from spatium_dns_agent import cache
from spatium_dns_agent.blocklist_entries import entry_count, iter_entries
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.drivers.technitium import _blocking_payload


def _run(attrs: dict[str, Any], domains: list[str]) -> dict[str, Any]:
    blob = gzip.compress("\n".join(domains).encode("utf-8"), mtime=0)
    return {"packed": attrs, "count": len(domains), "domains_gz": base64.b64encode(blob).decode()}


def _entry(domain: str, **over: Any) -> dict[str, Any]:
    return {
        "domain": domain,
        "action": "block",
        "block_mode": "nxdomain",
        "target": None,
        "is_wildcard": True,
        **over,
    }


def _attrs(**over: Any) -> dict[str, Any]:
    return {k: v for k, v in _entry("x", **over).items() if k != "domain"}


def _bundles() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The same entries as per-entry objects and as the control plane packs them:
    a wildcard feed, an object between runs, an exact-match feed, a sinkhole
    feed, and a domain two lists disagree about (the first must win)."""
    feed_a = [f"ads{i}.example" for i in range(40)] + ["dup.example"]
    odd = _entry("www.google.com", action="redirect", target="forcesafesearch.google.com")
    feed_b = ["dup.example", *[f"trk{i}.example" for i in range(35)], "bücher.example"]
    feed_c = [f"sink{i}.example" for i in range(33)]
    sink = {"block_mode": "sinkhole", "sinkhole_ip": "192.0.2.7"}
    plain = [
        *(_entry(d) for d in feed_a),
        odd,
        *(_entry(d, is_wildcard=False) for d in feed_b),
        *(_entry(d, **sink) for d in feed_c),
    ]
    packed = [
        _run(_attrs(), feed_a),
        odd,
        _run(_attrs(is_wildcard=False), feed_b),
        _run(_attrs(**sink), feed_c),
    ]
    return plain, packed


def _write_zone(tmp_path: Path, name: str, entries: list[dict[str, Any]]) -> bytes:
    driver = Bind9Driver(state_dir=tmp_path / name)
    out = tmp_path / f"{name}.zone"
    driver._write_rpz_zone_file(
        out,
        {
            "rpz_zone_name": "spatium-blocklist.rpz.",
            "entries": entries,
            "exceptions": ["ads3.example"],
            # The control plane hashes the per-entry form in both shapes, so
            # the serial derived from it is the same.
            "rpz_sha256": "sha256:" + "ab" * 32,
        },
    )
    return out.read_bytes()


def test_iter_entries_expands_in_order_and_counts_without_expanding() -> None:
    plain, packed = _bundles()
    bl = {"entries": packed}
    assert list(iter_entries(bl)) == plain
    assert entry_count(bl) == len(plain)
    assert entry_count({"entries": plain}) == len(plain)
    assert list(iter_entries({})) == []


def test_the_rendered_zone_is_byte_identical_to_the_per_entry_one(tmp_path: Path) -> None:
    plain, packed = _bundles()
    zone = _write_zone(tmp_path, "plain", plain)
    assert _write_zone(tmp_path, "packed", packed) == zone
    text = zone.decode()
    # The disagreement kept its first writer, and the exception its own line.
    assert "dup.example CNAME ." in text and "dup.example A" not in text
    assert "ads3.example CNAME ." not in text


def test_a_cached_bundle_renders_alone(tmp_path: Path) -> None:
    """Non-negotiable #5: what is on disk is all a restart needs."""
    plain, packed = _bundles()
    state = tmp_path / "state"
    cache.ensure_layout(state)
    bundle = {"blocklists": [{"rpz_zone_name": "z.rpz.", "entries": packed, "exceptions": []}]}
    cache.save_config(state, bundle, "sha256:x")
    loaded, etag = cache.load_config(state)
    assert etag == "sha256:x"
    assert loaded is not None
    assert list(iter_entries(loaded["blocklists"][0])) == plain
    assert _write_zone(tmp_path, "cached", loaded["blocklists"][0]["entries"]) == _write_zone(
        tmp_path, "plain", plain
    )


def test_technitium_reads_packed_entries() -> None:
    plain, packed = _bundles()
    one = _blocking_payload({"blocklists": [{"entries": plain, "exceptions": []}]})
    two = _blocking_payload({"blocklists": [{"entries": packed, "exceptions": []}]})
    assert two == one


def _big(n: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    domains = [f"host-{i:07d}.tracker{i % 977}.example.com" for i in range(n)]
    runs = [_run(_attrs(), domains[i : i + 100_000]) for i in range(0, n, 100_000)]
    return [_entry(d) for d in domains], runs


def _peak(path: Path) -> int:
    tracemalloc.start()
    try:
        cache.parse_bundle_file(path)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_a_packed_bundle_is_far_smaller_on_disk_and_in_memory(tmp_path: Path) -> None:
    plain, packed = _big(200_000)
    one, two = tmp_path / "plain.json", tmp_path / "packed.json"
    one.write_text(json.dumps({"blocklists": [{"rpz_zone_name": "z.", "entries": plain}]}))
    two.write_text(json.dumps({"blocklists": [{"rpz_zone_name": "z.", "entries": packed}]}))
    assert two.stat().st_size * 5 < one.stat().st_size
    assert _peak(two) * 5 < _peak(one)
    parsed = cache.parse_bundle_file(two)
    assert entry_count(parsed["blocklists"][0]) == 200_000
