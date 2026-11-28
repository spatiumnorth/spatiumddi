"""The agent takes blocklist entries from their own stream (#4041).

A bundle that names a ``blocklist_etag`` carries RPZ zones with no entries.
The agent downloads the stream only when its version is not the one on disk,
merges it into the bundle so the driver and the cache see the embedded shape,
and folds the stream's ETag into the structural one, so an entry edit that
moves nothing else in the bundle is still applied.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import httpx

from spatium_dns_agent.cache import ensure_layout, load_config
from spatium_dns_agent.fetch import BLOCKLIST_ETAG_HEADER, held_blocklist_etag

from .test_config_revert import _Driver, _loop

ZONE = "spatium-blocklist.rpz."


def _doc(*domains: str) -> dict[str, Any]:
    return {
        "blocklists": [
            {
                "rpz_zone_name": ZONE,
                "view_name": None,
                "entries": [{"domain": d, "action": "block"} for d in domains],
                "rpz_sha256": "sha256:" + "ab" * 32,
            }
        ]
    }


def _bundle(etag: str, blocklist_etag: str) -> dict[str, Any]:
    return {
        "etag": etag,
        "structural_etag": "s1",
        "blocklist_etag": blocklist_etag,
        "zones": [],
        "blocklists": [
            {"rpz_zone_name": ZONE, "view_name": None, "entries": [], "exceptions": []}
        ],
        "pending_record_ops": [],
    }


class _Http:
    """The control plane: a queue of bundles and the stream documents by ETag."""

    def __init__(self, bundles: list[dict[str, Any]], streams: dict[str, dict[str, Any]]):
        self.bundles = bundles
        self.streams = streams
        self.stream_unavailable = False
        self.stream_gets = 0
        self.config_headers: list[dict[str, str]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        req = httpx.Request("GET", url)
        if url.endswith("/blocklist"):
            self.stream_gets += 1
            if self.stream_unavailable:
                return httpx.Response(503, request=req)
            tag = self.streams["current"]["etag"]
            return httpx.Response(
                200, json=self.streams["current"]["doc"], headers={"ETag": f'W/"{tag}"'}, request=req
            )
        self.config_headers.append(dict(headers or {}))
        return httpx.Response(200, json=self.bundles.pop(0), request=req)

    def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={}, request=httpx.Request("POST", url))


class _Capturing(_Driver):
    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        self.entries: list[list[str]] = []
        self.hashes: list[str | None] = []

    def apply_config(self, bundle: dict[str, Any]) -> None:
        super().apply_config(bundle)
        zone = bundle["blocklists"][0]
        self.entries.append([e["domain"] for e in zone["entries"]])
        self.hashes.append(zone.get("rpz_sha256"))


def test_entries_come_from_the_stream_and_only_a_new_version_is_downloaded(
    tmp_path: Path, monkeypatch: Any
) -> None:
    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    monkeypatch.setattr("spatium_dns_agent.sync.time.sleep", lambda s: None)
    driver = _Capturing(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http(
        [_bundle("e1", "b1"), _bundle("e1", "b2"), _bundle("e2", "b2")],
        {"current": {"etag": "b1", "doc": _doc("a.example")}},
    )
    loop._client = lambda: http  # type: ignore[method-assign]

    loop._poll_once()
    assert driver.entries == [["a.example"]]
    assert driver.hashes == ["sha256:" + "ab" * 32]
    assert http.stream_gets == 1
    assert loop._current_structural_etag == "s1+b1"
    cached, _ = load_config(tmp_path)
    assert cached is not None and cached["blocklists"][0]["entries"], "the cache holds them whole"
    assert held_blocklist_etag(tmp_path) == "b1"

    # The entries change and nothing else does: the bundle's ETag and
    # structural ETag are the same, the poll answered because the agent named
    # the version it holds, and the new stream is applied.
    http.streams["current"] = {"etag": "b2", "doc": _doc("a.example", "b.example")}
    loop._poll_once()
    assert http.config_headers[1][BLOCKLIST_ETAG_HEADER] == "b1"
    assert driver.entries[-1] == ["a.example", "b.example"]
    assert http.stream_gets == 2
    assert loop._current_structural_etag == "s1+b2"

    # A record-only change: the held stream is merged from disk, nothing is
    # downloaded and nothing is re-applied.
    loop._poll_once()
    assert http.config_headers[2][BLOCKLIST_ETAG_HEADER] == "b2"
    assert http.stream_gets == 2
    assert len(driver.entries) == 2


def test_an_unavailable_stream_applies_nothing_and_changes_nothing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    monkeypatch.setattr("spatium_dns_agent.sync.time.sleep", lambda s: None)
    driver = _Capturing(tmp_path)
    loop = _loop(tmp_path, driver)
    http = _Http(
        [_bundle("e1", "b1"), _bundle("e1", "b1")],
        {"current": {"etag": "b1", "doc": _doc("a.example")}},
    )
    loop._client = lambda: http  # type: ignore[method-assign]
    http.stream_unavailable = True

    loop._poll_once()
    assert driver.entries == [] and loop._current_etag is None
    assert load_config(tmp_path) == (None, None), "no half bundle is cached"

    http.stream_unavailable = False
    loop._poll_once()
    assert driver.entries == [["a.example"]]


def test_a_bundle_with_embedded_entries_is_untouched(tmp_path: Path, monkeypatch: Any) -> None:
    """An agent served the old embedded form (a control plane that does not
    know the stream) never contacts the stream endpoint."""
    ensure_layout(tmp_path)
    monkeypatch.setattr("spatium_dns_agent.sync.push_rendered_config", lambda *a: None)
    driver = _Capturing(tmp_path)
    loop = _loop(tmp_path, driver)
    bundle = _bundle("e1", "b1")
    del bundle["blocklist_etag"]
    bundle["blocklists"][0]["entries"] = [{"domain": "x.example", "action": "block"}]
    http = _Http([bundle], {"current": {"etag": "b1", "doc": _doc()}})
    loop._client = lambda: http  # type: ignore[method-assign]

    loop._poll_once()
    assert driver.entries == [["x.example"]] and http.stream_gets == 0
    assert loop._current_structural_etag == "s1"
