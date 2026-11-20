"""PowerDNS agent and split-horizon views (#4565).

PowerDNS has no views and holds one zone per name, while a views bundle
carries a copy of a zone for each view it renders in. The driver used to
reconcile every copy into that one zone: the copy reconciled last won and its
sweep removed the others' records, so a record of an internal view was
answered to every client, with the apply reported ok.

The rule now: copies that render the same are one zone, sent once; copies that
differ are reduced to the rrsets identical in every copy (no view's data reaches
another view's clients) and the zone is reported through ``refused_zones()``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import httpx
import pytest

from spatium_dns_agent.drivers import powerdns as powerdns_mod
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


def _zone(name: str, view: str | None, www: str, **extra: Any) -> dict[str, Any]:
    zone: dict[str, Any] = {
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 7,
        "view_name": view,
        "records": [{"name": "www", "type": "A", "value": www}],
    }
    zone.update(extra)
    return zone


_VIEWS = [{"name": "internal"}, {"name": "external"}]

# The issue's reproduction: ``www`` differs, and ``secret`` is internal only.
_SPLIT = [
    _zone(
        "split.example.",
        "internal",
        "10.1.1.1",
        records=[
            {"name": "www", "type": "A", "value": "10.1.1.1"},
            {"name": "secret", "type": "A", "value": "10.9.9.9"},
        ],
    ),
    _zone("split.example.", "external", "198.51.100.1"),
]


def _render(tmp_path: Path, zones: list[dict[str, Any]]) -> tuple[PowerDNSDriver, list[Any]]:
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver.render({"zones": zones, "views": _VIEWS, "options": {}})
    return driver, json.loads((tmp_path / "rendered.new" / "zones.json").read_text())


def test_copies_that_differ_between_views_keep_only_what_they_share(tmp_path: Path) -> None:
    """Only rrsets identical in every copy reach the payload, in either bundle
    order: ``www`` differs and ``secret`` is internal only, so neither is
    served to anyone."""
    for zones in (_SPLIT, list(reversed(_SPLIT))):
        _, payload = _render(tmp_path, zones)
        (zone,) = payload
        served = json.dumps(zone["rrsets"])
        assert "10.9.9.9" not in served
        assert "10.1.1.1" not in served
        assert "198.51.100.1" not in served


def test_a_zone_no_view_changes_is_sent_once(tmp_path: Path) -> None:
    """An unpinned zone with no scoped record renders the same in every view:
    one zone, and nothing to refuse."""
    same = [
        _zone("plain.example.", "internal", "192.0.2.1"),
        _zone("plain.example.", "external", "192.0.2.1"),
    ]
    driver, payload = _render(tmp_path, same + _SPLIT)
    assert sorted(z["name"] for z in payload) == ["plain.example.", "split.example."]
    plain = next(z for z in payload if z["name"] == "plain.example.")
    assert any("192.0.2.1" in json.dumps(r) for r in plain["rrsets"])
    assert len(driver._view_conflicts) == 1


def test_a_bundle_without_views_is_untouched(tmp_path: Path) -> None:
    driver, payload = _render(
        tmp_path, [_zone("a.example.", None, "192.0.2.1"), _zone("b.example.", None, "192.0.2.2")]
    )
    assert [z["name"] for z in payload] == ["a.example.", "b.example."]
    assert driver._view_conflicts == ()


class _Resp:
    def __init__(self, status: int = 200, body: Any = None) -> None:
        self.status_code = status
        self.text = ""
        self._body = body if body is not None else []

    def json(self) -> Any:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPError(f"HTTP {self.status_code}")


class _FakeClient:
    def __init__(self, calls: list[tuple[str, str, Any]]) -> None:
        self._calls = calls

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("GET", url, None))
        # PowerDNS already holds the zone, from before the refusal.
        if url.endswith("/zones"):
            return _Resp(200, [{"name": "split.example.", "kind": "Master"}])
        return _Resp(200, {"rrsets": []})

    def post(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("POST", url, json))
        return _Resp(201, {})

    def put(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("PUT", url, json))
        return _Resp(200, {})

    def patch(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("PATCH", url, json))
        return _Resp(200, {})

    def delete(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("DELETE", url, None))
        return _Resp(200, {})


def test_apply_leaves_the_zone_alone_and_reports_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through ``apply_config``: what PowerDNS is sent carries no view's own
    data, and the zone is named in ``refused_zones()`` so the apply is reported
    as partial, not ok."""
    calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        powerdns_mod,
        "httpx",
        SimpleNamespace(Client=lambda **kw: _FakeClient(calls), HTTPError=httpx.HTTPError),
    )
    driver = PowerDNSDriver(state_dir=tmp_path)
    monkeypatch.setattr(driver, "validate", lambda: None)
    monkeypatch.setattr(driver, "daemon_running", lambda: True)
    monkeypatch.setattr(driver, "_load_or_generate_api_key", lambda: "k")

    driver.apply_config(
        {
            "zones": [*_SPLIT, _zone("plain.example.", "internal", "192.0.2.1")],
            "views": _VIEWS,
            "options": {},
        }
    )

    writes = [(m, u) for m, u, _ in calls if m != "GET"]
    assert writes, "the zone no view changes is still reconciled"
    sent = json.dumps([body for _, _, body in calls])
    for leaked in ("10.9.9.9", "10.1.1.1", "198.51.100.1"):
        assert leaked not in sent
    (refusal,) = driver.refused_zones()
    assert refusal.startswith("split.example. views: ")
    assert "external, internal" in refusal
    assert driver.unconverged_zones() == {"split.example"}
