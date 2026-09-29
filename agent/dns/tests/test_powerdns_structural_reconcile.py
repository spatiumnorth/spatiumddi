"""PowerDNS serves the TTLs that were configured, and a zone it refuses fails the apply (#1225).

The structural (full) render stamped the ZONE TTL on every rrset, so every
reconcile (agent start, any structural change) REPLACEd each rrset at the
zone default and PowerDNS answered with TTLs nobody set, while the record-op
path honoured each record's own. And the reconcile logged-and-skipped a zone
PowerDNS refused to create or patch, so #882's apply status reported ``ok``
for a zone that was never served.

The render tests read the ``zones.json`` the driver writes; the reconcile
tests drive it against an ``httpx.MockTransport`` standing in for the pdns
REST API, so every refusal can be produced without a daemon.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest

from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


def _render(tmp_path: Path, zone: dict[str, Any]) -> dict[tuple[str, str], int]:
    """Render one zone; return ``{(name, type): ttl}`` from zones.json."""
    PowerDNSDriver(state_dir=tmp_path).render(
        {"options": {}, "zones": [{"type": "primary", **zone}]}
    )
    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    return {(rs["name"], rs["type"]): rs["ttl"] for rs in payload[0]["rrsets"]}


def _rec(name: str, rtype: str, value: str, ttl: int | None) -> dict[str, Any]:
    return {"name": name, "type": rtype, "value": value, "ttl": ttl}


# ── the render ────────────────────────────────────────────────────────────────


def test_each_rrset_carries_its_records_ttl(tmp_path: Path) -> None:
    ttls = _render(
        tmp_path,
        {
            "name": "example.com",
            "ttl": 3600,
            "records": [
                _rec("www", "A", "192.0.2.1", 60),
                _rec("mail", "A", "192.0.2.2", 86400),
            ],
        },
    )
    assert ttls[("www.example.com.", "A")] == 60
    assert ttls[("mail.example.com.", "A")] == 86400


def test_a_record_without_a_ttl_inherits_the_zone_ttl(tmp_path: Path) -> None:
    ttls = _render(
        tmp_path,
        {"name": "example.com", "ttl": 900, "records": [_rec("www", "A", "192.0.2.1", None)]},
    )
    assert ttls[("www.example.com.", "A")] == 900


def test_a_zone_without_a_ttl_defaults_to_an_hour(tmp_path: Path) -> None:
    ttls = _render(
        tmp_path,
        {"name": "example.com", "records": [_rec("www", "A", "192.0.2.1", None)]},
    )
    assert ttls[("www.example.com.", "A")] == 3600


def test_a_ttl_of_zero_is_kept(tmp_path: Path) -> None:
    """Absence, not falsiness: 0 means "do not cache", and ``or`` would have
    turned it into the zone TTL."""
    ttls = _render(
        tmp_path,
        {"name": "example.com", "ttl": 3600, "records": [_rec("www", "A", "192.0.2.1", 0)]},
    )
    assert ttls[("www.example.com.", "A")] == 0


def test_disagreeing_records_in_one_rrset_resolve_to_the_lowest(tmp_path: Path) -> None:
    """RFC 2181: one TTL per rrset. The lowest is also what the control plane
    stamps on a record op's rrset (backend ``rrset._rrset_payload``), so a
    full reconcile and an incremental write agree instead of flapping."""
    ttls = _render(
        tmp_path,
        {
            "name": "example.com",
            "ttl": 3600,
            "records": [
                _rec("www", "A", "192.0.2.1", 300),
                _rec("www", "A", "192.0.2.2", 60),
                _rec("www", "A", "192.0.2.3", None),  # inherits 3600
            ],
        },
    )
    assert ttls[("www.example.com.", "A")] == 60


# ── the reconcile ─────────────────────────────────────────────────────────────

Handler = Callable[[httpx.Request], httpx.Response]


def _api(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> list[httpx.Request]:
    """Point every ``httpx.Client`` the driver opens at ``handler``."""
    seen: list[httpx.Request] = []
    real_client = httpx.Client

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(recording), **kwargs)

    monkeypatch.setattr(powerdns.httpx, "Client", client)
    return seen


def _zone(name: str, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "kind": "Native",
        "rrsets": [
            {"name": f"www.{name}", "type": "A", "ttl": 60, "records": [{"content": "192.0.2.1"}]}
        ],
        "update_acl": [],
        "update_tsig_keys": [],
        **extra,
    }


def _ok(request: httpx.Request) -> httpx.Response:
    if request.method == "GET":
        return httpx.Response(200, json=[{"name": "old.test."}])
    if request.method == "DELETE":
        return httpx.Response(404)  # metadata already absent: benign
    return httpx.Response(204 if request.method == "PATCH" else 201, json={})


def test_a_clean_reconcile_passes(tmp_path: Path, monkeypatch) -> None:
    seen = _api(monkeypatch, _ok)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test."), _zone("new.test.")])
    methods = [(r.method, r.url.path) for r in seen]
    assert ("PATCH", "/api/v1/servers/localhost/zones/old.test.") in methods
    assert ("POST", "/api/v1/servers/localhost/zones") in methods


def test_patch_carries_the_rrset_ttl(tmp_path: Path, monkeypatch) -> None:
    seen = _api(monkeypatch, _ok)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])
    patch = next(r for r in seen if r.method == "PATCH")
    assert json.loads(patch.content)["rrsets"][0]["ttl"] == 60


def test_a_zone_listing_that_fails_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    """It used to fall back to "no zones exist", sending every zone down the
    create path, where PowerDNS answers 409, logged and skipped."""
    _api(monkeypatch, lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(RuntimeError, match="cannot list PowerDNS zones"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])


def test_a_refused_create_fails_the_apply_after_the_rest(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and b"bad.test." in request.content:
            return httpx.Response(422, json={"error": "RRset bad.test. IN CNAME: Conflicts with other records"})
        return _ok(request)

    seen = _api(monkeypatch, handler)
    with pytest.raises(RuntimeError) as exc:
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
            "k", [_zone("bad.test."), _zone("old.test.")]
        )
    assert "bad.test. create: HTTP 422" in str(exc.value)
    assert "Conflicts with other records" in str(exc.value), "PowerDNS's own reason is surfaced"
    assert any(r.method == "PATCH" for r in seen), "one refused zone must not strand the rest"


def test_a_refused_patch_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            return httpx.Response(422, json={"error": "bad content"})
        return _ok(request)

    _api(monkeypatch, handler)
    with pytest.raises(RuntimeError, match=r"old\.test\. update: HTTP 422 bad content"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])


def test_a_dynamic_update_acl_that_fails_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    """A failed CLEAR leaves the zone accepting updates the operator turned
    off, which used to be logged while the apply reported ok."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE":
            return httpx.Response(500, json={"error": "backend error"})
        return _ok(request)

    _api(monkeypatch, handler)
    with pytest.raises(RuntimeError, match="dynamic-update ACL: ALLOW-DNSUPDATE-FROM: HTTP 500"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])


def test_a_tsig_key_that_will_not_import_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tsigkeys") or "/tsigkeys/" in request.url.path:
            return httpx.Response(422, json={"error": "invalid algorithm"})
        return _ok(request)

    _api(monkeypatch, handler)
    key = {"name": "ddns-key", "algorithm": "hmac-sha256", "secret": "c2VjcmV0"}
    with pytest.raises(RuntimeError, match="TSIG key ddns-key: HTTP 422 invalid algorithm"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
            "k", [_zone("old.test.", update_tsig_keys=[key])]
        )


def test_an_unreadable_payload_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    """``render`` always writes zones.json; not being able to read it means
    nothing was reconciled, which used to return as a success."""
    drv = PowerDNSDriver(state_dir=tmp_path)
    (tmp_path / "rendered.new").mkdir()
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    monkeypatch.setattr(drv, "_load_or_generate_api_key", lambda: "k")
    with pytest.raises(RuntimeError, match="cannot read the rendered zones payload"):
        drv.swap_and_reload()


def test_a_refused_key_keeps_pdns_reason_when_the_put_404s(tmp_path: Path, monkeypatch) -> None:
    """pdns refuses a bad key with 422, the same status the driver reads as
    "already present"; the follow-up PUT then 404s, and that must not be the
    only reason reported."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/tsigkeys"):
            return httpx.Response(422, json={"error": "invalid algorithm"})
        if request.method == "PUT" and "/tsigkeys/" in request.url.path:
            return httpx.Response(404, json={"error": "TSIG key not found"})
        return _ok(request)

    _api(monkeypatch, handler)
    key = {"name": "ddns-key", "algorithm": "hmac-bogus", "secret": "c2VjcmV0"}
    with pytest.raises(RuntimeError, match=r"HTTP 404 .*\(create: HTTP 422 invalid algorithm\)"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
            "k", [_zone("old.test.", update_tsig_keys=[key])]
        )


def test_a_key_shared_by_zones_is_imported_once(tmp_path: Path, monkeypatch) -> None:
    seen = _api(monkeypatch, _ok)
    key = {"name": "ddns-key", "algorithm": "hmac-sha256", "secret": "c2VjcmV0"}
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
        "k",
        [
            _zone("old.test.", update_tsig_keys=[key]),
            _zone("new.test.", update_tsig_keys=[key]),
        ],
    )
    assert sum(1 for r in seen if r.url.path.endswith("/tsigkeys")) == 1


def test_a_zone_pdns_stored_lowercased_is_patched_not_recreated(tmp_path: Path, monkeypatch) -> None:
    """PowerDNS stores zone names lowercased (verified). Comparing exactly
    re-POSTed ``Case.Test.`` on every reconcile after the first, which answers
    409 and would now fail every apply."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=[{"name": "case.test."}])
        if request.method == "POST":
            return httpx.Response(409, json={"error": "Conflict"})
        return _ok(request)

    seen = _api(monkeypatch, handler)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("Case.Test.")])
    assert not any(r.method == "POST" and r.url.path.endswith("/zones") for r in seen)
    assert any(r.method == "PATCH" for r in seen)
