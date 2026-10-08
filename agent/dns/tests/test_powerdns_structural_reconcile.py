"""PowerDNS serves the TTLs that were configured, and a zone it refuses is reported (#1225).

The structural (full) render stamped the ZONE TTL on every rrset, so every
reconcile (agent start, any structural change) REPLACEd each rrset at the
zone default and PowerDNS answered with TTLs nobody set, while the record-op
path honoured each record's own. And the reconcile logged-and-skipped a zone
PowerDNS refused to create or patch, so #882's apply status reported ``ok``
for a zone that was never served. A refusal is now a per-zone verdict
(``refused_zones()``) that leaves every other zone served; identical records
are sent once (#1379); and an rrset the bundle dropped is deleted (#1380).

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


def _zone_doc(request: httpx.Request, rrsets: list[dict[str, Any]] | None = None) -> httpx.Response:
    """``GET /zones/{zone}``: the zone as PowerDNS holds it."""
    return httpx.Response(
        200, json={"name": request.url.path.rsplit("/", 1)[-1], "rrsets": rrsets or []}
    )


def _ok(request: httpx.Request) -> httpx.Response:
    if request.method == "GET" and request.url.path.endswith("/zones"):
        return httpx.Response(200, json=[{"name": "old.test."}])
    if request.method == "GET":
        return _zone_doc(request)
    if request.method == "DELETE":
        return httpx.Response(404)  # metadata already absent: benign
    return httpx.Response(204 if request.method == "PATCH" else 201, json={})


def test_a_clean_reconcile_passes(tmp_path: Path, monkeypatch) -> None:
    seen = _api(monkeypatch, _ok)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
        "k", [_zone("old.test."), _zone("new.test.")]
    )
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


def test_a_refused_create_is_reported_and_the_rest_is_served(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and b"bad.test." in request.content:
            return httpx.Response(
                422, json={"error": "RRset bad.test. IN CNAME: Conflicts with other records"}
            )
        return _ok(request)

    seen = _api(monkeypatch, handler)
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", [_zone("bad.test."), _zone("old.test.")])  # no raise
    (refusal,) = drv.refused_zones()
    assert refusal.startswith("bad.test. create: HTTP 422")
    assert "Conflicts with other records" in refusal, "PowerDNS's own reason is surfaced"
    assert any(r.method == "PATCH" for r in seen), "one refused zone must not strand the rest"


def test_one_refused_zone_leaves_the_good_zone_served(tmp_path: Path, monkeypatch) -> None:
    """ddi-pg's gate walk of #1280: one refused zone kept the whole server
    ``revert_failed``. The good zone is patched, the bad one reported, and the
    apply does not fail — so the sync loop neither reverts nor stops draining
    record ops."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/zones"):
            return httpx.Response(200, json=[{"name": "bad.test."}, {"name": "good.test."}])
        if request.method == "PATCH" and request.url.path.endswith("/bad.test."):
            return httpx.Response(
                422,
                json={
                    "error": 'Duplicate record in RRset www.bad.test. IN A with content "192.0.2.1"'
                },
            )
        return _ok(request)

    seen = _api(monkeypatch, handler)
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", [_zone("bad.test."), _zone("good.test.")])
    assert any(r.method == "PATCH" and r.url.path.endswith("/good.test.") for r in seen)
    (refusal,) = drv.refused_zones()
    assert refusal.startswith("bad.test. update: HTTP 422 Duplicate record in RRset")


def test_a_5xx_patch_still_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    """A 5xx says nothing about the zone's data: the whole apply fails."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH":
            return httpx.Response(500, json={"error": "backend error"})
        return _ok(request)

    _api(monkeypatch, handler)
    with pytest.raises(RuntimeError, match=r"old\.test\. update: HTTP 500 backend error"):
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


def test_a_zone_pdns_stored_lowercased_is_patched_not_recreated(
    tmp_path: Path, monkeypatch
) -> None:
    """PowerDNS stores zone names lowercased (verified). Comparing exactly
    re-POSTed ``Case.Test.`` on every reconcile after the first, which answers
    409 and would now fail every apply."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/zones"):
            return httpx.Response(200, json=[{"name": "case.test."}])
        if request.method == "POST":
            return httpx.Response(409, json={"error": "Conflict"})
        return _ok(request)

    seen = _api(monkeypatch, handler)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("Case.Test.")])
    assert not any(r.method == "POST" and r.url.path.endswith("/zones") for r in seen)
    assert any(r.method == "PATCH" for r in seen)


# ── identical records are sent once (#1379) ─────────────────────────────────


def _render_payload(tmp_path: Path, zone: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    PowerDNSDriver(state_dir=tmp_path).render(
        {"options": {}, "zones": [{"type": "primary", **zone}]}
    )
    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    return {(rs["name"].lower(), rs["type"]): rs for rs in payload[0]["rrsets"]}


def test_identical_records_collapse_to_one(tmp_path: Path) -> None:
    """A manual A record beside the identical IPAM-generated one is two rows
    with one value. PowerDNS refuses an rrset that repeats a record, which
    refused the whole zone; on main it was never served at all."""
    rrsets = _render_payload(
        tmp_path,
        {
            "name": "example.com",
            "ttl": 3600,
            "records": [
                _rec("www", "A", "192.0.2.1", 300),
                _rec("www", "A", "192.0.2.1", 60),  # the IPAM twin, lower TTL
                _rec("WWW", "A", "192.0.2.2", None),  # same name, other case
                _rec("alias", "CNAME", "Target.example.com.", None),
                _rec("alias", "CNAME", "target.example.com", None),
                _rec("txt", "TXT", "Hello", None),
                _rec("txt", "TXT", "hello", None),  # free text: case matters
            ],
        },
    )
    www = rrsets[("www.example.com.", "A")]
    assert [r["content"] for r in www["records"]] == ["192.0.2.1", "192.0.2.2"]
    assert www["ttl"] == 60, "the lowest TTL, the duplicate's included"
    assert len(rrsets[("alias.example.com.", "CNAME")]["records"]) == 1
    assert len(rrsets[("txt.example.com.", "TXT")]["records"]) == 2


def test_a_record_op_rrset_drops_duplicate_members(tmp_path: Path, monkeypatch) -> None:
    seen = _api(monkeypatch, _ok)
    drv = PowerDNSDriver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "_load_or_generate_api_key", lambda: "k")
    drv.apply_record_op(
        {
            "op_id": "1",
            "op": "create",
            "zone_name": "old.test.",
            "record": {
                "name": "www",
                "type": "A",
                "value": "192.0.2.1",
                "ttl": 300,
                "rrset": {"ttl": 300, "members": [{"value": "192.0.2.1"}, {"value": "192.0.2.1"}]},
            },
        }
    )
    patch = next(r for r in seen if r.method == "PATCH")
    assert json.loads(patch.content)["rrsets"][0]["records"] == [
        {"content": "192.0.2.1", "disabled": False}
    ]


# ── rrsets the bundle dropped are deleted (#1380) ───────────────────────────


def _held(*rrsets: tuple[str, str]) -> list[dict[str, Any]]:
    return [{"name": n, "type": t, "ttl": 3600, "records": [{"content": "x"}]} for n, t in rrsets]


def _patch_changes(seen: list[httpx.Request]) -> list[tuple[str, str, str]]:
    patch = next(r for r in seen if r.method == "PATCH")
    return [
        (rs["changetype"], rs["name"], rs["type"]) for rs in json.loads(patch.content)["rrsets"]
    ]


def test_an_rrset_absent_from_the_bundle_is_deleted(tmp_path: Path, monkeypatch) -> None:
    """In a views group every record change is a full render and the op is
    retired without being sent, so the reconcile is the only path a delete
    has. It used to REPLACE what the bundle carried and leave the rest."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/old.test."):
            return _zone_doc(
                request,
                _held(
                    ("old.test.", "SOA"),
                    ("old.test.", "NS"),
                    ("www.old.test.", "A"),
                    ("gone.old.test.", "A"),
                    ("Sub.old.test.", "NS"),  # a delegation the bundle dropped
                    ("old.test.", "DNSKEY"),
                ),
            )
        return _ok(request)

    seen = _api(monkeypatch, handler)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])
    changes = _patch_changes(seen)
    assert ("DELETE", "gone.old.test.", "A") in changes
    assert ("DELETE", "Sub.old.test.", "NS") in changes
    assert ("REPLACE", "www.old.test.", "A") in changes
    # Deletes first, so a name changing type is cleared before it is replaced.
    assert changes.index(("DELETE", "gone.old.test.", "A")) < changes.index(
        ("REPLACE", "www.old.test.", "A")
    )


def test_the_apex_soa_and_ns_are_never_deleted(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/old.test."):
            return _zone_doc(
                request, _held(("old.test.", "SOA"), ("OLD.test.", "NS"), ("old.test.", "DNSKEY"))
            )
        return _ok(request)

    seen = _api(monkeypatch, handler)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])
    assert not [c for c in _patch_changes(seen) if c[0] == "DELETE"]


def test_a_dynamic_update_zone_is_not_swept(tmp_path: Path, monkeypatch) -> None:
    """RFC 2136 clients write records the bundle never carries."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/old.test."):
            return _zone_doc(request, _held(("laptop.old.test.", "A")))
        return _ok(request)

    seen = _api(monkeypatch, handler)
    acl = [{"action": "grant", "match_kind": "ip", "ip_cidr": "10.0.0.0/8"}]
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.", update_acl=acl)])
    assert not [c for c in _patch_changes(seen) if c[0] == "DELETE"]


def test_a_zone_that_cannot_be_read_back_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/old.test."):
            return httpx.Response(500, json={"error": "backend error"})
        return _ok(request)

    _api(monkeypatch, handler)
    with pytest.raises(RuntimeError, match=r"old\.test\. read: HTTP 500 backend error"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [_zone("old.test.")])
