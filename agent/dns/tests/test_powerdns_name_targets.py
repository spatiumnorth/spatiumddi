"""PowerDNS: a dot-less name target is served, and one bad rrset no longer
strands the rest of its zone (#2060).

PowerDNS's API refuses a name target written without its trailing dot —
``422 Not in expected format (parsed as 'db1.example.com.')``, verified
against 5.0.7 — and applies a PATCH as one transaction. So one such row
refused its zone's whole structural PATCH (every other change to the zone
stranded), refused the zone's CREATE outright (the zone did not exist at
all), and failed every record op touching its rrset until the op's retries
ran out.

The render qualifies a dot-less target against the zone's origin — what a
BIND9 agent serves for the same row — and a zone PowerDNS still refuses is
retried one rrset at a time, so only the refused rrset keeps what PowerDNS
held. The reconcile tests drive an ``httpx.MockTransport`` standing in for
the pdns REST API; the live behaviour was checked against pdns-auth 5.0.7.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _record_content

# ── the content PowerDNS is sent ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("rec", "expected"),
    [
        ({"type": "CNAME", "value": "www"}, "www.example.com."),
        ({"type": "CNAME", "value": "db1.example.com"}, "db1.example.com.example.com."),
        ({"type": "CNAME", "value": "@"}, "example.com."),
        ({"type": "CNAME", "value": "x.example.net."}, "x.example.net."),
        ({"type": "PTR", "value": "host.example.com"}, "host.example.com.example.com."),
        ({"type": "PTR", "value": "host.example.com."}, "host.example.com."),
        ({"type": "NS", "value": "ns1"}, "ns1.example.com."),
        ({"type": "DNAME", "value": "other"}, "other.example.com."),
        ({"type": "ALIAS", "value": "lb"}, "lb.example.com."),
        ({"type": "MX", "value": "mail", "priority": 10}, "10 mail.example.com."),
        ({"type": "MX", "value": "20 mail", "priority": 10}, "20 mail.example.com."),
        ({"type": "MX", "value": ".", "priority": 0}, "0 ."),
        (
            {"type": "SRV", "value": "sip", "priority": 0, "weight": 5, "port": 5060},
            "0 5 5060 sip.example.com.",
        ),
        ({"type": "SRV", "value": "0 5 5060 sip"}, "0 5 5060 sip.example.com."),
        ({"type": "HTTPS", "value": "1 web alpn=h2"}, "1 web.example.com. alpn=h2"),
        ({"type": "SVCB", "value": "1 . alpn=h2"}, "1 . alpn=h2"),
        (
            {"type": "NAPTR", "value": '100 10 "u" "E2U+sip" "" sip'},
            '100 10 "u" "E2U+sip" "" sip.example.com.',
        ),
        ({"type": "NAPTR", "value": '100 10 "u" "E2U+sip" "!^.*$!sip:x@y!" .'}, None),
        ({"type": "A", "value": "192.0.2.1"}, "192.0.2.1"),
        ({"type": "TXT", "value": "no dots here"}, '"no dots here"'),
    ],
)
def test_a_dotless_target_is_qualified_against_the_zone(
    rec: dict[str, Any], expected: str | None
) -> None:
    content = _record_content(rec, "example.com.")
    assert content == (rec["value"] if expected is None else expected)


def test_without_a_zone_the_content_is_unchanged() -> None:
    assert _record_content({"type": "CNAME", "value": "www"}) == "www"


def test_the_render_ships_qualified_targets(tmp_path: Path) -> None:
    PowerDNSDriver(state_dir=tmp_path).render(
        {
            "options": {},
            "zones": [
                {
                    "type": "primary",
                    "name": "example.com",
                    "records": [
                        {"name": "db", "type": "CNAME", "value": "db1.example.com"},
                        {"name": "@", "type": "MX", "value": "mail", "priority": 10},
                    ],
                }
            ],
        }
    )
    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    contents = {
        (rs["name"], rs["type"]): [r["content"] for r in rs["records"]]
        for rs in payload[0]["rrsets"]
    }
    assert contents[("db.example.com.", "CNAME")] == ["db1.example.com.example.com."]
    assert contents[("example.com.", "MX")] == ["10 mail.example.com."]


# ── the pdns API, mocked ──────────────────────────────────────────────────────

Handler = Callable[[httpx.Request], httpx.Response]


def _api(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> list[httpx.Request]:
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


def _refuses_dotless(request: httpx.Request) -> httpx.Response | None:
    """What pdns-auth 5.0.7 answers for a dot-less CNAME / PTR target, or None."""
    if request.method not in ("POST", "PATCH"):
        return None
    for rs in json.loads(request.content).get("rrsets") or []:
        if rs.get("type") not in ("CNAME", "PTR"):
            continue
        for rec in rs.get("records") or []:
            if not rec["content"].endswith("."):
                return httpx.Response(
                    422,
                    json={
                        "error": f"Record {rs['name']}/{rs['type']} '{rec['content']}': "
                        f"Not in expected format (parsed as '{rec['content']}.')"
                    },
                )
    return None


def _conflict(request: httpx.Request) -> httpx.Response | None:
    """A CNAME beside other data at ``clash`` — refused as pdns does."""
    if request.method not in ("POST", "PATCH"):
        return None
    for rs in json.loads(request.content).get("rrsets") or []:
        if rs.get("type") == "CNAME" and rs["name"].startswith("clash."):
            return httpx.Response(
                422, json={"error": f"RRset {rs['name']} IN CNAME: Conflicts with another RRset"}
            )
    return None


def _pdns(*zones: str, refuse: Callable[[httpx.Request], httpx.Response | None]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        refusal = refuse(request)
        if refusal is not None:
            return refusal
        if request.method == "GET" and request.url.path.endswith("/zones"):
            return httpx.Response(200, json=[{"name": z} for z in zones])
        if request.method == "GET":
            return httpx.Response(200, json={"name": "x", "rrsets": []})
        if request.method == "DELETE":
            return httpx.Response(404)
        return httpx.Response(204 if request.method == "PATCH" else 201, json={})

    return handler


def _rendered(tmp_path: Path, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    PowerDNSDriver(state_dir=tmp_path).render(
        {
            "options": {},
            "zones": [{"type": "primary", "name": "example.com", "serial": 7, "records": records}],
        }
    )
    return json.loads((tmp_path / "rendered.new" / "zones.json").read_text())


def _patched(seen: list[httpx.Request]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for r in seen:
        if r.method == "PATCH":
            out += [(rs["name"], rs["type"]) for rs in json.loads(r.content)["rrsets"]]
    return out


_RECORDS = [
    {"name": "www", "type": "A", "value": "192.0.2.1"},
    {"name": "db", "type": "CNAME", "value": "db1.example.com"},
    {"name": "later", "type": "A", "value": "192.0.2.7"},
]


def test_a_dotless_row_no_longer_refuses_its_zone(tmp_path: Path, monkeypatch) -> None:
    """On unpatched code the dot-less CNAME refused the zone's whole PATCH,
    so ``later`` (and the SOA) never reached PowerDNS."""
    seen = _api(monkeypatch, _pdns("example.com.", refuse=_refuses_dotless))
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", _rendered(tmp_path, _RECORDS))
    assert not drv.refused_zones()
    assert ("later.example.com.", "A") in _patched(seen)


def test_a_dotless_row_no_longer_refuses_its_zones_create(tmp_path: Path, monkeypatch) -> None:
    """On unpatched code the zone was never created at all."""
    seen = _api(monkeypatch, _pdns(refuse=_refuses_dotless))
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", _rendered(tmp_path, _RECORDS))
    assert not drv.refused_zones()
    (create,) = [r for r in seen if r.method == "POST"]
    contents = {
        rs["name"]: [x["content"] for x in rs["records"]]
        for rs in json.loads(create.content)["rrsets"]
    }
    assert contents["db.example.com."] == ["db1.example.com.example.com."]


def test_a_record_op_with_a_dotless_target_applies(tmp_path: Path, monkeypatch) -> None:
    """On unpatched code this raised, and the op burnt its retries."""
    seen = _api(monkeypatch, _pdns("example.com.", refuse=_refuses_dotless))
    drv = PowerDNSDriver(state_dir=tmp_path)
    monkeypatch.setattr(drv, "_load_or_generate_api_key", lambda: "k")
    drv.apply_record_op(
        {
            "op_id": "1",
            "op": "create",
            "zone_name": "2.0.192.in-addr.arpa.",
            "record": {
                "name": "5",
                "type": "PTR",
                "value": "host.example.com",
                "ttl": 60,
                "rrset": {"ttl": 60, "members": [{"value": "host.example.com"}]},
            },
        }
    )
    patch = next(r for r in seen if r.method == "PATCH")
    assert json.loads(patch.content)["rrsets"][0]["records"] == [
        {"content": "host.example.com.2.0.192.in-addr.arpa.", "disabled": False}
    ]


_CLASH = [
    {"name": "www", "type": "A", "value": "192.0.2.1"},
    {"name": "clash", "type": "A", "value": "192.0.2.9"},
    {"name": "clash", "type": "CNAME", "value": "www"},
    {"name": "later", "type": "A", "value": "192.0.2.7"},
]


def test_one_refused_rrset_does_not_strand_the_rest_of_the_zone(
    tmp_path: Path, monkeypatch
) -> None:
    """A rrset PowerDNS refuses for its data is isolated; the rest of the
    zone lands, and the refusal names the rrset."""
    seen = _api(monkeypatch, _pdns("example.com.", refuse=_conflict))
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", _rendered(tmp_path, _CLASH))  # no raise
    patched = _patched(seen)
    assert ("later.example.com.", "A") in patched
    retries = [
        [(rs["name"], rs["type"]) for rs in json.loads(r.content)["rrsets"]]
        for r in seen
        if r.method == "PATCH"
    ][1:]
    assert [("clash.example.com.", "CNAME")] in retries, "isolated down to the bad rrset"
    assert retries[-1][-1] == ("example.com.", "SOA"), "the serial moves after the data"
    assert drv.unconverged_zones() == {"example.com"}
    (refusal,) = drv.refused_zones()
    assert refusal.startswith("example.com. update: HTTP 422")
    assert "refused: clash.example.com. CNAME" in refusal
    assert "www.example.com." not in refusal.split("refused:", 1)[1]


def test_one_refused_rrset_does_not_stop_the_zone_being_created(
    tmp_path: Path, monkeypatch
) -> None:
    seen = _api(monkeypatch, _pdns(refuse=_conflict))
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", _rendered(tmp_path, _CLASH))
    creates = [json.loads(r.content) for r in seen if r.method == "POST"]
    assert [bool(c["rrsets"]) for c in creates] == [True, False], "retried as an empty zone"
    assert creates[1]["serial"] == 7
    assert ("later.example.com.", "A") in _patched(seen)
    (refusal,) = drv.refused_zones()
    assert refusal.startswith("example.com. create: HTTP 422")
    assert "clash.example.com. CNAME" in refusal


def test_a_5xx_during_the_one_by_one_retry_fails_the_apply(tmp_path: Path, monkeypatch) -> None:
    calls = {"n": 0}

    def refuse(request: httpx.Request) -> httpx.Response | None:
        if request.method != "PATCH":
            return None
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(422, json={"error": "Conflicts with another RRset"})
        return httpx.Response(500, json={"error": "backend error"})

    _api(monkeypatch, _pdns("example.com.", refuse=refuse))
    with pytest.raises(RuntimeError, match="update: HTTP 500 backend error"):
        PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", _rendered(tmp_path, _CLASH))


# ── the piecemeal retry's cost and its edges ─────────────────────────────────


def _many(n: int) -> list[dict[str, Any]]:
    return [{"name": f"h{i}", "type": "A", "value": f"192.0.2.{i % 250 + 1}"} for i in range(n)]


def test_one_bad_rrset_in_a_big_zone_costs_a_handful_of_patches(
    tmp_path: Path, monkeypatch
) -> None:
    """Bisection, not one PATCH per rrset: a reconcile re-sends every rrset
    of the zone, and the retry runs on every structural apply until the bad
    row is fixed, so a 2,000-rrset zone must not cost 2,000 PATCHes each time."""
    records = [*_many(2000), {"name": "clash", "type": "A", "value": "192.0.2.9"}]
    records.append({"name": "clash", "type": "CNAME", "value": "www"})
    seen = _api(monkeypatch, _pdns("example.com.", refuse=_conflict))
    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._reconcile_zones("k", _rendered(tmp_path, records))
    patches = [r for r in seen if r.method == "PATCH"]
    assert len(patches) <= 30, len(patches)
    landed = {
        (rs["name"], rs["type"])
        for r in patches
        if _conflict(r) is None
        for rs in json.loads(r.content)["rrsets"]
    }
    assert ("h1999.example.com.", "A") in landed
    assert ("example.com.", "SOA") in landed
    assert ("clash.example.com.", "CNAME") not in landed
    (refusal,) = drv.refused_zones()
    assert "refused: clash.example.com. CNAME" in refusal


def test_a_zone_refused_whole_is_bounded_and_says_what_was_not_tried(
    tmp_path: Path, monkeypatch
) -> None:
    """Every rrset refused means the refusal was about the zone, not its data.
    The retry stops at its budget instead of sending a PATCH per rrset, the
    rest is reported as not attempted, and the serial does not move, so no
    NOTIFY announces data that is not there."""

    def refuse_all(request: httpx.Request) -> httpx.Response | None:
        if request.method == "PATCH":
            return httpx.Response(422, json={"error": "zone is broken"})
        return None

    seen = _api(monkeypatch, _pdns("example.com.", refuse=refuse_all))
    drv = PowerDNSDriver(state_dir=tmp_path)
    notified: list[str] = []
    monkeypatch.setattr(drv, "_send_notify", lambda *a: notified.append(a[-1]))
    drv._reconcile_zones("k", _rendered(tmp_path, _many(1000)))
    patches = [r for r in seen if r.method == "PATCH"]
    assert len(patches) <= powerdns._PIECEMEAL_PATCH_BUDGET + 1
    (refusal,) = drv.refused_zones()
    assert "not attempted" in refusal
    assert notified == []


def test_a_replaced_rrset_is_never_deleted_first(tmp_path: Path, monkeypatch) -> None:
    """Only rrsets the bundle dropped are DELETEd; one it still carries is a
    single REPLACE, so the piecemeal retry never leaves a served name absent."""

    def handler(request: httpx.Request) -> httpx.Response:
        refusal = _conflict(request)
        if refusal is not None:
            return refusal
        if request.method == "GET" and request.url.path.endswith("/zones"):
            return httpx.Response(200, json=[{"name": "example.com."}])
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "name": "example.com.",
                    "rrsets": [
                        {"name": "www.example.com.", "type": "A", "records": []},
                        {"name": "gone.example.com.", "type": "A", "records": []},
                    ],
                },
            )
        return httpx.Response(204 if request.method == "PATCH" else 201, json={})

    seen = _api(monkeypatch, handler)
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", _rendered(tmp_path, _CLASH))
    deletes = [
        rs["name"]
        for r in seen
        if r.method == "PATCH"
        for rs in json.loads(r.content)["rrsets"]
        if rs["changetype"] == "DELETE"
    ]
    assert set(deletes) == {"gone.example.com."}


def test_a_refused_zone_is_not_reported_converged(tmp_path: Path) -> None:
    """The sync loop leaves a partly-refused zone out of the zone-state
    report: its SOA may carry the new serial while a record is missing."""
    from types import SimpleNamespace

    from spatium_dns_agent.sync import SyncLoop

    drv = PowerDNSDriver(state_dir=tmp_path)
    drv._refused_zones = ("Example.COM. update: HTTP 422 x; refused: a CNAME (y)",)
    loop = SyncLoop.__new__(SyncLoop)
    loop.driver = drv
    assert loop._unconverged_zone_keys() == {"example.com"}
    drv._refused_zones = ()
    drv.held_back = (SimpleNamespace(zone="held.test", view=None),)
    assert loop._unconverged_zone_keys() == {"held.test"}
