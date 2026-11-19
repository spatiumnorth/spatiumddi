"""One target rule for every name-valued Technitium record type (#1759).

Technitium has no relative names: it trims the dots off ``cname`` /
``nameServer`` / ``exchange`` ... and stores what is left as an absolute name.
SpatiumDDI stores values the zone-file way (no trailing dot = relative to the
zone, ``@`` = the zone, ``.`` = the root), so the drivers translate. #1731 did
that for SVCB / HTTPS only.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns.base import RecordChange, RecordData
from app.services.dns.pull_from_server import _key, _normalize_value
from app.services.technitium.rdata import rdata_to_value, record_params
from tests.test_dns_driver_technitium_api import _driver, _ok, _Server

ZONE = "example.com"

# type, stored value, the param Technitium reads, for a relative / absolute /
# apex / root target.
_NAME_PARAM = {
    "CNAME": "cname",
    "DNAME": "dname",
    "NS": "nameServer",
    "PTR": "ptrName",
    "MX": "exchange",
    "SRV": "target",
}
_CASES = [
    ("web", "web.example.com"),  # relative -> value.zone
    ("web.sub", "web.sub.example.com"),
    ("web.example.net.", "web.example.net"),  # absolute stays
    ("localhost.", "localhost"),  # absolute, one label
    ("@", "example.com"),  # the zone
    (".", "."),  # root: never an empty parameter
]


@pytest.mark.parametrize("rtype", sorted(_NAME_PARAM))
@pytest.mark.parametrize(("value", "sent"), _CASES)
def test_record_params_one_rule_per_type(rtype: str, value: str, sent: str) -> None:
    got = record_params(rtype, value, priority=10, weight=1, port=5060, origin=ZONE)
    assert got[_NAME_PARAM[rtype]] == sent


@pytest.mark.parametrize(
    ("value", "sent"),
    [
        ('100 10 "S" "SIP+D2U" "" _sip._udp', "_sip._udp.example.com"),
        ('100 10 "S" "SIP+D2U" "" _sip._udp.example.net.', "_sip._udp.example.net"),
        ('100 10 "S" "SIP+D2U" "" @', "example.com"),
        ('100 10 "" "" "!^.*$!x!" .', "."),
    ],
)
def test_naptr_replacement_follows_the_rule(value: str, sent: str) -> None:
    got = record_params("NAPTR", value, origin=ZONE)
    assert got["naptrReplacement"] == sent


def test_without_an_origin_the_legacy_reading_stands() -> None:
    assert record_params("CNAME", "web.", origin=None) == {"cname": "web"}
    assert record_params("CNAME", "web", origin=None) == {"cname": "web"}


@pytest.mark.asyncio
@pytest.mark.parametrize("rtype", sorted(_NAME_PARAM))
@pytest.mark.parametrize(("value", "sent"), _CASES)
async def test_agentless_driver_sends_the_rule(
    monkeypatch: pytest.MonkeyPatch, rtype: str, value: str, sent: str
) -> None:
    drv, fake = _driver(monkeypatch, [_ok({}), _ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        RecordChange(
            op="create",
            zone_name="example.com.",
            record=RecordData(
                name="www", record_type=rtype, value=value, ttl=300, priority=10, weight=1, port=1
            ),
            target_serial=0,
        ),
    )
    params: dict[str, Any] = fake.calls[-1]["params"]
    assert params[_NAME_PARAM[rtype]] == sent
    assert params[_NAME_PARAM[rtype]] != ""


@pytest.mark.parametrize(
    ("rtype", "rdata", "expected"),
    [
        ("CNAME", {"cname": "web.example.net"}, "web.example.net."),
        ("CNAME", {"cname": "web"}, "web."),
        ("DNAME", {"dname": "o.example.net"}, "o.example.net."),
        ("NS", {"nameServer": "ns1.example.net"}, "ns1.example.net."),
        ("PTR", {"ptrName": "h.example.net"}, "h.example.net."),
        ("MX", {"exchange": "mail.example.net", "preference": 5}, "mail.example.net."),
        ("MX", {"exchange": ".", "preference": 0}, "."),
        (
            "SRV",
            {"target": "sip.example.net", "priority": 1, "weight": 1, "port": 1},
            "sip.example.net.",
        ),
        ("SRV", {"target": ".", "priority": 0, "weight": 0, "port": 0}, "."),
    ],
)
def test_rdata_to_value_emits_the_dot(rtype: str, rdata: dict, expected: str) -> None:
    assert rdata_to_value(rtype, rdata)[0] == expected


def test_rdata_to_value_naptr_replacement_gets_the_dot() -> None:
    value, _ = rdata_to_value(
        "NAPTR",
        {
            "order": 100,
            "preference": 10,
            "flags": "S",
            "services": "SIP+D2U",
            "regexp": "",
            "replacement": "_sip._udp.example.net",
        },
    )
    assert value == '100 10 "S" "SIP+D2U" "" _sip._udp.example.net.'


def test_a_pulled_value_round_trips_through_the_sender() -> None:
    """What the daemon reports, stored, then sent back is the same name."""
    value, _ = rdata_to_value("CNAME", {"cname": "web.example.net"})
    assert record_params("CNAME", value, origin=ZONE) == {"cname": "web.example.net"}


def test_dname_and_naptr_compare_canonically() -> None:
    z = "example.com."
    assert _normalize_value("DNAME", "other", z, relative_targets=True) == _normalize_value(
        "DNAME", "other.example.com.", z, relative_targets=True
    )
    a = _normalize_value("NAPTR", '100 10 "S" "SIP+D2U" "" _sip', z, relative_targets=True)
    b = _normalize_value(
        "NAPTR", '100 10 "S" "SIP+D2U" "" _sip.example.com.', z, relative_targets=True
    )
    assert a == b
    other = _normalize_value(
        "NAPTR", '100 10 "S" "SIP+D2U" "" _sip._udp.example.net.', z, relative_targets=True
    )
    assert other != a


def test_key_folds_dname_and_naptr() -> None:
    z = "example.com."
    dn = RecordData(name="d", record_type="DNAME", value="Other")
    dn2 = RecordData(name="d", record_type="DNAME", value="other.example.com.")
    assert _key(dn, z, relative_targets=True) == _key(dn2, z, relative_targets=True)
    np1 = RecordData(name="n", record_type="NAPTR", value='1 2 "" "" "" t')
    np2 = RecordData(name="n", record_type="NAPTR", value='1 2 "" "" "" t.example.com.')
    assert _key(np1, z, relative_targets=True) == _key(np2, z, relative_targets=True)


def test_bundle_marker_gates_the_new_types() -> None:
    from app.services.dns import agent_bundle_store, agent_config

    assert agent_config.NAME_TARGET_RULE_KEY == "name_target_rule"
    assert agent_config.SVCB_TARGET_RULE_KEY == "svcb_target_rule"
    assert agent_bundle_store.RENDERER_REVISION >= 7
