"""PowerDNS: a LOC value BIND accepts is sent in the form PowerDNS accepts (#4572).

PowerDNS refuses ``52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m``
(``Not in expected format``) and wants ``... 10000.00m 10.00m``; the refused
rrset failed every structural apply of its zone.
"""

from __future__ import annotations

import pytest

from spatium_dns_agent.drivers.powerdns import _record_content

CANON = "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000.00m 10.00m"


@pytest.mark.parametrize(
    "value",
    [
        "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        "52 22 23 N 4 53 32 E -2m 0m 10000m 10m",
        "52 22 23.000 n 4 53 32.000 e -2.00m 0.00m 10000m 10m",
        "  " + CANON + "  ",
    ],
)
def test_loc_sent_in_powerdns_form(value: str) -> None:
    assert _record_content({"type": "LOC", "value": value}, "example.com") == CANON


def test_unparseable_loc_is_sent_as_typed() -> None:
    assert _record_content({"type": "LOC", "value": "garbage"}, "example.com") == "garbage"
