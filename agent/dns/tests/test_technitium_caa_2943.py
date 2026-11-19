"""The agent's Technitium CAA write reads a stored value the way the control
plane does (#2943): quoted and bare are one record, escapes are undone."""

from __future__ import annotations

import pytest
from spatium_dns_agent.drivers.technitium import _record_params


@pytest.mark.parametrize(
    ("stored", "plain"),
    [
        ('0 issue "letsencrypt.org"', "letsencrypt.org"),
        ("0 issue letsencrypt.org", "letsencrypt.org"),
        ("0 issue ca.org.", "ca.org."),
        ('0 issue "ca.org; account=1"', "ca.org; account=1"),
        ('0 issue "say \\"hi\\""', 'say "hi"'),
        ('0 ISSUE "ca.org"', "ca.org"),
    ],
)
def test_caa_params(stored: str, plain: str) -> None:
    params = _record_params("CAA", stored, {})
    assert params["value"] == plain
    assert params["tag"] == "issue"
    assert params["flags"] == 0


@pytest.mark.parametrize(
    "stored",
    ["0 issue ca.org; account=1", '0 issue "ca.org"', '0 issue "say \\"hi\\""'],
)
def test_zone_file_and_powerdns_writers_quote_caa(stored: str) -> None:
    from spatium_dns_agent.drivers.bind9 import _wire_value
    from spatium_dns_agent.drivers.powerdns import _record_content

    wire = _wire_value("CAA", stored, {})
    assert wire.split(" ", 2)[2].startswith('"') and wire.endswith('"')
    # the quoted spelling is a fixed point, and PowerDNS gets the same text
    assert _wire_value("CAA", wire, {}) == wire
    assert _record_content({"type": "CAA", "value": stored}) == wire


@pytest.mark.parametrize(
    ("stored", "wire"),
    [
        ('0 issue "  pad  "', '0 issue "  pad  "'),
        ('0 issue "été"', '0 issue "\\195\\169t\\195\\169"'),
        ("0 issue ;", '0 issue ";"'),
        ("128 contactemail ops@example.com", '128 contactemail "ops@example.com"'),
        ('0 issue ""', '0 issue ""'),
    ],
)
def test_zone_file_writer_edge_values(stored: str, wire: str) -> None:
    from spatium_dns_agent.drivers.bind9 import _wire_value

    assert _wire_value("CAA", stored, {}) == wire


def test_technitium_keeps_padding_and_unescapes_decimal() -> None:
    assert _record_params("CAA", '0 issue "  pad  "', {})["value"] == "  pad  "
    assert (
        _record_params("CAA", '0 issue "\\195\\169t\\195\\169"', {})["value"] == "été"
    )
