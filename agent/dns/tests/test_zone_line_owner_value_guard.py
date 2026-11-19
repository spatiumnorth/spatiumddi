"""A record whose owner or value cannot be one zone-file line is left out.

A master-file line is ``<owner> <ttl> IN <type> <rdata>``. A blank or
whitespace-only owner renders a line starting with whitespace, which BIND reads
as "same owner as the previous record", so the address is published under
another host's name. A newline in the owner or the value ends the line early
and lets the remainder be read as a record of its own. The writer skips such a
row and reports it through ``refused_zones``, like an unparseable one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dns.rdataclass
import dns.rdatatype
import dns.zone

from spatium_dns_agent.drivers.bind9 import Bind9Driver

ORIGIN = "corp.example.test."


def _rec(name: Any, rtype: str, value: str, **kw: Any) -> dict[str, Any]:
    return {"name": name, "type": rtype, "ttl": 300, "value": value,
            "priority": None, "weight": None, "port": None, **kw}


def _bundle(records: list[dict[str, Any]]) -> dict[str, Any]:
    zone = {
        "id": ORIGIN, "name": ORIGIN, "type": "primary", "ttl": 3600,
        "serial": 2026102301, "forwarders": [], "forward_only": False,
        "view_name": None, "primary_ns": "ns1.example.net.",
        "admin_email": "hostmaster.example.net.", "records": records,
    }
    return {
        "server": {"name": "s1", "driver": "bind9"}, "options": {}, "acls": [],
        "views": [], "zones": [zone], "blocklists": [], "tsig_keys": [],
        "pending_ops": [],
    }


def _render(tmp_path: Path, records: list[dict[str, Any]]) -> tuple[Bind9Driver, str]:
    d = Bind9Driver(state_dir=tmp_path)
    d.render(_bundle(records))
    zf = next((tmp_path / "rendered.new" / "zones").rglob("*.db"))
    return d, zf.read_text()


def _parse(text: str) -> dns.zone.Zone:
    return dns.zone.from_text(text, origin=ORIGIN, relativize=False, check_origin=False)


def _a_addresses(zone: dns.zone.Zone, owner: str) -> set[str]:
    node = zone.get_node(owner)
    if node is None:
        return set()
    rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
    return {r.to_text() for r in rds} if rds is not None else set()


def test_whitespace_only_owner_is_not_published_under_the_previous_owner(
    tmp_path: Path,
) -> None:
    d, text = _render(
        tmp_path,
        [_rec("h1", "A", "192.0.2.1"), _rec("   ", "A", "192.0.2.99")],
    )
    # No line may start with whitespace: that is how BIND inherits the owner.
    assert not any(line[:1].isspace() for line in text.splitlines() if line)
    zone = _parse(text)
    assert _a_addresses(zone, f"h1.{ORIGIN}") == {"192.0.2.1"}
    assert "192.0.2.99" not in text
    assert any("skipped" in r and "owner" in r for r in d.refused_zones())


def test_owner_with_newline_is_skipped(tmp_path: Path) -> None:
    d, text = _render(
        tmp_path,
        [_rec("h1", "A", "192.0.2.1"), _rec("x\nevil", "A", "192.0.2.50")],
    )
    assert "evil" not in text
    assert "192.0.2.50" not in text
    _parse(text)
    assert len(d.refused_zones()) == 1


def test_value_with_newline_cannot_inject_a_second_record(tmp_path: Path) -> None:
    injected = "192.0.2.9\nevil 300 IN A 198.51.100.7"
    d, text = _render(
        tmp_path,
        [_rec("h1", "A", "192.0.2.1"), _rec("h2", "A", injected)],
    )
    zone = _parse(text)
    assert zone.get_node(f"evil.{ORIGIN}") is None
    assert "198.51.100.7" not in text
    assert zone.get_node(f"h2.{ORIGIN}") is None
    refused = d.refused_zones()
    assert len(refused) == 1 and "h2" in refused[0]


def test_txt_value_with_newline_is_skipped(tmp_path: Path) -> None:
    d, text = _render(
        tmp_path,
        [_rec("t", "TXT", "v=spf1 -all\nevil 300 IN A 198.51.100.7")],
    )
    assert "198.51.100.7" not in text
    assert len(d.refused_zones()) == 1


def test_ordinary_records_still_render(tmp_path: Path) -> None:
    """Negative control: legal owners and values (spaces in rdata included)."""
    d, text = _render(
        tmp_path,
        [
            _rec("h1", "A", "192.0.2.1"),
            _rec("", "A", "192.0.2.2"),  # empty name is the apex, as before
            _rec("_acme-challenge", "TXT", "token value with spaces"),
            _rec("caa", "CAA", '0 issue "letsencrypt.org"'),
        ],
    )
    zone = _parse(text)
    assert _a_addresses(zone, f"h1.{ORIGIN}") == {"192.0.2.1"}
    assert _a_addresses(zone, ORIGIN) == {"192.0.2.2"}
    assert zone.get_node(f"_acme-challenge.{ORIGIN}") is not None
    assert zone.get_node(f"caa.{ORIGIN}") is not None
    assert not d.refused_zones()
