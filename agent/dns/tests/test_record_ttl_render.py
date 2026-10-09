"""A record whose own TTL is 0 is written with TTL 0 (#1382).

The full zone render took ``rec.get("ttl") or ttl``, and 0 is falsy, so a
record set to TTL 0 — "do not cache this", what an operator sets for a
cut-over or a failover, and legal per RFC 2181 section 8 — was written with
the zone's TTL. In a group with views the full render is the only way a
record reaches named, so it was served that way every time; in a flat group
the RFC 2136 update wrote 0 and the zone's next full render undid it. Only a
record with no TTL of its own takes the zone's.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dns.name
import dns.rdatatype
import dns.zone

from spatium_dns_agent.drivers.bind9 import Bind9Driver

ORIGIN = "lab.example.test."


def _rec(name: str, value: str, ttl: int | None) -> dict[str, Any]:
    return {"name": name, "type": "A", "ttl": ttl, "value": value,
            "priority": None, "weight": None, "port": None}


def _served_ttls(tmp_path: Path, zone_ttl: int, records: list[dict[str, Any]]) -> dict[str, int]:
    zone = {
        "id": ORIGIN, "name": ORIGIN, "type": "primary", "ttl": zone_ttl,
        "serial": 2026100101, "forwarders": [], "forward_only": True, "view_name": None,
        "primary_ns": "ns1.example.net.", "admin_email": "hostmaster.example.net.",
        "records": records,
    }
    path = tmp_path / "zones" / "lab.example.test.db"
    Bind9Driver(state_dir=tmp_path)._write_zone_file(path, zone)
    parsed = dns.zone.from_text(path.read_text(), origin=ORIGIN, relativize=False,
                                check_origin=False)
    return {
        r["name"]: parsed.find_rdataset(dns.name.from_text(f"{r['name']}.{ORIGIN}"),
                                        dns.rdatatype.A).ttl
        for r in records
    }


def test_a_record_ttl_of_zero_is_written_as_zero(tmp_path: Path) -> None:
    ttls = _served_ttls(tmp_path, 1800, [_rec("t0", "192.0.2.10", 0)])

    assert ttls == {"t0": 0}


def test_an_explicit_ttl_and_an_inherited_one_are_unchanged(tmp_path: Path) -> None:
    ttls = _served_ttls(tmp_path, 1800, [_rec("t60", "192.0.2.60", 60),
                                         _rec("tinh", "192.0.2.20", None)])

    assert ttls == {"t60": 60, "tinh": 1800}
