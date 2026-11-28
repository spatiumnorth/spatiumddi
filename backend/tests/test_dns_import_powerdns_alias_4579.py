"""PowerDNS-only rdtypes in an import (#4579, C10).

ALIAS and LUA are authorable on a PowerDNS group, but the importer models
neither: it drops them and says so. Pinned so the loss is the announced one
(a warning naming each type and its count, the zone's other records kept)
and cannot turn into a silent drop or an import failure.
"""

from __future__ import annotations

from typing import Any

from app.services.dns_import.powerdns import _build_imported_zone


def _rrset(name: str, rtype: str, *contents: str) -> dict[str, Any]:
    return {
        "name": name,
        "type": rtype,
        "ttl": 60,
        "records": [{"content": c, "disabled": False} for c in contents],
    }


def test_alias_and_lua_are_dropped_with_a_warning_and_the_rest_is_kept() -> None:
    full = {
        "name": "example.com.",
        "kind": "Native",
        "rrsets": [
            _rrset("example.com.", "ALIAS", "lb.example.net."),
            _rrset("www.example.com.", "LUA", "A \"ifportup(443, {'192.0.2.1'})\""),
            _rrset("api.example.com.", "LUA", 'A "pickrandom({"192.0.2.2"})"'),
            _rrset("host.example.com.", "A", "192.0.2.9"),
        ],
    }
    z = _build_imported_zone({"name": "example.com.", "kind": "Native"}, full)
    assert [(r.name, r.record_type, r.value) for r in z.records] == [("host", "A", "192.0.2.9")]
    assert z.skipped_record_types == {"ALIAS": 1, "LUA": 2}
    # #4604: with no target group named, ALIAS / LUA are dropped as
    # PowerDNS-only (they import only into an all-PowerDNS group).
    (warning,) = [w for w in z.parse_warnings if "PowerDNS-only" in w]
    assert "ALIAS=1" in warning and "LUA=2" in warning
