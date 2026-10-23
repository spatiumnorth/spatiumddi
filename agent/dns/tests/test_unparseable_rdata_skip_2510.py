"""One stored record whose rdata does not parse must not take its zone down (#2510).

named-checkzone refuses a whole zone for one bad line, and #882 then quarantines
the whole bundle. The agent leaves the record out, renders the rest, and reports
it through the existing partial-apply channel (``refused_zones``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dns.zone

from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.sync import _partial_apply_error

ORIGIN = "corp.example.test."


def _rec(name: str, rtype: str, value: str, **kw: Any) -> dict[str, Any]:
    return {"name": name, "type": rtype, "ttl": 300, "value": value,
            "priority": None, "weight": None, "port": None, **kw}


def _bundle(records: list[dict[str, Any]]) -> dict[str, Any]:
    zone = {
        "id": ORIGIN, "name": ORIGIN, "type": "primary", "ttl": 3600,
        "serial": 2026100101, "forwarders": [], "forward_only": False,
        "view_name": None, "primary_ns": "ns1.example.net.",
        "admin_email": "hostmaster.example.net.", "records": records,
    }
    return {
        "server": {"name": "s1", "driver": "bind9"}, "options": {}, "acls": [],
        "views": [], "zones": [zone], "blocklists": [], "tsig_keys": [],
        "pending_ops": [],
    }


GOOD = [
    _rec("www", "A", "192.0.2.1"),
    _rec("alias", "CNAME", "www"),  # relative target is legal in a zone file
    _rec("mail", "MX", "mail.example.net.", priority=10),
    _rec("caa", "CAA", '0 issue "letsencrypt.org"'),
]
BAD = [
    _rec("badcaa", "CAA", "issue letsencrypt.org"),
    _rec("badmx", "MX", "10 mx1.example.net. extra"),
    _rec("badsshfp", "SSHFP", "x y z"),
]


def _render(tmp_path: Path, records: list[dict[str, Any]]) -> tuple[Bind9Driver, str]:
    d = Bind9Driver(state_dir=tmp_path)
    d.render(_bundle(records))
    zf = next((tmp_path / "rendered.new" / "zones").rglob("*.db"))
    return d, zf.read_text()


def test_bad_records_are_left_out_and_the_zone_still_parses(tmp_path: Path) -> None:
    d, text = _render(tmp_path, GOOD + BAD)
    for name in ("badcaa", "badmx", "badsshfp"):
        assert name not in text
    parsed = dns.zone.from_text(text, origin=ORIGIN, relativize=False, check_origin=False)
    names = {str(n) for n in parsed.nodes}
    assert {f"{n}.{ORIGIN}" for n in ("www", "alias", "mail", "caa")} <= names
    assert not any(n.startswith("bad") for n in names)


def test_skips_are_reported_with_zone_owner_and_type(tmp_path: Path) -> None:
    d, _ = _render(tmp_path, GOOD + BAD)
    refused = d.refused_zones()
    assert len(refused) == 3
    assert all(r.startswith("corp.example.test: record ") for r in refused)
    assert any("badcaa CAA" in r for r in refused)
    assert any("badmx MX" in r for r in refused)
    assert any("badsshfp SSHFP" in r for r in refused)
    msg = _partial_apply_error((), refused)
    assert msg.startswith("partial apply: ") and "badcaa" in msg


def test_output_and_report_are_deterministic(tmp_path: Path) -> None:
    d1, t1 = _render(tmp_path / "a", GOOD + BAD)
    d2, t2 = _render(tmp_path / "b", list(reversed(GOOD + BAD)))
    assert d1.refused_zones() == d2.refused_zones()
    d3, t3 = _render(tmp_path / "c", GOOD + BAD)
    assert t1 == t3


def test_clean_zone_reports_nothing_and_a_fixed_row_clears_the_report(tmp_path: Path) -> None:
    d, text = _render(tmp_path, GOOD)
    assert d.refused_zones() == []
    d2 = Bind9Driver(state_dir=tmp_path)
    d2.render(_bundle(GOOD + BAD))
    assert d2.refused_zones()
    d2.render(_bundle(GOOD))
    assert d2.refused_zones() == []
