"""A BIND9 zone's SOA carries the zone's own timers (#1171).

Every zone file used to open with the same SOA timers whatever the zone held:
``( <serial> 3600 600 86400 300 )``. The zone's REFRESH / RETRY / EXPIRE /
MINIMUM were stored, editable and exported but never reached the agent, so a
secondary checked the primary hourly and stopped serving the zone after a
day, and every resolver cached a negative answer for five minutes, whatever
the operator set. The bundle now ships them and the render writes them. A
bundle without them (an older control plane) renders the old bytes, and a
value BIND would refuse is served the old way and logged, never written.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import dns.rdatatype
import dns.zone
import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _soa_timers

STORED = {"refresh": 86400, "retry": 7200, "expire": 3600000, "minimum": 3600}


def _zone(name: str = "lab.example.test.", **extra: Any) -> dict[str, Any]:
    zone: dict[str, Any] = {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 2026100101,
        "forwarders": [],
        "forward_only": True,
        "view_name": None,
        "primary_ns": "ns1.example.net.",
        "admin_email": "hostmaster.example.net.",
        "records": [],
    }
    zone.update(extra)
    return zone


def _write(tmp_path: Path, zone: dict[str, Any]) -> tuple[str, tuple[tuple[str, str], ...]]:
    path = tmp_path / "zones" / f"{zone['name'].rstrip('.')}.db"
    notes = Bind9Driver(state_dir=tmp_path)._write_zone_file(path, zone)
    return path.read_text(), notes


def _soa(text: str, origin: str) -> Any:
    z = dns.zone.from_text(text, origin=origin, relativize=False, check_origin=False)
    return z.find_rdataset(origin, dns.rdatatype.SOA)[0]


def test_the_soa_carries_the_zones_own_timers(tmp_path: Path) -> None:
    text, notes = _write(tmp_path, _zone(**STORED))

    soa = _soa(text, "lab.example.test.")
    assert (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum) == (
        2026100101, 86400, 7200, 3600000, 3600)
    assert notes == ()


def test_an_edited_set_is_written_as_edited(tmp_path: Path) -> None:
    text, _ = _write(tmp_path, _zone(refresh=7200, retry=900, expire=1209600, minimum=60))

    soa = _soa(text, "lab.example.test.")
    assert (soa.refresh, soa.retry, soa.expire, soa.minimum) == (7200, 900, 1209600, 60)


def test_a_bundle_without_timers_renders_the_old_bytes(tmp_path: Path) -> None:
    """An older control plane ships no timers: the file must be byte-for-byte
    what the agent wrote before, so an agent-first upgrade reloads nothing."""
    text, notes = _write(tmp_path, _zone())

    assert "@ IN SOA ns1.example.net. hostmaster.example.net. ( 2026100101 3600 600 86400 300 )" in text
    assert notes == ()


@pytest.mark.parametrize(
    "bad",
    [-1, 2**31, "3600", True, 1.5],
)
def test_a_timer_bind_would_refuse_is_served_the_old_way_and_noted(
    tmp_path: Path, bad: object
) -> None:
    text, notes = _write(tmp_path, _zone(**{**STORED, "retry": bad}))

    soa = _soa(text, "lab.example.test.")
    assert (soa.refresh, soa.retry, soa.expire, soa.minimum) == (86400, 600, 3600000, 3600)
    assert notes == (("unusable_timer", f"retry={bad!r}"),)


def test_zero_is_a_timer_like_any_other() -> None:
    """RFC 2308 allows a MINIMUM of 0 ("do not cache the negative answer");
    0 is not "unset"."""
    assert _soa_timers({"refresh": 0, "retry": 0, "expire": 0, "minimum": 0}) == ("0 0 0 0", ())
