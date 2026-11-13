"""#3940: a BIND9 secondary serving serial 0 holds no copy, so is not in sync."""

import pytest

from app.models.dns import DNSZone
from app.services.dns.drift import zone_state_in_sync


@pytest.mark.parametrize("zone_type", ["secondary", "stub"])
def test_bind9_secondary_serving_zero_is_not_in_sync(zone_type: str) -> None:
    z = DNSZone(name="s.example.", zone_type=zone_type)
    assert not zone_state_in_sync(z, 0, 0, "bind9")
    assert zone_state_in_sync(z, 2026110101, 0, "bind9")


def test_an_older_bind9_agent_start_up_serial_reads_in_sync() -> None:
    """Its start-up report reads every zone from named, so a transferred
    secondary arrives at its real serial; 0 is "not reported", never synced."""
    z = DNSZone(name="s.example.", zone_type="secondary")
    assert zone_state_in_sync(z, 2026111302, 0, "bind9")
    assert not zone_state_in_sync(z, 0, 0, "bind9")


def test_bind9_primary_still_compares_target() -> None:
    z = DNSZone(name="p.example.", zone_type="primary")
    assert zone_state_in_sync(z, 0, 0, "bind9")
    assert not zone_state_in_sync(z, 1, 2, "bind9")


def test_reports_served_serials_reads_the_features_header() -> None:
    from app.services.dns.soa_timers import reports_served_serials

    assert reports_served_serials("soa-timers, Served-Serials")
    assert not reports_served_serials("soa-timers")
    assert not reports_served_serials(None)
