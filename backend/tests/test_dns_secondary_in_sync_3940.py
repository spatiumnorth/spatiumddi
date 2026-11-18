"""#3940: a BIND9 secondary serving serial 0 holds no copy, so is not in sync."""

import pytest

from app.models.dns import DNSZone
from app.services.dns.drift import zone_state_in_sync


@pytest.mark.parametrize("zone_type", ["secondary", "stub"])
def test_bind9_secondary_serving_zero_is_not_in_sync(zone_type: str) -> None:
    z = DNSZone(name="s.example.", zone_type=zone_type)
    assert not zone_state_in_sync(z, 0, 0, "bind9")
    assert zone_state_in_sync(z, 2026110101, 0, "bind9")


def test_an_older_bind9_agent_serial_reads_in_sync_4440() -> None:
    """rc.3 reports the bundle's serial, 0, for every secondary it holds (its
    ``served_zone_serials``), so without ``served-serials`` a 0 is unknown and
    a non-zero serial is served: both read in sync (#4440)."""
    z = DNSZone(name="s.example.", zone_type="secondary")
    assert zone_state_in_sync(z, 2026111302, 0, "bind9", reports_served_serials=False)
    assert zone_state_in_sync(z, 0, 0, "bind9", reports_served_serials=False)


def test_bind9_primary_still_compares_target() -> None:
    z = DNSZone(name="p.example.", zone_type="primary")
    assert zone_state_in_sync(z, 0, 0, "bind9")
    assert not zone_state_in_sync(z, 1, 2, "bind9")


def test_reports_served_serials_reads_the_features_header() -> None:
    from app.services.dns.soa_timers import reports_served_serials

    assert reports_served_serials("soa-timers, Served-Serials")
    assert not reports_served_serials("soa-timers")
    assert not reports_served_serials(None)


def test_only_bind9_reads_zero_as_unknown_without_served_serials_4440() -> None:
    """An rc.3 BIND9 agent reports 0 for every secondary; a rolling upgrade must
    not show them all "not in sync" (#4440). A declaring agent's 0 still is, and
    PowerDNS always reported what it serves, so its 0 is never unknown."""
    z = DNSZone(name="s.example.", zone_type="secondary")
    assert zone_state_in_sync(z, 0, 0, "bind9", reports_served_serials=False)
    assert not zone_state_in_sync(z, 0, 0, "bind9", reports_served_serials=True)
    assert not zone_state_in_sync(z, 0, 0, "powerdns", reports_served_serials=False)
