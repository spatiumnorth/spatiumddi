"""#3940: a BIND9 secondary serving serial 0 holds no copy, so is not in sync."""

import pytest

from app.models.dns import DNSZone
from app.services.dns.drift import zone_state_in_sync


@pytest.mark.parametrize("zone_type", ["secondary", "stub"])
def test_bind9_secondary_serving_zero_is_not_in_sync(zone_type: str) -> None:
    z = DNSZone(name="s.example.", zone_type=zone_type)
    assert not zone_state_in_sync(z, 0, 0, "bind9")
    assert zone_state_in_sync(z, 2026110101, 0, "bind9")


def test_bind9_primary_still_compares_target() -> None:
    z = DNSZone(name="p.example.", zone_type="primary")
    assert zone_state_in_sync(z, 0, 0, "bind9")
    assert not zone_state_in_sync(z, 1, 2, "bind9")
