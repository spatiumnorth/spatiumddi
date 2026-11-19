"""Every credentialed agentless DNS driver is health-checked through its API (#1455).

``app.tasks.dns._check_health`` calls ``driver.health_check(server)`` when
the driver has one and otherwise sends a SOA query to
``server.host:server.port``. For a cloud provider ``host`` is a label such
as ``"cloudflare"``, not a DNS server, so the fallback can never succeed
and the server is reported ``unreachable`` while every API call works.
A new cloud driver that forgets the hook would silently regress to that,
so pin it for the whole set rather than per driver.
"""

from __future__ import annotations

import pytest

from app.drivers.dns import CREDENTIALED_DNS_DRIVERS, get_driver


@pytest.mark.parametrize("driver_name", sorted(CREDENTIALED_DNS_DRIVERS))
def test_credentialed_agentless_driver_has_health_check(driver_name: str) -> None:
    driver = get_driver(driver_name)
    assert callable(getattr(driver, "health_check", None)), (
        f"{driver_name} has no health_check(); the DNS health task would "
        f"SOA-probe server.host instead and report it unreachable forever"
    )
