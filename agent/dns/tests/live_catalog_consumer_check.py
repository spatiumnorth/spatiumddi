#!/usr/bin/env python3
"""Live check: a catalog-zone consumer's config passes named-checkconf (#3764).

Runs INSIDE the built bind9 agent image, like ``live_long_zone_check.py``:
it renders a consumer bundle through the real :class:`Bind9Driver` and runs
its ``validate()``, which is the real ``named-checkconf`` the agent applies
behind. Two ways the consumer used to fail it, either of which declined the
whole bundle rather than just the catalog:

* ``default-masters`` named the producer's hostname;
* the ``catalog-zones`` entry named a zone the config never declared, which
  BIND refuses ("catalog zone ... is not a primary or secondary zone").

Checked for an IPv4 and an IPv6 producer, and for a hostname, which the
agent must leave out rather than render. Exits non-zero on the first failure.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _bundle(producer_addr: str) -> dict:
    return {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "no",
        },
        "tsig_keys": [
            {
                "name": "spatium-group",
                "secret": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE=",
                "algorithm": "hmac-sha256",
                "loopback": True,
            }
        ],
        "zones": [
            {
                "id": "a.test.",
                "name": "a.test.",
                "type": "primary",
                "ttl": 3600,
                "serial": 1,
                "dynamic_update_enabled": False,
                "update_acl": [],
                "allow_transfer": None,
                "records": [],
            }
        ],
        "blocklists": [],
        "catalog": {
            "mode": "consumer",
            "zone_name": "catalog.spatium.invalid.",
            "producer_addr": producer_addr,
        },
    }


def run_case(addr: str, *, expect_catalog: bool) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    state = Path(tempfile.mkdtemp(prefix="catz-"))
    driver = Bind9Driver(state_dir=state)
    driver.render(_bundle(addr))
    conf = (state / "rendered.new" / "named.conf").read_text()
    check(
        f"{addr}: catalog-zones rendered = {expect_catalog}",
        ("catalog-zones" in conf) is expect_catalog,
    )
    try:
        driver.validate()
        check(f"{addr}: named-checkconf accepts the config", True)
    except Exception as exc:  # noqa: BLE001 — reported, not swallowed
        check(f"{addr}: named-checkconf accepts the config", False, str(exc)[:400])


def main() -> int:
    run_case("192.0.2.7", expect_catalog=True)
    run_case("2001:db8::7", expect_catalog=True)
    run_case("ns1.example.com", expect_catalog=False)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
