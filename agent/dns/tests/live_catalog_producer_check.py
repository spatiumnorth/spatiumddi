#!/usr/bin/env python3
"""Live check: catalog zones are producer-only for an agent group (#3764).

Runs INSIDE the built bind9 agent image, like ``live_long_zone_check.py``:
it renders bundles through the real :class:`Bind9Driver` and runs its
``validate()``, which is the real ``named-checkconf`` the agent applies
behind.

* A producer's config, with its RFC 9432 catalog zone, passes
  ``named-checkconf``, and the catalog zone file passes ``named-checkzone``.
* A consumer block (only a control plane older than #3764 sends one) renders
  no ``catalog-zones`` entry and no catalog zone, and the config passes.

Exits non-zero on the first failure.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

_FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _bundle(catalog: dict) -> dict:
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
        "catalog": catalog,
    }


CATALOG = "catalog.spatium.invalid."


def _render(catalog: dict) -> tuple[object, Path, str]:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    state = Path(tempfile.mkdtemp(prefix="catz-"))
    driver = Bind9Driver(state_dir=state)
    driver.render(_bundle(catalog))
    conf = (state / "rendered.new" / "named.conf").read_text()
    return driver, state, conf


def _checkconf(label: str, driver: object) -> None:
    try:
        driver.validate()  # type: ignore[attr-defined]
        check(f"{label}: named-checkconf accepts the config", True)
    except Exception as exc:  # noqa: BLE001 — reported, not swallowed
        check(f"{label}: named-checkconf accepts the config", False, str(exc)[:400])


def producer_case() -> None:
    driver, state, conf = _render(
        {"mode": "producer", "zone_name": CATALOG, "members": [{"zone_name": "a.test."}]}
    )
    check("producer: catalog zone declared", f'zone "{CATALOG}" {{ type master;' in conf)
    check("producer: no catalog-zones consumer entry", "catalog-zones" not in conf)
    _checkconf("producer", driver)
    zfile = state / "rendered.new" / "zones" / f"{CATALOG.rstrip('.')}.db"
    res = subprocess.run(
        ["named-checkzone", CATALOG, str(zfile)], capture_output=True, text=True, check=False
    )
    check(
        "producer: named-checkzone accepts the catalog zone",
        res.returncode == 0,
        (res.stdout + res.stderr).strip()[:400],
    )


def consumer_case(addr: str) -> None:
    driver, _, conf = _render({"mode": "consumer", "zone_name": CATALOG, "producer_addr": addr})
    check(f"consumer {addr}: no catalog-zones entry", "catalog-zones" not in conf)
    check(f"consumer {addr}: no catalog zone", CATALOG not in conf)
    _checkconf(f"consumer {addr}", driver)


def main() -> int:
    producer_case()
    consumer_case("192.0.2.7")
    consumer_case("ns1.example.com")
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
