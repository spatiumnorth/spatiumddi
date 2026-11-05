#!/usr/bin/env python3
"""Live check: an identical zone loads once across views (#3551).

Runs INSIDE the built bind9 agent image, as ``spatium``, like
``live_query_log_check.py``: it drives the real :class:`Bind9Driver`
through ``apply_config`` against a real ``named``.

What it proves. Under split-horizon every zone used to load once per view,
so memory scaled with views × data. A zone whose copy renders identically in
a later view is now defined in the first view and referenced from the later
one with ``in-view``. Here, with two views told apart by the client's
source address (127.0.0.2 lands in ``restricted``, anything else in
``default``):

* named accepts and loads the shared config, and the shared zone answers in
  BOTH views; a zone with a view-specific record still answers differently
  per view; the group blocklist rewrites in both views;
* ``rndc zonestatus`` reports ONE zone object for the shared name;
* a record change to the shared zone reaches both views through the agent's
  reload path, which reloads the defining view's file;
* a zone moves from shared to per-view copies and back on a running named;
* the control plane's signed transfer selects the REFERENCING view with its
  #920 key and is answered from the shared zone.

Exits non-zero on the first failed expectation. Never skips.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_SHARED = "example.com."
_SPLIT = "split.example.com."
_BLOCKED = "ads.example.net"
_RESTRICTED_SRC = "127.0.0.2"
_DEFAULT_SRC = "127.0.0.3"
_FAILURES: list[str] = []
_VIEW_KEYS = {
    "restricted": "cmVzdHJpY3RlZHJlc3RyaWN0ZWRyZXN0cmljdGVkMDE=",
    "default": "ZGVmYXVsdGRlZmF1bHRkZWZhdWx0ZGVmYXVsdGRlZjA=",
}


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _zone(name: str, view: str, records: list[tuple[str, str]]) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 1,
        "dynamic_update_enabled": False,
        "update_acl": [],
        "allow_transfer": None,
        "view_name": view,
        "records": [
            {"name": n, "type": "A", "value": v, "ttl": 300} for n, v in records
        ],
    }


def _bundle(shared: dict[str, list[tuple[str, str]]]) -> dict:
    """``shared`` maps each view to its copy of ``example.com.``'s records."""
    return {
        "options": {
            "forwarders": [],
            # RPZ rewrites only recursive answers; ``qname-wait-recurse no``
            # answers a listed name without trying the (absent) upstream.
            "recursion_enabled": True,
            "allow_recursion": ["any"],
            "allow_query": ["any"],
            "dnssec_validation": "no",
        },
        "tsig_keys": [
            {
                "name": "spatium-group",
                "secret": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE=",
                "algorithm": "hmac-sha256",
            }
        ],
        "views": [
            {
                "id": vname,
                "name": vname,
                "match_clients": clients,
                "match_destinations": [],
                "recursion": True,
                "transfer_key": {
                    "name": f"spatium_xfr_{vname}",
                    "secret": _VIEW_KEYS[vname],
                    "algorithm": "hmac-sha256",
                },
            }
            for vname, clients in (
                ("restricted", [_RESTRICTED_SRC]),
                ("default", ["any"]),
            )
        ],
        "zones": [
            _zone(_SHARED, "restricted", shared["restricted"]),
            _zone(_SHARED, "default", shared["default"]),
            _zone(_SPLIT, "restricted", [("www", "192.0.2.20")]),
            _zone(_SPLIT, "default", [("www", "198.51.100.20")]),
        ],
        "blocklists": [
            {
                "rpz_zone_name": "spatium-blocklist.rpz.",
                "entries": [
                    {"domain": _BLOCKED, "action": "block", "block_mode": "nxdomain"}
                ],
                "exceptions": [],
                "view_name": None,
            }
        ],
    }


def _rndc_keys(state: Path) -> None:
    """What the image entrypoint does on first boot, into this state dir."""
    subprocess.run(
        [
            "rndc-confgen",
            "-a",
            "-k",
            "spatium-rndc",
            "-A",
            "hmac-sha256",
            "-c",
            str(state / "rndc.key"),
        ],
        check=True,
        capture_output=True,
    )
    (state / "rndc.conf").write_text(
        'options {\n    default-server 127.0.0.1;\n    default-key    "spatium-rndc";\n};\n'
        f'include "{state / "rndc.key"}";\n'
    )


def _q(qname: str, source: str) -> str:
    import dns.message
    import dns.query
    import dns.rcode

    try:
        r = dns.query.udp(
            dns.message.make_query(qname, "A"), "127.0.0.1", timeout=3, source=source
        )
    except Exception as exc:  # noqa: BLE001 — every failure is a result here
        return f"error {type(exc).__name__}"
    if r.rcode() != dns.rcode.NOERROR:
        return dns.rcode.to_text(r.rcode())
    return ",".join(sorted(rd.to_text() for rr in r.answer for rd in rr)) or "NODATA"


def _both(qname: str) -> tuple[str, str]:
    return _q(qname, _RESTRICTED_SRC), _q(qname, _DEFAULT_SRC)


def _zonestatus(driver, view: str) -> str:
    return subprocess.run(
        [*driver._rndc_base(), "zonestatus", _SHARED, "IN", view],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


def _axfr_with(view: str) -> list[str]:
    import dns.query
    import dns.tsigkeyring
    import dns.zone

    ring = dns.tsigkeyring.from_text(
        {f"spatium_xfr_{view}": ("hmac-sha256", _VIEW_KEYS[view])}
    )
    try:
        z = dns.zone.from_xfr(
            dns.query.xfr(
                "127.0.0.1",
                _SHARED,
                keyring=ring,
                keyname=f"spatium_xfr_{view}",
                keyalgorithm="hmac-sha256",
                timeout=5,
            )
        )
    except Exception as exc:  # noqa: BLE001 — every failure is a result here
        return [f"error {type(exc).__name__}: {exc}"]
    return sorted(
        f"{n} {rd.to_text()}"
        for n, node in z.nodes.items()
        for rds in node.rdatasets
        for rd in rds
        if rds.rdtype == 1
    )


def _stop(driver) -> None:
    pid = driver.daemon_pid
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return  # already gone; nothing to stop
    deadline = time.time() + 15
    while time.time() < deadline and driver.daemon_running():
        time.sleep(0.2)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass  # not our child to reap, or already reaped


def shared(state: Path) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    driver = Bind9Driver(state_dir=state)
    same = [("www", "192.0.2.10")]
    print("\n=== an identical zone in two views loads once ===")
    driver.apply_config(_bundle({"restricted": same, "default": same}))
    check("named started", driver.daemon_running(), f"pid {driver.daemon_pid}")
    conf = (state / "rendered" / "named.conf").read_text()
    check(
        "default references the restricted copy",
        f'zone "{_SHARED}" {{ in-view "restricted"; }};' in conf,
    )
    check(
        "one zone file",
        (state / "rendered/zones/restricted/example.com.db").exists()
        and not (state / "rendered/zones/default/example.com.db").exists(),
    )
    check(
        "shared zone answers in both views",
        _both(f"www.{_SHARED}") == ("192.0.2.10",) * 2,
        str(_both(f"www.{_SHARED}")),
    )
    check(
        "a view-specific zone still answers per view",
        _both(f"www.{_SPLIT}") == ("192.0.2.20", "198.51.100.20"),
        str(_both(f"www.{_SPLIT}")),
    )
    check(
        "the group blocklist rewrites in both views",
        _both(_BLOCKED) == ("NXDOMAIN",) * 2,
        str(_both(_BLOCKED)),
    )
    zs_r, zs_d = _zonestatus(driver, "restricted"), _zonestatus(driver, "default")
    check(
        "rndc sees the zone from both views",
        "serial" in zs_r and "serial" in zs_d,
        (zs_r + zs_d)[:200],
    )
    check(
        "the referencing view's #920 key is answered from the shared zone",
        _axfr_with("default") == _axfr_with("restricted")
        and any("192.0.2.10" in r for r in _axfr_with("default")),
        str(_axfr_with("default")),
    )

    print("\n=== a record change to the shared zone reaches both views ===")
    pid = driver.daemon_pid
    changed = [("www", "192.0.2.11")]
    driver.apply_config(_bundle({"restricted": changed, "default": changed}))
    check(
        "named was NOT restarted", driver.daemon_pid == pid, f"pid {driver.daemon_pid}"
    )
    check(
        "both views serve the change",
        _both(f"www.{_SHARED}") == ("192.0.2.11",) * 2,
        str(_both(f"www.{_SHARED}")),
    )

    print("\n=== the copies diverge: shared -> per view ===")
    driver.apply_config(
        _bundle(
            {"restricted": changed, "default": [*changed, ("app", "198.51.100.30")]}
        )
    )
    conf = (state / "rendered" / "named.conf").read_text()
    check(
        "no in-view for the diverged zone", f'zone "{_SHARED}" {{ in-view' not in conf
    )
    check(
        "the view-specific record answers in its view only",
        _both(f"app.{_SHARED}") == ("NXDOMAIN", "198.51.100.30"),
        str(_both(f"app.{_SHARED}")),
    )
    check(
        "the common record still answers in both",
        _both(f"www.{_SHARED}") == ("192.0.2.11",) * 2,
        str(_both(f"www.{_SHARED}")),
    )

    print("\n=== the copies converge again: per view -> shared ===")
    driver.apply_config(_bundle({"restricted": changed, "default": changed}))
    conf = (state / "rendered" / "named.conf").read_text()
    check("shared again", f'zone "{_SHARED}" {{ in-view "restricted"; }};' in conf)
    check(
        "the removed record is gone from default",
        _both(f"app.{_SHARED}") == ("NXDOMAIN",) * 2,
        str(_both(f"app.{_SHARED}")),
    )
    check(
        "both views still answer",
        _both(f"www.{_SHARED}") == ("192.0.2.11",) * 2,
        str(_both(f"www.{_SHARED}")),
    )
    check(
        "named was never restarted",
        driver.daemon_pid == pid,
        f"pid {driver.daemon_pid}",
    )
    _stop(driver)


def main() -> int:
    for tool in ("named", "rndc", "rndc-confgen"):
        if not shutil.which(tool):
            print(
                f"FAIL: `{tool}` not on PATH — this must run inside the bind9 agent image"
            )
            return 1
    state = Path(tempfile.mkdtemp(prefix="views-share-check-"))
    _rndc_keys(state)
    try:
        shared(state)
    finally:
        shutil.rmtree(state, ignore_errors=True)
    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll view-sharing expectations met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
