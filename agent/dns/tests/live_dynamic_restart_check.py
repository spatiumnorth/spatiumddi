#!/usr/bin/env python3
"""Live check: RFC 2136 records outlive an agent restart and a re-render (#2850).

Runs INSIDE the built bind9 agent image, as ``spatium``, like
``live_query_log_check.py``: it drives the real :class:`Bind9Driver`
through ``apply_config`` against a real ``named``.

What it proves. A third party (an AD DC, a DHCP server) adds records to a
dynamic zone over RFC 2136. named holds them in its journal and, once it
dumps the zone, in its file. Every agent start rendered the zone afresh
from the cached bundle and set named's file and journal aside, so a record
the bundle did not carry was gone; every structural re-render on a running
named did the same through the freeze it takes before the swap. Here:

* the records survive a named stop (SIGTERM and SIGKILL) followed by the
  boot-from-cache apply of a bundle that lacks them;
* they survive a structural re-render on a running named, and one under
  split-horizon views, where every record change is structural;
* a record the control plane DELETED while the agent was down (one it
  rendered, and one it added by record op) is not brought back, and a
  record the third party deleted stays deleted;
* where the control plane takes over a name, its record wins.

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

_ZONE = "dyn.example."
_SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="
_FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _bundle(
    records: list[tuple[str, str, str]], ttl: int = 3600, view: str | None = None
) -> dict:
    zone = {
        "name": _ZONE,
        "type": "primary",
        "ttl": ttl,
        "serial": 5,
        "dynamic_update_enabled": True,
        # The source-address grant a DHCP server or DC is given.
        "update_acl": [
            {"action": "grant", "match_kind": "ip", "ip_cidr": "127.0.0.1/32"}
        ],
        "allow_transfer": None,
        "records": [
            {"name": n, "type": t, "value": v, "ttl": 300} for n, t, v in records
        ],
    }
    bundle = {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "no",
        },
        "tsig_keys": [
            {"name": "spatium-group", "secret": _SECRET, "algorithm": "hmac-sha256"}
        ],
        "zones": [zone],
    }
    if view:
        zone["view_name"] = view
        bundle["views"] = [{"name": view, "match_clients": ["any"], "recursion": False}]
    return bundle


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


def _q(label: str, rtype: str = "A") -> str:
    import dns.message
    import dns.query
    import dns.rcode

    try:
        r = dns.query.udp(
            dns.message.make_query(f"{label}.{_ZONE}", rtype), "127.0.0.1", timeout=3
        )
    except Exception as exc:  # noqa: BLE001 — every failure is a result here
        return f"error {type(exc).__name__}"
    if r.rcode() != dns.rcode.NOERROR:
        return dns.rcode.to_text(r.rcode())
    return ",".join(sorted(rd.to_text() for rr in r.answer for rd in rr)) or "NODATA"


def _serial() -> int:
    import dns.message
    import dns.query

    r = dns.query.udp(dns.message.make_query(_ZONE, "SOA"), "127.0.0.1", timeout=3)
    return r.answer[0][0].serial


def _nsupdate(adds=(), deletes=()) -> str:
    """An RFC 2136 update from a third party, authorised by source address."""
    import dns.query
    import dns.rcode
    import dns.update

    upd = dns.update.Update(_ZONE)
    for name, ttl, rtype, value in adds:
        upd.add(name, ttl, rtype, value)
    for name, rtype in deletes:
        upd.delete(name, rtype)
    return dns.rcode.to_text(dns.query.tcp(upd, "127.0.0.1", timeout=5).rcode())


def _stop(driver, sig: int = signal.SIGTERM) -> None:
    """Stop named the way a container stop does, and wait for it."""
    pid = driver.daemon_pid
    if not pid:
        return
    try:
        os.kill(pid, sig)
    except OSError:
        return  # already gone; nothing to stop
    deadline = time.time() + 15
    while time.time() < deadline and driver.daemon_running():
        time.sleep(0.2)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass  # not our child to reap, or already reaped


def flat(state: Path, sig: int) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    name = signal.Signals(sig).name
    print(f"\n=== restart by {name}, no views ===")
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(
        _bundle([("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")])
    )
    check("named serves the render", _q("www") == "192.0.2.1", _q("www"))
    check(
        "a third party adds dc01 + an SRV",
        _nsupdate(
            adds=[
                ("dc01", 600, "A", "10.9.9.9"),
                ("_ldap._tcp", 600, "SRV", f"0 100 389 dc01.{_ZONE}"),
            ]
        )
        == "NOERROR",
    )
    op = {
        "op": "create",
        "op_id": "live-1",
        "zone_name": _ZONE.rstrip("."),
        "record": {
            "name": "opadd",
            "type": "A",
            "value": "192.0.2.3",
            "ttl": 300,
            "rrset": {"ttl": 300, "members": [{"value": "192.0.2.3"}]},
        },
    }
    driver.apply_record_op(op)
    # What the sync loop does after an op (an agent older than #2850 has no hook).
    note = getattr(driver, "note_record_op_applied", None)
    if callable(note):
        note(op)
    check(
        "the control plane adds opadd by record op",
        _q("opadd") == "192.0.2.3",
        _q("opadd"),
    )
    served = _serial()
    _stop(driver, sig)

    print("--- agent start, from a cached bundle lacking dc01, gone and opadd")
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(_bundle([("www", "A", "192.0.2.1")]))
    check("dc01 survives the restart", _q("dc01") == "10.9.9.9", _q("dc01"))
    check(
        "the SRV survives the restart",
        _q("_ldap._tcp", "SRV") == f"0 100 389 dc01.{_ZONE}",
        _q("_ldap._tcp", "SRV"),
    )
    check(
        "a rendered record the control plane deleted is not brought back",
        _q("gone") == "NXDOMAIN",
        _q("gone"),
    )
    check(
        "a record-op record the control plane deleted is not brought back",
        _q("opadd") == "NXDOMAIN",
        _q("opadd"),
    )
    check(
        "the serial does not go backwards",
        _serial() > served,
        f"{served} -> {_serial()}",
    )

    print("--- a structural re-render on the running named")
    check(
        "a third party adds dc02",
        _nsupdate(adds=[("dc02", 600, "A", "10.9.9.8")]) == "NOERROR",
    )
    served = _serial()
    driver.apply_config(
        _bundle([("www", "A", "192.0.2.10"), ("new1", "A", "192.0.2.4")], ttl=1800)
    )
    check("dc01 survives the re-render", _q("dc01") == "10.9.9.9", _q("dc01"))
    check("dc02 survives the re-render", _q("dc02") == "10.9.9.8", _q("dc02"))
    check("the render's change is served", _q("www") == "192.0.2.10", _q("www"))
    check("the serial moves forward", _serial() > served, f"{served} -> {_serial()}")

    print("--- the third party deletes dc02, the control plane new1; restart again")
    check("a third party deletes dc02", _nsupdate(deletes=[("dc02", "A")]) == "NOERROR")
    _stop(driver, sig)
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(_bundle([("www", "A", "192.0.2.10")], ttl=1800))
    check("dc01 survives a second restart", _q("dc01") == "10.9.9.9", _q("dc01"))
    check("dc02 stays deleted", _q("dc02") == "NXDOMAIN", _q("dc02"))
    check("new1 is not brought back", _q("new1") == "NXDOMAIN", _q("new1"))

    print("--- the control plane takes over dc01")
    driver.apply_config(
        _bundle([("www", "A", "192.0.2.10"), ("dc01", "A", "192.0.2.50")], ttl=1800)
    )
    check("the control plane's dc01 wins", _q("dc01") == "192.0.2.50", _q("dc01"))
    _stop(driver)


def views(state: Path) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    print("\n=== split-horizon: every record change re-renders ===")
    driver = Bind9Driver(state_dir=state)
    base = [("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")]
    driver.apply_config(_bundle(base, view="v1"))
    check(
        "a third party adds dc01",
        _nsupdate(adds=[("dc01", 600, "A", "10.9.9.9")]) == "NOERROR",
    )
    driver.apply_config(_bundle([*base, ("r2", "A", "192.0.2.5")], view="v1"))
    check("dc01 survives a record change", _q("dc01") == "10.9.9.9", _q("dc01"))
    driver.apply_config(
        _bundle([("www", "A", "192.0.2.1"), ("r2", "A", "192.0.2.5")], view="v1")
    )
    check(
        "a record the control plane deleted goes", _q("gone") == "NXDOMAIN", _q("gone")
    )
    _stop(driver)
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(_bundle([("www", "A", "192.0.2.1")], view="v1"))
    check("dc01 survives a restart", _q("dc01") == "10.9.9.9", _q("dc01"))
    check(
        "r2, deleted while the agent was down, is not brought back",
        _q("r2") == "NXDOMAIN",
        _q("r2"),
    )
    _stop(driver)


def main() -> int:
    for tool in ("named", "rndc", "rndc-confgen", "named-compilezone"):
        if not shutil.which(tool):
            print(
                f"FAIL: `{tool}` not on PATH — this must run inside the bind9 agent image"
            )
            return 1
    cases = [
        lambda s: flat(s, signal.SIGTERM),
        lambda s: flat(s, signal.SIGKILL),
        views,
    ]
    for case in cases:
        state = Path(tempfile.mkdtemp(prefix="ddns-restart-check-"))
        _rndc_keys(state)
        try:
            case(state)
        finally:
            shutil.rmtree(state, ignore_errors=True)
    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll dynamic-update restart expectations met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
