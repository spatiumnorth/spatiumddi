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
* where the control plane takes over a name, its record wins;
* a record the ingest mirrored and the third party then deleted is not
  brought back from the mirror row by a start before the next sweep.

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
    records: list[tuple[str, str, str]],
    ttl: int = 3600,
    view: str | None = None,
    other: str | None = None,
    learned: tuple[str, ...] = (),
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
    for rec in zone["records"]:
        # An ingest mirror of a third party's record (#641), as the control
        # plane marks it (#2850).
        if rec["name"] in learned:
            rec["learned"] = True
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
    if other:
        # A second zone, so an apply can be structural without touching this one.
        bundle["zones"].append(
            {
                "name": "other.example.",
                "type": "primary",
                "ttl": 3600,
                "serial": 1,
                "dynamic_update_enabled": False,
                "update_acl": [],
                "allow_transfer": None,
                "records": [{"name": "x", "type": "A", "value": other, "ttl": 300}],
            }
        )
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


def mirror_deleted(state: Path) -> None:
    """The walk's case 5: a record the ingest mirrored, deleted by the third
    party, and the agent restarting before the next sweep removes the mirror
    row from the cached bundle. It must stay deleted: served again, the next
    sweep reads it back and the mirror is never swept."""
    from spatium_dns_agent.drivers.bind9 import Bind9Driver
    from spatium_dns_agent.ingest import write_seen_keys

    print("\n=== a mirrored record the third party deleted, then a restart ===")
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(_bundle([("www", "A", "192.0.2.1")]))
    check(
        "a third party adds dc05",
        _nsupdate(adds=[("dc05", 600, "A", "10.9.9.5")]) == "NOERROR",
    )
    # The ingest sweep reads it, and the control plane mirrors it.
    write_seen_keys(
        state,
        _ZONE,
        [
            {"name": "www", "record_type": "A", "value": "192.0.2.1"},
            {"name": "dc05", "record_type": "A", "value": "10.9.9.5"},
        ],
    )
    check("a third party deletes dc05", _nsupdate(deletes=[("dc05", "A")]) == "NOERROR")
    _stop(driver)

    print("--- agent start, from a cached bundle still holding dc05's mirror")
    mirrored = [("www", "A", "192.0.2.1"), ("dc05", "A", "10.9.9.5")]
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(_bundle(mirrored, learned=("dc05",)))
    check("dc05 stays deleted", _q("dc05") == "NXDOMAIN", _q("dc05"))
    check("the render is served", _q("www") == "192.0.2.1", _q("www"))
    _stop(driver)
    driver = Bind9Driver(state_dir=state)
    driver.apply_config(_bundle(mirrored, learned=("dc05",)))
    check("dc05 stays deleted at a second start", _q("dc05") == "NXDOMAIN", _q("dc05"))

    print("--- a mirror named never held (a peer server's) is rendered")
    driver.apply_config(
        _bundle([*mirrored, ("dc06", "A", "10.9.9.6")], learned=("dc05", "dc06"))
    )
    check("dc06 is served", _q("dc06") == "10.9.9.6", _q("dc06"))
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


def serial_stable(state: Path) -> None:
    from spatium_dns_agent.drivers import bind9
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    print("\n=== a zone carrying an RFC 2136 record keeps its serial ===")
    driver = Bind9Driver(state_dir=state)
    base = [("www", "A", "192.0.2.1")]
    driver.apply_config(_bundle(base, other="192.0.2.100"))
    check(
        "a third party adds dc01",
        _nsupdate(adds=[("dc01", 600, "A", "10.9.9.9")]) == "NOERROR",
    )
    served = _serial()
    # Structural applies that change another zone only. The serial a running
    # named keeps through them is #2835's rule (``_same_zone_data``); main
    # before it moves every zone named is ahead of on every structural apply.
    keeps = hasattr(bind9, "_same_zone_data")
    for n in range(3):
        driver.apply_config(_bundle(base, other=f"192.0.2.{101 + n}"))
        check(
            f"structural apply {n + 1}: dc01 still served",
            _q("dc01") == "10.9.9.9",
            _q("dc01"),
        )
        if keeps:
            check(
                f"structural apply {n + 1}: the serial does not climb",
                _serial() == served,
                f"{served} -> {_serial()}",
            )
        else:
            print(
                f"  NOTE  structural apply {n + 1}: serial {_serial()} (no #2835 rule here)"
            )
    served = _serial()
    for n in range(3):
        _stop(driver)
        driver = Bind9Driver(state_dir=state)
        driver.apply_config(_bundle(base, other="192.0.2.103"))
        check(
            f"restart {n + 1}: dc01 still served", _q("dc01") == "10.9.9.9", _q("dc01")
        )
        check(
            f"restart {n + 1}: the serial does not climb",
            _serial() == served,
            f"{served} -> {_serial()}",
        )
    _stop(driver)


def races(state: Path) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    def update_first(driver, name: str):
        freeze = driver._freeze_before_swap

        def hooked(*a, **kw):
            check(
                f"a third party adds {name}",
                _nsupdate(adds=[(name, 600, "A", "10.9.9.9")]) == "NOERROR",
            )
            driver._freeze_before_swap = freeze
            return freeze(*a, **kw)

        driver._freeze_before_swap = hooked

    for changes in (True, False):
        what = (
            "changes, so it is frozen"
            if changes
            else "does not change: no freeze, no reload"
        )
        print(f"\n=== an update just before the freeze; the zone's render {what} ===")
        st = state / ("changed" if changes else "unchanged")
        st.mkdir()
        _rndc_keys(st)
        driver = Bind9Driver(state_dir=st)
        driver.apply_config(_bundle([("www", "A", "192.0.2.1")], other="192.0.2.100"))
        update_first(driver, "dc09")
        www = "192.0.2.5" if changes else "192.0.2.1"
        # The zone was a bare render, no journal, when the candidates were
        # chosen; the update lands after that.
        driver.apply_config(_bundle([("www", "A", www)], other="192.0.2.101"))
        check("dc09 served after the apply", _q("dc09") == "10.9.9.9", _q("dc09"))
        _stop(driver)
        driver = Bind9Driver(state_dir=st)
        driver.apply_config(_bundle([("www", "A", www)], other="192.0.2.101"))
        check("dc09 survives a restart", _q("dc09") == "10.9.9.9", _q("dc09"))
        _stop(driver)

    print("\n=== a render held back, then an update, then a fixed render (views) ===")
    state2 = state / "held"
    state2.mkdir()
    _rndc_keys(state2)
    driver = Bind9Driver(state_dir=state2)
    driver.apply_config(
        _bundle([("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")], view="v1")
    )
    # Deletes ``gone`` and names an in-zone NS with no address: held back.
    driver.apply_config(
        _bundle([("www", "A", "192.0.2.1"), ("@", "NS", "nsx.dyn.example.")], view="v1")
    )
    check("the zone is held back", bool(driver.held_back), str(driver.held_back))
    check(
        "a third party adds dc01",
        _nsupdate(adds=[("dc01", 600, "A", "10.9.9.9")]) == "NOERROR",
    )
    driver.apply_config(_bundle([("www", "A", "192.0.2.1")], view="v1"))
    check("dc01 is carried", _q("dc01") == "10.9.9.9", _q("dc01"))
    check(
        "gone, deleted by the held render, is not brought back",
        _q("gone") == "NXDOMAIN",
        _q("gone"),
    )
    _stop(driver)


def start_serial(state: Path) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    for signed in (False, True):
        kind = "inline-signed" if signed else "unsigned"
        print(
            f"\n=== {kind}: nothing to carry, the serial does not step back at a start (#2864) ==="
        )
        st = state / kind
        st.mkdir()
        _rndc_keys(st)

        def bundle(records, signed=signed):
            b = _bundle(records, learned=("dc01",))
            b["zones"][0]["dnssec_enabled"] = signed
            return b

        driver = Bind9Driver(state_dir=st)
        driver.apply_config(bundle([("www", "A", "192.0.2.1")]))
        time.sleep(1)
        check(
            "a third party adds dc01",
            _nsupdate(adds=[("dc01", 300, "A", "10.9.9.9")]) == "NOERROR",
        )
        time.sleep(1)
        served = _serial()
        _stop(driver)
        # The ingest mirrored dc01, so the cached bundle carries it: the
        # start has nothing to carry, and renders the control plane's serial.
        mirrored = [("www", "A", "192.0.2.1"), ("dc01", "A", "10.9.9.9")]
        driver = Bind9Driver(state_dir=st)
        driver.apply_config(bundle(mirrored))
        time.sleep(1)
        check("dc01 served", _q("dc01") == "10.9.9.9", _q("dc01"))
        check(
            "the same data keeps named's serial",
            _serial() == served,
            f"{served} -> {_serial()}",
        )
        served = _serial()
        _stop(driver)
        driver = Bind9Driver(state_dir=st)
        driver.apply_config(bundle([*mirrored, ("new1", "A", "192.0.2.4")]))
        time.sleep(1)
        check(
            "new data serves past named's serial",
            _serial() > served,
            f"{served} -> {_serial()}",
        )
        check("new1 served", _q("new1") == "192.0.2.4", _q("new1"))
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
        mirror_deleted,
        views,
        serial_stable,
        races,
        start_serial,
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
