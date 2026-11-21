#!/usr/bin/env python3
"""Live check: a record op is applied into the view it names (#2242).

Runs INSIDE the built bind9 agent image, as ``spatium``, like
``live_views_share_check.py``: it drives the real :class:`Bind9Driver` through
``apply_config`` and ``apply_record_op`` against a real ``named``.

What it proves. Two views told apart by the client's source address (127.0.0.2
lands in ``restricted``, anything else in ``default``) each hold a copy of
``example.com.``, and an RFC 2136 update to 127.0.0.1 would land in whichever
view matches the agent's own source address. Each op names its view and is
signed with that view's update key, so:

* an op for ``restricted`` changes what ``restricted`` serves and leaves
  ``default`` alone, and the reverse;
* the SOA serial the op carries is the serial that view then serves, and the
  driver reports it (``reached_serial``);
* a structural re-render afterwards keeps what the ops wrote, with named not
  restarted;
* an op naming no view is refused.

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

_ZONE = "example.com."
_RESTRICTED_SRC = "127.0.0.2"
_DEFAULT_SRC = "127.0.0.3"
_FAILURES: list[str] = []
_UPDATE_KEYS = {
    "restricted": "cmVzdHJpY3RlZHVwZGF0ZXJlc3RyaWN0ZWR1cGQ=",
    "default": "ZGVmYXVsdHVwZGF0ZWRlZmF1bHR1cGRhdGVkZWZhdWw=",
}
_XFR_KEYS = {
    "restricted": "cmVzdHJpY3RlZHJlc3RyaWN0ZWRyZXN0cmljdGVkMDE=",
    "default": "ZGVmYXVsdGRlZmF1bHRkZWZhdWx0ZGVmYXVsdGRlZjA=",
}


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _zone(view: str, records: list[tuple[str, str]], serial: int) -> dict:
    return {
        "id": _ZONE,
        "name": _ZONE,
        "type": "primary",
        "ttl": 3600,
        "serial": serial,
        "dynamic_update_enabled": False,
        "update_acl": [],
        "allow_transfer": None,
        "view_name": view,
        "records": [
            {"name": n, "type": "A", "value": v, "ttl": 300} for n, v in records
        ],
    }


def _bundle(
    restricted: list[tuple[str, str]], default: list[tuple[str, str]], serial: int
) -> dict:
    return {
        "options": {
            "forwarders": [],
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
                "loopback": True,
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
                    "secret": _XFR_KEYS[vname],
                    "algorithm": "hmac-sha256",
                },
                "update_key": {
                    "name": f"spatium_upd_{vname}",
                    "secret": _UPDATE_KEYS[vname],
                    "algorithm": "hmac-sha256",
                },
            }
            for vname, clients in (
                ("restricted", [_RESTRICTED_SRC]),
                ("default", ["any"]),
            )
        ],
        "zones": [
            _zone("restricted", restricted, serial),
            _zone("default", default, serial),
        ],
        "blocklists": [],
    }


def _rndc_keys(state: Path) -> None:
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


def _serial(source: str) -> int | None:
    import dns.message
    import dns.query

    try:
        r = dns.query.udp(
            dns.message.make_query(_ZONE, "SOA"), "127.0.0.1", timeout=3, source=source
        )
        return int(r.answer[0][0].serial)
    except Exception:  # noqa: BLE001
        return None


def _op(view: str | None, name: str, value: str, serial: int) -> dict:
    op: dict = {
        "op_id": f"op-{name}-{view}",
        "zone_name": _ZONE,
        "op": "create",
        "target_serial": serial,
        "record": {
            "name": name,
            "type": "A",
            "value": value,
            "ttl": 300,
            "rrset": {"ttl": 300, "members": [{"value": value}]},
        },
    }
    if view is not None:
        op["view_name"] = view
    return op


def _stop(driver) -> None:
    pid = driver.daemon_pid
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + 15
    while time.time() < deadline and driver.daemon_running():
        time.sleep(0.2)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def case(state: Path) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    driver = Bind9Driver(state_dir=state)
    base_r = [("www", "192.0.2.10")]
    base_d = [("www", "198.51.100.10")]
    print("\n=== two views, one zone each, per-view update keys ===")
    driver.apply_config(_bundle(base_r, base_d, 10))
    check("named started", driver.daemon_running(), f"pid {driver.daemon_pid}")
    conf = (state / "rendered" / "named.conf").read_text()
    check("each view loads its own copy (no in-view)", "in-view" not in conf)
    check(
        "the views answer their own record",
        _both(f"www.{_ZONE}") == ("192.0.2.10", "198.51.100.10"),
        str(_both(f"www.{_ZONE}")),
    )
    pid = driver.daemon_pid

    print("\n=== an op lands in the view it names ===")
    driver.apply_record_op(_op("restricted", "app", "192.0.2.77", 11))
    check(
        "restricted serves the new record, default does not",
        _both(f"app.{_ZONE}") == ("192.0.2.77", "NXDOMAIN"),
        str(_both(f"app.{_ZONE}")),
    )
    check(
        "restricted serves the op's serial",
        _serial(_RESTRICTED_SRC) == 11,
        str(_serial(_RESTRICTED_SRC)),
    )
    check(
        "default's serial is unmoved",
        _serial(_DEFAULT_SRC) == 10,
        str(_serial(_DEFAULT_SRC)),
    )
    check(
        "the driver reports the serial it reached",
        driver.reached_serial(_ZONE) == 11,
        str(driver.reached_serial(_ZONE)),
    )
    driver.apply_record_op(_op("default", "app", "198.51.100.77", 12))
    check(
        "default serves its own, restricted keeps its",
        _both(f"app.{_ZONE}") == ("192.0.2.77", "198.51.100.77"),
        str(_both(f"app.{_ZONE}")),
    )
    check(
        "default serves the op's serial; restricted still its own",
        (_serial(_RESTRICTED_SRC), _serial(_DEFAULT_SRC)) == (11, 12),
        str((_serial(_RESTRICTED_SRC), _serial(_DEFAULT_SRC))),
    )
    # The same name changed in both views keeps each view's own set.
    driver.apply_record_op(_op("restricted", "www", "192.0.2.11", 13))
    check(
        "an op rewrites its own view's RRset only",
        _both(f"www.{_ZONE}") == ("192.0.2.11", "198.51.100.10"),
        str(_both(f"www.{_ZONE}")),
    )

    print("\n=== a structural re-render keeps what the ops wrote ===")
    driver.apply_config(
        _bundle(
            [("www", "192.0.2.11"), ("app", "192.0.2.77")],
            [("www", "198.51.100.10"), ("app", "198.51.100.77")],
            13,
        )
    )
    check(
        "named was NOT restarted", driver.daemon_pid == pid, f"pid {driver.daemon_pid}"
    )
    check(
        "both views still serve the ops' records",
        _both(f"app.{_ZONE}") == ("192.0.2.77", "198.51.100.77")
        and _both(f"www.{_ZONE}") == ("192.0.2.11", "198.51.100.10"),
        f"{_both(f'app.{_ZONE}')} {_both(f'www.{_ZONE}')}",
    )

    print("\n=== refusals ===")
    try:
        driver.apply_record_op(_op(None, "x", "192.0.2.1", 14))
        check("an op naming no view is refused", False)
    except RuntimeError:
        check("an op naming no view is refused", True)
    check(
        "nothing was written by the refused op",
        _both(f"x.{_ZONE}") == ("NXDOMAIN",) * 2,
        str(_both(f"x.{_ZONE}")),
    )
    _stop(driver)


def main() -> int:
    for tool in ("named", "rndc", "rndc-confgen"):
        if not shutil.which(tool):
            print(
                f"FAIL: `{tool}` not on PATH — this must run inside the bind9 agent image"
            )
            return 1
    state = Path(tempfile.mkdtemp(prefix="per-view-ops-check-"))
    _rndc_keys(state)
    try:
        case(state)
    finally:
        shutil.rmtree(state, ignore_errors=True)
    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll per-view op expectations met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
