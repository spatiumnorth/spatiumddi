#!/usr/bin/env python3
"""Live check: a zone too long to store or serve holds back alone (#3672).

Runs INSIDE the built bind9 agent image, as ``spatium``, like
``live_views_share_check.py``: it drives the real :class:`Bind9Driver`
through ``apply_config`` against a real ``named``.

A zone name may be 253 characters. The agent stores a zone as
``<zone>.db`` with sidecars beside it, and a file name is capped at 255
bytes, so a long zone has file names the file system refuses. Before #3672
the #1403 hold-back of such a zone raised ``ENAMETOOLONG`` out of the
driver and the agent rejected its whole configuration: one zone stopped
every change on the server until it was deleted.

What this proves, against the named we ship:

* named opens a primary zone's journal (``<file>.jnl``) on every load,
  dynamic or not, and refuses the zone when that name cannot exist; with
  inline-signing, the same for ``<file>.signed.jnl``. So a zone of 249
  characters or more (242 or more, signed) is one named will never load:
  before this, it passed ``named-checkzone`` and failed the reload
  verification, and with it the whole apply. Each is now held back alone,
  as are a 250-character zone served with the placeholder ``ns1.<zone>``
  and ``admin.<zone>`` (the case met live), a 253-character zone whose
  ``.db`` cannot be named at all, and a 250-character dynamic zone whose
  ownership sidecar cannot be named. A record change in another zone still
  goes live, and named is not restarted;
* a signed zone of 215 characters or more never gets its keys (#3750:
  BIND writes each key file through a longer temporary name), so it is
  held back too, rather than served unsigned;
* a held zone's stanza stays in ``named.conf`` with no file behind it:
  named starts and reloads with it, and answers SERVFAIL for the zone
  rather than handing its names to recursion;
* the longest zones named can load (248, and 214 inline-signed) are
  served, and a refused edit of one keeps its live copy;
* removing the long zones clears the hold: the next apply holds nothing.

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

_FAILURES: list[str] = []
_GOOD = "good.example."


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _long(n: int, tail: str) -> str:
    """A valid DNS name of exactly ``n`` characters (labels <= 63), no dot."""
    labels: list[str] = []
    room = n - len(tail)
    while room > 0:
        size = min(60, room - 1)
        labels.append(chr(ord("a") + len(labels)) * size)
        room -= size + 1
    name = ".".join([*labels, tail])
    assert len(name) == n, len(name)
    return name


_L250 = _long(250, "held.example")
_L249 = _long(249, "jnl.example")
_L253 = _long(253, "nofile.example")
_L250_DYN = _long(250, "dyn.example")
_L248 = _long(248, "fine.example")
_L214_SIG = _long(214, "sig.example")
_L215_SIG = _long(215, "sig.example")
_L241_SIG = _long(241, "sig.example")
_L242_SIG = _long(242, "sig.example")


def _zone(name: str, records: list[tuple[str, str, str]], **extra) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": extra.pop("serial", 1),
        "dynamic_update_enabled": False,
        "update_acl": [],
        "allow_transfer": None,
        "records": [
            {"name": n, "type": t, "value": v, "ttl": 300} for n, t, v in records
        ],
        **extra,
    }


def _bundle(zones: list[dict]) -> dict:
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
            }
        ],
        "zones": zones,
        "blocklists": [],
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


def _q(qname: str, rdtype: str = "A") -> str:
    import dns.message
    import dns.query
    import dns.rcode

    try:
        r = dns.query.udp(dns.message.make_query(qname, rdtype), "127.0.0.1", timeout=3)
    except Exception as exc:  # noqa: BLE001 — every failure is a result here
        return f"error {type(exc).__name__}"
    if r.rcode() != dns.rcode.NOERROR:
        return dns.rcode.to_text(r.rcode())
    return ",".join(sorted(rd.to_text() for rr in r.answer for rd in rr)) or "NODATA"


def _apply(driver, bundle: dict) -> str | None:
    try:
        driver.apply_config(bundle)
    except Exception as exc:  # noqa: BLE001 — the failure is the result
        return f"{type(exc).__name__}: {exc}"
    return None


def _held(driver) -> dict[str, bool]:
    return {h.zone.rstrip("."): h.served for h in driver.held_back}


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


def _apex(name: str, serial: int = 1, **extra) -> dict:
    """A zone with real apex names (a Primary NS and Admin Email set)."""
    return _zone(
        name,
        [("@", "NS", "ns.good.example.")],
        serial=serial,
        primary_ns="ns.good.example.",
        admin_email="hostmaster.good.example.",
        **extra,
    )


def _signed(name: str) -> dict:
    """An inline-signed zone with real apex names, under the default policy."""
    z = _apex(name + ".", dnssec_enabled=True)
    z["dnssec_policy_name"] = "default"
    return z


def run(state: Path) -> None:
    from spatium_dns_agent.drivers.bind9 import Bind9Driver

    driver = Bind9Driver(state_dir=state)
    ns = [("@", "NS", "ns.good.example."), ("ns", "A", "192.0.2.53")]

    def good(serial: int, www: str) -> dict:
        return _zone(_GOOD, [*ns, ("www", "A", www)], serial=serial)

    # The longest zones named can load: 248 (``.db.jnl`` is 255) and,
    # inline-signed, 214 (its key files' names, #3750).
    served = [_apex(_L248 + "."), _signed(_L214_SIG)]

    print("\n=== a good zone, and the longest zones named can load ===")
    err = _apply(driver, _bundle([good(1, "192.0.2.10"), *served]))
    check("apply succeeds", err is None, err or "")
    check("named started", driver.daemon_running(), f"pid {driver.daemon_pid}")
    check("nothing held", not driver.held_back, str(_held(driver)))
    check("good zone answers", _q(f"www.{_GOOD}") == "192.0.2.10", _q(f"www.{_GOOD}"))
    for zname in (_L248, _L214_SIG):
        got = _q(zname + ".", "NS")
        check(
            f"the {len(zname)}-character zone is served", got == "ns.good.example.", got
        )
    pid = driver.daemon_pid

    print("\n=== add the long zones the issue and its siblings name ===")
    zones = [
        good(2, "192.0.2.11"),
        *served,
        # #3672 as met live: ns1.<zone> / admin.<zone> pass 253.
        _zone(_L250 + ".", [("@", "A", "192.0.2.250")]),
        # Real apex names, but named cannot name ``.db.jnl`` (256).
        _apex(_L249 + "."),
        # ``.db`` is 256 bytes: no file at all.
        _apex(_L253 + "."),
        # ``.db`` fits, ``.db.owned`` does not.
        _apex(_L250_DYN + ".", dynamic_update_enabled=True),
        # Inline-signed: ``.db.signed.jnl`` is 256.
        _signed(_L242_SIG),
        # Inline-signed: BIND cannot write the key files (#3750).
        _signed(_L215_SIG),
        _signed(_L241_SIG),
    ]
    long_held = (_L250, _L249, _L253, _L250_DYN, _L242_SIG, _L215_SIG, _L241_SIG)
    err = _apply(driver, _bundle(zones))
    check("apply does not raise", err is None, err or "")
    held = _held(driver)
    check(
        "exactly the long zones are held, none served",
        held == {z: False for z in long_held},
        str({k[-20:]: v for k, v in held.items()}),
    )
    check(
        "each is held with the worded reason",
        all("Shorten the zone name" in h.reason for h in driver.held_back),
        str([h.reason[:60] for h in driver.held_back]),
    )
    check("named still running", driver.daemon_running())
    check("named was not restarted", driver.daemon_pid == pid, f"{driver.daemon_pid}")
    check(
        "the good zone's change went live",
        _q(f"www.{_GOOD}") == "192.0.2.11",
        _q(f"www.{_GOOD}"),
    )
    conf = (state / "rendered" / "named.conf").read_text()
    check(
        "every held zone keeps its stanza",
        all(f'zone "{z}."' in conf for z in long_held),
    )
    for zname in long_held:
        got = _q(zname + ".", "SOA")
        check(
            f"held zone of {len(zname)} answers SERVFAIL, not recursion",
            got == "SERVFAIL",
            got,
        )
    for zname in (_L248, _L214_SIG):
        got = _q(zname + ".", "NS")
        check(
            f"the {len(zname)}-character zone is still served",
            got == "ns.good.example.",
            got,
        )

    print("\n=== a refused edit of a served long zone keeps its live copy ===")
    broken = _apex(_L248 + ".", serial=2)
    # An in-zone NS with no address: named-checkzone refuses it.
    broken["records"] = [{"name": "@", "type": "NS", "value": "ns", "ttl": 300}]
    zones[1] = broken
    zones[0] = good(3, "192.0.2.12")
    err = _apply(driver, _bundle(zones))
    check("apply does not raise", err is None, err or "")
    check(
        "the served long zone is held and still served",
        _held(driver).get(_L248) is True,
        str({k[-20:]: v for k, v in _held(driver).items()}),
    )
    got = _q(_L248 + ".", "NS")
    check("it keeps answering its live copy", got == "ns.good.example.", got)
    check("the good zone's change went live", _q(f"www.{_GOOD}") == "192.0.2.12")

    print("\n=== a restart from the held config: named still starts ===")
    _stop(driver)
    err = _apply(driver, _bundle(zones))
    check("apply from a stopped named succeeds", err is None, err or "")
    check("named started", driver.daemon_running(), f"pid {driver.daemon_pid}")
    check("the good zone answers", _q(f"www.{_GOOD}") == "192.0.2.12")

    print("\n=== the long zones are deleted: nothing stays held ===")
    err = _apply(driver, _bundle([good(4, "192.0.2.13"), *served]))
    check("apply succeeds", err is None, err or "")
    check("nothing held", not driver.held_back, str(_held(driver)))
    check("the good zone's change went live", _q(f"www.{_GOOD}") == "192.0.2.13")
    _stop(driver)


def main() -> int:
    for tool in ("named", "rndc", "rndc-confgen", "named-checkzone"):
        if not shutil.which(tool):
            print(
                f"FAIL: `{tool}` not on PATH — this must run inside the bind9 agent image"
            )
            return 1
    state = Path(tempfile.mkdtemp(prefix="long-zone-check-"))
    if os.pathconf(state, "PC_NAME_MAX") != 255:
        print("FAIL: this check is sized for a 255-byte NAME_MAX")
        return 1
    _rndc_keys(state)
    try:
        run(state)
    finally:
        shutil.rmtree(state, ignore_errors=True)
    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll long-zone expectations met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
