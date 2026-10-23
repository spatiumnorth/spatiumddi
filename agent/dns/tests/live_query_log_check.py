#!/usr/bin/env python3
"""Live query/response-logging toggle check against a real ``named`` (#2249).

Runs INSIDE the built bind9 agent image, where ``named``, ``rndc``,
``python3``, dnspython and the agent package all already exist. Unlike
``live_axfr_check.py`` it does not start ``named`` itself: it drives the
real :class:`Bind9Driver` through ``render()`` + ``swap_and_reload()``,
so the first apply starts the daemon and every later one goes through the
same ``rndc reconfig`` path a running agent takes.

What it proves: toggling query (and response) logging on a RUNNING named
takes effect without a restart, in both directions. ``rndc reconfig``
applies neither ``querylog`` nor ``responselog`` — both are runtime
switches it leaves as they were — so before #2249 a group whose named
started with query logging off rendered the ``queries`` category, applied
cleanly, and logged nothing until named restarted. Asserted twice over:
on what ``rndc status`` reports, and on the lines named actually writes to
the file the agent's shipper tails.

Exits non-zero on the first failed expectation. Never skips: a missing
prerequisite is a failure, because "the check quietly didn't run" is the
failure mode these live checks exist to replace.
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

_ZONE = "live.example."
_QUERY_LOG = Path("/var/log/named/queries.log")
_FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{f'  — {detail}' if detail else ''}")
    if not ok:
        _FAILURES.append(label)


def _bundle(query_log: bool, response_log: bool) -> dict:
    return {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "no",
            "allow_transfer": ["none"],
            "query_log_enabled": query_log,
            "response_log_enabled": response_log,
        },
        "tsig_keys": [],
        "zones": [
            {
                "name": _ZONE,
                "type": "primary",
                "ttl": 3600,
                "serial": 1,
                "dynamic_update_enabled": False,
                "update_acl": [],
                "allow_transfer": None,
                "records": [{"name": "www", "type": "A", "value": "192.0.2.1", "ttl": 300}],
            }
        ],
    }


def _rndc_keys(state: Path) -> None:
    """What the image entrypoint does on first boot, into this state dir."""
    subprocess.run(  # noqa: S603 — fixed argv
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
        "options {\n"
        "    default-server 127.0.0.1;\n"
        '    default-key    "spatium-rndc";\n'
        "};\n"
        f'include "{state / "rndc.key"}";\n'
    )


def _status(driver) -> tuple[str, str]:
    out = subprocess.run(  # noqa: S603 — fixed argv
        [*driver._rndc_base(), "status"], capture_output=True, text=True, check=False
    ).stdout
    q = r = "?"
    for line in out.splitlines():
        if line.startswith("query logging is "):
            q = line.removeprefix("query logging is ").strip()
        elif line.startswith("response logging is "):
            r = line.removeprefix("response logging is ").strip()
    return q, r


def _log_lines_for(label: str) -> tuple[int, int]:
    """Send one query for a fresh name and count the lines it produced:
    (query lines, response lines)."""
    import dns.message
    import dns.query

    # named logs the name without its trailing dot.
    qname = f"{label}.{_ZONE}".rstrip(".")
    before = _QUERY_LOG.stat().st_size if _QUERY_LOG.exists() else 0
    dns.query.udp(dns.message.make_query(qname, "A"), "127.0.0.1", timeout=5)
    time.sleep(1.0)  # the channel is not flushed synchronously
    if not _QUERY_LOG.exists():
        return 0, 0
    with _QUERY_LOG.open() as fh:
        fh.seek(before)
        new = [line for line in fh if f" {qname} " in line]
    return (
        sum(": query: " in line for line in new),
        sum(": response: " in line for line in new),
    )


def _apply(driver, bundle: dict) -> None:
    driver.render(bundle)
    driver.swap_and_reload()


def _stop(driver) -> None:
    """Stop the named this case started and wait for it, so the next case
    binds 53 and 953 itself instead of adopting a dying daemon."""
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


def main() -> int:
    for tool in ("named", "rndc", "rndc-confgen"):
        if not shutil.which(tool):
            print(f"FAIL: `{tool}` not on PATH — this must run inside the bind9 agent image")
            return 1
    try:
        from spatium_dns_agent.drivers.bind9 import Bind9Driver  # noqa: PLC0415
    except ImportError as exc:
        print(f"FAIL: agent package not importable ({exc})")
        return 1

    def started_off(driver) -> None:
        print("\n=== named starts with query logging OFF ===")
        _apply(driver, _bundle(query_log=False, response_log=False))
        pid = driver.daemon_pid
        check("named started", driver.daemon_running(), f"pid {pid}")
        q, r = _status(driver)
        check("rndc status: query logging OFF", q == "OFF", q)
        check("no query line is written", _log_lines_for("off1") == (0, 0))

        print("\n=== reconfig to query + response logging ON ===")
        _apply(driver, _bundle(query_log=True, response_log=True))
        check("named was NOT restarted", driver.daemon_pid == pid, f"pid {driver.daemon_pid}")
        q, r = _status(driver)
        check("rndc status: query logging ON", q == "ON", q)
        check("rndc status: response logging ON", r == "ON", r)
        # Before #2249 this was (0, 1): the response line with no query
        # line, which the control plane then drops as an orphan.
        lines = _log_lines_for("on1")
        check("a query line AND its response line are written", lines == (1, 1), str(lines))

        print("\n=== reconfig to query logging ON, response logging OFF ===")
        _apply(driver, _bundle(query_log=True, response_log=False))
        q, r = _status(driver)
        check("rndc status: query logging ON", q == "ON", q)
        check("rndc status: response logging OFF", r == "OFF", r)
        lines = _log_lines_for("on2")
        check("only the query line is written", lines == (1, 0), str(lines))

        print("\n=== reconfig back to logging OFF ===")
        _apply(driver, _bundle(query_log=False, response_log=False))
        check("named was NOT restarted", driver.daemon_pid == pid, f"pid {driver.daemon_pid}")
        q, r = _status(driver)
        check("rndc status: query logging OFF", q == "OFF", q)
        check("rndc status: response logging OFF", r == "OFF", r)
        check("no line is written", _log_lines_for("off2") == (0, 0))

    def started_on(driver) -> None:
        # The other direction: a named that STARTED with query logging on
        # (the config-file value) keeps logging after a reconfig that removes
        # it, unless told otherwise.
        print("\n=== named starts with query + response logging ON ===")
        _apply(driver, _bundle(query_log=True, response_log=True))
        pid = driver.daemon_pid
        check("named started", driver.daemon_running(), f"pid {pid}")
        q, r = _status(driver)
        check("rndc status: query logging ON at startup", q == "ON", q)
        check("rndc status: response logging ON at startup", r == "ON", r)

        print("\n=== reconfig to logging OFF ===")
        _apply(driver, _bundle(query_log=False, response_log=False))
        check("named was NOT restarted", driver.daemon_pid == pid, f"pid {driver.daemon_pid}")
        q, r = _status(driver)
        check("rndc status: query logging OFF", q == "OFF", q)
        check("rndc status: response logging OFF", r == "OFF", r)
        check("no line is written", _log_lines_for("off3") == (0, 0))

    for case in (started_off, started_on):
        state = Path(tempfile.mkdtemp(prefix="querylog-check-"))
        _rndc_keys(state)
        driver = Bind9Driver(state_dir=state)
        try:
            case(driver)
        finally:
            _stop(driver)
            shutil.rmtree(state, ignore_errors=True)

    if _FAILURES:
        print(f"\n{len(_FAILURES)} expectation(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("\nAll query-logging expectations met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
