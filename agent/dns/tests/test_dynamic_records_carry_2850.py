"""RFC 2136 records outlive an agent start and a re-render (#2850).

A third party (an AD DC, a DHCP server) adds records to a dynamic zone over
RFC 2136; named holds them in its journal and, once it dumps the zone, in its
file. Every render wrote the zone's file afresh from the bundle and the swap
set named's file and journal aside, so a record the bundle did not carry was
lost at every container start (the boot-from-cache apply) and every
structural re-render. Now each dynamic zone named may hold more of is read
back (``named-compilezone -j``) before the swap and what the control plane
does not account for is carried into the staged file.

These drive the driver with a scripted ``subprocess.run``; the live half,
against a real named, is ``live_dynamic_restart_check.py`` (run by CI in the
built image).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.base import HeldZone
from spatium_dns_agent.drivers.bind9 import (
    Bind9Driver,
    _carried_records,
    _may_hold_unrendered,
    _NamedZoneState,
    _read_owned,
    _soa_serial,
)

ZONE = "dyn.test"
ORIGIN = "dyn.test."


def _bundle(
    records: list[tuple[str, str, str]], dynamic: bool = True
) -> dict[str, Any]:
    return {
        "options": {"forwarders": [], "recursion_enabled": False},
        "tsig_keys": [
            {"name": "grp", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"}
        ],
        "zones": [
            {
                "name": ZONE + ".",
                "type": "primary",
                "ttl": 3600,
                "serial": 5,
                "dynamic_update_enabled": dynamic,
                "update_acl": [],
                "records": [
                    {"name": n, "type": t, "value": v, "ttl": 300}
                    for n, t, v in records
                ],
            }
        ],
    }


# What named holds: the last render (www, gone, the placeholder NS and its
# glue) plus a DC's A record and SRV, at serial 9. Laid out as
# ``named-compilezone -s full`` prints it.
NAMED_STATE = (
    "dyn.test.\t3600 IN SOA\tns1.dyn.test. admin.dyn.test. 9 86400 7200 3600000 3600\n"
    "dyn.test.\t3600 IN NS\tns1.dyn.test.\n"
    "_ldap._tcp.dyn.test.\t600 IN SRV\t0 100 389 dc01.dyn.test.\n"
    "dc01.dyn.test.\t600 IN A\t10.9.9.9\n"
    "gone.dyn.test.\t300 IN A\t192.0.2.2\n"
    "ns1.dyn.test.\t3600 IN A\t127.0.0.1\n"
    "www.dyn.test.\t300 IN A\t192.0.2.1\n"
)
# The same zone as named writes it back on a freeze (serial on its own line).
NAMED_DUMP = (
    "$TTL 3600\t; 1 hour\n"
    "dyn.test.\t\tIN SOA\tns1.dyn.test. admin.dyn.test. (\n"
    "\t\t\t\t9          ; serial\n"
    "\t\t\t\t86400 7200 3600000 3600 )\n"
    "\t\t\tNS\tns1.dyn.test.\n"
    "dc01\t\t\t600\tA\t10.9.9.9\n"
)


class Named:
    """A scripted ``subprocess.run``: named-compilezone prints ``state``,
    named-checkzone accepts (unless told not to), rndc answers like a named
    that serves serial 9 until a reload makes it serve the staged file."""

    def __init__(self, state: str = NAMED_STATE, checkzone_ok: bool = True):
        self.state = state
        self.checkzone_ok = checkzone_ok
        self.calls: list[list[str]] = []
        self.reloaded = False
        self.live: Path | None = None

    def __call__(
        self, cmd: list[str], *a: Any, **kw: Any
    ) -> subprocess.CompletedProcess:
        cmd = list(cmd)
        self.calls.append(cmd)
        tool = Path(cmd[0]).name
        out = ""
        rc = 0
        if tool == "named-compilezone":
            Path(cmd[cmd.index("-o") + 1]).write_text(self.state)
        elif tool == "named-checkzone":
            rc = 0 if self.checkzone_ok else 1
            out = "" if self.checkzone_ok else "dyn.test: CNAME and other data"
        elif tool == "rndc":
            verb = next(
                (c for c in cmd[1:] if not c.startswith("-") and "/" not in c), ""
            )
            if verb == "reload":
                self.reloaded = True
            if verb == "zonestatus":
                serial = _soa_serial(self.live) if self.reloaded and self.live else 9
                out = f"name: {ZONE}\nserial: {serial}\n"
        return subprocess.CompletedProcess(cmd, rc, out, "")

    def tool_calls(self, tool: str) -> list[list[str]]:
        return [c for c in self.calls if Path(c[0]).name == tool]


@pytest.fixture
def driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    monkeypatch.setattr(bind9, "_ZONE_LOAD_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9.time, "sleep", lambda _s: None)
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")
    return Bind9Driver(state_dir=tmp_path)


def _previous_tree(drv: Bind9Driver, records: list[tuple[str, str, str]]) -> Path:
    """What the last apply left live: its render, promoted."""
    drv.render(_bundle(records))
    live = drv.state_dir / "rendered"
    (drv.state_dir / "rendered.new").rename(live)
    return live / "zones" / f"{ZONE}.db"


def _boot(drv: Bind9Driver, monkeypatch: pytest.MonkeyPatch) -> None:
    """No named running: the swap starts one (stubbed)."""
    monkeypatch.setattr(drv, "daemon_running", lambda: False)
    monkeypatch.setattr(drv, "start_daemon", lambda: None)
    monkeypatch.setattr(drv, "_await_named_started", lambda: False)


# ── the boot-from-cache apply (the reported failure) ─────────────────────────


def test_a_start_keeps_the_records_named_held(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue's sequence: named took dc01 + an SRV, the container stopped,
    and the start applies a cached bundle that lacks them. The zone named
    starts on must carry them; the record the control plane deleted (gone)
    must not come back; and the serial must move past the one named served."""
    live_file = _previous_tree(
        driver, [("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")]
    )
    live_file.with_name(live_file.name + ".jnl").write_bytes(b"journal")
    named = Named()
    monkeypatch.setattr(bind9.subprocess, "run", named)
    _boot(driver, monkeypatch)

    driver.render(_bundle([("www", "A", "192.0.2.1")]))
    driver.swap_and_reload()

    served = live_file.read_text()
    assert "dc01.dyn.test. 600 IN A 10.9.9.9" in served
    assert "_ldap._tcp.dyn.test. 600 IN SRV 0 100 389 dc01.dyn.test." in served
    assert "gone" not in served
    assert "www 300 IN A 192.0.2.1" in served
    assert _soa_serial(live_file) == 10
    # read back with the journal applied
    assert any("-j" in c for c in named.tool_calls("named-compilezone"))


def test_a_start_after_an_upgrade_without_a_sidecar_still_carries(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tree an older agent wrote has no ``.owned`` sidecar: the start that
    upgrades into this fix is itself the restart the issue is about."""
    live_file = _previous_tree(
        driver, [("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")]
    )
    live_file.with_name(live_file.name + ".owned").unlink(missing_ok=True)
    live_file.write_text(NAMED_DUMP)
    monkeypatch.setattr(bind9.subprocess, "run", Named())
    _boot(driver, monkeypatch)

    driver.render(_bundle([("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")]))
    driver.swap_and_reload()

    assert "dc01.dyn.test. 600 IN A 10.9.9.9" in live_file.read_text()


def test_a_live_file_that_is_still_a_render_is_not_read_back(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No journal and our own render: named holds nothing else, so nothing
    is read back (a views group re-renders on every record change)."""
    _previous_tree(driver, [("www", "A", "192.0.2.1")])
    named = Named()
    monkeypatch.setattr(bind9.subprocess, "run", named)
    _boot(driver, monkeypatch)

    driver.render(_bundle([("www", "A", "192.0.2.2")]))
    driver.swap_and_reload()

    assert named.tool_calls("named-compilezone") == []


def test_a_static_zone_is_never_read_back(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver.render(_bundle([("www", "A", "192.0.2.1")], dynamic=False))
    live = driver.state_dir / "rendered"
    (driver.state_dir / "rendered.new").rename(live)
    (live / "zones" / f"{ZONE}.db").write_text(NAMED_DUMP)
    named = Named()
    monkeypatch.setattr(bind9.subprocess, "run", named)
    _boot(driver, monkeypatch)

    driver.render(_bundle([("www", "A", "192.0.2.1")], dynamic=False))
    driver.swap_and_reload()

    assert named.tool_calls("named-compilezone") == []
    assert not (live / "zones" / f"{ZONE}.db.owned").exists()


def test_a_merge_named_refuses_holds_the_zone_back_on_named_copy(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A conflict the filters miss costs the zone this render, not its
    records: named keeps serving its own copy, reported as held back."""
    live_file = _previous_tree(driver, [("www", "A", "192.0.2.1")])
    live_file.write_text(NAMED_DUMP)
    monkeypatch.setattr(bind9.subprocess, "run", Named(checkzone_ok=False))
    _boot(driver, monkeypatch)

    driver.render(_bundle([("www", "A", "192.0.2.9")]))
    driver.swap_and_reload()

    assert live_file.read_text() == NAMED_STATE
    assert driver.held_back == (
        HeldZone(ZONE, None, "dyn.test: CNAME and other data", True),
    )


# ── a structural re-render on a running named ─────────────────────────────────


def test_a_running_re_render_freezes_and_carries_an_unchanged_zone(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The render of this zone did not change, but named took an update since
    (a journal): the swap would set the journal aside and the next start
    would lose the record. The zone is frozen, read back and reloaded with
    the record carried."""
    records = [("www", "A", "192.0.2.1"), ("gone", "A", "192.0.2.2")]
    live_file = _previous_tree(driver, records)
    live_file.with_name(live_file.name + ".jnl").write_bytes(b"journal")
    named = Named()
    named.live = live_file
    monkeypatch.setattr(bind9.subprocess, "run", named)
    monkeypatch.setattr(driver, "daemon_running", lambda: True)
    monkeypatch.setattr(driver, "_sync_logging_runtime", lambda base: None)

    driver.render(_bundle(records))
    driver.swap_and_reload()

    rndc = [c for c in named.tool_calls("rndc")]
    assert any("freeze" in c and ZONE in c for c in rndc)
    assert any("thaw" in c and ZONE in c for c in rndc)
    served = live_file.read_text()
    assert "dc01.dyn.test. 600 IN A 10.9.9.9" in served
    assert "gone 300 IN A 192.0.2.2" in served  # still managed: the render's own
    assert served.count("192.0.2.2") == 1
    assert _soa_serial(live_file) == 10


# ── the rules ─────────────────────────────────────────────────────────────────


def _state(lines: list[str]) -> _NamedZoneState:
    records = []
    for line in lines:
        owner, _ttl, _cls, rtype, _rd = line.split(None, 4)
        records.append((f"{owner.lower()} {rtype}", line))
    return _NamedZoneState("\n".join(lines), records, 9)


def test_what_is_carried_and_what_is_not() -> None:
    state = _state(
        [
            "dyn.test. 3600 IN SOA ns1.dyn.test. a.dyn.test. 9 1 1 1 1",
            "dyn.test. 3600 IN NS ns1.dyn.test.",
            "dyn.test. 3600 IN DNSKEY 257 3 13 AAAA",
            "DC01.dyn.test. 600 IN A 10.9.9.9",
            "gone.dyn.test. 300 IN A 192.0.2.2",
            "www.dyn.test. 300 IN A 192.0.2.99",
            "alias.dyn.test. 300 IN CNAME www.dyn.test.",
            "host.dyn.test. 300 IN A 192.0.2.7",
            "sub.dyn.test. 300 IN NS ns.elsewhere.",
        ]
    )
    staged = {
        "dyn.test. SOA",
        "dyn.test. NS",
        "www.dyn.test. A",
        "alias.dyn.test. TXT",
        "host.dyn.test. CNAME",
    }
    owned = {"dyn.test. SOA", "www.dyn.test. A", "gone.dyn.test. A"}
    lines, conflicts = _carried_records(state, ORIGIN, staged, owned)
    assert lines == [
        "DC01.dyn.test. 600 IN A 10.9.9.9",  # a third party's: carried
        "sub.dyn.test. 300 IN NS ns.elsewhere.",  # a delegation below the apex
    ]
    # gone: the control plane shipped it and stopped (deleted); www: the
    # render's value wins; SOA / apex NS / DNSKEY: the daemon's own.
    assert conflicts == ["alias.dyn.test. CNAME", "host.dyn.test. A"]


def test_without_a_sidecar_everything_the_render_lacks_is_carried() -> None:
    state = _state(["gone.dyn.test. 300 IN A 192.0.2.2"])
    lines, _ = _carried_records(state, ORIGIN, set(), None)
    assert lines == ["gone.dyn.test. 300 IN A 192.0.2.2"]


def test_the_render_writes_what_the_control_plane_owns(driver: Bind9Driver) -> None:
    driver.render(
        _bundle(
            [
                ("www", "A", "192.0.2.1"),
                ("@", "MX", "10 mail"),
                ("x.dyn.test.", "TXT", "t"),
            ]
        )
    )
    owned = _read_owned(
        driver.state_dir / "rendered.new" / "zones" / f"{ZONE}.db.owned"
    )
    assert owned == {
        "dyn.test. SOA",
        "dyn.test. NS",
        "ns1.dyn.test. A",  # the placeholder glue the render writes
        "www.dyn.test. A",
        "dyn.test. MX",
        "x.dyn.test. TXT",
    }


def test_record_ops_update_the_live_sidecar(driver: Bind9Driver) -> None:
    sidecar = _previous_tree(driver, [("www", "A", "192.0.2.1")]).with_name(
        f"{ZONE}.db.owned"
    )

    def op(kind: str, name: str, members: list | None, **rec: Any) -> dict[str, Any]:
        record = {"name": name, "type": "A", "value": "192.0.2.3", **rec}
        if members is not None:
            record["rrset"] = {"members": members}
        return {"op": kind, "zone_name": ZONE, "record": record}

    driver.note_record_op_applied(op("create", "opadd", [{"value": "192.0.2.3"}]))
    assert "opadd.dyn.test. A" in (_read_owned(sidecar) or set())
    # a per-value delete may leave other values: still owned
    driver.note_record_op_applied(
        op("delete", "opadd", None, rrset_action="delete_value")
    )
    assert "opadd.dyn.test. A" in (_read_owned(sidecar) or set())
    # the RRset's last value went: no longer the control plane's
    driver.note_record_op_applied(op("delete", "www", []))
    assert "www.dyn.test. A" not in (_read_owned(sidecar) or set())
    # never raises on a malformed op
    driver.note_record_op_applied({"op": "create", "zone_name": ZONE, "record": None})
    driver.note_record_op_applied({"op": "dnssec_rollover", "zone_name": ZONE})


def test_a_zone_without_a_sidecar_takes_no_op_note(driver: Bind9Driver) -> None:
    driver.note_record_op_applied(
        {
            "op": "create",
            "zone_name": "other.test",
            "record": {"name": "a", "type": "A"},
        }
    )
    assert not list(driver.state_dir.rglob("*.owned"))


def test_which_live_files_may_hold_more_than_a_render(tmp_path: Path) -> None:
    render = tmp_path / "r.db"
    render.write_text("$TTL 3600\n@ IN SOA ns1 admin ( 5 1 1 1 1 )\n")
    assert not _may_hold_unrendered(render)
    assert not _may_hold_unrendered(tmp_path / "missing.db")
    dump = tmp_path / "d.db"
    dump.write_text(NAMED_DUMP)
    assert _may_hold_unrendered(dump)
    carried = tmp_path / "c.db"
    carried.write_text(bind9._CARRY_MARKER + "\n" + render.read_text())
    assert _may_hold_unrendered(carried)
    (tmp_path / "r.db.jnl").write_bytes(b"j")
    assert _may_hold_unrendered(render)
