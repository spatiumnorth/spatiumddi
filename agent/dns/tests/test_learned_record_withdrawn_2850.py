"""A record a third party removed stays removed across an agent start (#2850).

The ingest-back loop (#641) mirrors a record a third party wrote by RFC 2136
into the control plane as a ``ddns_external`` row, and the bundle then carries
it like any other record. When the third party deletes it again, named drops
it at once, but the mirror row survives until the next ingest sweep reports
the zone without it. A dns agent that starts inside that window rendered the
zone from its cached bundle, mirror row included, and the carry let the
render win: the deleted record was served again, the next sweep read it back
off named, and the mirror row was never swept. A deletion lost for good.

The bundle now marks each mirror row ``learned``. For a learned RRset, named's
copy wins: one the render has, that named no longer holds and that named is
known to have held (this agent's last ingest sweep read it, or the agent
shipped it here), is withdrawn from the staged file. Managed records keep
"the render wins", and a learned record named never held (one a peer server
learned, on its way here) is still rendered.

Driven through ``Named``, the scripted ``subprocess.run`` of
``test_dynamic_records_carry_2850``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent import ingest
from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _read_owned, _soa_serial

from .test_dynamic_records_carry_2850 import ORIGIN, ZONE, Named

# What named holds after the third party deleted dc01 (and before it, the
# render's www): no dc01 anywhere.
NAMED_AFTER_DELETE = (
    "dyn.test.\t3600 IN SOA\tns1.dyn.test. admin.dyn.test. 9 86400 7200 3600000 3600\n"
    "dyn.test.\t3600 IN NS\tns1.dyn.test.\n"
    "ns1.dyn.test.\t3600 IN A\t127.0.0.1\n"
    "www.dyn.test.\t300 IN A\t192.0.2.1\n"
)
DC01 = f"dc01.{ORIGIN} A"


def _bundle(records: list[tuple[str, str, str, bool]]) -> dict[str, Any]:
    recs = []
    for name, rtype, value, learned in records:
        rec: dict[str, Any] = {"name": name, "type": rtype, "value": value, "ttl": 300}
        if learned:
            rec["learned"] = True
        recs.append(rec)
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
                "dynamic_update_enabled": True,
                "update_acl": [],
                "records": recs,
            }
        ],
    }


WWW = ("www", "A", "192.0.2.1", False)
DC01_LEARNED = ("dc01", "A", "10.9.9.9", True)
DC01_MANAGED = ("dc01", "A", "10.9.9.9", False)


@pytest.fixture
def driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    monkeypatch.setattr(bind9, "_ZONE_LOAD_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9.time, "sleep", lambda _s: None)
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")
    return Bind9Driver(state_dir=tmp_path)


def _previous_tree(drv: Bind9Driver, records: list[tuple[str, str, str, bool]]) -> Path:
    """The last apply's render, promoted, with a journal beside it: named took
    updates since (the third party's add, then its delete)."""
    drv.render(_bundle(records))
    live = drv.state_dir / "rendered"
    (drv.state_dir / "rendered.new").rename(live)
    zone_file = live / "zones" / f"{ZONE}.db"
    zone_file.with_name(zone_file.name + ".jnl").write_bytes(b"journal")
    return zone_file


def _boot(drv: Bind9Driver, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drv, "daemon_running", lambda: False)
    monkeypatch.setattr(drv, "start_daemon", lambda: None)
    monkeypatch.setattr(drv, "_await_named_started", lambda: False)


def _ingest_saw(drv: Bind9Driver, records: list[dict[str, Any]]) -> None:
    ingest.write_seen_keys(drv.state_dir, ZONE, records)


def _named() -> Named:
    # The staged file reads back as named's copy: nothing else differs.
    return Named(state=NAMED_AFTER_DELETE, staged_state=NAMED_AFTER_DELETE)


# ── the walk's case 5 ─────────────────────────────────────────────────────────


def test_a_start_does_not_bring_back_a_mirrored_record_the_third_party_deleted(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """nsupdate added dc01, the ingest read it and the control plane mirrored
    it, nsupdate deleted it, and the pod restarted before the next sweep. The
    cached bundle still carries the mirror row; named does not. It must stay
    deleted, or the next sweep reads it back and the mirror is never swept."""
    live_file = _previous_tree(driver, [WWW])  # rendered before the mirror
    _ingest_saw(
        driver,
        [
            {"name": "www", "record_type": "A", "value": "192.0.2.1"},
            {"name": "dc01", "record_type": "A", "value": "10.9.9.9"},
        ],
    )
    monkeypatch.setattr(bind9.subprocess, "run", _named())
    _boot(driver, monkeypatch)

    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()

    served = live_file.read_text()
    assert "dc01" not in served
    assert "www 300 IN A 192.0.2.1" in served
    # Not the control plane's any more: a third party's re-add is carried.
    assert DC01 not in (_read_owned(live_file.with_name(f"{ZONE}.db.owned")) or set())
    # Served at named's serial: the zone is exactly what named served.
    assert _soa_serial(live_file) == 9


def test_the_next_start_inside_the_window_keeps_it_deleted(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second restart before the mirror is swept: the file the first start
    wrote is not a bare render of the bundle, so it is read back again."""
    live_file = _previous_tree(driver, [WWW])
    _ingest_saw(driver, [{"name": "dc01", "record_type": "A", "value": "10.9.9.9"}])
    monkeypatch.setattr(bind9.subprocess, "run", _named())
    _boot(driver, monkeypatch)
    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()
    live_file.with_name(live_file.name + ".jnl").unlink(missing_ok=True)

    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()

    assert "dc01" not in live_file.read_text()


def test_a_mirrored_record_the_agent_rendered_here_is_withdrawn_too(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mirror was rendered here before the delete (``.owned`` says so),
    and no ingest sweep has been recorded: the agent's own shipping is the
    evidence named held it."""
    live_file = _previous_tree(driver, [WWW, DC01_LEARNED])
    monkeypatch.setattr(bind9.subprocess, "run", _named())
    _boot(driver, monkeypatch)

    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()

    assert "dc01" not in live_file.read_text()


def test_a_running_re_render_withdraws_it_as_well(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A structural re-render on a running named: frozen, read back, and the
    deleted mirror is not reloaded into it."""
    live_file = _previous_tree(driver, [WWW])
    _ingest_saw(driver, [{"name": "dc01", "record_type": "A", "value": "10.9.9.9"}])
    named = _named()
    named.live = live_file
    monkeypatch.setattr(bind9.subprocess, "run", named)
    monkeypatch.setattr(driver, "daemon_running", lambda: True)
    monkeypatch.setattr(driver, "_sync_logging_runtime", lambda base: None)

    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()

    assert any("freeze" in c for c in named.tool_calls("rndc"))
    assert "dc01" not in live_file.read_text()


# ── what keeps "the render wins" ──────────────────────────────────────────────


def test_a_managed_record_named_lost_is_still_rendered(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A third party deleting a MANAGED record does not delete it: the
    control plane's copy wins, as it always has."""
    live_file = _previous_tree(driver, [WWW, DC01_MANAGED])
    _ingest_saw(driver, [{"name": "dc01", "record_type": "A", "value": "10.9.9.9"}])
    monkeypatch.setattr(bind9.subprocess, "run", _named())
    _boot(driver, monkeypatch)

    driver.render(_bundle([WWW, DC01_MANAGED]))
    driver.swap_and_reload()

    assert "dc01 300 IN A 10.9.9.9" in live_file.read_text()


def test_a_learned_record_named_never_held_is_still_rendered(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A record a PEER server learned, on its way here (its op retired by a
    forced re-render): named never held it, so its absence is not a delete
    and the render delivers it."""
    live_file = _previous_tree(driver, [WWW])
    _ingest_saw(driver, [{"name": "www", "record_type": "A", "value": "192.0.2.1"}])
    monkeypatch.setattr(bind9.subprocess, "run", _named())
    _boot(driver, monkeypatch)

    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()

    assert "dc01 300 IN A 10.9.9.9" in live_file.read_text()


def test_a_learned_record_named_still_holds_is_rendered(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cases 1 and 7 of the walk: the mirror and named agree."""
    live_file = _previous_tree(driver, [WWW])
    _ingest_saw(driver, [{"name": "dc01", "record_type": "A", "value": "10.9.9.9"}])
    state = NAMED_AFTER_DELETE + "dc01.dyn.test.\t300 IN A\t10.9.9.9\n"
    monkeypatch.setattr(bind9.subprocess, "run", Named(state=state, staged_state=state))
    _boot(driver, monkeypatch)

    driver.render(_bundle([WWW, DC01_LEARNED]))
    driver.swap_and_reload()

    assert "dc01 300 IN A 10.9.9.9" in live_file.read_text()


# ── the evidence ──────────────────────────────────────────────────────────────


def test_the_ingest_records_what_it_read(tmp_path: Path) -> None:
    ingest.write_seen_keys(
        tmp_path,
        "Dyn.Test.",
        [
            {"name": "@", "record_type": "MX", "value": "10 mx"},
            {"name": "DC01", "record_type": "a", "value": "10.9.9.9"},
            {"name": "_ldap._tcp", "record_type": "SRV", "value": "dc01"},
        ],
    )
    assert ingest.read_seen_keys(tmp_path, "dyn.test") == {
        "dyn.test. MX",
        "dc01.dyn.test. A",
        "_ldap._tcp.dyn.test. SRV",
    }
    assert ingest.read_seen_keys(tmp_path, "other.test") is None


def test_an_ingest_sweep_writes_what_it_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = ingest.IngestWorker.__new__(ingest.IngestWorker)
    worker.cfg = type("Cfg", (), {"state_dir": tmp_path})()
    monkeypatch.setattr(worker, "_sweep_inputs", lambda: (None, [ZONE]))
    monkeypatch.setattr(
        worker,
        "_read_live_zone",
        lambda z, k: [{"name": "dc01", "record_type": "A", "value": "10.9.9.9"}],
    )
    shipped: list[str] = []
    monkeypatch.setattr(worker, "_ship", lambda z, r: shipped.append(z))
    worker._sweep()
    assert ingest.read_seen_keys(tmp_path, ZONE) == {DC01}
    assert shipped == [ZONE]
