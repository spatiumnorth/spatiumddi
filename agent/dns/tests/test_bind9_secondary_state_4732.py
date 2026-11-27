"""#4732 — a BIND9 agent reports each secondary zone's refresh / expiry state.

``rndc zonestatus`` carries ``next refresh:`` and ``expires:`` for a zone named
receives by transfer; a zone that never transferred has no ``expires:`` line,
which must come out as ``None`` and not as a guessed time.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _zonestatus_time

TRANSFERRED = """name: example.org
type: secondary
files: example.org.db
serial: 2024010105
nodes: 4
last loaded: Mon, 01 Jan 2024 10:00:00 GMT
next refresh: Mon, 01 Jan 2024 11:00:00 GMT
expires: Mon, 08 Jan 2024 10:00:00 GMT
secure: no
"""

NEVER = """name: example.net
type: secondary
next refresh: Mon, 01 Jan 2024 11:00:00 GMT
secure: no
"""


def test_zonestatus_times_are_utc_iso_and_missing_is_none() -> None:
    assert _zonestatus_time(TRANSFERRED, "expires") == "2024-01-08T10:00:00+00:00"
    assert _zonestatus_time(TRANSFERRED, "next refresh") == "2024-01-01T11:00:00+00:00"
    assert _zonestatus_time(NEVER, "expires") is None
    assert _zonestatus_time("expires: not a date\n", "expires") is None


def _driver(monkeypatch: pytest.MonkeyPatch, outputs: dict[str, tuple[int, str]]) -> Bind9Driver:
    d = Bind9Driver.__new__(Bind9Driver)
    d._rendered_secondaries = sorted(outputs)  # type: ignore[attr-defined]
    monkeypatch.setattr(bind9.shutil, "which", lambda _n: "/usr/sbin/rndc")
    monkeypatch.setattr(Bind9Driver, "_zone_rndc_scopes", lambda self, z: [[z]])
    monkeypatch.setattr(Bind9Driver, "_rndc_base", lambda self: ["rndc"])

    def fake_run(_base: list[str], *args: str) -> tuple[int, str, str]:
        rc, out = outputs[args[1].rstrip(".")]
        return rc, out, ""

    monkeypatch.setattr(bind9, "_rndc_run", fake_run)
    soa = SimpleNamespace(refresh=3600, retry=600, expire=604800)

    def fake_soa(self: Any, zone: str) -> tuple[Any, int, int | None, bool]:
        return (soa if zone.startswith("example.org") else None), 300, None, False

    monkeypatch.setattr(Bind9Driver, "_served_soa", fake_soa)
    return d


def test_periodic_secondary_state_reports_what_named_says(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    d = _driver(
        monkeypatch,
        {"example.org": (0, TRANSFERRED), "example.net": (0, NEVER), "gone.test": (1, "")},
    )
    got = {e["zone_name"]: e for e in d.periodic_secondary_state()}
    # A zone rndc cannot answer for is left out, not reported as healthy.
    assert set(got) == {"example.org", "example.net"}
    org = got["example.org"]
    assert org["serial"] == 2024010105
    assert org["expires_at"] == "2024-01-08T10:00:00+00:00"
    assert (org["soa_refresh"], org["soa_retry"], org["soa_expire"]) == (3600, 600, 604800)
    net = got["example.net"]
    assert net["serial"] is None and net["expires_at"] is None
    assert net["soa_refresh"] is None


# ── what a real BIND 9.20.30 secondary printed (captured live, #4732) ─────────

_FIXTURES = Path(__file__).parent / "fixtures"


def _fx(name: str) -> str:
    return (_FIXTURES / f"zonestatus_secondary_{name}_4732.txt").read_text()


def test_real_zonestatus_output_parses_in_every_live_state() -> None:
    # In sync, and primary down before / after the first missed refresh: the
    # same keys; a failed attempt moves ``next refresh`` out, not ``expires``.
    for name, serial, nxt, exp in (
        ("in_sync", 2, "2026-11-27T22:17:32+00:00", "2026-11-27T22:26:41+00:00"),
        ("primary_down", 1, "2026-11-27T22:03:22+00:00", "2026-11-27T22:08:58+00:00"),
        ("after_failed_refresh", 1, "2026-11-27T22:11:28+00:00", "2026-11-27T22:08:58+00:00"),
    ):
        out = _fx(name)
        assert bind9._zonestatus_serial(out) == serial
        assert _zonestatus_time(out, "next refresh") == nxt
        assert _zonestatus_time(out, "expires") == exp
        assert _zonestatus_time(out, "last loaded") is not None


def test_expired_zone_is_reported_not_loaded_instead_of_left_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """named drops an expired secondary copy and then answers ``zone not
    loaded`` (rc 1). Leaving the zone out of the report froze the control
    plane on the snapshot taken before it expired."""
    d = Bind9Driver.__new__(Bind9Driver)
    d._rendered_secondaries = ["expired.test", "absent.test"]  # type: ignore[attr-defined]
    monkeypatch.setattr(bind9.shutil, "which", lambda _n: "/usr/sbin/rndc")
    monkeypatch.setattr(Bind9Driver, "_zone_rndc_scopes", lambda self, z: [[z]])
    monkeypatch.setattr(Bind9Driver, "_rndc_base", lambda self: ["rndc"])

    def fake_run(_base: list[str], *args: str) -> tuple[int, str, str]:
        if args[1] == "expired.test.":
            return 1, "", _fx("expired")
        return 1, "", "rndc: 'zonestatus' failed: not found\nno matching zone 'absent.test'\n"

    monkeypatch.setattr(bind9, "_rndc_run", fake_run)
    monkeypatch.setattr(Bind9Driver, "_served_soa", lambda self, z: (None, 0, None, False))
    assert d.periodic_secondary_state() == [{"zone_name": "expired.test", "loaded": False}]
