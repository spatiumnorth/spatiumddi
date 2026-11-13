"""#4147 — rows Kea appends just before its lease-file cleanup are not lost.

Kea's LFC renames the live ``kea-leases{4,6}.csv`` to ``.1``, starts a new
file, and shortly replaces the old one with a compacted ``.2``. The tailer
used to see a smaller file, restart at offset 0 and never read what Kea had
appended to the old file since the agent's last read.
"""

from __future__ import annotations

import os
import types
from pathlib import Path

import pytest

from spatium_dhcp_agent.leases import LeaseWatcher, _parse_row, _parse_row_v6


def _v4(n: int) -> str:
    return f"10.0.0.{n},aa:bb:cc:dd:ee:{n:02x},,3600,2000000000,1,0,0,h{n},0\n"


def _v6(n: int) -> str:
    return (
        f"2001:db8::{n:x},00:03:00:01:aa:bb:cc:dd:ee:{n:02x},3600,2000000000,1,7200,0,{n},128,"
        f"0,0,h{n},,0,,,,0\n"
    )


def _watcher(tmp_path: Path) -> LeaseWatcher:
    w = LeaseWatcher.__new__(LeaseWatcher)
    w._offsets = {}
    w._handles = {}
    return w


def _ips(rows: list[list[str]]) -> list[str]:
    return [r[0] for r in rows]


@pytest.mark.parametrize(
    "gen,fam", [(_v4, "kea-leases4.csv"), (_v6, "kea-leases6.csv")]
)
@pytest.mark.parametrize("delete_old", [False, True])
def test_rows_before_and_after_rotation_each_read_once(
    tmp_path: Path, gen, fam: str, delete_old: bool
) -> None:
    live = tmp_path / fam
    w = _watcher(tmp_path)
    live.write_text(gen(1) + gen(2))
    seen = _ips(w._read_new_rows(live))
    assert len(seen) == 2

    # Kea appends, then LFC rotates: live -> .1, new file, compacted .2.
    with live.open("a") as f:
        f.write(gen(3) + gen(4))
    old = tmp_path / (fam + ".1")
    os.rename(live, old)
    live.write_text(gen(5))
    if delete_old:
        old.unlink()  # LFC already finished; only the compacted .2 remains
    (tmp_path / (fam + ".2")).write_text(gen(1) + gen(2) + gen(3) + gen(4))
    # The new file has already outgrown the old offset: size alone misreads.
    with live.open("a") as f:
        f.write("".join(gen(n) for n in range(6, 12)))

    seen += _ips(w._read_new_rows(live))
    assert _ips(w._read_new_rows(live)) == []
    with live.open("a") as f:
        f.write(gen(12))
    seen += _ips(w._read_new_rows(live))

    expected = [gen(n).split(",")[0] for n in list(range(1, 5)) + list(range(5, 13))]
    assert sorted(seen) == sorted(expected)
    assert len(seen) == len(set(seen)) == 12


def test_rotation_between_unlink_and_recreate(tmp_path: Path) -> None:
    live = tmp_path / "kea-leases4.csv"
    w = _watcher(tmp_path)
    live.write_text(_v4(1))
    assert len(w._read_new_rows(live)) == 1
    with live.open("a") as f:
        f.write(_v4(2))
    live.unlink()
    assert _ips(w._read_new_rows(live)) == ["10.0.0.2"]
    live.write_text(_v4(3))
    assert _ips(w._read_new_rows(live)) == ["10.0.0.3"]


def test_truncation_in_place_restarts_at_zero(tmp_path: Path) -> None:
    live = tmp_path / "kea-leases4.csv"
    w = _watcher(tmp_path)
    live.write_text(_v4(1) + _v4(2))
    assert len(w._read_new_rows(live)) == 2
    live.write_text(_v4(3))
    assert _ips(w._read_new_rows(live)) == ["10.0.0.3"]


def test_tail_posts_every_row_across_rotation(tmp_path: Path) -> None:
    """End to end through _tail: parsed events, v4 and v6."""
    for gen, parse, name in (
        (_v4, _parse_row, "a4.csv"),
        (_v6, _parse_row_v6, "a6.csv"),
    ):
        live = tmp_path / name
        w = _watcher(tmp_path)
        w._pending = []
        w._shipper = types.SimpleNamespace(spool=types.SimpleNamespace(enabled=False))
        live.write_text(gen(1))
        w._tail(live, parse, "_pending")
        with live.open("a") as f:
            f.write(gen(2))
        os.rename(live, tmp_path / (name + ".1"))
        live.write_text(gen(3))
        w._tail(live, parse, "_pending")
        assert [e["ip_address"] for e in w._pending] == [
            gen(n).split(",")[0] for n in (1, 2, 3)
        ]
