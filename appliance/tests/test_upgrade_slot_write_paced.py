"""#1804 — the slot write is paced.

O_DIRECT keeps the 8 GiB image out of the node's page cache
(test_upgrade_slot_write_direct.py), but dd still wrote as fast as the disk
would take it. On a three-node cluster whose members' disks shared one host
disk that was up to 166 MB/s, every member's etcd slowed at once, and the
cluster's leases were lost on the staged node and on each node that took
them over. The runner now feeds dd itself, through ``_paced_copy``, which
keeps the write at ``_WRITE_RATE_BYTES_PER_SECOND``.
"""

from __future__ import annotations

import ast
import importlib.util
import io
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-upgrade-slot"
)


@pytest.fixture()
def slot_cli():
    """Import the extensionless CLI."""
    loader = SourceFileLoader("spatium_upgrade_slot_paced", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class _Clock:
    """Time that moves only when something spends it: a sleep, or a write."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class _Disk(io.BytesIO):
    """A destination whose every write takes ``per_write`` seconds of the
    clock. ``marks`` holds (time the write began, bytes written before it)."""

    def __init__(self, clock: _Clock, per_write: float = 0.0) -> None:
        super().__init__()
        self.clock = clock
        self.per_write = per_write
        self.marks: list[tuple[float, int]] = []

    def write(self, b) -> int:
        self.marks.append((self.clock.now, self.tell()))
        n = super().write(b)
        self.clock.now += self.per_write
        return n


class _Xz:
    """xz's pipe, ``chunks`` full chunks of zeros long. The read after the
    first ``stall_after`` chunks returns ``stall`` seconds of the clock late;
    ``resumed`` is when it returned. Holds one chunk, however long the copy."""

    def __init__(self, clock: _Clock, chunk: int, chunks: int, stall_after: int, stall: float):
        self.clock = clock
        self.block = bytes(chunk)
        self.chunks = chunks
        self.stall_after = stall_after
        self.stall = stall
        self.served = 0
        self.resumed: float | None = None

    def read(self, n: int) -> bytes:
        if self.served == self.chunks:
            return b""
        if self.served == self.stall_after:
            self.clock.now += self.stall
            self.resumed = self.clock.now
        self.served += 1
        return self.block[:n]


class _Dd:
    """dd on a disk that takes every write at once, except the write after
    the first ``stall_after`` chunks, which takes ``stall`` seconds of the
    clock; ``resumed`` is when it returned. Keeps no bytes; ``marks`` holds
    (time the write began, bytes written before it), as _Disk's does."""

    def __init__(self, clock: _Clock, stall_after: int, stall: float):
        self.clock = clock
        self.stall_after = stall_after
        self.stall = stall
        self.marks: list[tuple[float, int]] = []
        self.written = 0
        self.resumed: float | None = None

    def write(self, b) -> int:
        self.marks.append((self.clock.now, self.written))
        if len(self.marks) == self.stall_after + 1:
            self.clock.now += self.stall
            self.resumed = self.clock.now
        self.written += len(b)
        return len(b)


def test_every_byte_reaches_dd_in_order(slot_cli) -> None:
    # Not a whole number of chunks, so the last read is short.
    data = bytes(range(256)) * (10 * 4096 + 3)
    clock = _Clock()
    disk = _Disk(clock)
    copied = slot_cli._paced_copy(io.BytesIO(data), disk, clock=clock, sleep=clock.sleep)
    assert copied == len(data)
    assert disk.getvalue() == data


def test_the_write_never_gets_ahead_of_the_rate(slot_cli) -> None:
    """A disk that takes every write at once is held to the rate: no write
    begins before the bytes already written could have gone at the rate."""
    rate = slot_cli._WRITE_RATE_BYTES_PER_SECOND
    chunk = slot_cli._WRITE_CHUNK_BYTES
    data = b"\0" * (16 * chunk)
    clock = _Clock()
    disk = _Disk(clock)
    slot_cli._paced_copy(io.BytesIO(data), disk, clock=clock, sleep=clock.sleep)
    assert len(disk.marks) == 16
    for began, written_before in disk.marks:
        assert began >= written_before / rate - 1e-9
    assert clock.now == pytest.approx(len(data) / rate)


def test_a_disk_slower_than_the_rate_is_not_slowed_further(slot_cli) -> None:
    """Pacing only holds the write back: a disk that already takes longer
    than the rate allows is never made to wait as well."""
    rate = slot_cli._WRITE_RATE_BYTES_PER_SECOND
    chunk = slot_cli._WRITE_CHUNK_BYTES
    clock = _Clock()
    disk = _Disk(clock, per_write=2 * chunk / rate)
    slot_cli._paced_copy(io.BytesIO(b"\0" * (8 * chunk)), disk, clock=clock, sleep=clock.sleep)
    assert clock.slept == []


def test_a_dd_that_stops_reading_is_not_hidden(slot_cli) -> None:
    """When dd exits mid-write the copy stops with the broken pipe, and
    cmd_apply then reports dd's own failure."""

    class _Gone(io.BytesIO):
        def write(self, b) -> int:
            raise BrokenPipeError(32, "Broken pipe")

    clock = _Clock()
    with pytest.raises(BrokenPipeError):
        slot_cli._paced_copy(io.BytesIO(b"\0" * 1024), _Gone(), clock=clock, sleep=clock.sleep)


def test_the_rate_is_well_under_what_lost_the_leases(slot_cli) -> None:
    """Leases were lost at 96-166 MB/s. At the cap the 8 GiB write takes
    over four minutes, which the stage spends in service."""
    rate = slot_cli._WRITE_RATE_BYTES_PER_SECOND
    assert 0 < rate <= 48 * 1000 * 1000
    assert slot_cli._WRITE_CHUNK_BYTES == 4 * 1024 * 1024  # dd's bs=4M


@pytest.mark.parametrize("held_up", ["xz", "dd"])
def test_a_stall_is_not_made_up_at_the_disks_full_speed(slot_cli, held_up) -> None:
    """A stall puts the copy behind the rate: xz decompressing slowly, or dd
    held up by a busy disk. Once the stall is over, the copy keeps to the
    rate again. It may catch up by a second at most, with the chunk the
    stall held up, never by the whole stall: catching up runs at the disk's
    full speed, the burst #1804 is about."""
    rate = slot_cli._WRITE_RATE_BYTES_PER_SECOND
    chunk = slot_cli._WRITE_CHUNK_BYTES
    stall = 10.0
    clock = _Clock()
    # A second at the rate, the stall, then 12 seconds' worth on a fast disk.
    src = _Xz(clock, chunk, chunks=104, stall_after=8 if held_up == "xz" else -1, stall=stall)
    dd = _Dd(clock, stall_after=8 if held_up == "dd" else -1, stall=stall)
    copied = slot_cli._paced_copy(src, dd, clock=clock, sleep=clock.sleep)
    assert copied == dd.written == 104 * chunk

    resumed = src.resumed if held_up == "xz" else dd.resumed
    after = [(began, before) for began, before in dd.marks if began >= resumed]
    first = after[0][1]
    at_once = sum(1 for began, _ in after if began == resumed)
    mib_s = (dd.written - first) / (clock.now - resumed) / (1024 * 1024)
    burst = (
        f"{at_once} chunks ({at_once * chunk // (1024 * 1024)} MiB) went to dd at once "
        f"after a {stall:.0f} s stall, and the rest of the copy averaged {mib_s:.0f} MiB/s"
    )
    for began, before in after:
        assert began - resumed >= (before - first) / rate - 1.0 - chunk / rate - 1e-9, burst


def _cmd_apply() -> ast.FunctionDef:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    return next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "cmd_apply"
    )


def test_cmd_apply_feeds_dd_through_the_paced_copy() -> None:
    """dd reads a pipe the runner writes through _paced_copy, not xz's
    output directly, which would let it run at the disk's full speed."""
    apply = _cmd_apply()
    paced = [
        n
        for n in ast.walk(apply)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_paced_copy"
    ]
    assert len(paced) == 1, "cmd_apply must write the slot through _paced_copy once"

    dd_calls = [
        n
        for n in ast.walk(apply)
        if isinstance(n, ast.Call)
        and n.args
        and isinstance(n.args[0], ast.List)
        and n.args[0].elts
        and isinstance(n.args[0].elts[0], ast.Constant)
        and n.args[0].elts[0].value == "dd"
    ]
    assert len(dd_calls) == 1
    stdin = next(kw.value for kw in dd_calls[0].keywords if kw.arg == "stdin")
    assert isinstance(stdin, ast.Attribute) and stdin.attr == "PIPE"
