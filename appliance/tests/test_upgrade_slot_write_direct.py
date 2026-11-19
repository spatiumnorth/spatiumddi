"""#1804 — the slot write bypasses the page cache.

``spatium-upgrade-slot apply`` writes the new slot while the node is still
serving (#1743). A buffered ``dd`` let hundreds of MB of the 8 GiB image pile
up in the page cache and flush ahead of every other write on the disk: etcd's
WAL fdatasync waited behind it for seconds, and on the node holding the
cluster's leases the controller-manager missed its lease renewal and k3s
exited in the middle of the write.

The fix is two dd flags, and both are needed: ``oflag=direct`` writes through
to the disk one block at a time, and ``iflag=fullblock`` keeps it direct, since
the input is xz's pipe and dd turns O_DIRECT off at the first write shorter
than ``bs``. The write cannot run in a hermetic test, so these tests read the
dd command out of ``cmd_apply``.
"""

from __future__ import annotations

import ast
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-upgrade-slot"


def _dd_argv() -> list[str]:
    """The string literals of the ``dd`` argv in ``cmd_apply``. The f-string
    ``of=`` operand reads as ``of=`` — its device is computed at run time."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    apply = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "cmd_apply"
    )
    found: list[list[str]] = []
    for node in ast.walk(apply):
        if not (isinstance(node, ast.List) and node.elts):
            continue
        first = node.elts[0]
        if not (isinstance(first, ast.Constant) and first.value == "dd"):
            continue
        argv = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                argv.append(elt.value)
            elif isinstance(elt, ast.JoinedStr):
                argv.append(
                    "".join(
                        v.value
                        for v in elt.values
                        if isinstance(v, ast.Constant) and isinstance(v.value, str)
                    )
                )
        found.append(argv)
    assert len(found) == 1, f"expected exactly one dd command in cmd_apply, found {found}"
    return found[0]


def test_the_slot_write_goes_to_the_inactive_partition_in_4m_blocks() -> None:
    argv = _dd_argv()
    assert "of=" in argv
    assert "bs=4M" in argv


def test_the_slot_write_bypasses_the_page_cache() -> None:
    """O_DIRECT: the 8 GiB write never piles up as dirty pages in front of
    etcd's fdatasync on a node that is still serving (#1804)."""
    assert "oflag=direct" in _dd_argv()


def test_the_slot_write_reads_full_blocks_so_it_stays_direct() -> None:
    """Without fullblock, a short read from xz's pipe makes a short write,
    and GNU dd turns O_DIRECT off for the rest of the copy at the first one
    — the write would be buffered again with nothing to show it."""
    assert "iflag=fullblock" in _dd_argv()


def test_the_slot_write_is_still_flushed_before_the_bootloader_changes() -> None:
    """O_DIRECT skips the page cache but not the disk's own write cache:
    conv=fsync still flushes the device before grub is pointed at it."""
    assert "conv=fsync" in _dd_argv()
