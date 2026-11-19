"""Staging an upgrade image must leave the kubelet's eviction margin free (#2400).

The kubelet evicts at nodefs.available<5% and then keeps evicting until a
further 10% (evictionMinimumReclaim) is free, so /var needs 15% free AFTER
the image lands. These tests drive the real ``fetch_to`` / ``_fetch_image``
against a local server with ``shutil.disk_usage`` faked.
"""

from __future__ import annotations

import shutil
from collections import namedtuple

import pytest

from test_upgrade_slot_fetch import BODY, serve, slot_cli  # noqa: F401

Usage = namedtuple("Usage", "total used free")
GIB = 1024**3


def _disk(monkeypatch, total, free):
    monkeypatch.setattr(shutil, "disk_usage", lambda p: Usage(total, total - free, free))


def test_a_download_that_would_cross_the_margin_is_refused_before_a_byte_lands(
    slot_cli, serve, tmp_path, monkeypatch  # noqa: F811
):
    # 15 GiB volume, 15% = 2.25 GiB must stay free; the image is 1 MiB but
    # only 2.25 GiB - 1 KiB is free, so staging it would cross the line.
    _disk(monkeypatch, 15 * GIB, int(2.25 * GIB) - 1024)
    s = serve(("full",))
    dst = tmp_path / "slot.raw.xz"
    with pytest.raises(slot_cli.InsufficientSpace, match="15%"):
        slot_cli.fetch_to(s.url, dst)
    assert not dst.exists() or dst.stat().st_size == 0
    assert len(s.requests) == 1  # refused, never retried


def test_a_download_that_leaves_the_margin_free_proceeds(
    slot_cli, serve, tmp_path, monkeypatch  # noqa: F811
):
    _disk(monkeypatch, 15 * GIB, int(2.25 * GIB) + len(BODY) + 1024)
    s = serve(("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY


def test_fetch_image_returns_7_and_removes_the_staged_file(
    slot_cli, serve, tmp_path, monkeypatch, capsys  # noqa: F811
):
    _disk(monkeypatch, 15 * GIB, 1 * GIB)
    s = serve(("full",))
    staged = tmp_path / "slot.raw.xz"
    assert slot_cli._fetch_image(s.url, staged, insecure=False) == 7
    assert not staged.exists()
    assert "Nothing was written to the inactive slot" in capsys.readouterr().err


def test_an_unreadable_volume_does_not_block_the_upgrade(
    slot_cli, serve, tmp_path, monkeypatch  # noqa: F811
):
    def boom(p):
        raise OSError("no such device")

    monkeypatch.setattr(shutil, "disk_usage", boom)
    s = serve(("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY


def test_the_wrapper_names_rc_7():
    from pathlib import Path

    w = Path(__file__).parent.parent / "mkosi.extra/usr/local/bin/spatiumddi-slot-upgrade"
    assert '"$apply_rc" -eq 7' in w.read_text()
