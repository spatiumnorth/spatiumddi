"""The storage request directory is shared with the previous release's supervisor."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from spatium_supervisor import storage_proxy


def test_request_dir_is_group_writable_and_setgid(tmp_path: Path, monkeypatch) -> None:
    d = tmp_path / "storage"
    d.mkdir()
    d.chmod(0o755)
    # Unprivileged: use a group this process holds in place of the host group.
    monkeypatch.setattr(storage_proxy, "_HOST_GID", os.getgid())
    storage_proxy._share_request_dir(d)
    st = d.stat()
    assert stat.S_IMODE(st.st_mode) == 0o2770
    assert st.st_gid == os.getgid()


def test_run_action_shares_the_directory_it_creates(tmp_path: Path, monkeypatch) -> None:
    d = tmp_path / "storage"
    monkeypatch.setattr(storage_proxy, "_request_dir", lambda: d)
    monkeypatch.setattr(storage_proxy, "_HOST_GID", os.getgid())
    monkeypatch.setattr(storage_proxy, "_RESULT_TIMEOUT_S", 0.01)
    storage_proxy.run_action({"action": "scrub"})
    assert stat.S_IMODE(d.stat().st_mode) == 0o2770
