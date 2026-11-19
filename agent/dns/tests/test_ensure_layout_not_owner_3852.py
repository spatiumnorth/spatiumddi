"""``ensure_layout`` must survive a state directory it does not own (#3852).

Under OpenShift's restricted SCC the agent runs as a random uid and the volume
is owned by root with the pod's fsGroup; only an owner may chmod, so
``os.chmod(state_dir, 0o700)`` raised PermissionError and the agent died at
start. The DHCP agent already tolerated it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from spatium_dns_agent import cache


def test_a_chmod_refused_because_we_are_not_the_owner_is_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: object, mode: int) -> None:
        raise PermissionError(1, "Operation not permitted", str(path))

    monkeypatch.setattr(os, "chmod", refuse)
    cache.ensure_layout(tmp_path)
    assert (tmp_path / "config").is_dir()
    assert (tmp_path / "ops" / "inflight").is_dir()


def test_an_owned_directory_is_still_locked_down(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    cache.ensure_layout(tmp_path)
    assert (tmp_path.stat().st_mode & 0o777) == 0o700
