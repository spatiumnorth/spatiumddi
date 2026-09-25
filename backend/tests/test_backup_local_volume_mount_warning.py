"""Local-volume test connection warns when the path is not a volume (#1160).

**What this exists to prevent.** A ``local_volume`` target at a path no
volume covers passes its connection test and reports every run as a
success — the path is writable, because it is the container's own
filesystem. Each archive then exists only inside the container that wrote
it: scheduled runs execute in the worker, so the api never lists them, and
every archive is gone at the next container recreate. Reproduced on the
release Docker Compose file, which shipped the backup volume commented out.

The probe cannot tell a volume from the writable layer, so the test now
also walks to the path's nearest mountpoint (the removable-disk guard's
walk) and warns when that is ``/``. ``os.path.ismount`` is faked the same
way ``test_backup_removable_disk.py`` fakes it: the probe really writes
under ``tmp_path``, only the answer to "is this a mountpoint" is declared.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.services.appliance.removable import REMOVABLE_ROOT
from app.services.backup.targets.local_volume import (
    LocalVolumeDestination,
    _not_on_a_volume_warning,
)


@pytest.fixture
def fake_mounts(monkeypatch):
    """Declare which paths are live mountpoints, as the kernel would."""
    live: set[str] = set()

    def _ismount(path):
        return str(path).rstrip("/") in live

    monkeypatch.setattr(os.path, "ismount", _ismount)
    monkeypatch.delenv("NODE_NAME", raising=False)
    return live


@pytest.mark.asyncio
async def test_a_path_on_no_volume_passes_with_a_warning(fake_mounts, tmp_path):
    """The #1160 shape: writable, so the probe passes — and nothing is
    mounted anywhere above it, so the warning says what that costs."""
    root = tmp_path / "backups"
    out = await LocalVolumeDestination().test_connection(config={"path": str(root)})
    assert out["ok"] is True, out
    warning = out.get("warning", "")
    assert f"{root} is not on a mounted volume" in warning
    assert "lost when the container is recreated" in warning
    assert "worker" in warning and "never listed" in warning


@pytest.mark.asyncio
async def test_a_path_on_a_mounted_volume_carries_no_warning(fake_mounts, tmp_path):
    root = tmp_path / "backups"
    fake_mounts.add(str(root))
    out = await LocalVolumeDestination().test_connection(config={"path": str(root)})
    assert out["ok"] is True, out
    assert "warning" not in out, out


@pytest.mark.asyncio
async def test_a_subdirectory_of_a_mounted_volume_carries_no_warning(fake_mounts, tmp_path):
    """A target pointed at a folder INSIDE the volume (one directory per
    target is a common layout) is on that volume."""
    volume = tmp_path / "backups"
    fake_mounts.add(str(volume))
    out = await LocalVolumeDestination().test_connection(config={"path": str(volume / "site-a")})
    assert out["ok"] is True, out
    assert "warning" not in out, out


@pytest.mark.asyncio
async def test_a_refused_path_reports_the_refusal_not_the_warning(fake_mounts):
    """A config error is a failure, and the warning is only about a path
    that works — the two never mix."""
    out = await LocalVolumeDestination().test_connection(config={"path": "/etc"})
    assert out["ok"] is False
    assert "warning" not in out


def test_a_mounted_removable_disk_is_a_volume(fake_mounts):
    """The removable-disk guard already requires a live mount under the
    removable root; this check must agree and stay quiet there."""
    fake_mounts.add(f"{REMOVABLE_ROOT}/usb1")
    assert _not_on_a_volume_warning(Path(f"{REMOVABLE_ROOT}/usb1/spatiumddi")) is None


def test_only_the_container_root_counts_as_no_volume(fake_mounts):
    """Any mountpoint between the path and ``/`` — the volume itself or
    a parent the operator mounted — is a volume."""
    fake_mounts.add("/var/lib/spatiumddi")
    assert _not_on_a_volume_warning(Path("/var/lib/spatiumddi/backups")) is None
    fake_mounts.clear()
    warning = _not_on_a_volume_warning(Path("/var/lib/spatiumddi/backups"))
    assert warning and "/var/lib/spatiumddi/backups is not on a mounted volume" in warning


def test_the_path_field_says_the_volume_is_shared_by_api_and_worker():
    """The form's help text is where an operator reads what the path
    must be; it must say both containers need it, not only "mount it"."""
    field = next(f for f in LocalVolumeDestination.config_fields if f.name == "path")
    assert "api and worker" in field.description
    assert "/var/lib/spatiumddi/backups" in field.description
