"""local_volume is per node on a multi-node appliance, and says so (#1838)."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from app.api.v1.backup.targets import _node_local_listing_note
from app.services.backup.targets.base import BackupDestinationError
from app.services.backup.targets.local_volume import LocalVolumeDestination

NAME = "spatiumddi-backup-api-x-20261013-065126-a1a455.zip"


@pytest.fixture
def on_node(monkeypatch):
    monkeypatch.setenv("NODE_NAME", "ddipg-member-2")
    monkeypatch.setattr("app.api.v1.backup.targets.settings.node_name", "ddipg-member-2")
    monkeypatch.setattr(os.path, "ismount", lambda p: str(p).rstrip("/") == "/data")


@pytest.mark.asyncio
async def test_download_miss_names_the_node_and_remedy(on_node, tmp_path):
    with pytest.raises(BackupDestinationError) as ei:
        await LocalVolumeDestination().download(config={"path": str(tmp_path)}, filename=NAME)
    msg = str(ei.value)
    assert "ddipg-member-2" in msg and "per node" in msg and "S3" in msg


@pytest.mark.asyncio
async def test_download_miss_off_appliance_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.delenv("NODE_NAME", raising=False)
    with pytest.raises(BackupDestinationError) as ei:
        await LocalVolumeDestination().download(config={"path": str(tmp_path)}, filename=NAME)
    assert "per node" not in str(ei.value)


@pytest.mark.asyncio
async def test_test_connection_warns_and_listing_carries_node(on_node, tmp_path):
    d = LocalVolumeDestination()
    out = await d.test_connection(config={"path": str(tmp_path)})
    assert out["ok"] is True
    assert "per node" in out["warning"] and "ddipg-member-2" in out["warning"]
    await d.write(config={"path": str(tmp_path)}, filename=NAME, archive_bytes=b"x")
    rows = await d.list_archives(config={"path": str(tmp_path)})
    assert [r.node_name for r in rows] == ["ddipg-member-2"]


def test_listing_note_says_last_archive_is_elsewhere(on_node):
    row = SimpleNamespace(
        kind="local_volume", last_run_status="success", last_run_filename="gone.zip"
    )
    note = _node_local_listing_note(row, [])
    assert note and "another node, not missing" in note
    assert _node_local_listing_note(SimpleNamespace(kind="s3"), []) is None
