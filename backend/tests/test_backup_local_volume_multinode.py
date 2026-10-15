"""A ``local_volume`` target is per node on a multi-node appliance (#1838).

The backups directory is a per-node hostPath, so an archive exists only on
the disk of the node whose pod wrote it. These tests drive the real API and
the real local-volume driver against a real directory, standing in for
"this pod's node" with ``settings.node_name`` and for "the cluster" with
approved control-plane ``appliance`` rows, which is what the api counts.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup import drill as drill_mod
from app.services.backup import node_local
from app.services.backup.runner import run_backup_for_target

THIS = "ddipg-member-2"
WRITER = "ddipg-member-1"
NAME = "spatiumddi-backup-spatium-control-api-s4cl7-20261013-065126-a1a455.zip"


@pytest.fixture
def on_node(monkeypatch: pytest.MonkeyPatch) -> None:
    """This api pod runs on node ``THIS`` (the downward-API NODE_NAME)."""
    monkeypatch.setattr("app.config.settings.node_name", THIS)
    monkeypatch.setenv("NODE_NAME", THIS)
    monkeypatch.setattr("app.api.v1.backup.targets.decrypt_config_secrets", lambda _d, c: c)


async def _token(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="multinode",
        email="multinode@example.com",
        display_name="multinode",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []  # is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _cluster(db: AsyncSession, nodes: int) -> None:
    for i in range(nodes):
        der = os.urandom(32)
        db.add(
            Appliance(
                id=uuid.uuid4(),
                hostname=f"node-{i}",
                public_key_der=der,
                public_key_fingerprint=hashlib.sha256(der).hexdigest(),
                state=APPLIANCE_STATE_APPROVED,
                deployment_kind="appliance",
                appliance_variant="control-plane",
                cluster_role=CLUSTER_ROLE_PRIMARY if i == 0 else CLUSTER_ROLE_MEMBER,
            )
        )
    await db.flush()


async def _target(db: AsyncSession, path: Path, **kw: object) -> BackupTarget:
    row = BackupTarget(
        name=f"lv-{uuid.uuid4().hex[:6]}",
        description="",
        kind="local_volume",
        enabled=True,
        config={"path": str(path)},
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
        **kw,  # type: ignore[arg-type]
    )
    db.add(row)
    await db.flush()
    return row


def _written_elsewhere() -> dict[str, object]:
    return {"last_run_status": "success", "last_run_filename": NAME, "last_run_node": WRITER}


# ── restore / download: the reported case ─────────────────────────────


@pytest.mark.asyncio
async def test_restore_of_an_archive_on_another_node_names_the_holder(
    client: AsyncClient, db_session: AsyncSession, on_node: None, tmp_path: Path
):
    hdr = await _token(db_session)
    await _cluster(db_session, 3)
    target = await _target(db_session, tmp_path, **_written_elsewhere())
    res = await client.post(
        f"/api/v1/backup/targets/{target.id}/archives/restore",
        json={"filename": NAME, "passphrase": "hunter2hunter2", "confirmation_phrase": "x"},
        headers=hdr,
    )
    assert res.status_code == 502, res.text
    detail = res.json()["detail"]
    assert f"written on node {WRITER}" in detail
    assert f"answered by the api on node {THIS}" in detail
    assert "Nothing was restored" in detail and "S3" in detail


@pytest.mark.asyncio
async def test_download_miss_on_a_cluster_without_a_recorded_writer_names_this_node(
    client: AsyncClient, db_session: AsyncSession, on_node: None, tmp_path: Path
):
    # A pre-#1838 run: no last_run_node. The miss can still say which
    # node answered and that the volume is per node.
    hdr = await _token(db_session)
    await _cluster(db_session, 3)
    target = await _target(db_session, tmp_path)
    res = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{NAME}/download", headers=hdr
    )
    assert res.status_code == 502, res.text
    detail = res.json()["detail"]
    assert f"node {THIS}" in detail and "per node" in detail


@pytest.mark.asyncio
async def test_download_miss_on_a_single_node_appliance_has_no_cluster_caveat(
    client: AsyncClient, db_session: AsyncSession, on_node: None, tmp_path: Path
):
    # One node: the archive is genuinely missing, and telling the operator
    # it is "on another node" would send them looking for a node that
    # does not exist.
    hdr = await _token(db_session)
    await _cluster(db_session, 1)
    target = await _target(db_session, tmp_path)
    res = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{NAME}/download", headers=hdr
    )
    assert res.status_code == 502, res.text
    detail = res.json()["detail"]
    assert "per node" not in detail and THIS not in detail


# ── listing ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_listing_says_the_last_archive_is_held_elsewhere(
    client: AsyncClient, db_session: AsyncSession, on_node: None, tmp_path: Path
):
    hdr = await _token(db_session)
    await _cluster(db_session, 3)
    (tmp_path / "spatiumddi-backup-old-20261001-000000-aaaaaa.zip").write_bytes(b"x")
    target = await _target(db_session, tmp_path, **_written_elsewhere())
    res = await client.get(f"/api/v1/backup/targets/{target.id}/archives", headers=hdr)
    assert res.status_code == 200, res.text
    assert [a["node_name"] for a in res.json()] == [THIS]
    note = res.headers["x-archive-listing-note"]
    assert f"written on node {WRITER}" in note and "not missing" in note


@pytest.mark.asyncio
async def test_listing_on_a_cluster_says_whose_disk_it_is(
    client: AsyncClient, db_session: AsyncSession, on_node: None, tmp_path: Path
):
    hdr = await _token(db_session)
    await _cluster(db_session, 3)
    target = await _target(db_session, tmp_path)
    res = await client.get(f"/api/v1/backup/targets/{target.id}/archives", headers=hdr)
    assert res.status_code == 200, res.text
    note = res.headers["x-archive-listing-note"]
    assert f"node {THIS}'s disk only" in note and "3-node" in note


@pytest.mark.asyncio
async def test_listing_off_a_cluster_carries_no_note(
    client: AsyncClient, db_session: AsyncSession, on_node: None, tmp_path: Path
):
    hdr = await _token(db_session)
    await _cluster(db_session, 1)
    target = await _target(db_session, tmp_path)
    res = await client.get(f"/api/v1/backup/targets/{target.id}/archives", headers=hdr)
    assert res.status_code == 200, res.text
    assert "x-archive-listing-note" not in res.headers


# ── test connection ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_connection_warns_on_a_multi_node_appliance(
    client: AsyncClient,
    db_session: AsyncSession,
    on_node: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    # tmp_path is not a mountpoint; pretend it is so only the #1838
    # warning is in play, not the #1160 not-on-a-volume one.
    monkeypatch.setattr(os.path, "ismount", lambda p: str(p) == str(tmp_path))
    hdr = await _token(db_session)
    await _cluster(db_session, 3)
    target = await _target(db_session, tmp_path)
    res = await client.post(f"/api/v1/backup/targets/{target.id}/test", headers=hdr)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert "3 control-plane nodes" in body["warning"] and THIS in body["warning"]
    assert "S3" in body["warning"]


@pytest.mark.asyncio
async def test_test_connection_on_a_single_node_does_not_warn(
    client: AsyncClient,
    db_session: AsyncSession,
    on_node: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os.path, "ismount", lambda p: str(p) == str(tmp_path))
    hdr = await _token(db_session)
    await _cluster(db_session, 1)
    target = await _target(db_session, tmp_path)
    res = await client.post(f"/api/v1/backup/targets/{target.id}/test", headers=hdr)
    assert res.status_code == 200, res.text
    assert "warning" not in res.json()


# ── the run records its node ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_successful_run_records_the_writing_node(
    db_session: AsyncSession, on_node: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    async def _build(_db, **_kw):
        return b"PK\x05\x06" + b"\x00" * 18, NAME

    monkeypatch.setattr("app.services.backup.runner.build_backup_archive", _build)
    target = await _target(db_session, tmp_path)
    await db_session.commit()
    result = await run_backup_for_target(db_session, target=target, triggered_by="manual")
    assert result["success"] is True, result
    assert target.last_run_node == THIS
    assert result["node_name"] == THIS
    assert (tmp_path / NAME).is_file()


# ── drills ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_drill_with_the_archive_on_another_node_is_error_not_failed(
    db_session: AsyncSession, on_node: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # An empty directory on this node is not evidence the target holds no
    # archives: the one it has is on the node that wrote it. ``failed``
    # would raise a false "your backups are gone" finding.
    async def _ok(**_kw):
        return None

    monkeypatch.setattr(drill_mod, "preflight", _ok)
    target = await _target(db_session, tmp_path, **_written_elsewhere())
    outcome = await drill_mod._execute(target, live_db_url="postgresql://unused")
    assert outcome.state == "error"
    assert outcome.error and WRITER in outcome.error and THIS in outcome.error


def test_removable_disk_targets_are_left_to_their_own_node_check(on_node: None):
    # A removable disk already names its node (#989 item 3).
    row = BackupTarget(
        kind="local_volume",
        config={"path": "/var/lib/spatiumddi/removable/usb1/spatiumddi"},
        **_written_elsewhere(),  # type: ignore[arg-type]
    )
    assert not node_local.applies(row)
    assert node_local.miss_hint(row, NAME, 3) == ""
