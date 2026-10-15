"""#1919 — the slot-image mirror answers its presence HEAD, and the node
``disk_headroom`` need follows the Plan's image size.

FastAPI's ``APIRoute`` does not add HEAD to a GET route, so the mirror
answered the preflight's HEAD with 405 and #1885's "already on the mirror"
exemption was never reached. These tests go through the REAL router (no
``httpx.MockTransport``).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import slot_image_mirror
from app.config import settings
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance, ApplianceUpgradeImage
from app.services.upgrades import preflight

GIB = 1024**3
PREFIX = "/api/v1/appliance/internal/slot-images"
IMAGE = uuid.UUID("6f1c6c1e-0000-4000-8000-0000000019d9")
MISSING = uuid.UUID("6f1c6c1e-0000-4000-8000-0000000019da")


@pytest.fixture
def mirror_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.setenv("SPATIUM_SLOT_IMAGE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "slot_image_mirror_secret", "test-mirror-secret")
    (tmp_path / f"{IMAGE}.raw.xz").write_bytes(b"x" * 1234)
    app = FastAPI()
    app.include_router(slot_image_mirror.router, prefix=PREFIX)
    return app


def _hdr(image: uuid.UUID, op: str = "get") -> dict[str, str]:
    return {"X-Mirror-Auth": slot_image_mirror.mirror_auth_token(op, image)}


@pytest.mark.asyncio
async def test_head_on_the_real_route_is_200_stored_404_missing(mirror_app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mirror_app), base_url="http://mirror"
    ) as c:
        stored = await c.head(f"{PREFIX}/{IMAGE}", headers=_hdr(IMAGE))
        missing = await c.head(f"{PREFIX}/{MISSING}", headers=_hdr(MISSING))
        noauth = await c.head(f"{PREFIX}/{IMAGE}")
        badauth = await c.head(f"{PREFIX}/{IMAGE}", headers=_hdr(IMAGE, "put"))
    assert stored.status_code == 200
    assert stored.content == b""
    assert stored.headers["content-length"] == "1234"
    assert missing.status_code == 404
    assert missing.content == b""
    assert noauth.status_code == 401
    assert badauth.status_code == 403


class _AsgiClient(httpx.AsyncClient):
    app: FastAPI

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = httpx.ASGITransport(app=self.app)
        super().__init__(*args, **kwargs)


def _route_httpx_to(monkeypatch: pytest.MonkeyPatch, app: FastAPI) -> None:
    cls = type("Routed", (_AsgiClient,), {"app": app})
    monkeypatch.setattr(httpx, "AsyncClient", cls)
    monkeypatch.setattr(settings, "slot_image_mirror_url", "http://mirror")


@pytest.mark.asyncio
async def test_mirror_preflight_reaches_the_exemption_through_the_real_route(
    mirror_app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    _route_httpx_to(monkeypatch, mirror_app)
    # Mirror has 2 GiB free: short of 4+1 GiB, enough for the 1 GiB margin.
    monkeypatch.setattr(
        slot_image_mirror.shutil,
        "disk_usage",
        lambda _p: type("U", (), {"free": 2 * GIB, "total": 20 * GIB, "used": 18 * GIB})(),
    )
    held = await preflight.check_mirror_disk_headroom(slot_image_id=IMAGE)
    absent = await preflight.check_mirror_disk_headroom(slot_image_id=MISSING)
    assert held.level == "ok", held.message
    assert held.detail["target_on_mirror"] is True
    assert absent.level == "fail"
    assert absent.detail["target_on_mirror"] is False


async def _node(db: AsyncSession, free: int) -> None:
    der = os.urandom(32)
    total = 24 * GIB
    db.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="n1",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            installed_appliance_version="2026.10.01-1",
            last_seen_at=datetime.now(UTC) - timedelta(seconds=30),
            cluster_health={
                "host_disk_partitions": [
                    {"mount": "/var", "total_bytes": total, "used_bytes": total - free}
                ]
            },
        )
    )
    db.add(
        ApplianceUpgradeImage(
            id=IMAGE,
            filename="img.raw.xz",
            size_bytes=1_921_378_068,
            sha256="a" * 64,
            appliance_version="2026.10.15-900",
        )
    )
    await db.commit()


def _stub_others(monkeypatch: pytest.MonkeyPatch) -> None:
    ok = preflight.PreflightResult(name="x", level="ok", message="fine", detail={})

    def _sync(**_k: Any) -> preflight.PreflightResult:
        return ok

    async def _async(**_k: Any) -> preflight.PreflightResult:
        return ok

    for name in ("check_inflight_conflict", "check_version_path", "check_quorum"):
        monkeypatch.setattr(preflight, name, _sync)
    for name in (
        "check_replication_lag",
        "check_kea_ha_version_skew",
        "check_powerdns_lmdb_migration",
        "check_etcd_snapshot_freshness",
        "check_pre_upgrade_backup",
    ):
        monkeypatch.setattr(preflight, name, _async)


@pytest.mark.asyncio
async def test_node_need_follows_the_plan_images_size(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_others(monkeypatch)
    monkeypatch.setattr(settings, "slot_image_mirror_url", "")
    # 3.5 GiB free: short of the 4+1 GiB default, room for 1.79+1 GiB.
    await _node(db_session, int(3.5 * GIB))

    sized = await preflight.run_all(target_version="2026.10.15-900", slot_image_id=IMAGE)
    unsized = await preflight.run_all(target_version="2026.10.15-900")

    disk = [r for r in sized.results if r.name == "disk_headroom"][0]
    assert disk.level == "ok", disk.message
    assert sized.can_start is True
    # Unknown size (no image named) stays fail-closed at the 4 GiB default.
    udisk = [r for r in unsized.results if r.name == "disk_headroom"][0]
    assert udisk.level == "fail"
