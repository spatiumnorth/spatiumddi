"""#1709 — a target already on the mirror needs no room on it.

ddi-pg's rolling twin (2026-10-11) was refused at Plan by
``mirror_disk_headroom``: 4.43 GB free on the mirror, against 4 GiB for the
slot image plus a 1 GiB margin, for a target the operator had uploaded, whose
bytes an upload streams to the mirror. Nothing in the check knew which image
the run would fetch. Every node's chain re-runs the same preflight, so the
same question is asked again before each node.

The contract: when the run's target is an uploaded image the mirror already
holds (a HEAD on the mirror answers 200), the check needs only the margin. An
external URL, an image the mirror does not hold, or a presence check that
fails keep today's need. Plan and every node's preflight ask about the same
image, which the run's plan carries.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.appliance import ApplianceUpgradeImage
from app.services.appliance.slot_image_target import SlotImageTarget, resolve_slot_image_target
from app.services.upgrades import orchestrator, per_node, preflight

GIB = 1024**3
TWIN_B_FREE = 4_430_000_000  # the mirror's free bytes when twin B was refused
IMAGE = uuid.UUID("6f1c6c1e-0000-4000-8000-0000000017d9")


class Mirror:
    """The slot-image mirror's two answers the check reads."""

    def __init__(self, free: int, present: set[uuid.UUID], head_status: int | None = None):
        self.free = free
        self.present = present
        self.head_status = head_status
        self.heads: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-Mirror-Auth")
        path = request.url.path
        if path.endswith("/internal/slot-images/_/disk-usage") and request.method == "GET":
            return httpx.Response(
                200, json={"free_bytes": self.free, "total_bytes": 20 * GIB, "path": "/data"}
            )
        if request.method == "HEAD" and "/internal/slot-images/" in path:
            image = path.rsplit("/", 1)[1]
            self.heads.append(image)
            if self.head_status is not None:
                return httpx.Response(self.head_status)
            return httpx.Response(200 if uuid.UUID(image) in self.present else 404)
        return httpx.Response(405)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = httpx.AsyncClient

        def _client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = httpx.MockTransport(self.handler)
            return real(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _client)
        monkeypatch.setattr(settings, "slot_image_mirror_url", "http://slot-image-mirror:8080")
        monkeypatch.setattr(settings, "slot_image_mirror_secret", "test-mirror-secret")


async def _check(**kwargs: Any) -> preflight.PreflightResult:
    return await preflight.check_mirror_disk_headroom(**kwargs)


@pytest.mark.asyncio
async def test_a_target_already_on_the_mirror_needs_only_the_margin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Mirror(TWIN_B_FREE, present={IMAGE})
    mirror.install(monkeypatch)

    result = await _check(slot_image_id=IMAGE)

    assert result.level == "ok", result.message
    assert "already on the mirror" in result.message
    assert result.detail["needed_bytes"] == 1 * GIB
    assert mirror.heads == [str(IMAGE)]


@pytest.mark.asyncio
async def test_a_target_the_mirror_does_not_hold_still_needs_room_for_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Mirror(TWIN_B_FREE, present=set())
    mirror.install(monkeypatch)

    result = await _check(slot_image_id=IMAGE)

    assert result.level == "fail"
    assert result.detail["needed_bytes"] == 5 * GIB


@pytest.mark.asyncio
async def test_a_presence_check_that_fails_keeps_the_full_need(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Mirror(TWIN_B_FREE, present={IMAGE}, head_status=503)
    mirror.install(monkeypatch)

    result = await _check(slot_image_id=IMAGE)

    assert result.level == "fail"
    assert result.detail["needed_bytes"] == 5 * GIB


@pytest.mark.asyncio
async def test_an_external_url_target_keeps_the_full_need(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Mirror(TWIN_B_FREE, present={IMAGE})
    mirror.install(monkeypatch)

    result = await _check()

    assert result.level == "fail"
    assert mirror.heads == []


@pytest.mark.asyncio
async def test_a_mirror_with_room_is_asked_nothing_more(monkeypatch: pytest.MonkeyPatch) -> None:
    mirror = Mirror(50 * GIB, present=set())
    mirror.install(monkeypatch)

    result = await _check(slot_image_id=IMAGE)

    assert result.level == "ok"
    assert mirror.heads == []


# ── Plan and every node's preflight ask about the run's image ────────────────


def _capture_run_all(monkeypatch: pytest.MonkeyPatch, module: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def _run_all(**kwargs: Any) -> preflight.PreflightReport:
        calls.append(kwargs)
        fail = preflight.PreflightResult("mirror_disk_headroom", "fail", "stop here", {})
        return preflight.PreflightReport(
            target_version=kwargs["target_version"],
            current_version="2026.10.13-1",
            overall="fail",
            can_start=False,
            results=[fail],
        )

    monkeypatch.setattr(module.preflight, "run_all", _run_all)
    return calls


@pytest.mark.asyncio
async def test_plan_asks_about_the_uploaded_image(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_run_all(monkeypatch, orchestrator)
    monkeypatch.setattr(orchestrator, "detect_cnpg_cluster_name", lambda *_a, **_k: "")
    target = SlotImageTarget(url="https://cp.example/x.raw.xz?t=1", image_id=IMAGE)

    with pytest.raises(orchestrator.OrchestratorError):
        await orchestrator.plan_upgrade(
            db_session, target_version="2026.10.14-1", slot_image=target
        )

    assert calls[0].get("slot_image_id") == IMAGE


@pytest.mark.asyncio
async def test_every_nodes_preflight_asks_about_the_same_image(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_run_all(monkeypatch, per_node)
    target = SlotImageTarget(url="https://cp.example/x.raw.xz?t=1", image_id=IMAGE)

    result = await per_node.single_node_upgrade(
        db_session, node_name="node-b", target_version="2026.10.14-1", slot_image=target
    )

    assert result.failed_at == "preflight"
    assert calls[0].get("slot_image_id") == IMAGE


@pytest.mark.asyncio
async def test_the_runs_plan_carries_the_uploaded_images_id(db_session: AsyncSession) -> None:
    image = ApplianceUpgradeImage(
        id=uuid.uuid4(),
        filename="spatiumddi-appliance-slot-2026.10.14-1-amd64.raw.xz",
        size_bytes=4 * GIB,
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        appliance_version="2026.10.14-1",
        architecture="amd64",
    )
    db_session.add(image)
    await db_session.flush()

    target = await resolve_slot_image_target(
        db_session, base_url="https://cp.example/", slot_image_id=image.id
    )
    external = await resolve_slot_image_target(
        db_session, base_url="https://cp.example/", slot_image_url="https://github.com/x.raw.xz"
    )

    assert target.image_id == image.id
    assert SlotImageTarget.from_plan_fields(target.as_plan_fields()) == target
    assert external.image_id is None
    assert SlotImageTarget.from_plan_fields(external.as_plan_fields()).image_id is None
