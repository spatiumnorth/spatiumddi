"""An air-gapped upload must not fill the receiving node's /var (#2572).

#2452 refuses an upgrade image that would leave the *store* volume under
the kubelet's eviction margin. On a multi-node control plane with the
slot-image mirror on, the store volume is the mirror's PVC on the mirror's
node. But an air-gapped multipart upload is spooled whole onto the
*receiving* api pod's node ``/var`` (Starlette rolls its
``SpooledTemporaryFile`` over to a temp file past 1 MiB) before the handler
runs, and that node is never the mirror's. So with a roomy mirror and a
near-full receiving node the store check passes while the transfer alone
takes the receiving node into DiskPressure.

The fix refuses before the body is read, checking the receiving node's own
spool volume against Content-Length as well as the store volume.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import upgrade_images
from app.config import settings
from app.services.appliance import upgrade_image_space
from tests.test_upgrade_image_space_2400 import GIB, TOTAL, _disk, _image_count
from tests.test_upgrade_images import _BASE, _hdr, _token

pytestmark = pytest.mark.asyncio

# The spool guard's margin is the kubelet's 5 % eviction trigger, not the
# store rule's 15 % keep: a transient upload spool only has to stay above the
# trigger (see upgrade_image_space.EVICTION_HARD_PCT).
HARD = TOTAL * 5 // 100


def _mirror(monkeypatch: pytest.MonkeyPatch, *, free_bytes: int) -> None:
    """Turn the mirror on and answer its disk-usage / byte ops as if it
    had ``free_bytes`` free, so the store rule (#2452) would accept."""
    monkeypatch.setattr(settings, "slot_image_mirror_url", "http://mirror.test")
    monkeypatch.setattr(settings, "slot_image_mirror_secret", "s3cret")
    real = httpx.AsyncClient

    def usage_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"path": "/x", "free_bytes": free_bytes, "total_bytes": TOTAL},
        )

    monkeypatch.setattr(
        upgrade_image_space.httpx,
        "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(usage_handler)}),
    )

    def byte_handler(request: httpx.Request) -> httpx.Response:
        # HEAD (presence) is a miss so a new upload stores; PUT accepts.
        return httpx.Response(404 if request.method == "HEAD" else 201)

    monkeypatch.setattr(
        upgrade_images.httpx,
        "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(byte_handler)}),
    )


def test_spool_shortfall_message_arithmetic() -> None:
    # Fits above the 5% eviction trigger with the margin to spare → no message.
    u = upgrade_image_space.StoreUsage(total_bytes=TOTAL, free_bytes=HARD + 1000)
    assert upgrade_image_space.spool_shortfall_message(u, 1000) is None
    # One byte over the trigger → a sentence that names the receiving node
    # and the eviction, at 5% (not the store rule's 15%).
    msg = upgrade_image_space.spool_shortfall_message(u, 1001)
    assert msg is not None
    assert "receiving" in msg and "evict" in msg and "5%" in msg and "15%" not in msg
    # The spool refusal names the threshold and the receiving node, not the
    # node's free/total figures.
    assert "MiB" not in msg


def test_local_volume_usage_reads_the_spool_volume_not_the_mirror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even with the mirror configured, the spool-volume read is local: it
    # must never consult the mirror (that is the whole point of #2572).
    monkeypatch.setattr(settings, "slot_image_mirror_url", "http://mirror.test")
    monkeypatch.setattr(
        upgrade_image_space,
        "shutil",
        SimpleNamespace(disk_usage=lambda _p: SimpleNamespace(total=TOTAL, free=7)),
    )
    assert upgrade_image_space.local_volume_usage() == upgrade_image_space.StoreUsage(
        total_bytes=TOTAL, free_bytes=7
    )


async def test_upload_refused_when_receiving_node_full_though_mirror_roomy(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """The defect: a roomy mirror, a near-full receiving node. #2452's store
    rule would accept; #2572's spool rule must refuse before the body lands."""
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _mirror(monkeypatch, free_bytes=50 * GIB)  # the store volume is roomy
    _disk(monkeypatch, HARD)  # the receiving node's /var is at the 5% trigger
    token = await _token(db_session)
    content = b"x" * 4096
    resp = await client.post(
        _BASE,
        headers=_hdr(token),
        files={"file": ("img.raw.xz", content, "application/octet-stream")},
        data={"sha256": hashlib.sha256(content).hexdigest(), "appliance_version": "1.0.0"},
    )
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert "receiving" in detail and "evict" in detail
    assert list(tmp_path.iterdir()) == []
    assert await _image_count(db_session) == 0


async def test_upload_accepted_when_both_node_and_mirror_have_room(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """The guard must not refuse a healthy upload: both volumes have room."""
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _mirror(monkeypatch, free_bytes=50 * GIB)
    _disk(monkeypatch, HARD + 10 * 1024 * 1024)
    token = await _token(db_session)
    content = b"x" * 4096
    resp = await client.post(
        _BASE,
        headers=_hdr(token),
        files={"file": ("img.raw.xz", content, "application/octet-stream")},
        data={"sha256": hashlib.sha256(content).hexdigest(), "appliance_version": "1.0.0"},
    )
    assert resp.status_code == 200, resp.text
    assert await _image_count(db_session) == 1
