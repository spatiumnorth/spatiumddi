"""Free-space pre-flight for storing an upgrade image (#2400).

Why 15 % and not "image size plus a margin": the appliance's kubelet evicts
pods at ``nodefs.available<5%`` and, once it has started, keeps evicting
until a further ``evictionMinimumReclaim`` of 10 % is free. A node that
dips under 5 % is therefore not healthy again until 15 % of the volume is
free. On a 15 GB ``/var`` that is ~2.25 GB, so a 1.5 GiB image written with
2 GB free leaves the node in DiskPressure, evicting the api, worker and
supervisor every ~30 s, although the write itself "fit".

So the rule is: after the image lands, :data:`EVICTION_HEADROOM_PCT` of the
volume must still be free. Keep in step with ``kubelet-arg`` in
``appliance/mkosi.extra/etc/rancher/k3s/config.yaml`` and
``_EVICTION_HEADROOM_PCT`` in ``spatium-upgrade-slot`` (the node-side
staging download applies the same rule).
"""

from __future__ import annotations

import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx
import structlog

from app.api.v1.appliance.slot_image_mirror import mirror_auth_token
from app.config import settings

logger = structlog.get_logger(__name__)

# evictionHard 5 % + evictionMinimumReclaim 10 %.
EVICTION_HEADROOM_PCT = 15

# Just evictionHard, with no reclaim term (#2572). The store rule above keeps
# 15 % because a stored image stays on the volume, so the node is not healthy
# again until the reclaim target is met. An upload's spool is temporary: it is
# freed when the request ends, so the only thing it must not do is cross the
# kubelet's eviction trigger (``nodefs.available<5%`` in
# ``appliance/mkosi.extra/etc/rancher/k3s/config.yaml``). Checking it against
# 15 % would refuse uploads that dip the node to, say, 10 % and recover without
# ever evicting a pod. Keep in step with that config's ``evictionHard``.
EVICTION_HARD_PCT = 5

_MIB = 1024 * 1024


@dataclass(frozen=True)
class StoreUsage:
    total_bytes: int
    free_bytes: int


def shortfall_message(usage: StoreUsage, image_bytes: int) -> str | None:
    """None when ``image_bytes`` fits with the eviction margin to spare,
    else a sentence naming the numbers."""
    keep = usage.total_bytes * EVICTION_HEADROOM_PCT // 100
    if usage.free_bytes - image_bytes >= keep:
        return None
    return (
        f"Not enough free disk space for this upgrade image: it needs "
        f"{image_bytes // _MIB} MiB, and {keep // _MIB} MiB "
        f"({EVICTION_HEADROOM_PCT}% of the volume) must stay free afterwards "
        f"or the kubelet will evict the control plane, but only "
        f"{usage.free_bytes // _MIB} MiB of {usage.total_bytes // _MIB} MiB is free. "
        f"Free at least {(image_bytes + keep - usage.free_bytes) // _MIB + 1} MiB "
        f"(delete unused upgrade images in Fleet) and retry."
    )


def spool_shortfall_message(usage: StoreUsage, body_bytes: int) -> str | None:
    """None when a ``body_bytes`` upload can be buffered on the receiving
    node without crossing the kubelet's eviction trigger, else a short
    sentence that names the receiving node and the 5 % threshold.

    Companion to :func:`shortfall_message` for a different volume and a
    different margin (#2572). An air-gapped multipart upload is spooled
    whole onto the receiving api pod's node ``/var`` (Starlette rolls the
    ``SpooledTemporaryFile`` over to a temp file past 1 MiB) *before* the
    handler runs, while :func:`get_store_usage` reads the volume the bytes
    are finally stored on, which is the mirror's PVC on a different node
    when the mirror is configured. So the room the spool consumes on the
    receiving node is never checked by the store rule.

    The margin is :data:`EVICTION_HARD_PCT` (5 %), not the store rule's
    15 %: the spool is freed when the request ends, so it only has to stay
    above the eviction trigger, and once it crosses that trigger the
    kubelet keeps evicting past the moment the spool is gone. The refusal
    names that threshold rather than the node's free and total space, which
    move with every concurrent upload; the threshold is the stable thing to
    act on."""
    keep = usage.total_bytes * EVICTION_HARD_PCT // 100
    if usage.free_bytes - body_bytes >= keep:
        return None
    return (
        "Not enough free disk space to receive this upgrade image: it is "
        "buffered on the control-plane node receiving the upload before it "
        f"is stored, and at least {EVICTION_HARD_PCT}% of that node's volume "
        "must stay free or the kubelet will evict the control plane. Free "
        "space on the node receiving the upload (delete unused upgrade "
        "images or backups) and retry."
    )


def local_volume_usage(path: Path | None = None) -> StoreUsage | None:
    """Usage of a volume on THIS api pod's own node, never the mirror.

    The multipart upload body is spooled to a temp file under
    :func:`tempfile.gettempdir` (the api container's ``/tmp``, on the
    node's ``/var`` overlay) before the upload handler runs.
    :func:`get_store_usage` reads the *store* volume (the mirror's PVC on
    another node when the mirror is on), so a separate read of the spool
    volume is needed to see the room the transfer itself consumes (#2572).
    None when it cannot be determined; the caller then lets the upload
    proceed rather than refusing on a reading it does not have."""
    probe = path if path is not None else Path(tempfile.gettempdir())
    try:
        usage = shutil.disk_usage(probe)
    except OSError as exc:
        logger.warning("upgrade_image_spool_usage_unavailable", error=str(exc))
        return None
    return StoreUsage(usage.total, usage.free)


async def get_store_usage(local_dir: Path) -> StoreUsage | None:
    """Usage of the volume the image bytes will be written to: the
    mirror's PVC when the mirror is configured, else ``local_dir``.
    None when it cannot be determined; the caller then lets the write
    proceed (the write itself reports a failure)."""
    if settings.slot_image_mirror_url:
        base = settings.slot_image_mirror_url.rstrip("/")
        url = f"{base}/api/v1/appliance/internal/slot-images/_/disk-usage"
        try:
            headers = {"X-Mirror-Auth": mirror_auth_token("disk-usage", uuid.UUID(int=0))}
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            body = resp.json()
            return StoreUsage(int(body["total_bytes"]), int(body["free_bytes"]))
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
            logger.warning("upgrade_image_mirror_usage_unavailable", error=str(exc))
            return None
    probe = local_dir if local_dir.exists() else local_dir.parent
    try:
        usage = shutil.disk_usage(probe)
    except OSError as exc:
        logger.warning("upgrade_image_store_usage_unavailable", error=str(exc))
        return None
    return StoreUsage(usage.total, usage.free)
