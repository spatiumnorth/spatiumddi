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
