"""What the Upgrade images table knows about each image (#2399, #2410).

One home for the derivations the REST list endpoints and the copilot's
``find_upgrade_images`` / ``find_available_upgrade_images`` tools both
report: the fleet's architectures and the per-image verdict, who has an
image installed / scheduled / named by a run, which staged image a
GitHub row corresponds to, and an image's channel. Two copies of these
had already drifted (the MCP tool matched staged rows differently and
derived the channel without the release's prerelease flag), so both
surfaces call these functions and cannot disagree.

Nothing here makes an outbound call: release data comes either from the
caller (the GitHub listing it already fetched) or from the release cache.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance, ApplianceUpgradeImage
from app.models.system_upgrade import SystemUpgradeRun
from app.services.appliance.architecture import normalize
from app.services.appliance.releases import UpgradeImageRelease, release_channel

_ACTIVE_RUN_STATES = ("planned", "running", "halted")

# #2400 — the upgrade-image catalogue lock (transaction-scoped advisory).
# SHARED by every path that turns an image into a schedule (from resolving
# the image until that transaction commits), EXCLUSIVE by the paths that
# delete images (the delete endpoint, the reclaim sweep). So an image can
# never be deleted between "is anything using it?" and a new schedule.
CATALOG_LOCK_KEY = 0x53504D55504749  # "SPMUPGI"


async def lock_catalog_shared(db: AsyncSession) -> None:
    await db.execute(text("SELECT pg_advisory_xact_lock_shared(:k)"), {"k": CATALOG_LOCK_KEY})


async def lock_catalog_exclusive(db: AsyncSession) -> None:
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CATALOG_LOCK_KEY})


async def try_lock_catalog_exclusive(db: AsyncSession) -> bool:
    got = await db.scalar(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": CATALOG_LOCK_KEY})
    return bool(got)


_IMAGE_URL_RE = re.compile(r"/upgrade-images/([0-9a-fA-F-]{36})/raw\.xz")


class FleetArchitectures(BaseModel):
    """What the fleet runs, as far as it has told us (#2399)."""

    # Distinct non-null ``architecture`` of approved appliances.
    architectures: list[str]
    # Approved appliances that have not reported one (older supervisor,
    # or not yet heartbeated). They could be any architecture, so while
    # any exist nothing is refused or filtered.
    unknown_count: int
    # Approved appliances per architecture, for "which nodes is this for".
    counts: dict[str, int]
    # True when images for other architectures are hidden / refused.
    restricted: bool


async def fleet_architectures(db: AsyncSession) -> FleetArchitectures:
    """Architectures of the approved appliances (#2399).

    ``restricted`` is only true when every approved appliance has
    reported an architecture: a NULL one (older supervisor) could be
    either, so it must not block an import (#1026 treats NULL as
    unknown). An empty fleet is likewise unrestricted.
    """
    rows = (
        await db.execute(
            select(Appliance.architecture, func.count())
            .where(Appliance.state == APPLIANCE_STATE_APPROVED)
            .group_by(Appliance.architecture)
        )
    ).all()
    counts: dict[str, int] = {}
    unknown = 0
    for arch, n in rows:
        canon = normalize(arch)
        if canon is None:
            unknown += n
        else:
            counts[canon] = counts.get(canon, 0) + n
    return FleetArchitectures(
        architectures=sorted(counts),
        unknown_count=unknown,
        counts=counts,
        restricted=bool(counts) and unknown == 0,
    )


def fleet_verdict(fleet: FleetArchitectures, architecture: str | None) -> tuple[str, int | None]:
    """#2399's answer for one image: ``(verdict, matching node count)``."""
    arch = normalize(architecture)
    if arch is None or not fleet.restricted:
        return "unknown", None
    if arch in fleet.architectures:
        return "matches", fleet.counts.get(arch, 0)
    return "no_node", 0


@dataclass
class ImageUsage:
    """Who installed / is scheduled for / has a run naming one image."""

    installed_on: list[str] = field(default_factory=list)
    scheduled_for: list[str] = field(default_factory=list)
    run_id: uuid.UUID | None = None


def _scheduled_image_id(url: str | None) -> uuid.UUID | None:
    if not url:
        return None
    m = _IMAGE_URL_RE.search(url)
    if not m:
        return None
    try:
        return uuid.UUID(m.group(1))
    except ValueError:
        return None


async def image_usage(
    db: AsyncSession, images: Sequence[ApplianceUpgradeImage]
) -> dict[uuid.UUID, ImageUsage]:
    """Derive usage for ``images`` from columns that already exist (#2410).

    Only APPROVED appliances count, for both lists: a pending, rejected
    or revoked row cannot authenticate to fetch an image, so a stale
    ``desired_slot_image_url`` on one must not block a delete. Only the
    handful of columns read here are selected — an ``Appliance`` row
    carries several large JSONB blobs and this runs on every list,
    delete and copilot call.
    """
    usage = {i.id: ImageUsage() for i in images}
    if not usage:
        return usage
    by_version: dict[str, list[ApplianceUpgradeImage]] = {}
    for img in images:
        by_version.setdefault(img.appliance_version, []).append(img)
    appliances = (
        await db.execute(
            select(
                Appliance.hostname,
                Appliance.architecture,
                Appliance.desired_slot_image_url,
                Appliance.installed_appliance_version,
                Appliance.slot_a_version,
                Appliance.slot_b_version,
            )
            .where(Appliance.state == APPLIANCE_STATE_APPROVED)
            .order_by(Appliance.hostname)
        )
    ).all()
    for hostname, arch, desired_url, installed, slot_a, slot_b in appliances:
        target = _scheduled_image_id(desired_url)
        if target in usage and hostname not in usage[target].scheduled_for:
            usage[target].scheduled_for.append(hostname)
        node_arch = normalize(arch)
        for v in {installed, slot_a, slot_b}:
            for img in by_version.get(v or "", []):
                # An image labelled for another architecture is not what
                # this node runs, even if the version string matches.
                img_arch = normalize(img.architecture)
                if img_arch and node_arch and img_arch != node_arch:
                    continue
                if hostname not in usage[img.id].installed_on:
                    usage[img.id].installed_on.append(hostname)
    runs = (
        await db.execute(
            select(SystemUpgradeRun.id, SystemUpgradeRun.plan)
            .where(SystemUpgradeRun.state.in_(_ACTIVE_RUN_STATES))
            .order_by(SystemUpgradeRun.started_at.desc())
        )
    ).all()
    for run_id, plan in runs:
        raw = (plan or {}).get("slot_image_id")
        try:
            rid = uuid.UUID(str(raw)) if raw else None
        except ValueError:
            rid = None
        if rid in usage and usage[rid].run_id is None:
            usage[rid].run_id = run_id
    return usage


def staged_assignment(
    staged: Sequence[ApplianceUpgradeImage],
    releases: Sequence[UpgradeImageRelease],
) -> dict[tuple[str, str], uuid.UUID]:
    """Which staged image is the image for each ``(tag, architecture)``.

    A labelled image maps to its own tag + architecture. An UNLABELLED
    one (architecture NULL, an air-gap upload nobody labelled) could be
    either architecture, so it maps to at most one row, and only when
    the evidence says which: the release publishes exactly ONE
    architecture for that tag and no labelled image already holds that
    row. Otherwise it maps to nothing and the table shows it as its own
    "unknown architecture" row. Attaching it to every architecture of
    the tag — the first cut — showed both amd64 and arm64 as staged when
    at most one of them can be. The fleet's architecture is deliberately
    not used as evidence: it says what the nodes run, not what an
    unlabelled image contains.

    ``releases`` must be the UNFILTERED listing, or a fleet filter
    hiding one architecture would make a two-architecture release look
    like a one-architecture release.
    """
    out: dict[tuple[str, str], uuid.UUID] = {}
    ordered = sorted(staged, key=lambda s: (s.uploaded_at is None, s.uploaded_at, str(s.id)))
    for s in ordered:
        arch = normalize(s.architecture)
        if arch is not None:
            out.setdefault((s.appliance_version, arch), s.id)
    arches_by_tag: dict[str, set[str]] = {}
    for r in releases:
        arches_by_tag.setdefault(r.tag, set()).add(r.architecture)
    for s in ordered:
        if normalize(s.architecture) is not None:
            continue
        arches = arches_by_tag.get(s.appliance_version, set())
        if len(arches) != 1:
            continue
        key = (s.appliance_version, next(iter(arches)))
        if key not in out:
            out[key] = s.id
    return out


def release_for_staged(
    image: ApplianceUpgradeImage, cached: Sequence[UpgradeImageRelease]
) -> UpgradeImageRelease | None:
    """The GitHub release a staged image came from, if the cache has it.

    Release date / URL / prerelease flag are per TAG, so an unlabelled
    image matches any architecture's row of its tag.
    """
    arch = normalize(image.architecture)
    return next(
        (
            c
            for c in cached
            if c.tag == image.appliance_version and (arch is None or arch == c.architecture)
        ),
        None,
    )


def staged_channel(image: ApplianceUpgradeImage, release: UpgradeImageRelease | None) -> str:
    """``nightly`` / ``prerelease`` / ``stable`` for a staged image."""
    return release_channel(image.appliance_version, bool(release and release.is_prerelease))
