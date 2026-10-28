"""Running-version + release-check endpoint.

Answers everyone, but tells a signed-in caller more (#2935). Version and
stack details are for signed-in users only: the exact version tells an
anonymous scanner which advisories apply, so an anonymous caller gets only
the coarse handshake below — ``product`` and ``api_level`` — with every
version and release-check field withheld (``restricted`` says so).

Why the route stays public at all: the appliance installer probes it before
it wipes a disk (#995 item 13), asking "is that URL MY control plane?" with
no credential to offer. ``product`` answers that. Every console consumer
(sidebar, update banner, Settings → Updates, the appliance pages) and the
mobile client's Overview call it signed in, so they keep the full answer.

SECURITY (#400 / L6): the appliance-specific fields (``appliance_version`` /
``appliance_hostname``) were the first things withheld from anonymous
callers; #2935 extends the same rule to the product version and the release
check.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.deps import DB, OptionalUser
from app.config import settings
from app.core.versions import canonical_version
from app.models.settings import PlatformSettings

router = APIRouter(tags=["version"])

_SINGLETON_ID = 1

#: The product name every SpatiumDDI control plane reports, signed in or not.
PRODUCT = "SpatiumDDI"

#: The major version of the REST surface (the ``/api/v1`` prefix). Coarse on
#: purpose: it changes only when a client built against v1 can no longer talk
#: to this server, so it tells an anonymous caller nothing about patch level.
API_LEVEL = 1


class VersionResponse(BaseModel):
    # Always present, signed in or not (#2935): enough for a client or the
    # installer's probe to know it reached a SpatiumDDI control plane.
    product: str
    api_level: int
    # True when the caller is anonymous and every version, release-check and
    # appliance-identity field below is withheld (null / false). Lets a
    # client tell "withheld" from "no data" without guessing.
    restricted: bool
    # The running version (the image tag / env var the operator set).
    # Null for an anonymous caller (#2935).
    version: str | None
    # GitHub release-check result. All nullable so a deployment with
    # the release check disabled (or that's never successfully checked)
    # reports a clean "no data yet" state rather than misleading zeros.
    latest_version: str | None
    update_available: bool
    latest_release_url: str | None
    latest_checked_at: datetime | None
    # Set when the release check is turned off — so the UI can
    # distinguish "never checked" from "operator opted out". False for an
    # anonymous caller, alongside ``restricted``.
    release_check_enabled: bool
    # Most recent error, if any. Null on success or if the check has
    # never run.
    latest_check_error: str | None
    # Appliance-mode signal — true when the API runs on the SpatiumDDI
    # OS appliance ISO (set by the appliance compose env). Gates the
    # "Appliance" sidebar entry + /api/v1/appliance/* router family.
    # Phase 4, issue #134. On plain Docker / K8s deploys this is false
    # and the appliance management surface stays hidden.
    appliance_mode: bool
    appliance_version: str | None
    appliance_hostname: str | None


def _appliance_fields(authenticated: bool) -> dict[str, str | bool | None]:
    """Appliance-mode signals.

    SECURITY (#400 / L6): ``appliance_mode`` is a harmless boolean the
    login page needs to decide whether to even hint at the appliance
    surface, so it's always returned. ``appliance_version`` and
    ``appliance_hostname`` disclose the host identity / patch level and
    are returned ONLY to authenticated callers; anonymous callers get
    ``None`` for both.
    """
    return {
        "appliance_mode": settings.appliance_mode,
        "appliance_version": (settings.appliance_version or None) if authenticated else None,
        "appliance_hostname": (settings.appliance_hostname or None) if authenticated else None,
    }


@router.get("", response_model=VersionResponse)
async def get_version(db: DB, current_user: OptionalUser) -> VersionResponse:
    if current_user is None:
        # #2935 — the coarse handshake only. No DB read either: nothing an
        # anonymous caller is given depends on the settings row.
        return VersionResponse(
            product=PRODUCT,
            api_level=API_LEVEL,
            restricted=True,
            version=None,
            latest_version=None,
            update_available=False,
            latest_release_url=None,
            latest_checked_at=None,
            release_check_enabled=False,
            latest_check_error=None,
            **_appliance_fields(False),
        )
    running = canonical_version(settings.version, settings.app_version)
    ps = await db.get(PlatformSettings, _SINGLETON_ID)
    if ps is None:
        # Settings row hasn't been seeded yet (first boot before
        # /admin/settings is opened). Report the runtime version and
        # leave everything else empty — no fabricated state.
        return VersionResponse(
            product=PRODUCT,
            api_level=API_LEVEL,
            restricted=False,
            version=running,
            latest_version=None,
            update_available=False,
            latest_release_url=None,
            latest_checked_at=None,
            release_check_enabled=True,
            latest_check_error=None,
            **_appliance_fields(True),
        )
    return VersionResponse(
        product=PRODUCT,
        api_level=API_LEVEL,
        restricted=False,
        version=running,
        latest_version=ps.latest_version,
        update_available=ps.update_available,
        latest_release_url=ps.latest_release_url,
        latest_checked_at=ps.latest_checked_at,
        release_check_enabled=ps.github_release_check_enabled,
        latest_check_error=ps.latest_check_error,
        **_appliance_fields(True),
    )
