"""Running-version + release-check endpoint.

Public (no auth) because the sidebar renders before login and the
release-check banner is visible even on the login screen. The response
is tiny and cacheable; no sensitive data leaks beyond the version
string itself — which is also stamped on every Docker image's OCI
label anyway.

SECURITY (#400 / L6): the appliance-specific fields
(``appliance_version`` / ``appliance_hostname``) DO leak operational
detail — most notably the host's configured hostname — so they are
withheld from unauthenticated callers. The endpoint stays public for
the bare ``version`` + release-check banner; appliance fields populate
only when a valid Bearer credential is presented.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, get_current_user
from app.config import settings
from app.core.versions import canonical_version
from app.db import get_db
from app.models.auth import User
from app.models.settings import PlatformSettings

router = APIRouter(tags=["version"])

_SINGLETON_ID = 1

# Optional-auth bearer — ``auto_error=False`` so an anonymous caller
# (login screen / sidebar pre-login) still gets a 200 with the public
# fields. A *present* credential is fully validated; only on success do
# the appliance fields populate.
_optional_bearer = HTTPBearer(auto_error=False)


async def _maybe_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_optional_bearer)],
) -> User | None:
    """Return the authenticated user if a valid Bearer is presented, else None.

    SECURITY (#400 / L6): never raises — an absent / invalid / expired
    credential resolves to ``None`` so the version endpoint stays public,
    but the appliance fields are gated on a non-None return.
    """
    if credentials is None:
        return None
    try:
        return await get_current_user(request, db, credentials)
    except Exception:  # noqa: BLE001 — any auth failure = treat as anonymous
        return None


MaybeUser = Annotated[User | None, Depends(_maybe_current_user)]


class VersionResponse(BaseModel):
    # The running version (the image tag / env var the operator set).
    version: str
    # GitHub release-check result. All nullable so a deployment with
    # the release check disabled (or that's never successfully checked)
    # reports a clean "no data yet" state rather than misleading zeros.
    latest_version: str | None
    update_available: bool
    latest_release_url: str | None
    latest_checked_at: datetime | None
    # Set when the release check is turned off — so the UI can
    # distinguish "never checked" from "operator opted out".
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
async def get_version(db: DB, current_user: MaybeUser) -> VersionResponse:
    authenticated = current_user is not None
    ps = await db.get(PlatformSettings, _SINGLETON_ID)
    if ps is None:
        # Settings row hasn't been seeded yet (first boot before
        # /admin/settings is opened). Report the runtime version and
        # leave everything else empty — no fabricated state.
        return VersionResponse(
            version=canonical_version(settings.version, settings.app_version),
            latest_version=None,
            update_available=False,
            latest_release_url=None,
            latest_checked_at=None,
            release_check_enabled=True,
            latest_check_error=None,
            **_appliance_fields(authenticated),
        )
    return VersionResponse(
        version=canonical_version(settings.version, settings.app_version),
        latest_version=ps.latest_version,
        update_available=ps.update_available,
        latest_release_url=ps.latest_release_url,
        latest_checked_at=ps.latest_checked_at,
        release_check_enabled=ps.github_release_check_enabled,
        latest_check_error=ps.latest_check_error,
        **_appliance_fields(authenticated),
    )
