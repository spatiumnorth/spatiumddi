"""SpatiumDDI release management — Phase 4c.

Mounted at ``/api/v1/appliance/releases``. Read-only:
    GET / — list available releases + currently-installed version.

#294 — the old ``POST /apply`` + ``GET /log`` endpoints were removed.
They drove a pre-#183 docker-compose update (a trigger file watched by
a host-side ``spatiumddi-update.path`` unit running
``docker-compose pull && up -d``), which does nothing on the k3s
appliance — no compose stack, no such unit. OS upgrades on the
appliance go through the A/B slot image flow (``slot.py`` /
``services/appliance/slot.py``, surfaced on the Fleet tab); docker/k8s
control planes run the manual ``docker compose`` / ``helm upgrade``
commands the UI shows.
"""

from __future__ import annotations

from datetime import datetime

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.permissions import require_permission
from app.services.api_token_scopes import token_outbound
from app.services.appliance.releases import (
    get_installed_version,
)
from app.services.appliance.releases import (
    list_releases as svc_list_releases,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


class ReleaseInfo(BaseModel):
    tag: str
    name: str
    published_at: datetime
    body: str
    html_url: str
    is_prerelease: bool
    is_installed: bool


class ReleasesResponse(BaseModel):
    installed_version: str
    releases: list[ReleaseInfo]


@router.get(
    "",
    response_model=ReleasesResponse,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="List available releases + currently-installed version",
)
@token_outbound
async def list_releases() -> ReleasesResponse:
    rels = await svc_list_releases()
    return ReleasesResponse(
        installed_version=get_installed_version(),
        releases=[
            ReleaseInfo(
                tag=r.tag,
                name=r.name,
                published_at=r.published_at,
                body=r.body,
                html_url=r.html_url,
                is_prerelease=r.is_prerelease,
                is_installed=r.is_installed,
            )
            for r in rels
        ],
    )
