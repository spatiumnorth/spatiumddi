"""DHCP API router aggregation.

``agents.router`` is deliberately NOT included here (#1068). It is
mounted separately at the v1 level, under the same ``/dhcp`` prefix so
the wire path is unchanged, because this router carries the
``core.dhcp`` gate and ``require_module`` answers **404** — the one
status that makes a DHCP agent discard its JWT and re-bootstrap from the
PSK ("Agent bootstrap + reconnection" in CLAUDE.md). Gating the agent
long-poll would not disable a fleet, it would put every live Kea agent
into a re-bootstrap loop against a surface that keeps saying 404.

It keeps ``wake_publishing`` at that mount point, because
``/dhcp/agents/lease-events`` drives subnet DDNS and so does enqueue
record ops.

The DNS side has always had this shape; only DHCP nested its agent
router, which is why this file changed and ``dns/__init__.py`` did not.
"""

from fastapi import APIRouter

from app.api.v1.dhcp.client_classes import router as client_classes_router
from app.api.v1.dhcp.device_policies import router as device_policies_router
from app.api.v1.dhcp.lease_history import router as lease_history_router
from app.api.v1.dhcp.leases import router as leases_router
from app.api.v1.dhcp.mac_blocks import router as mac_blocks_router
from app.api.v1.dhcp.option_codes import router as option_codes_router
from app.api.v1.dhcp.option_templates import router as option_templates_router
from app.api.v1.dhcp.phone_profiles import router as phone_profiles_router
from app.api.v1.dhcp.pools import router as pools_router
from app.api.v1.dhcp.pxe_profiles import router as pxe_profiles_router
from app.api.v1.dhcp.responders import router as responders_router
from app.api.v1.dhcp.scopes import router as scopes_router
from app.api.v1.dhcp.server_groups import router as server_groups_router
from app.api.v1.dhcp.servers import router as servers_router
from app.api.v1.dhcp.statics import router as statics_router
from app.api.v1.dhcp.vendor_presets import router as vendor_presets_router
from app.api.v1.dhcp.voip_options import router as voip_options_router

router = APIRouter()
router.include_router(server_groups_router)
router.include_router(servers_router)
router.include_router(lease_history_router)
router.include_router(leases_router)
router.include_router(scopes_router)
router.include_router(pools_router)
router.include_router(pxe_profiles_router)
router.include_router(phone_profiles_router)
router.include_router(statics_router)
router.include_router(client_classes_router)
# #700 — fingerprint-driven device policies, which compile into the same
# Kea client-class list the router above manages by hand.
router.include_router(device_policies_router)
router.include_router(mac_blocks_router)
router.include_router(option_codes_router)
router.include_router(option_templates_router)
router.include_router(voip_options_router)
router.include_router(vendor_presets_router)
router.include_router(responders_router)

__all__ = ["router"]
