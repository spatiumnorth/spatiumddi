"""The DHCP agent's config version key (#1109); mechanism in ``agents/config_version``.

``DHCP_CONFIG_PROBES`` lists every table ``build_config_bundle`` (and the
long-poll's own ETag mix: PlatformSettings blocks, the server's fleet columns)
reads. The guard in ``tests/test_agent_config_version.py`` records the tables a
real build touches and fails when one is missing here, so a new contributor
cannot be added to the bundle without the key learning of it.

Group-scoped where it is cheap and certain (the group's own rows), and
whole-table where a row's relationship to the group is indirect (E911 bindings
resolve through subnets, VLANs and sites): a whole-table probe only ever
over-triggers.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.services.agents.config_version import (
    Probe,
    config_version,
    raw_probe,
    row_probe,
    xmin_probe,
)

_G = "CAST(:g AS uuid)"
_SCOPES_OF_GROUP = f"(SELECT id FROM dhcp_scope WHERE group_id = {_G})"

#: dhcp_server columns the agents' own reports rewrite (heartbeat, config
#: apply, daemon state, HA state), none of which the bundle or the long-poll's
#: ETag reads. Every other column counts as config, including ones that look
#: runtime (agent_capabilities decides whether peer TLS renders).
DHCP_SERVER_VOLATILE = (
    "status",
    "last_sync_at",
    "last_sync_error",
    "last_sync_error_at",
    "last_health_check_at",
    "agent_last_seen",
    "last_seen_ip",
    "config_apply_status",
    "config_apply_error",
    "config_failed_etag",
    "config_apply_at",
    "spool_status",
    "daemon_status",
    "daemon_reason",
    "daemon_status_since",
    "agent_instance_seen_at",
    "config_etag",
    "config_pushed_at",
    "ha_state",
    "ha_last_heartbeat_at",
    "scopes_observed_at",
    "failover_observed_at",
    "failover_error",
    "modified_at",
)

#: dhcp_fingerprint columns every observation / enrichment rewrites; the
#: device-policy compiler reads the option strings, class and score only.
DHCP_FINGERPRINT_VOLATILE = (
    "first_seen_at",
    "last_seen_at",
    "fingerbank_last_lookup_at",
    "fingerbank_last_error",
    "modified_at",
)

DHCP_CONFIG_PROBES: list[Probe] = [
    xmin_probe("dhcp_server_group", f"id = {_G}"),
    # The group's members (HA peers) and this server's own fleet columns.
    row_probe(
        "dhcp_server",
        exclude=DHCP_SERVER_VOLATILE,
        where=f"server_group_id = {_G} OR id = CAST(:sid AS uuid)",
    ),
    xmin_probe("dhcp_scope", f"group_id = {_G}"),
    xmin_probe("dhcp_pool", f"scope_id IN {_SCOPES_OF_GROUP}"),
    xmin_probe("dhcp_static_assignment", f"scope_id IN {_SCOPES_OF_GROUP}"),
    xmin_probe("dhcp_client_class", f"group_id = {_G}"),
    xmin_probe("dhcp_mac_block", f"group_id = {_G}"),
    # A block expires with no row changing; the bundle drops it by the clock.
    raw_probe(
        "dhcp_mac_block_live",
        f"SELECT count(*) FROM dhcp_mac_block WHERE group_id = {_G} AND enabled "
        "AND (expires_at IS NULL OR expires_at > clock_timestamp())",
    ),
    xmin_probe("dhcp_pxe_profile"),
    xmin_probe("dhcp_pxe_arch_match"),
    xmin_probe("dhcp_phone_profile"),
    xmin_probe("dhcp_phone_profile_scope"),
    xmin_probe("dhcp_device_policy", f"group_id = {_G}"),
    xmin_probe("subnet", f"id IN (SELECT subnet_id FROM dhcp_scope WHERE group_id = {_G})"),
    xmin_probe("emergency_response_location"),
    xmin_probe("erl_binding"),
    # Read by the device-policy classes and the E911 resolver (found by the
    # capture guard in the tests, not by reading code).
    # Fingerprints compile into device-policy classes (so the bundle moves
    # without an operator edit), but only while an enabled policy exists, and
    # every observation rewrites ``last_seen_at``: fingerprinted by what the
    # compiler reads, and only then.
    row_probe(
        "dhcp_fingerprint",
        exclude=DHCP_FINGERPRINT_VOLATILE,
        order_by="mac_address",
        where=f"EXISTS (SELECT 1 FROM dhcp_device_policy WHERE group_id = {_G} AND enabled)",
    ),
    xmin_probe("vlan"),
    xmin_probe("router"),
    xmin_probe("feature_module"),
    xmin_probe("platform_settings"),
]


async def dhcp_config_version(db: AsyncSession, server: DHCPServer) -> str:
    """The key for ``server``'s bundle plus the fleet / host-config mix."""
    return await config_version(
        db,
        DHCP_CONFIG_PROBES,
        g=str(server.server_group_id) if server.server_group_id else None,
        sid=str(server.id),
    )
