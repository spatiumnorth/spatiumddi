import asyncio
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress

import structlog
import structlog.contextvars
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.acme_well_known import router as acme_well_known_router
from app.api.health import router as health_router
from app.api.v1.e911.held_router import router as e911_held_router
from app.api.v1.router import api_v1_router
from app.config import settings
from app.core.maintenance_mode import MaintenanceModeMiddleware
from app.core.openapi_compat import collapse_nullable_unions
from app.log import configure_logging
from app.metrics import PrometheusMiddleware, metrics_endpoint

# Import for side-effect: registers the SQLAlchemy after_commit listener
# that forwards audit events to syslog + webhook targets. Must run at app
# startup so the listener is attached before any request handler writes
# an AuditLog row.
from app.services import (
    audit_forward,  # noqa: F401
    event_publisher,  # noqa: F401
)
from app.services.feature_modules import require_module

logger = structlog.get_logger(__name__)


async def _assert_demo_mode_not_on_prod_data() -> None:
    """SECURITY (#400 / M7): DEMO_MODE seeds an unlocked admin/admin
    superadmin (``force_password_change`` skipped) and unlocks abusable
    surfaces — it must NEVER land on a production image. Detect the
    tell-tale signs of a real deployment (configured backup targets,
    integration mirror targets, or external auth providers) and fail
    fast so the demo flag can't silently leak onto prod.

    No-op unless ``DEMO_MODE=1``. On a genuine demo image these tables
    are empty, so the legitimate demo flow is untouched. Failure-tolerant
    on the pre-migration / missing-table case — we can't assert against a
    schema that isn't there yet, and that's not a prod install anyway.
    """
    if not settings.demo_mode:
        return

    from sqlalchemy import text  # noqa: PLC0415

    from app.db import AsyncSessionLocal  # noqa: PLC0415

    # Tables whose presence of ANY row means "this is a real deployment".
    # Fixed allow-list of literal identifiers (no user input) — the only
    # values ever interpolated below are these constants, so the count
    # query carries no injection surface. A missing table (pre-migration)
    # degrades to the failure-tolerant skip path rather than crashing boot.
    prod_signal_tables = (
        "backup_target",
        "audit_forward_target",
        "auth_provider",
        "kubernetes_cluster",
        "docker_host",
        "proxmox_node",
        "tailscale_tenant",
        "unifi_controller",
        "cloud_endpoint",
    )
    offenders: list[str] = []
    try:
        async with AsyncSessionLocal() as session:
            for table in prod_signal_tables:
                try:
                    # ``table`` is a hardcoded constant from the tuple
                    # above, never request-derived — safe to interpolate.
                    n = await session.scalar(text(f"SELECT count(*) FROM {table}"))  # noqa: S608
                except Exception as exc:  # noqa: BLE001
                    # Table missing (pre-migration) or unreadable — can't
                    # be a populated prod install; skip this signal.
                    logger.debug("demo_mode_prod_check_skipped", table=table, reason=str(exc))
                    continue
                if n and n > 0:
                    offenders.append(f"{table}={n}")
    except RuntimeError:
        raise
    except Exception as exc:  # noqa: BLE001
        # DB unreachable at boot — can't prove prod data either way.
        # Don't crash the (possibly legitimate) demo boot on transient
        # connectivity; the offender check below simply finds nothing.
        logger.debug("demo_mode_prod_check_db_unavailable", reason=str(exc))

    if offenders:
        # SECURITY (#400 / M7): a demo image with real deployment data is
        # a leaked demo flag on prod — refuse to boot rather than serve an
        # unlocked admin/admin superadmin.
        raise RuntimeError(
            "DEMO_MODE=1 is set but real configured deployment data was "
            "found ("
            + ", ".join(offenders)
            + "). DEMO_MODE seeds an unlocked admin/admin superadmin and "
            "must NOT run against a production install. Unset DEMO_MODE "
            "(or wipe the demo data) before booting."
        )


async def _seed_default_admin() -> None:
    """Create the default admin user if no users exist yet."""
    from sqlalchemy import func, select

    from app.core.security import hash_password
    from app.db import AsyncSessionLocal
    from app.models.auth import User

    # SECURITY (#400 / M7): hard-stop the demo flag from booting on a real
    # install BEFORE we (possibly) seed an unlocked admin. Raises on a
    # prod-data collision; no-op otherwise.
    await _assert_demo_mode_not_on_prod_data()

    async with AsyncSessionLocal() as session:
        try:
            count = await session.scalar(select(func.count()).select_from(User))
            if count == 0:
                # Demo deployments lock the password (admin/admin
                # sticks for the next visitor); skip the
                # force-password-change flag so the demo lands on the
                # dashboard instead of a redirect to a 403'd form.
                admin = User(
                    username="admin",
                    email="admin@localhost",
                    display_name="Administrator",
                    hashed_password=hash_password("admin"),
                    is_superadmin=True,
                    is_active=True,
                    auth_source="local",
                    force_password_change=not settings.demo_mode,
                )
                session.add(admin)
                await session.commit()
                logger.warning(
                    "default_admin_created",
                    username="admin",
                    message="Default admin created with password 'admin' — change it immediately",
                )
        except Exception as exc:
            # Table may not exist yet (pre-migration). Skip silently.
            logger.debug("default_admin_seed_skipped", reason=str(exc))


# Built-in roles installed on first boot. Shape matches docs/PERMISSIONS.md.
# Keys are the role names; the tuple is (description, permissions).
_BUILTIN_ROLES: dict[str, tuple[str, list[dict[str, object]]]] = {
    "Superadmin": (
        "Full control — wildcard on all actions and resources.",
        [{"action": "*", "resource_type": "*"}],
    ),
    "Viewer": (
        "Read-only access to every resource.",
        [{"action": "read", "resource_type": "*"}],
    ),
    "IPAM Editor": (
        "Full CRUD on IPAM objects (spaces, blocks, subnets, addresses, VLANs, "
        "NAT mappings, custom fields, IPAM templates) plus the logical "
        "ownership tags (customer / site / provider) IPAM rows reference and "
        "the customer-deliverable services (#94) those bundles belong to.",
        [
            {"action": "admin", "resource_type": "ip_space"},
            {"action": "admin", "resource_type": "ip_block"},
            {"action": "admin", "resource_type": "subnet"},
            {"action": "admin", "resource_type": "ip_address"},
            {"action": "admin", "resource_type": "address_set"},
            {"action": "admin", "resource_type": "vlan"},
            {"action": "admin", "resource_type": "nat_mapping"},
            {"action": "admin", "resource_type": "custom_field"},
            {"action": "admin", "resource_type": "manage_ipam_templates"},
            {"action": "admin", "resource_type": "customer"},
            {"action": "admin", "resource_type": "site"},
            {"action": "admin", "resource_type": "provider"},
            {"action": "admin", "resource_type": "network_service"},
        ],
    ),
    "Address Set Editor": (
        "Admin on address sets — delegated edit of a named IP slice within a "
        "subnet (its own range) without subnet-wide write. Grant on a specific "
        "address-set id to scope a department admin to just their slice. Note: "
        "creating a set or resizing its range additionally requires write on the "
        "parent subnet (carving/widening a delegation slice is a subnet-owner "
        "operation); set-scoped admins may still edit name / description / tags / "
        "ownership without subnet write.",
        [
            {"action": "admin", "resource_type": "address_set"},
        ],
    ),
    "Change Approver": (
        "Approve or reject queued change requests in the two-person approval "
        "workflow (#62). Grants ``approve`` + ``read`` on the synthetic "
        "``change_request`` resource_type. Note: this role only confers the "
        "second-person decision capability — to approve a specific request the "
        "operator must ALSO hold the underlying operation's permission (e.g. "
        "``delete,subnet`` to approve a subnet delete), enforced server-side at "
        "the approve endpoint, and may never approve their own request.",
        [
            {"action": "approve", "resource_type": "change_request"},
            {"action": "read", "resource_type": "change_request"},
        ],
    ),
    "Requester": (
        "Submit self-service requests for IP addresses, subnets, DNS records and "
        "DHCP reservations (#696). This is the LOW-privilege half of the workflow "
        "and is meant to be granted broadly — to a whole department, not just the "
        "network team. Holding it confers no ability to provision anything: a "
        "submitted request only becomes a change when a *different* operator who "
        "holds the underlying operation's own permission (e.g. ``write,subnet`` to "
        "approve a subnet request) approves it, enforced server-side by the shared "
        "#62 approve spine. Requesters see only their own requests.",
        [
            {"action": "write", "resource_type": "provisioning_request"},
            {"action": "read", "resource_type": "provisioning_request"},
        ],
    ),
    "DNS Editor": (
        "Full CRUD on DNS zones, records, server groups, blocklists, and pools.",
        [
            {"action": "admin", "resource_type": "dns_group"},
            {"action": "admin", "resource_type": "dns_zone"},
            {"action": "admin", "resource_type": "dns_record"},
            {"action": "admin", "resource_type": "dns_blocklist"},
            {"action": "admin", "resource_type": "manage_dns_pools"},
        ],
    ),
    "DHCP Editor": (
        "Full CRUD on DHCP servers, scopes, pools, statics, client classes, "
        "option templates, and MAC blocks.",
        [
            {"action": "admin", "resource_type": "dhcp_server"},
            {"action": "admin", "resource_type": "dhcp_scope"},
            {"action": "admin", "resource_type": "dhcp_pool"},
            {"action": "admin", "resource_type": "dhcp_static"},
            {"action": "admin", "resource_type": "dhcp_client_class"},
            {"action": "admin", "resource_type": "dhcp_option_template"},
            {"action": "admin", "resource_type": "dhcp_mac_block"},
        ],
    ),
    "Network Editor": (
        "Full CRUD on SNMP-polled network devices (routers, switches, APs), "
        "on-demand nmap scans, the ASN registry, VRFs, WAN circuits, "
        "SD-WAN overlay topology + routing policies + the application "
        "catalog (#95), the customer-deliverable services (#94) those "
        "resources bundle into, the vertical network-awareness registries "
        "(AV-over-IP flows, BACnet/IP devices, industrial-OT devices, "
        "DICOM application entities), and "
        "the logical ownership tags (customer / site / provider) those "
        "entities reference.",
        [
            {"action": "admin", "resource_type": "manage_network_devices"},
            {"action": "admin", "resource_type": "manage_nmap_scans"},
            {"action": "admin", "resource_type": "manage_packet_capture"},
            {"action": "admin", "resource_type": "manage_block_sync"},
            {"action": "admin", "resource_type": "use_network_tools"},
            {"action": "admin", "resource_type": "manage_asns"},
            {"action": "admin", "resource_type": "vrf"},
            {"action": "admin", "resource_type": "circuit"},
            {"action": "admin", "resource_type": "multicast"},
            {"action": "admin", "resource_type": "av_flow"},
            {"action": "admin", "resource_type": "bacnet_device"},
            {"action": "admin", "resource_type": "dicom_ae"},
            {"action": "admin", "resource_type": "e911_location"},
            {"action": "admin", "resource_type": "ot_device"},
            {"action": "admin", "resource_type": "network_service"},
            {"action": "admin", "resource_type": "overlay_network"},
            {"action": "admin", "resource_type": "routing_policy"},
            {"action": "admin", "resource_type": "application_category"},
            {"action": "admin", "resource_type": "customer"},
            {"action": "admin", "resource_type": "site"},
            {"action": "admin", "resource_type": "provider"},
            {"action": "admin", "resource_type": "tls_cert"},
            {"action": "admin", "resource_type": "dnsbl"},
        ],
    ),
    "Auditor": (
        "Read-only on conformity evaluations (issue #106) plus read on "
        "audit log + classifications. Suitable for an external auditor "
        "account that should be able to pull the conformity PDF and "
        "verify the underlying evidence without making changes.",
        [
            {"action": "read", "resource_type": "conformity"},
            {"action": "read", "resource_type": "audit"},
            {"action": "read", "resource_type": "subnet"},
            {"action": "read", "resource_type": "ip_address"},
            {"action": "read", "resource_type": "dns_zone"},
            {"action": "read", "resource_type": "dhcp_scope"},
            {"action": "read", "resource_type": "tls_cert"},
        ],
    ),
    "Compliance Editor": (
        "Full CRUD on conformity policies (issue #106) plus read on the "
        "underlying resources (subnets / IPs / zones / scopes) so the "
        "compliance team can author + tune policies without touching "
        "operational config.",
        [
            {"action": "admin", "resource_type": "conformity"},
            {"action": "read", "resource_type": "audit"},
            {"action": "read", "resource_type": "subnet"},
            {"action": "read", "resource_type": "ip_address"},
            {"action": "read", "resource_type": "dns_zone"},
            {"action": "read", "resource_type": "dhcp_scope"},
        ],
    ),
    "Appliance Operator": (
        "Full control of the SpatiumDDI OS appliance management surface "
        "(issue #134, Phase 4): TLS cert upload, release manager, "
        "container start/stop/restart + live logs, host network + "
        "firewall config, maintenance mode, diagnostic bundle download. "
        "Intended for ops staff who manage the appliance lifecycle "
        "without needing full superadmin over the DDI data plane. "
        "Granted ``admin`` on resource_type=appliance; superadmin "
        "always bypasses anyway.",
        [
            {"action": "admin", "resource_type": "appliance"},
        ],
    ),
}


async def _seed_builtin_roles() -> None:
    """Insert built-in roles on first start; refresh their permissions on every boot.

    The permissions on built-in roles are owned by the code, not the admin UI —
    if the role already exists we still overwrite `permissions` and `description`
    so upgrades ship new resource types without a manual edit. `name` is used
    as the stable identity; admins who want to tweak built-in permission sets
    should clone the role first.
    """
    from sqlalchemy import select

    from app.db import AsyncSessionLocal
    from app.models.auth import Role

    async with AsyncSessionLocal() as session:
        try:
            for name, (description, perms) in _BUILTIN_ROLES.items():
                existing = await session.scalar(select(Role).where(Role.name == name))
                if existing is None:
                    session.add(
                        Role(
                            name=name,
                            description=description,
                            is_builtin=True,
                            permissions=perms,
                        )
                    )
                else:
                    existing.description = description
                    existing.permissions = perms
                    existing.is_builtin = True
            await session.commit()
        except Exception as exc:
            logger.debug("builtin_roles_seed_skipped", reason=str(exc))


def _log_backup_section_catalog_gap() -> None:
    """Report tables the selective-restore section catalog doesn't classify.

    ``assert_catalog_covers_models`` was written to run here and never wired
    up, so the catalog silently fell behind the models: a table nobody
    classified cannot be *chosen* for a selective restore.
    ``tests/test_rewrap_coverage.py`` keeps the gap from *growing*; this makes
    the current gap visible to an operator reading the logs rather than only
    to someone running the suite (#781).

    Note this is now a usability gap, not a data-loss one. Uncatalogued
    tables used to be cascade-truncated and left empty; since the same issue
    taught selective restore to restore the whole FK-cascade closure, they
    are repopulated from the archive — reverted along with the selection
    rather than emptied.

    Synchronous + non-fatal on purpose: it reads mapped metadata only, touches
    no database, and must never be able to keep the api from starting.
    """
    try:
        from app.models.base import Base  # noqa: PLC0415
        from app.services.backup.sections import (  # noqa: PLC0415
            assert_catalog_covers_models,
        )

        missing = assert_catalog_covers_models({t.name for t in Base.metadata.sorted_tables})
        if missing:
            logger.warning(
                "backup_section_catalog_incomplete",
                missing_count=len(missing),
                missing=missing,
                impact=(
                    "these tables cannot be explicitly selected for a selective "
                    "restore; they are still reverted to the archive's state "
                    "whenever a selected section's FK-cascade closure reaches them"
                ),
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("backup_section_catalog_check_skipped", reason=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_logging()
    logger.info("startup", service="api", version=settings.version, debug=settings.debug)
    await _seed_default_admin()
    await _seed_builtin_roles()
    _log_backup_section_catalog_gap()
    # Standard / well-known BGP communities (RFC 1997 / 7611 / 7999).
    # Idempotent; failure-tolerant.
    try:
        from app.services.bgp_communities import (  # noqa: PLC0415
            seed_standard_communities,
        )

        await seed_standard_communities()
    except Exception as exc:  # noqa: BLE001
        logger.debug("bgp_communities_seed_skipped", reason=str(exc))
    # Curated SD-WAN application catalog (Office365, Zoom, Slack,
    # GitHub, …). Idempotent; failure-tolerant.
    try:
        from app.services.applications import (  # noqa: PLC0415
            seed_builtin_applications,
        )

        await seed_builtin_applications()
    except Exception as exc:  # noqa: BLE001
        logger.debug("builtin_applications_seed_skipped", reason=str(exc))
    # Compliance-change alert rules — three disabled stubs (PCI /
    # HIPAA / internet-facing). Issue #105. Idempotent;
    # failure-tolerant. The seeder only inserts a row when no rule
    # of the matching ``rule_type + classification`` already exists,
    # so operators who toggled / customised one are never overridden.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_builtin_compliance_alert_rules,
        )

        await seed_builtin_compliance_alert_rules()
    except Exception as exc:  # noqa: BLE001
        logger.debug("compliance_alert_rules_seed_skipped", reason=str(exc))
    # Conformity policies — eight starter rows covering PCI / HIPAA /
    # internet-facing / SOC2 (issue #106). Disabled by default so
    # they don't burn cycles until the operator opts in.
    # Idempotent; failure-tolerant.
    try:
        from app.services.conformity import (  # noqa: PLC0415
            seed_builtin_conformity_policies,
        )

        await seed_builtin_conformity_policies()
    except Exception as exc:  # noqa: BLE001
        logger.debug("conformity_policies_seed_skipped", reason=str(exc))
    # Audit-chain-broken alert rule — singleton, enabled by default
    # (issue #73). Idempotent; if an operator has disabled it the
    # seeder doesn't re-flip the toggle.
    try:
        from app.services.alerts import seed_audit_chain_alert_rule  # noqa: PLC0415

        await seed_audit_chain_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("audit_chain_alert_rule_seed_skipped", reason=str(exc))
    # schema-behind-head alert rule — singleton, enabled by default
    # (issue #565). Fires when the Celery worker/beat finds the DB
    # schema behind the bundled Alembic head. Idempotent seed.
    try:
        from app.services.alerts import seed_schema_behind_head_alert_rule  # noqa: PLC0415

        await seed_schema_behind_head_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("schema_behind_head_alert_rule_seed_skipped", reason=str(exc))
    # cluster-upgrade-failed alert rule — singleton, enabled by default
    # (issue #296 Phase F). Fires when the rolling-upgrade orchestrator
    # flips a SystemUpgradeRun to ``state='failed'``.
    try:
        from app.services.upgrades.alerts import (  # noqa: PLC0415
            seed_cluster_upgrade_failed_alert_rule,
        )

        await seed_cluster_upgrade_failed_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("cluster_upgrade_failed_alert_rule_seed_skipped", reason=str(exc))
    # Firewall-apply-stalled alert rule — singleton, DISABLED by default
    # (issue #285 Phase 2d). Fires when a node's control-plane-rendered
    # firewall ruleset goes un-applied past a grace window. Idempotent.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_firewall_apply_stalled_alert_rule,
        )

        await seed_firewall_apply_stalled_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("firewall_apply_stalled_alert_rule_seed_skipped", reason=str(exc))
    # Agent config-apply-rejected alert rule — singleton, ENABLED by default
    # (issue #882). Fires when an agent reverts to its last-known-good config
    # because the one we sent would not apply. Idempotent.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_agent_config_rejected_alert_rule,
        )

        await seed_agent_config_rejected_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("agent_config_rejected_alert_rule_seed_skipped", reason=str(exc))
    # Agent push-spool-trimmed alert rule — singleton, ENABLED by default
    # (issue #1077). Silent unless an agent's outage spool hit its byte cap
    # and discarded data. Idempotent.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_agent_spool_trimmed_alert_rule,
        )

        await seed_agent_spool_trimmed_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("agent_spool_trimmed_alert_rule_seed_skipped", reason=str(exc))
    # Uncoordinated DHCP scope alert rule — singleton, ENABLED by default
    # (issue #1110). Silent unless two servers already serve one scope
    # without coordinating. Idempotent.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_dhcp_scope_uncoordinated_alert_rule,
        )

        await seed_dhcp_scope_uncoordinated_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dhcp_scope_uncoordinated_alert_rule_seed_skipped", reason=str(exc))
    # Node resource-pressure (PSI) alert rule — singleton, ENABLED by default
    # (issue #983 Phase 2). Cannot fire on a kubelet below 1.36, which reports
    # no PSI at all, so enabling it everywhere is silent until it is real.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_appliance_storage_alert_rule,
            seed_cluster_dns_alert_rule,
            seed_node_pressure_alert_rule,
        )

        await seed_node_pressure_alert_rule()
        await seed_cluster_dns_alert_rule()
        # Storage redundancy (#999 Part A) — cannot fire on an appliance
        # with no arrays, or on a supervisor too old to report them.
        await seed_appliance_storage_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("node_pressure_alert_rule_seed_skipped", reason=str(exc))
    # DHCP packet-loss alert rule — singleton, ENABLED by default (issue
    # #980). Reads counters every Kea agent reports unconditionally; a server
    # whose agent is too old to report them is skipped, not alarmed on, so
    # enabling it everywhere is silent until it is real. Idempotent.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_dhcp_packets_dropped_alert_rule,
        )

        await seed_dhcp_packets_dropped_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dhcp_packets_dropped_alert_rule_seed_skipped", reason=str(exc))
    # DNS query-anomaly alert rules — NXDOMAIN-spike + query-rate-spike,
    # singletons, DISABLED by default (issue #371). Discoverable in the
    # Alerts UI; fire only on agent-based BIND9 installs with metric data.
    try:
        from app.services.alerts import (  # noqa: PLC0415
            seed_dns_query_anomaly_alert_rules,
        )

        await seed_dns_query_anomaly_alert_rules()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dns_query_anomaly_alert_rule_seed_skipped", reason=str(exc))
    # IP-reconciliation hygiene alert rules — free-but-responding /
    # stale-reservation / unknown-MAC-in-static-range, DISABLED by default
    # (issue #369). Fire only on installs running subnet discovery.
    try:
        from app.services.alerts import seed_ip_hygiene_alert_rules  # noqa: PLC0415

        await seed_ip_hygiene_alert_rules()
    except Exception as exc:  # noqa: BLE001
        logger.debug("ip_hygiene_alert_rule_seed_skipped", reason=str(exc))
    # Rogue DHCP server alert rule — singleton, DISABLED by default (issue
    # #370). Fires only on segments running the agent's active DHCP probe.
    try:
        from app.services.alerts import seed_rogue_dhcp_alert_rule  # noqa: PLC0415

        await seed_rogue_dhcp_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("rogue_dhcp_alert_rule_seed_skipped", reason=str(exc))
    # Rogue IPv6 RA alert rule — singleton, DISABLED by default (issue #524).
    # Fires only on segments running the agent's passive RA sniffer.
    try:
        from app.services.alerts import seed_rogue_ra_alert_rule  # noqa: PLC0415

        await seed_rogue_ra_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("rogue_ra_alert_rule_seed_skipped", reason=str(exc))
    # Wake-on-LAN verify-failed alert rule — singleton, DISABLED by default
    # (issue #596). Fires only for schedules that arm post-wake verify.
    try:
        from app.services.alerts import seed_wol_wake_failed_alert_rule  # noqa: PLC0415

        await seed_wol_wake_failed_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("wol_wake_failed_alert_rule_seed_skipped", reason=str(exc))
    # New-device (arpwatch) alert rule — singleton, DISABLED by default (issue
    # #459). Fires on never-before-seen MACs once new-device watch is on.
    try:
        from app.services.alerts import seed_new_mac_seen_alert_rule  # noqa: PLC0415

        await seed_new_mac_seen_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("new_mac_seen_alert_rule_seed_skipped", reason=str(exc))
    # TLS certificate monitoring alert rules — four, DISABLED by default
    # (issue #118). Opt-in once the operator adds probe targets.
    try:
        from app.services.alerts import seed_tls_cert_alert_rules  # noqa: PLC0415

        await seed_tls_cert_alert_rules()
    except Exception as exc:  # noqa: BLE001
        logger.debug("tls_cert_alert_rules_seed_skipped", reason=str(exc))
    # BGP prefix-hijack alert rules — two, DISABLED by default (issue
    # #527). Fire only once BGP monitoring (bgp_monitoring_enabled) is on
    # and the operator has curated tracked prefixes.
    try:
        from app.services.alerts import seed_bgp_hijack_alert_rules  # noqa: PLC0415

        await seed_bgp_hijack_alert_rules()
    except Exception as exc:  # noqa: BLE001
        logger.debug("bgp_hijack_alert_rules_seed_skipped", reason=str(exc))
    # BGP Looking Glass troubleshooting alert rules — six, DISABLED by
    # default (issue #566 Phase 5). Fire only once peers are configured
    # (session_down / rpki_invalid_route / route_flap / a peer's own
    # feed) and, for unexpected_origin / more_specific, at least one
    # BGPTrackedPrefix owned-prefix row exists via the #527 UI; for
    # missing_advertisement, at least one Subnet has
    # bgp_should_advertise=true.
    try:
        from app.services.alerts import seed_bgp_lg_alert_rules  # noqa: PLC0415

        await seed_bgp_lg_alert_rules()
    except Exception as exc:  # noqa: BLE001
        logger.debug("bgp_lg_alert_rules_seed_skipped", reason=str(exc))
    # DNSBL / RBL reputation catalog + alert rule (issue #528). The catalog
    # seeds the curated blocklists as platform rows (all disabled); the
    # ip_blocklisted alert rule seeds disabled. No off-prem calls at seed time.
    try:
        from app.services.dnsbl import seed_dnsbl_catalog  # noqa: PLC0415

        await seed_dnsbl_catalog()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dnsbl_catalog_seed_skipped", reason=str(exc))
    try:
        from app.services.alerts import seed_ip_blocklisted_alert_rule  # noqa: PLC0415

        await seed_ip_blocklisted_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("ip_blocklisted_alert_rule_seed_skipped", reason=str(exc))
    try:
        from app.services.alerts import seed_restore_drill_failed_alert_rule  # noqa: PLC0415

        await seed_restore_drill_failed_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("restore_drill_alert_rule_seed_skipped", reason=str(exc))
    try:
        from app.services.alerts import seed_dns_tunneling_alert_rule  # noqa: PLC0415

        await seed_dns_tunneling_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dns_tunneling_alert_rule_seed_skipped", reason=str(exc))
    try:
        from app.services.alerts import seed_dns_beaconing_alert_rule  # noqa: PLC0415

        await seed_dns_beaconing_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dns_beaconing_alert_rule_seed_skipped", reason=str(exc))
    try:
        from app.services.alerts import seed_dns_dga_alert_rule  # noqa: PLC0415

        await seed_dns_dga_alert_rule()
    except Exception as exc:  # noqa: BLE001
        logger.debug("dns_dga_alert_rule_seed_skipped", reason=str(exc))
    # Appliance Web UI cert bootstrap (issue #134, Phase 4b.5). On
    # appliance installs without an active row in appliance_certificate,
    # generate a self-signed default + deploy it to /etc/nginx/certs
    # so the frontend container has something to serve from the very
    # first HTTPS hit. No-op on plain Docker / K8s deploys (gated on
    # settings.appliance_mode). Failure-tolerant — the appliance must
    # still come up on a non-TLS path even if cert bootstrap fails.
    try:
        from app.services.appliance.bootstrap import ensure_self_signed_cert  # noqa: PLC0415

        await ensure_self_signed_cert()
    except Exception as exc:  # noqa: BLE001
        logger.warning("appliance_self_signed_bootstrap_failed", error=str(exc))
    # Backfill enclosing IPBlocks for any pre-existing multicast
    # groups (issue #126 — IPAM-side rendering). Idempotent; only
    # creates blocks where missing. Cheap enough to run on every
    # boot since it's a single pass over ``multicast_group``.
    try:
        from app.db import AsyncSessionLocal  # noqa: PLC0415
        from app.services.multicast.auto_block import (  # noqa: PLC0415
            backfill_blocks_for_existing_groups,
        )

        async with AsyncSessionLocal() as session:
            n = await backfill_blocks_for_existing_groups(session)
        if n > 0:
            logger.info("multicast_blocks_backfilled", created=n)
    except Exception as exc:  # noqa: BLE001
        logger.debug("multicast_block_backfill_skipped", reason=str(exc))
    # Demo-mode lockdown — force the restricted feature modules off
    # and mirror the integration toggles into PlatformSettings so the
    # beat reconcilers stop. Idempotent; failure-tolerant. The PATCH
    # endpoint refuses to re-enable any restricted module while
    # ``DEMO_MODE=1`` is in effect (see app.core.demo_mode).
    if settings.demo_mode:
        try:
            from sqlalchemy import select  # noqa: PLC0415

            from app.core.demo_mode import (  # noqa: PLC0415
                DEMO_RESTRICTED_MODULES,
            )
            from app.db import AsyncSessionLocal  # noqa: PLC0415
            from app.models.settings import PlatformSettings  # noqa: PLC0415
            from app.services import feature_modules as fm_svc  # noqa: PLC0415

            async with AsyncSessionLocal() as session:
                for module_id in DEMO_RESTRICTED_MODULES:
                    if not fm_svc.is_known(module_id):
                        continue
                    await fm_svc.set_module_enabled(session, module_id, False, user_id=None)
                    mirror = fm_svc.INTEGRATION_SETTINGS_MIRROR.get(module_id)
                    if mirror is not None:
                        ps = await session.scalar(
                            select(PlatformSettings).where(PlatformSettings.id == 1)
                        )
                        if ps is not None:
                            setattr(ps, mirror, False)
                await session.commit()
            fm_svc.invalidate_cache()
            logger.info(
                "demo_mode_lockdown_applied",
                restricted_modules=sorted(DEMO_RESTRICTED_MODULES),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("demo_mode_lockdown_skipped", reason=str(exc))

    # #272 Phase 7c — periodic self-signed cert SAN reconcile. On a
    # multi-node appliance control plane the shared Web UI cert must
    # cover every cluster member's hostname + node IP (and the VIP), so
    # the UI validates on any node. This loop grows the self-signed cert
    # as nodes join (no-op on operator-uploaded certs + once converged).
    # All api replicas run it; a Postgres advisory lock + coverage check
    # keep it to one cheap query per tick + a single regenerate per
    # membership change. Appliance-mode only.
    cert_reconcile_task: asyncio.Task[None] | None = None
    if settings.appliance_mode:

        async def _cert_reconcile_loop() -> None:
            from app.services.appliance.bootstrap import (  # noqa: PLC0415
                reconcile_cluster_cert_sans,
            )

            while True:
                try:
                    await asyncio.sleep(90)
                    result = await reconcile_cluster_cert_sans()
                    if result.get("status") == "regenerated":
                        logger.info("appliance_cluster_cert_reconciled", **result)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.warning("appliance_cert_reconcile_failed", error=str(exc))

        cert_reconcile_task = asyncio.create_task(_cert_reconcile_loop())

    yield

    if cert_reconcile_task is not None:
        cert_reconcile_task.cancel()
        with suppress(asyncio.CancelledError):
            await cert_reconcile_task
    logger.info("shutdown", service="api")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request_id to structlog context for every request."""

    async def dispatch(self, request: Request, call_next: object) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            service="api",
        )
        response: Response = await call_next(request)  # type: ignore[arg-type]
        response.headers["X-Request-ID"] = request_id
        return response


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_title,
        description="Open-source DDI — DNS, DHCP, and IP Address Management",
        # #903 — the RUNNING version, not a literal. This was hardcoded
        # ``"0.1.0"`` while ``settings.version`` (from the ``VERSION`` env var
        # the compose file and Helm chart both already set) carried the real
        # one, so ``/api/docs`` and ``/api/openapi.json`` misreported every
        # deployment since the first release. It matters more now that the
        # document is published as a release asset and used to generate
        # clients: a spec that always claims 0.1.0 cannot be pinned against.
        # Falls back to ``"dev"`` for unversioned local builds, same as every
        # other consumer of ``settings.version``. The ``or`` is load-bearing:
        # pydantic-settings honours an EMPTY ``VERSION`` (so ``settings.version``
        # becomes ``""`` rather than defaulting), and FastAPI asserts on a falsy
        # version in ``__init__`` — which would turn a harmless misconfiguration
        # into an api container that dies at import with a bare AssertionError,
        # before logging is even configured.
        version=settings.version or "dev",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # Middleware (outermost first). Note Starlette wraps in REVERSE add
    # order: the LAST-added middleware runs outermost. So the request
    # flows in as TrustedHost → CORS → Prometheus → Maintenance →
    # RequestContext, and the response unwinds the other way.
    app.add_middleware(RequestContextMiddleware)

    # Maintenance mode (issue #57). Added AFTER RequestContextMiddleware so
    # it sits OUTSIDE it in the add list but — given the reverse wrap —
    # runs just before RequestContext on the way in; that's fine, the 503
    # short-circuit doesn't need request_id bound. Mutating requests are
    # 503'd while maintenance is on (superadmin + exempt-path bypass);
    # reads + the maintenance-off common case pass through with no DB hit.
    app.add_middleware(MaintenanceModeMiddleware)

    if settings.prometheus_metrics_enabled:
        app.add_middleware(PrometheusMiddleware)

    # CORS — origins come from ``CORS_ORIGINS`` (comma-separated; default
    # "*"). With a wildcard we MUST NOT enable credentials: Starlette
    # would otherwise reflect the request Origin back with
    # Access-Control-Allow-Credentials: true, effectively trusting every
    # site. The API authenticates via the Bearer Authorization header
    # (not cookies), so wildcard-without-credentials is correct + safe.
    # When the operator pins explicit origins we enable credentials for
    # them (future cookie-based flows / withCredentials fetches).
    #
    # SECURITY (#400 / M6): ``cors_origins_list`` collapses to ``["*"]``
    # whenever a wildcard is present — even mixed with explicit origins
    # ("*,https://app.example.com"). So ``allow_credentials`` below can
    # never be True while any wildcard is in play; the dangerous
    # "reflect every Origin + send credentials" combo is impossible.
    _cors_origins = settings.cors_origins_list
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=_cors_origins != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        # Custom response headers the browser must be allowed to read via
        # fetch(). ``X-Total-Count`` backs server-side pagination on the IPAM
        # address list + cross-subnet search (issues #517 / #520);
        # ``X-Adoption-Required`` marks the cloud-driver adoption 409 so the
        # scope modal can offer an adopt-and-retry instead of the generic
        # error (#865). Without this the header is present on the wire but
        # the JS layer can't read it under CORS — for a cross-origin
        # frontend the feature would silently degrade to the dead end it
        # fixes.
        expose_headers=["X-Total-Count", "X-Adoption-Required"],
    )

    # SECURITY (#400 / L3): Host-header allow-list. Added LAST so — given
    # Starlette's reverse wrap — it runs OUTERMOST and rejects a forged /
    # unexpected Host header (Host-header injection, DNS-rebinding, cache
    # poisoning) before any other middleware or handler sees the request.
    # Default ``["*"]`` accepts any host so existing reverse-proxy /
    # appliance deploys are unaffected; operators set TRUSTED_HOSTS to
    # lock the API to their real hostnames. (TrustedHostMiddleware
    # short-circuits ``["*"]`` so there's no per-request cost when open.)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts_list,
    )

    # Routes
    app.include_router(health_router)
    # Unauthenticated ACME http-01 well-known endpoint (issue #438 Phase 4),
    # mounted at root so the public CA can fetch it anonymously.
    app.include_router(acme_well_known_router)
    # HELD (RFC 5985) at the application root, not under /api/v1: a HELD
    # client is configured with a whole URL and the protocol names this
    # path. Module-gated like the JSON surface; the third-party route is
    # permission-gated on its own dependency and the self-query route is
    # unauthenticated by design and off by default (#972).
    app.include_router(
        e911_held_router,
        dependencies=[Depends(require_module("network.e911"))],
    )
    app.include_router(api_v1_router, prefix="/api/v1")

    if settings.prometheus_metrics_enabled:
        app.add_route("/metrics", metrics_endpoint)

    # Transient-DB-connection handler (issue #117). When a backup
    # restore disposes the engine + ``pg_terminate_backend``s every
    # connection, requests that had ALREADY checked one out get
    # their underlying socket killed mid-flight. ``pool_pre_ping``
    # only fires at checkout, so it can't recover those — they
    # surface as ``InterfaceError: cannot call PreparedStatement
    # .fetch(): the underlying connection is closed`` (or
    # ``OperationalError`` for similar pool-level failures).
    #
    # Same self-healing logic applies: the very next request from
    # the same caller will go through pool_pre_ping and succeed.
    # Convert to a clean 503 + ``Retry-After: 1`` so agent
    # long-polls back off and retry instead of cascading the
    # failure into the diagnostics surface.
    #
    # Registered BEFORE the broader Exception handler so connection-
    # closed errors take this path and skip the unhandled-exception
    # capture (they're transient noise, not real bugs).
    from sqlalchemy.exc import (  # noqa: PLC0415
        InterfaceError as SAInterfaceError,
    )
    from sqlalchemy.exc import (
        OperationalError as SAOperationalError,
    )

    @app.exception_handler(SAInterfaceError)
    @app.exception_handler(SAOperationalError)
    async def _transient_db_connection(request: Request, exc: Exception) -> Response:
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        text = str(exc).lower()
        is_connection_closed = (
            "connection is closed" in text
            or "connection was closed" in text
            or "connection lost" in text
            or "server closed the connection unexpectedly" in text
        )
        if not is_connection_closed:
            # Some other InterfaceError — let it fall through to
            # the unhandled-exception path so it gets captured.
            raise exc
        logger.info(
            "db_connection_closed_transient",
            method=request.method,
            path=request.url.path,
            error=str(exc)[:200],
        )
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "Database connection was closed mid-request "
                    "(likely a backup restore in progress). Retry."
                )
            },
            headers={"Retry-After": "1"},
        )

    # A dependency that did not answer (issue #1083). asyncpg raises the
    # bare ``TimeoutError`` for a connect or a command that ran past the
    # ``connect_args`` bounds db.py sets (5 s / 30 s), and SQLAlchemy's
    # asyncpg adapter re-raises anything that is not an asyncpg error class
    # untranslated — so the handler above never sees it. During a CNPG
    # failover (the primary's node partitioned or lost) every request whose
    # session lookup or query needed a fresh connection answered ``500
    # Internal Server Error`` for the 60-90 s the promotion took, beside the
    # 503s the connection-closed shape of the same outage already got, and a
    # client could not tell the failover from a bug. A dependency that did
    # not answer in time is the 503 case: same Retry-After. The same holds
    # for the connect a fresh checkout makes while the new primary's socket
    # is not yet listening (``ConnectionError``) and for the pool's own
    # checkout timeout (``sqlalchemy.exc.TimeoutError`` — every pooled
    # connection parked on a dead peer).
    #
    # Not captured to the diagnostics surface on purpose: the capture opens
    # a database session, and during the outage that is another 5 s connect
    # timeout in front of the 503. The warning line carries the route.
    from sqlalchemy.exc import TimeoutError as SAPoolTimeoutError  # noqa: PLC0415

    # The dependency-down exceptions this converts to 503. asyncpg's pre-ping
    # times out as a bare ``TimeoutError``; a fresh checkout onto the not-yet-
    # listening new primary raises ``ConnectionError`` (``ConnectionRefusedError``
    # is a subclass); the pool's own checkout timeout is ``sqlalchemy.exc
    # .TimeoutError``. All observed live on nightly-2026.09.12's partition rig
    # while CNPG promoted a new primary.
    _dependency_down = (TimeoutError, ConnectionError, SAPoolTimeoutError)

    def _dependency_down_response(request: Request, error_class: str, detail: str) -> Response:
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        logger.warning(
            "dependency_unavailable",
            method=request.method,
            path=request.url.path,
            error_class=error_class,
            error=detail[:200],
        )
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "A backend dependency did not answer in time "
                    "(database failover or restart in progress). Retry."
                )
            },
            headers={"Retry-After": "2"},
        )

    @app.exception_handler(TimeoutError)
    @app.exception_handler(ConnectionError)
    @app.exception_handler(SAPoolTimeoutError)
    async def _dependency_unavailable(request: Request, exc: Exception) -> Response:
        return _dependency_down_response(request, type(exc).__name__, str(exc))

    # The same timeout sometimes arrives WRAPPED. SQLAlchemy's asyncpg driver
    # runs the connection on an anyio task group, so a pre-ping timeout can
    # surface as an ``ExceptionGroup`` rather than a bare ``TimeoutError`` —
    # observed on ``GET /appliance/cluster/health`` on the partition rig
    # (``ExceptionGroup`` over one ``TimeoutError`` from ``asyncpg _async_ping``).
    # A group whose leaves are ALL dependency-down errors is the same 503; a
    # group carrying anything else re-raises unchanged so a real bug still
    # reaches the 500 path and the diagnostics capture.
    @app.exception_handler(ExceptionGroup)
    async def _dependency_unavailable_group(request: Request, exc: ExceptionGroup) -> Response:
        matched, rest = exc.split(_dependency_down)
        if rest is not None or matched is None:
            raise exc
        leaves = getattr(matched, "exceptions", ())
        first = leaves[0] if leaves else exc
        return _dependency_down_response(request, type(first).__name__, str(first))

    from sqlalchemy.exc import DBAPIError as SADBAPIError  # noqa: PLC0415
    from sqlalchemy.exc import IntegrityError as SAIntegrityError  # noqa: PLC0415

    from app.core.integrity_errors import (  # noqa: PLC0415
        FOREIGN_KEY_VIOLATION,
        classify_foreign_key_violation,
        extract_detail,
    )

    # A unique violation (SQLSTATE 23505) is the data conflicting.
    #
    # NOT NULL (23502) and CHECK (23514) violations are OUR code being wrong,
    # and answering 409 would blame the client for a server bug — worse, it
    # would hide it: a 4xx is invisible to the conformance fuzz's no-5xx
    # assertion. That is not hypothetical here. Item 3 of the change that
    # added this handler was a NOT NULL violation (the delete denial path
    # writing an AuditLog without resource_display); a blanket handler would
    # answer 409 for it, and the suite that caught it would sail straight
    # past the regression. A handler must not blind the test that guards the
    # bug class it sits on.
    #
    # Foreign key (23503) is the one arm that splits (#922). A dangling
    # reference the CLIENT sent — a stale group id in a request body — is an
    # ordinary client error; the same violation on a value the SERVER
    # computed is exactly the bug the paragraph above protects. Postgres
    # names the offending column and value in DETAIL, so
    # ``classify_foreign_key_violation`` answers 4xx only when that value is
    # one the request actually carried, and returns None — re-raise, 500 —
    # otherwise.
    unique_violation = "23505"

    @app.exception_handler(SAIntegrityError)
    async def _integrity_conflict(request: Request, exc: Exception) -> Response:
        """A UNIQUE violation is the DATA conflicting, and 409 is its answer.

        Handlers that pre-check (SELECT then INSERT — asns, agent register's
        group auto-create) race between the check and the flush; the loser's
        unique violation surfaced as a 500 where the pre-check's own answer
        would have been 409.

        A foreign-key violation carrying a value THIS REQUEST supplied is a
        client error too (#922): 422 for a reference to a row that does not
        exist, 409 for a delete of a row still referenced. Every other
        integrity error re-raises to the 500 path, because it means the
        server sent something it shouldn't.
        """
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        orig = getattr(exc, "orig", None)
        sqlstate = str(getattr(orig, "sqlstate", "") or "")

        if sqlstate == FOREIGN_KEY_VIOLATION:
            # ``request._body`` rather than ``await request.body()``: the
            # receive channel is already consumed by the time a handler has
            # flushed, and re-reading it would block. FastAPI caches the
            # bytes there when it parsed the JSON body, which is every route
            # that can carry a client-supplied reference; a route with no
            # body simply has nothing to match and re-raises.
            classified = classify_foreign_key_violation(
                extract_detail(exc),
                getattr(request, "_body", None),
                dict(request.path_params or {}),
                request.url.query,
            )
            if classified is None:
                raise exc
            status_code, message = classified
            logger.info(
                "integrity_foreign_key",
                method=request.method,
                path=request.url.path,
                sqlstate=sqlstate,
                status=status_code,
                error=str(orig or exc)[:200],
            )
            return JSONResponse(status_code=status_code, content={"detail": message})

        if sqlstate != unique_violation:
            raise exc
        logger.info(
            "integrity_conflict",
            method=request.method,
            path=request.url.path,
            sqlstate=sqlstate,
            error=str(orig or exc)[:200],
        )
        return JSONResponse(
            status_code=409,
            content={"detail": "The request conflicts with existing data."},
        )

    @app.exception_handler(SADBAPIError)
    async def _unstorable_value(request: Request, exc: Exception) -> Response:
        """A value Postgres refuses as DATA (over-length string, NUL byte,
        malformed macaddr/uuid/inet literal, out-of-range number) is the
        CLIENT's input, same class as a pydantic 422 — it reached the driver
        only because a request model didn't bound it.

        The asyncpg dialect wraps most driver errors as the GENERIC
        DBAPIError, not sqlalchemy.exc.DataError (observed live:
        InvalidTextRepresentationError and UntranslatableCharacterError both
        arrive as bare DBAPIError), so the discriminator is the error itself:
        SQLSTATE class 22 is "data exception" by definition, and asyncpg's
        client-side bind failures subclass asyncpg.exceptions.DataError.
        Anything else (ProgrammingError — OUR query is wrong; transient
        connection errors — their own handler above, which wins by being the
        more specific registered class) re-raises unchanged."""
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        orig = getattr(exc, "orig", None)
        sqlstate = str(getattr(orig, "sqlstate", "") or "")
        is_data = sqlstate.startswith("22") or any(
            c.__name__ == "DataError" for c in type(orig).__mro__
        )
        if not is_data:
            raise exc
        logger.info(
            "unstorable_value",
            method=request.method,
            path=request.url.path,
            error=str(orig or exc)[:200],
        )
        return JSONResponse(
            status_code=422,
            content={"detail": "A supplied value cannot be stored as sent."},
        )

    # Unhandled-exception capture (issue #123). Registered last so it
    # only catches what slipped past every other handler — auth /
    # permission / validation errors raise typed HTTPException
    # subclasses that FastAPI's own machinery turns into 4xx
    # responses without ever hitting this path.
    @app.exception_handler(Exception)
    async def _capture_unhandled(request: Request, exc: Exception) -> Response:
        # Lazy imports — keep app boot-time import graph small + avoid
        # circulars (services/diagnostics imports models which imports
        # base which Alembic also imports at migration time).
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        from app.db import AsyncSessionLocal  # noqa: PLC0415
        from app.services.diagnostics import (  # noqa: PLC0415
            record_unhandled_exception_async,
        )

        request_id = request.headers.get("X-Request-ID")
        try:
            sanitised_headers = {
                k: v
                for k, v in request.headers.items()
                if k.lower() not in {"authorization", "cookie", "x-api-token"}
            }
        except Exception:
            sanitised_headers = {}
        context = {
            "method": request.method,
            "path": request.url.path,
            "query": dict(request.query_params),
            "headers": sanitised_headers,
            "client": request.client.host if request.client else None,
        }
        try:
            async with AsyncSessionLocal() as db:
                await record_unhandled_exception_async(
                    db,
                    service="api",
                    exc=exc,
                    route_or_task=f"{request.method} {request.url.path}",
                    request_id=request_id,
                    context=context,
                )
        except Exception:
            # Capture failures must never replace the original
            # exception's response. Eat it.
            pass
        logger.exception(
            "unhandled_exception",
            method=request.method,
            path=request.url.path,
            request_id=request_id,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"},
        )

    # The 422 the document declares is not the only 422 the API returns.
    #
    # FastAPI auto-declares ``HTTPValidationError`` (detail: array of
    # ValidationError) on every operation that validates a parameter, and that
    # is honest for the 422s its own request validation produces. But 270 call
    # sites across ``backend/app/api/v1`` — 57 router files, led by
    # ipam/router.py (24), dns/router.py (22), cutover/router.py (18) — raise
    # ``HTTPException(status_code=422, detail="...")`` by hand for semantic
    # validation a signature cannot express ("invalid classification"), and
    # FastAPI serialises those as ``{"detail": "<string>"}``. The document said
    # array, the wire said string, and nothing reconciled them: every one of
    # those responses violated the API's own published contract.
    #
    # Found by the conformance fuzz, which validates live responses against
    # this very document —
    #   GET /api/v1/new-devices/sightings?classification=null
    #   -> 422 {"detail":"invalid classification"}
    # — where the declared schema demands an array. 29 of 39 red conformance
    # rows on one build were this single defect.
    #
    # Widening the DOCUMENT rather than rewriting the BODIES is deliberate. The
    # string form is the established contract: the frontend's ``formatApiError``
    # normalises string, array and object shapes (issues #31 / #186), so both
    # already render correctly. Rewriting 270 response bodies to chase the
    # schema would break clients outside this repo in order to fix what is a
    # documentation defect.
    #
    # The wrapper below carries a second rewrite too (#907, nullable unions);
    # both exist for the same reason — the document is generated FOR consumers
    # we do not control, so a defect in it breaks a client somewhere else with
    # no local symptom.
    #
    # Wraps FastAPI's own ``openapi()`` rather than re-deriving the document
    # with ``get_openapi``, so every generation setting the app carries
    # (webhooks, separate input/output schemas, servers) keeps applying. That
    # call caches into ``app.openapi_schema`` and returns the cached object, so
    # this patches it in place, once.
    _generate_openapi = app.openapi
    _normalised: dict | None = None

    def _openapi_for_generators() -> dict:
        nonlocal _normalised

        schema = _generate_openapi()
        # ``_generate_openapi`` caches into ``app.openapi_schema`` and hands
        # back the same object every time, so the rewrites below have already
        # been applied to it — re-walking a 1.8 MB document on every
        # ``/api/docs`` load would be pure waste. Identity, not a marker key:
        # the published document must carry nothing that is not OpenAPI.
        if _normalised is not None and schema is _normalised:
            return schema

        props = (
            schema.get("components", {})
            .get("schemas", {})
            .get("HTTPValidationError", {})
            .get("properties", {})
        )
        detail = props.get("detail")
        # Absent when no operation validates anything — nothing to widen.
        if isinstance(detail, dict) and "anyOf" not in detail:
            props["detail"] = {
                "anyOf": [detail, {"type": "string"}],
                "title": detail.get("title", "Detail"),
            }

        # #907 — FastAPI's 3.1 ``anyOf: [X, {"type": "null"}]`` nullable idiom
        # makes strict generators DROP the property (a warning, not an error),
        # so a generated client is silently missing thousands of fields. Runs
        # after the widening above so the union it just added — which has no
        # null arm — is left alone.
        collapse_nullable_unions(schema)

        _normalised = schema
        return schema

    app.openapi = _openapi_for_generators  # type: ignore[method-assign]

    return app


app = create_app()
