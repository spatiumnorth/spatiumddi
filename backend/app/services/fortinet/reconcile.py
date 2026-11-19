"""Per-firewall FortiGate read-only reconciler (#606).

For one ``FortinetFirewall`` row: fetch system status + address objects/groups
(+ VIPs, interfaces, DHCP leases per the mirror toggles) from the FortiOS REST
API, map them into the neutral mirror shapes, and converge the shared
``firewall_mirror`` engine with the Fortinet owner. Strictly read-only —
FortiGate enforcement is the credential-free threat-feed path
(``app.services.firewall_feeds`` / ``FirewallFeed``), never a write here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.fortinet import FortinetFirewall
from app.services.firewall_mirror import (
    FORTINET_OWNER,
    MirrorAddress,
    MirrorNat,
    MirrorObject,
    MirrorSubnet,
    MirrorSummary,
    apply_addresses,
    apply_nat,
    apply_objects,
    apply_subnets,
)
from app.services.fortinet.client import (
    FortinetClient,
    FortinetClientError,
    _FortiAddressObject,
    _FortiInterface,
    _FortiLease,
    _FortiNatRule,
)
from app.services.integration_ownership import refuse_sync_into_trashed_space

logger = structlog.get_logger(__name__)


def _to_object(o: _FortiAddressObject) -> MirrorObject:
    return MirrorObject(
        name=o.name, kind=o.kind, value=o.value, description=o.description, tags=list(o.tags)
    )


def _to_nat(fw: FortinetFirewall, r: _FortiNatRule) -> MirrorNat:
    # A FortiGate VIP is a destination NAT: extip (public) → mappedip (LAN).
    return MirrorNat(
        name=r.name,
        kind=r.kind,
        internal_ip=r.translated_dst,
        external_ip=r.original_dst,
        description=r.description or f"FortiGate VIP on {fw.name}",
    )


def _to_subnet(fw: FortinetFirewall, iface: _FortiInterface) -> MirrorSubnet:
    return MirrorSubnet(
        cidr=iface.cidr,
        name=f"{fw.name}/{iface.zone or iface.name}",
        description=f"FortiGate interface {iface.name}"
        + (f" (zone {iface.zone})" if iface.zone else ""),
        gateway=iface.address,
    )


def _to_address(ls: _FortiLease) -> MirrorAddress:
    return MirrorAddress(
        address=ls.address,
        mac=ls.mac,
        hostname=ls.hostname,
        description=f"FortiGate DHCP lease ({ls.state})",
        status="dhcp",
        auto_from_lease=True,
    )


async def reconcile_firewall(db: AsyncSession, fw: FortinetFirewall) -> MirrorSummary:
    summary = MirrorSummary(ok=False)
    # #2577 — a target whose IP space is in Trash syncs nothing: it would
    # rebuild its rows as live rows inside the trashed space.
    if await refuse_sync_into_trashed_space(db, fw, summary):
        return summary

    token = ""
    if fw.api_token_encrypted:
        try:
            token = decrypt_str(fw.api_token_encrypted)
        except ValueError as exc:
            summary.error = f"api-token decrypt failed: {exc}"
    if not token:
        summary.error = summary.error or "no API token configured"
        fw.last_sync_error = summary.error
        fw.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        async with FortinetClient(
            host=fw.host,
            port=fw.port,
            api_token=token,
            vdom=fw.vdom,
            verify_tls=fw.verify_tls,
            ca_bundle_pem=fw.ca_bundle_pem or "",
        ) as client:
            info = await client.get_system_info()
            objects: list[_FortiAddressObject] = []
            if fw.mirror_address_objects:
                objects = await client.list_address_objects()
                objects += await client.list_address_groups()
            nat_rules = await client.list_nat_rules() if fw.mirror_nat_rules else []
            interfaces = await client.list_interfaces() if fw.mirror_interfaces else []
            leases = await client.list_dhcp_leases() if fw.mirror_dhcp_leases else []
    except FortinetClientError as exc:
        summary.error = str(exc)
        fw.last_sync_error = summary.error
        fw.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("fortinet_reconcile_fetch_failed", firewall=str(fw.id), error=summary.error)
        return summary

    summary.sw_version = info.version
    summary.model = info.model
    summary.object_count = len(objects)
    summary.nat_rule_count = len(nat_rules)
    summary.interface_count = len(interfaces)
    summary.lease_count = len(leases)

    await apply_objects(
        db, FORTINET_OWNER, fw.id, fw.ipam_space_id, [_to_object(o) for o in objects], summary
    )
    await apply_nat(
        db, FORTINET_OWNER, fw.id, fw.name, [_to_nat(fw, r) for r in nat_rules], summary
    )
    await apply_subnets(
        db,
        FORTINET_OWNER,
        fw.id,
        fw.ipam_space_id,
        fw.name,
        [_to_subnet(fw, i) for i in interfaces],
        summary,
    )
    await apply_addresses(
        db, FORTINET_OWNER, fw.id, fw.ipam_space_id, [_to_address(ls) for ls in leases], summary
    )

    fw.last_synced_at = datetime.now(UTC)
    fw.last_sync_error = None
    fw.sw_version = info.version
    fw.model = info.model
    fw.object_count = summary.object_count
    fw.nat_rule_count = summary.nat_rule_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="fortinet.reconcile",
            resource_type="fortinet_firewall",
            resource_id=str(fw.id),
            resource_display=fw.name,
            new_value={
                # #2577 — what the sync released outside the target's IP space.
                "released": summary.released.as_dict(),
                "objects": {
                    "created": summary.objects_created,
                    "updated": summary.objects_updated,
                    "deleted": summary.objects_deleted,
                },
                "nat": {
                    "created": summary.nat_created,
                    "updated": summary.nat_updated,
                    "deleted": summary.nat_deleted,
                },
                "subnets": {
                    "created": summary.subnets_created,
                    "updated": summary.subnets_updated,
                    "deleted": summary.subnets_deleted,
                    "matched": summary.subnets_matched,
                },
                "addresses": {
                    "created": summary.addresses_created,
                    "updated": summary.addresses_updated,
                    "deleted": summary.addresses_deleted,
                },
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "fortinet_reconcile_ok",
        **summary.released.log_fields(),
        firewall=str(fw.id),
        version=summary.sw_version,
        objects=summary.object_count,
        nat=summary.nat_rule_count,
    )
    return summary


__all__ = ["reconcile_firewall"]
