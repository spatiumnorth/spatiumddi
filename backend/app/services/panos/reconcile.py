"""Per-firewall PAN-OS / Panorama read-only reconciler (#605).

For one ``PANOSFirewall`` row: fetch system info + address objects/groups
(+ NAT rules, interfaces, DHCP leases per the mirror toggles) from the PAN-OS
API, map them into the neutral mirror shapes, and converge the shared
``firewall_mirror`` engine (#606) with the PAN-OS owner. Strictly read-only on
the firewall — the DAG-enforcement writes live in
``app.services.block_sync.reconcile``.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.panos import PANOSFirewall
from app.services.firewall_mirror import (
    PALOALTO_OWNER,
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
from app.services.integration_ownership import refuse_sync_into_trashed_space
from app.services.panos.client import (
    PANOSClient,
    PANOSClientError,
    _PANAddressObject,
    _PANInterface,
    _PANLease,
    _PANNatRule,
)

logger = structlog.get_logger(__name__)

# Preserve the #605 public name — the sweep task + router reference it.
ReconcileSummary = MirrorSummary


def _nat_ips(rule: _PANNatRule) -> tuple[str | None, str | None]:
    """Map a PAN-OS NAT rule to ``(internal_ip, external_ip)``. DNAT: external =
    original dst, internal = translated dst. SNAT: internal = original source,
    external = translated source."""

    def _one_ip(value: str | None) -> str | None:
        if not value:
            return None
        v = value.strip()
        try:
            return str(ipaddress.ip_interface(v).ip) if "/" in v else str(ipaddress.ip_address(v))
        except (ValueError, TypeError):
            return None  # named object / range / 'any' — not a bare IP

    if rule.translated_dst:  # inbound DNAT / port-forward
        return _one_ip(rule.translated_dst), _one_ip(rule.original_dst)
    if rule.translated_src:  # SNAT
        return _one_ip(rule.source), _one_ip(rule.translated_src)
    return None, None


def _to_object(o: _PANAddressObject) -> MirrorObject:
    return MirrorObject(
        name=o.name, kind=o.kind, value=o.value, description=o.description, tags=list(o.tags)
    )


def _to_nat(fw: PANOSFirewall, r: _PANNatRule) -> MirrorNat:
    internal, external = _nat_ips(r)
    return MirrorNat(
        name=r.name,
        kind=r.kind,
        internal_ip=internal,
        external_ip=external,
        description=r.description or f"PAN-OS NAT rule on {fw.name}",
    )


def _to_subnet(fw: PANOSFirewall, iface: _PANInterface) -> MirrorSubnet:
    return MirrorSubnet(
        cidr=iface.cidr,
        name=f"{fw.name}/{iface.zone or iface.name}",
        description=f"PAN-OS interface {iface.name}"
        + (f" (zone {iface.zone})" if iface.zone else ""),
        gateway=iface.address,
    )


def _to_address(ls: _PANLease) -> MirrorAddress:
    return MirrorAddress(
        address=ls.address,
        mac=ls.mac,
        hostname=ls.hostname,
        description=f"PAN-OS DHCP lease ({ls.state})",
        status="dhcp",
        auto_from_lease=True,
    )


async def reconcile_firewall(db: AsyncSession, fw: PANOSFirewall) -> MirrorSummary:
    summary = MirrorSummary(ok=False)
    # #2577 — a target whose IP space is in Trash syncs nothing: it would
    # rebuild its rows as live rows inside the trashed space.
    if await refuse_sync_into_trashed_space(db, fw, summary):
        return summary

    api_key = ""
    if fw.api_key_encrypted:
        try:
            api_key = decrypt_str(fw.api_key_encrypted)
        except ValueError as exc:
            summary.error = f"api-key decrypt failed: {exc}"
    if not api_key:
        summary.error = summary.error or "no API key configured"
        fw.last_sync_error = summary.error
        fw.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        async with PANOSClient(
            host=fw.host,
            port=fw.port,
            api_key=api_key,
            api_version=fw.api_version,
            is_panorama=fw.is_panorama,
            vsys=fw.vsys,
            device_group=fw.device_group,
            verify_tls=fw.verify_tls,
            ca_bundle_pem=fw.ca_bundle_pem or "",
        ) as client:
            info = await client.get_system_info()
            objects: list[_PANAddressObject] = []
            if fw.mirror_address_objects:
                objects = await client.list_address_objects()
                objects += await client.list_address_groups()
            nat_rules = await client.list_nat_rules() if fw.mirror_nat_rules else []
            interfaces = await client.list_interfaces() if fw.mirror_interfaces else []
            leases = await client.list_dhcp_leases() if fw.mirror_dhcp_leases else []
    except PANOSClientError as exc:
        summary.error = str(exc)
        fw.last_sync_error = summary.error
        fw.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("panos_reconcile_fetch_failed", firewall=str(fw.id), error=summary.error)
        return summary

    summary.sw_version = info.version
    summary.model = info.model
    summary.object_count = len(objects)
    summary.nat_rule_count = len(nat_rules)
    summary.interface_count = len(interfaces)
    summary.lease_count = len(leases)

    # Always apply (even for a disabled mirror toggle, the desired set is empty
    # so the apply sweeps rows a prior enabled sync created).
    await apply_objects(
        db, PALOALTO_OWNER, fw.id, fw.ipam_space_id, [_to_object(o) for o in objects], summary
    )
    await apply_nat(
        db, PALOALTO_OWNER, fw.id, fw.name, [_to_nat(fw, r) for r in nat_rules], summary
    )
    await apply_subnets(
        db,
        PALOALTO_OWNER,
        fw.id,
        fw.ipam_space_id,
        fw.name,
        [_to_subnet(fw, i) for i in interfaces],
        summary,
    )
    await apply_addresses(
        db, PALOALTO_OWNER, fw.id, fw.ipam_space_id, [_to_address(ls) for ls in leases], summary
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
            action="panos.reconcile",
            resource_type="panos_firewall",
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
        "panos_reconcile_ok",
        **summary.released.log_fields(),
        firewall=str(fw.id),
        version=summary.sw_version,
        objects=summary.object_count,
        nat=summary.nat_rule_count,
        objects_created=summary.objects_created,
        nat_created=summary.nat_created,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_firewall"]
