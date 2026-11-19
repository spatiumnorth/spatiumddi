"""Per-organization Cisco Meraki read-only reconciler (#606).

For one ``MerakiOrg`` row: walk the org's appliance networks and mirror

* per-network **VLANs** → IPAM subnets;
* appliance **DHCP fixed-IP reservations** → IPAM addresses;
* org **policy objects / groups** → ``FirewallObject``;
* MX **1:1 NAT + port-forward** rules → ``nat_mapping``;
* (opt-in) network **clients** → IPAM addresses.

Everything is accumulated across all networks first, then converged through the
shared ``firewall_mirror`` engine with the Meraki owner in ONE apply per kind —
so the whole-owner diff sees every network's desired state at once (a per-
network apply would delete the other networks' rows). Strictly read-only — the
per-client Blocked enforcement lives in ``app.services.block_sync.reconcile``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.meraki import MerakiOrg
from app.services.firewall_mirror import (
    MERAKI_OWNER,
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
from app.services.meraki.client import (
    MerakiClient,
    MerakiClientError,
    _MerakiClientRow,
    _MerakiNatRule,
    _MerakiPolicyObject,
    _MerakiReservation,
    _MerakiVlan,
)

logger = structlog.get_logger(__name__)


def _to_object(o: _MerakiPolicyObject) -> MirrorObject:
    return MirrorObject(
        name=o.name, kind=o.kind, value=o.value, description=o.description, tags=list(o.tags)
    )


def _to_nat(net_name: str, r: _MerakiNatRule) -> MirrorNat:
    # Scope the name by network (Meraki network names are unique within an org)
    # so two networks' same-named rules don't collapse in the whole-owner
    # nat_mapping diff, which dedupes by name.
    return MirrorNat(
        name=f"{net_name}/{r.name}",
        kind=r.kind,
        internal_ip=r.translated_dst,
        external_ip=r.original_dst,
        description=r.description or f"Meraki {r.kind} on {net_name}",
    )


def _to_subnet(v: _MerakiVlan) -> MirrorSubnet:
    label = v.name or f"vlan{v.vlan_id}"
    return MirrorSubnet(
        cidr=v.cidr,
        name=f"{v.network_name}/{label}",
        description=f"Meraki VLAN {v.vlan_id} on {v.network_name}",
        gateway=v.appliance_ip or None,
    )


def _to_reservation(r: _MerakiReservation) -> MirrorAddress:
    return MirrorAddress(
        address=r.address,
        mac=r.mac,
        hostname=r.name,
        description="Meraki DHCP reservation",
        status="reserved",
        auto_from_lease=False,
    )


def _to_client(c: _MerakiClientRow) -> MirrorAddress:
    return MirrorAddress(
        address=c.address,
        mac=c.mac,
        hostname=c.hostname,
        description=c.description or "Meraki client",
        status="dhcp",
        auto_from_lease=True,
    )


async def reconcile_org(db: AsyncSession, org: MerakiOrg) -> MirrorSummary:
    summary = MirrorSummary(ok=False)
    # #2577 — a target whose IP space is in Trash syncs nothing: it would
    # rebuild its rows as live rows inside the trashed space.
    if await refuse_sync_into_trashed_space(db, org, summary):
        return summary

    api_key = ""
    if org.api_key_encrypted:
        try:
            api_key = decrypt_str(org.api_key_encrypted)
        except ValueError as exc:
            summary.error = f"api-key decrypt failed: {exc}"
    if not api_key or not org.org_id.strip():
        summary.error = summary.error or (
            "no API key configured" if not api_key else "no organization id configured"
        )
        org.last_sync_error = summary.error
        org.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    subnets: list[MirrorSubnet] = []
    addresses: list[MirrorAddress] = []
    nats: list[MirrorNat] = []
    objects: list[MirrorObject] = []
    network_count = 0

    try:
        async with MerakiClient(
            api_key=api_key,
            org_id=org.org_id.strip(),
            base_url=org.base_url or "https://api.meraki.com/api/v1",
            verify_tls=True,
        ) as client:
            info = await client.get_organization()
            if org.mirror_policy_objects:
                objects = [_to_object(o) for o in await client.list_policy_objects()]
            networks = await client.list_networks(list(org.network_ids or []))
            network_count = len(networks)
            for net in networks:
                try:
                    if org.mirror_vlans or org.mirror_dhcp_reservations:
                        # One fetch feeds both — halves the vlans API calls.
                        vlans, reservations = await client.list_vlans_and_reservations(
                            net.id, net.name
                        )
                        if org.mirror_vlans:
                            subnets += [_to_subnet(v) for v in vlans]
                        if org.mirror_dhcp_reservations:
                            addresses += [_to_reservation(r) for r in reservations]
                    if org.mirror_nat_rules:
                        nats += [_to_nat(net.name, r) for r in await client.list_nat_rules(net.id)]
                    if org.mirror_clients:
                        addresses += [_to_client(c) for c in await client.list_clients(net.id)]
                except MerakiClientError as exc:
                    # A permanent per-network access error (key not scoped to this
                    # network, or the network is gone) skips just that network — its
                    # rows legitimately drop from the mirror. A transient error
                    # (5xx / timeout / 429-exhausted) re-raises to abort the whole
                    # org so we never diff the shared owner-set against a partial
                    # fetch and sweep good rows (NN#5).
                    if exc.status_code in (403, 404):
                        summary.warnings.append(f"network {net.name}: skipped ({exc})")
                        continue
                    raise
    except MerakiClientError as exc:
        summary.error = str(exc)
        org.last_sync_error = summary.error
        org.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning("meraki_reconcile_fetch_failed", org=str(org.id), error=summary.error)
        return summary

    summary.network_count = network_count
    summary.object_count = len(objects)
    summary.nat_rule_count = len(nats)

    await apply_objects(db, MERAKI_OWNER, org.id, org.ipam_space_id, objects, summary)
    await apply_nat(db, MERAKI_OWNER, org.id, info.name or org.name, nats, summary)
    await apply_subnets(
        db, MERAKI_OWNER, org.id, org.ipam_space_id, info.name or org.name, subnets, summary
    )
    await apply_addresses(db, MERAKI_OWNER, org.id, org.ipam_space_id, addresses, summary)

    org.last_synced_at = datetime.now(UTC)
    org.last_sync_error = None
    org.network_count = network_count
    org.object_count = summary.object_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="meraki.reconcile",
            resource_type="meraki_org",
            resource_id=str(org.id),
            resource_display=org.name,
            new_value={
                # #2577 — what the sync released outside the target's IP space.
                "released": summary.released.as_dict(),
                "networks": network_count,
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
        "meraki_reconcile_ok",
        **summary.released.log_fields(),
        org=str(org.id),
        networks=network_count,
        objects=summary.object_count,
        nat=summary.nat_rule_count,
    )
    return summary


__all__ = ["reconcile_org"]
