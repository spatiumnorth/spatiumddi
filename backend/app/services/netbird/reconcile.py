"""Per-instance NetBird reconciler.

For one ``NetbirdInstance`` row:

  1. Fetch peers from the NetBird management API.
  2. Auto-create the overlay block + subnet under the bound space if
     they don't already exist (FK-stamped to this instance).
  3. Compute desired IP rows from each peer's ``ip``. Skip peers whose
     NetBird login has expired when the instance has
     ``skip_expired=True``.
  4. Apply diff: claim pre-existing operator rows, write new rows,
     update changed soft fields (gated by ``user_modified_at`` lock),
     un-claim or delete rows that disappeared upstream.
  5. Phase 2 — synthesise the mesh's DNS domain as a read-only zone in
     the bound DNS group (A records only; NetBird peers are IPv4).
  6. Persist ``last_synced_at`` / ``last_sync_error`` / ``dns_domain`` /
     ``peer_count``.

NetBird overlaps Tailscale on the default CGNAT range (100.64.0.0/10),
so the cross-integration ownership guard here checks *every* sibling
integration FK — a peer and a tailnet device could legitimately land on
the same address.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.models.netbird import NetbirdInstance
from app.services.integration_ownership import owned_by_other_integration
from app.services.netbird.client import (
    NetbirdClient,
    NetbirdClientError,
    _NetbirdPeer,
    derive_netbird_domain,
)

logger = structlog.get_logger(__name__)

_BIGINT_MAX = 2**63 - 1
_STATUS = "netbird-peer"


@dataclass(frozen=True)
class _DesiredAddress:
    address: str
    hostname: str
    description: str
    custom_fields: dict[str, Any]


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    dns_domain: str | None = None
    peer_count: int = 0
    blocks_created: int = 0
    subnets_created: int = 0
    addresses_created: int = 0
    addresses_updated: int = 0
    addresses_deleted: int = 0
    skipped_expired: int = 0
    skipped_no_subnet: int = 0
    # Phase 2: synthetic DNS zone + records.
    dns_zones_created: int = 0
    dns_records_created: int = 0
    dns_records_updated: int = 0
    dns_records_deleted: int = 0
    dns_skipped: bool = False
    warnings: list[str] = field(default_factory=list)


# ── Helpers ──────────────────────────────────────────────────────────


def _parse_net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def _lan_total_ips(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    # The overlay is a routed mesh — no broadcast, every host usable.
    return net.num_addresses


def _find_subnet_for_ip(subnets: list[Subnet], ip: str) -> Subnet | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: Subnet | None = None
    best_prefix: int = -1
    for s in subnets:
        net = _parse_net(str(s.network))
        if net is None:
            continue
        if addr in net and net.prefixlen > best_prefix:
            best = s
            best_prefix = net.prefixlen
    return best


async def _recompute_subnet_utilization(db: AsyncSession, subnet_id: Any) -> None:
    allocated = (
        await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == subnet_id)
            .where(IPAddress.status != "available")
        )
        or 0
    )
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        return
    subnet.allocated_ips = allocated
    subnet.utilization_percent = (
        round(allocated / subnet.total_ips * 100, 2) if subnet.total_ips > 0 else 0.0
    )


def _is_expired(instance: NetbirdInstance, peer: _NetbirdPeer) -> bool:
    """A peer is filtered only when the instance opts in AND the peer
    actually has login-expiration enabled AND it has expired. Long-lived
    setup keys / service peers commonly disable expiration entirely."""
    return bool(instance.skip_expired and peer.login_expiration_enabled and peer.login_expired)


# ── Desired state computation ────────────────────────────────────────


def _compute_desired(
    instance: NetbirdInstance,
    peers: list[_NetbirdPeer],
    summary: ReconcileSummary,
) -> list[_DesiredAddress]:
    out: list[_DesiredAddress] = []
    for p in peers:
        if _is_expired(instance, p):
            summary.skipped_expired += 1
            continue
        if not p.ip:
            continue
        os_label = p.os or "unknown"
        version_label = p.version or ""
        description = f"{os_label} {version_label}".strip()
        cf: dict[str, Any] = {
            "netbird_id": p.id,
            "os": p.os,
            "version": p.version,
            "hostname": p.hostname,
            "dns_label": p.dns_label,
            "groups": list(p.groups),
            "connected": p.connected,
            "last_seen": p.last_seen,
            "login_expired": p.login_expired,
            "ssh_enabled": p.ssh_enabled,
            "approval_required": p.approval_required,
            "user_id": p.user_id,
        }
        cf = {k: v for k, v in cf.items() if v not in (None, "", [], False)}
        # The peer's FQDN is the most useful "hostname" for an IPAM row;
        # fall back to the short hostname / name while onboarding.
        hostname = p.dns_label or p.hostname or p.name
        out.append(
            _DesiredAddress(
                address=p.ip,
                hostname=hostname,
                description=description,
                custom_fields=cf,
            )
        )
    return out


# ── Apply: block + subnet ────────────────────────────────────────────


async def _ensure_block_and_subnet(
    db: AsyncSession,
    instance: NetbirdInstance,
    cidr: str,
    label: str,
    summary: ReconcileSummary,
) -> Subnet | None:
    net = _parse_net(cidr)
    if net is None:
        summary.warnings.append(f"unparseable CIDR on instance: {cidr!r}")
        return None
    cidr_norm = str(net)

    existing_block = (
        await db.execute(
            select(IPBlock).where(
                IPBlock.netbird_instance_id == instance.id,
                IPBlock.network == cidr_norm,
            )
        )
    ).scalar_one_or_none()
    if existing_block is None:
        existing_block = IPBlock(
            space_id=instance.ipam_space_id,
            network=cidr_norm,
            name=f"{instance.name} {cidr_norm}",
            description=f"Auto-created for NetBird instance {instance.name} ({label})",
            netbird_instance_id=instance.id,
        )
        db.add(existing_block)
        await db.flush()
        summary.blocks_created += 1

    existing_subnet = (
        await db.execute(
            select(Subnet).where(
                Subnet.netbird_instance_id == instance.id,
                Subnet.network == cidr_norm,
            )
        )
    ).scalar_one_or_none()
    if existing_subnet is None:
        existing_subnet = Subnet(
            space_id=instance.ipam_space_id,
            block_id=existing_block.id,
            network=cidr_norm,
            name=f"netbird:{label}",
            description=f"NetBird {label} for instance {instance.name}",
            netbird_instance_id=instance.id,
            total_ips=_lan_total_ips(net),
        )
        db.add(existing_subnet)
        await db.flush()
        summary.subnets_created += 1
    return existing_subnet


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    instance: NetbirdInstance,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == instance.ipam_space_id)))
        .scalars()
        .all()
    )
    subnets = list(subnet_rows)

    desired_map: dict[str, _DesiredAddress] = {}
    for d in desired:
        if d.address in desired_map:
            continue
        desired_map[d.address] = d

    # Claim pre-existing operator rows at desired addresses.
    desired_addrs = list(desired_map.keys())
    if desired_addrs:
        existing = (
            (await db.execute(select(IPAddress).where(IPAddress.address.in_(desired_addrs))))
            .scalars()
            .all()
        )
        for row in existing:
            if row.netbird_instance_id == instance.id:
                continue  # already ours
            if row.netbird_instance_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another NetBird instance; not claiming"
                )
                continue
            if owned_by_other_integration(row, "netbird_instance_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            row.netbird_instance_id = instance.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.netbird_instance_id == instance.id))
    current = {str(a.address): a for a in res.scalars().all()}

    dirty_subnets: set[Any] = {s.id for s in subnets if s.netbird_instance_id == instance.id}

    for addr, row in current.items():
        if addr not in desired_map:
            dirty_subnets.add(row.subnet_id)
            if row.user_modified_at is not None:
                # Operator invested edits — un-claim, leave as a
                # manually-managed row rather than deleting their data.
                row.netbird_instance_id = None
                summary.addresses_updated += 1
            else:
                await db.delete(row)
                summary.addresses_deleted += 1

    for addr, d in desired_map.items():
        subnet = _find_subnet_for_ip(subnets, d.address)
        if subnet is None:
            summary.skipped_no_subnet += 1
            continue
        if addr in current:
            row = current[addr]
            changed = False
            if row.subnet_id != subnet.id:
                dirty_subnets.add(row.subnet_id)
                row.subnet_id = subnet.id
                changed = True
            if row.user_modified_at is None:
                if row.status != _STATUS:
                    row.status = _STATUS
                    changed = True
                if (row.hostname or "") != d.hostname:
                    row.hostname = d.hostname
                    changed = True
                if (row.description or "") != d.description:
                    row.description = d.description
                    changed = True
                # Peer metadata (last_seen / version / groups) refreshes
                # alongside the other soft fields on non-locked rows so it
                # stays current.
                if (row.custom_fields or {}) != d.custom_fields:
                    row.custom_fields = d.custom_fields
                    changed = True
            if changed:
                dirty_subnets.add(subnet.id)
                summary.addresses_updated += 1
        else:
            db.add(
                IPAddress(
                    subnet_id=subnet.id,
                    address=d.address,
                    status=_STATUS,
                    hostname=d.hostname,
                    description=d.description,
                    custom_fields=d.custom_fields,
                    netbird_instance_id=instance.id,
                )
            )
            dirty_subnets.add(subnet.id)
            summary.addresses_created += 1

    if dirty_subnets:
        await db.flush()
        for subnet_id in dirty_subnets:
            await _recompute_subnet_utilization(db, subnet_id)


# ── Phase 2: synthetic DNS zone + records ────────────────────────────


_SYNTHESISED_RECORD_TTL = 300


def _peer_records(
    instance: NetbirdInstance,
    peers: list[_NetbirdPeer],
    zone_name: str,
) -> list[tuple[str, str, str]]:
    """Desired (label, "A", value) tuples — one A record per peer IP.

    Label is the peer's short name (its FQDN minus the zone suffix).
    Peers with no FQDN, or whose FQDN doesn't end in our zone, are
    skipped. Expired peers are filtered the same way the IPAM mirror
    filters them so the two surfaces stay consistent.
    """
    suffix = "." + zone_name
    out: list[tuple[str, str, str]] = []
    for p in peers:
        if _is_expired(instance, p):
            continue
        name = (p.dns_label or "").strip().rstrip(".")
        if not name or not name.endswith(suffix):
            continue
        label = name[: -len(suffix)] or "@"
        if not p.ip:
            continue
        try:
            addr = ipaddress.ip_address(p.ip)
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv4Address):
            out.append((label, "A", str(addr)))
    return out


async def _apply_synthetic_dns(
    db: AsyncSession,
    instance: NetbirdInstance,
    peers: list[_NetbirdPeer],
    summary: ReconcileSummary,
) -> None:
    """Materialise the mesh DNS domain zone + per-peer A records.

    Skips silently when the instance has no ``dns_group_id`` bound
    (Phase 2 is opt-in) or when no peer carries a usable FQDN. Refuses
    to claim a pre-existing operator-managed zone of the same name in
    the bound group — surfaced as a warning.
    """
    if instance.dns_group_id is None:
        summary.dns_skipped = True
        return
    if not summary.dns_domain:
        summary.dns_skipped = True
        return

    zone_name = summary.dns_domain.rstrip(".") + "."

    res = await db.execute(
        select(DNSZone).where(
            DNSZone.group_id == instance.dns_group_id,
            DNSZone.name == zone_name,
        )
    )
    zone = res.scalar_one_or_none()
    if zone is not None and zone.netbird_instance_id is None:
        summary.warnings.append(
            f"DNS zone {zone_name!r} already exists in the bound group and is "
            f"operator-managed; not synthesising. Delete it or rename to "
            f"unblock the NetBird Phase 2 surface."
        )
        summary.dns_skipped = True
        return
    if zone is not None and zone.netbird_instance_id != instance.id:
        summary.warnings.append(
            f"DNS zone {zone_name!r} owned by another NetBird instance; not synthesising."
        )
        summary.dns_skipped = True
        return

    if zone is None:
        zone = DNSZone(
            group_id=instance.dns_group_id,
            name=zone_name,
            zone_type="primary",
            kind="forward",
            ttl=_SYNTHESISED_RECORD_TTL,
            primary_ns=zone_name,
            admin_email=f"hostmaster.{zone_name}",
            is_auto_generated=True,
            netbird_instance_id=instance.id,
        )
        db.add(zone)
        await db.flush()
        summary.dns_zones_created += 1

    desired = _peer_records(instance, peers, summary.dns_domain)
    desired_keys: set[tuple[str, str, str]] = set(desired)

    rec_res = await db.execute(
        select(DNSRecord).where(
            DNSRecord.zone_id == zone.id,
            DNSRecord.netbird_instance_id == instance.id,
        )
    )
    current_by_key: dict[tuple[str, str, str], DNSRecord] = {}
    for r in rec_res.scalars().all():
        current_by_key.setdefault((r.name, r.record_type, r.value), r)

    for key, row in current_by_key.items():
        if key in desired_keys:
            continue
        await db.delete(row)
        summary.dns_records_deleted += 1

    for key in desired_keys - current_by_key.keys():
        label, rtype, value = key
        fqdn = zone_name.rstrip(".") if label == "@" else f"{label}.{zone_name.rstrip('.')}"
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=label,
                fqdn=fqdn,
                record_type=rtype,
                value=value,
                ttl=_SYNTHESISED_RECORD_TTL,
                auto_generated=True,
                netbird_instance_id=instance.id,
            )
        )
        summary.dns_records_created += 1


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_instance(db: AsyncSession, instance: NetbirdInstance) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)

    api_key = ""
    if instance.api_key_encrypted:
        try:
            api_key = decrypt_str(instance.api_key_encrypted)
        except ValueError as exc:
            summary.error = f"api-key decrypt failed: {exc}"
            instance.last_sync_error = summary.error
            instance.last_synced_at = datetime.now(UTC)
            await db.commit()
            return summary
    if not api_key:
        summary.error = "no API key configured"
        instance.last_sync_error = summary.error
        instance.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        async with NetbirdClient(
            api_key=api_key, api_url=instance.api_url, verify=instance.verify_tls
        ) as client:
            peers = await client.list_peers()
    except NetbirdClientError as exc:
        summary.error = str(exc)
        instance.last_sync_error = summary.error
        instance.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "netbird_reconcile_fetch_failed", instance=str(instance.id), error=summary.error
        )
        return summary

    summary.peer_count = len(peers)
    summary.dns_domain = derive_netbird_domain(peers)

    await _ensure_block_and_subnet(db, instance, instance.network_cidr, "peers", summary)

    desired = _compute_desired(instance, peers, summary)
    await _apply_addresses(db, instance, desired, summary)

    # Phase 2 — synthesise the mesh DNS surface in the bound group.
    # Skipped when no group is bound; an operator-managed same-name zone
    # is left alone (warning surfaced via summary.warnings).
    await _apply_synthetic_dns(db, instance, peers, summary)

    instance.last_synced_at = datetime.now(UTC)
    instance.last_sync_error = None
    instance.dns_domain = summary.dns_domain
    instance.peer_count = summary.peer_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="netbird.reconcile",
            resource_type="netbird_instance",
            resource_id=str(instance.id),
            resource_display=instance.name,
            new_value={
                "blocks_created": summary.blocks_created,
                "subnets_created": summary.subnets_created,
                "addresses": {
                    "created": summary.addresses_created,
                    "updated": summary.addresses_updated,
                    "deleted": summary.addresses_deleted,
                    "skipped_expired": summary.skipped_expired,
                    "skipped_no_subnet": summary.skipped_no_subnet,
                },
                "dns": {
                    "zones_created": summary.dns_zones_created,
                    "records_created": summary.dns_records_created,
                    "records_updated": summary.dns_records_updated,
                    "records_deleted": summary.dns_records_deleted,
                    "skipped": summary.dns_skipped,
                },
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "netbird_reconcile_ok",
        instance=str(instance.id),
        dns_domain=summary.dns_domain,
        peers=summary.peer_count,
        blocks_created=summary.blocks_created,
        subnets_created=summary.subnets_created,
        addresses_created=summary.addresses_created,
        addresses_updated=summary.addresses_updated,
        addresses_deleted=summary.addresses_deleted,
        dns_zones_created=summary.dns_zones_created,
        dns_records_created=summary.dns_records_created,
        dns_records_deleted=summary.dns_records_deleted,
    )
    return summary


__all__ = ["ReconcileSummary", "reconcile_instance"]
