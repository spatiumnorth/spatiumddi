"""Per-tenant Tailscale reconciler.

For one ``TailscaleTenant`` row:

  1. Fetch devices from the Tailscale REST API.
  2. Auto-create the CGNAT IPv4 + IPv6 ULA blocks under the bound
     space if they don't already exist (FK-stamped to this tenant).
  3. Auto-create one subnet per block (the whole CGNAT slice as a
     single subnet — the tailnet is a flat overlay, not subdivided
     LAN segments).
  4. Compute desired IP rows from each device's ``addresses[]``.
     Skip devices whose ``expires`` has passed when the tenant has
     ``skip_expired=True``.
  5. Apply diff: claim pre-existing operator rows, write new rows,
     update changed soft fields (gated by ``user_modified_at``
     lock), un-claim or delete rows that disappeared upstream.
  6. Persist ``last_synced_at`` / ``last_sync_error`` /
     ``tailnet_domain`` / ``device_count``.
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
from app.models.tailscale import TailscaleTenant
from app.services.integration_ownership import owned_by_other_integration
from app.services.tailscale.client import (
    TailscaleClient,
    TailscaleClientError,
    _TailscaleDevice,
    derive_tailnet_domain,
)

logger = structlog.get_logger(__name__)

_BIGINT_MAX = 2**63 - 1


# ── Desired-state dataclasses ────────────────────────────────────────


@dataclass(frozen=True)
class _DesiredAddress:
    address: str  # IPv4 or IPv6
    hostname: str  # FQDN (`<host>.<tailnet>.ts.net`)
    description: str
    custom_fields: dict[str, Any]


@dataclass
class ReconcileSummary:
    ok: bool
    error: str | None = None
    tailnet_domain: str | None = None
    device_count: int = 0
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
    if net.prefixlen >= 31:
        return net.num_addresses
    # Tailnet CGNAT block is a routed overlay — no broadcast, every
    # host in the block is usable. Same logic as Kubernetes pod CIDR.
    return net.num_addresses


def _expires_in_past(iso: str | None) -> bool:
    """True when ``iso`` is non-empty and earlier than now (UTC).

    Tailscale uses ISO 8601 with a trailing ``Z``; the ``0001-01-01``
    sentinel means "never expires" and is in the past, so we
    explicitly guard for that and treat it as not-expired.
    """
    if not iso:
        return False
    try:
        # ``fromisoformat`` accepts ``Z`` only on Python 3.11+, which
        # is what we ship. Strip it just in case.
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.year <= 1:
        # 0001-01-01T00:00:00Z is Tailscale's "never" sentinel.
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt < datetime.now(UTC)


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


# ── Desired state computation ────────────────────────────────────────


def _compute_desired(
    tenant: TailscaleTenant,
    devices: list[_TailscaleDevice],
    summary: ReconcileSummary,
) -> list[_DesiredAddress]:
    """One ``_DesiredAddress`` per (device, address) tuple.

    Description carries OS + client version + user (the bits an
    operator scanning IPAM wants to see at a glance). Custom fields
    carry the rest — tags, expires, last_seen, routes, etc.
    """
    out: list[_DesiredAddress] = []
    for d in devices:
        # ``expires`` is stamped on every Tailscale device but it's
        # only enforced when ``keyExpiryDisabled`` is false. When
        # the operator has turned key expiry off (a common pattern
        # for long-lived servers / appliances), the timestamp may
        # still sit in the past — the device is operationally fine
        # and must not be filtered out.
        if tenant.skip_expired and not d.key_expiry_disabled and _expires_in_past(d.expires):
            summary.skipped_expired += 1
            continue
        if not d.addresses:
            continue
        os_label = d.os or "unknown"
        version_label = d.client_version or "unknown"
        user_label = d.user or "unknown"
        desc_bits = [f"{os_label} {version_label}".strip()]
        if user_label != "unknown":
            desc_bits.append(f"— {user_label}")
        description = " ".join(desc_bits).strip()
        cf: dict[str, Any] = {
            "tailscale_id": d.id,
            "tailscale_node_id": d.node_id,
            "os": d.os,
            "client_version": d.client_version,
            "user": d.user,
            "tags": list(d.tags),
            "authorized": d.authorized,
            "last_seen": d.last_seen,
            "expires": d.expires,
            "key_expiry_disabled": d.key_expiry_disabled,
            "update_available": d.update_available,
            "advertised_routes": list(d.advertised_routes),
            "enabled_routes": list(d.enabled_routes),
        }
        # Drop nulls / empties so the JSON column stays compact in
        # the UI (operators looking at the IPAM row don't need to
        # squint past empty arrays).
        cf = {k: v for k, v in cf.items() if v not in (None, "", [], False)}
        for ip in d.addresses:
            out.append(
                _DesiredAddress(
                    address=ip,
                    hostname=d.name,
                    description=description,
                    custom_fields=cf,
                )
            )
    return out


# ── Apply: blocks + subnets ──────────────────────────────────────────


async def _ensure_block_and_subnet(
    db: AsyncSession,
    tenant: TailscaleTenant,
    cidr: str,
    label: str,
    summary: ReconcileSummary,
) -> Subnet | None:
    """Ensure a tenant-owned block + subnet exist for ``cidr``.

    Returns the subnet row, or ``None`` if the CIDR is unparseable
    (operator typo on the tenant config). Idempotent — safe to call
    on every reconcile pass.
    """
    net = _parse_net(cidr)
    if net is None:
        summary.warnings.append(f"unparseable CIDR on tenant: {cidr!r}")
        return None
    cidr_norm = str(net)

    existing_block = (
        await db.execute(
            select(IPBlock).where(
                IPBlock.tailscale_tenant_id == tenant.id,
                IPBlock.network == cidr_norm,
            )
        )
    ).scalar_one_or_none()
    if existing_block is None:
        existing_block = IPBlock(
            space_id=tenant.ipam_space_id,
            network=cidr_norm,
            name=f"{tenant.name} {cidr_norm}",
            description=f"Auto-created for Tailscale tenant {tenant.name} ({label})",
            tailscale_tenant_id=tenant.id,
        )
        db.add(existing_block)
        await db.flush()
        summary.blocks_created += 1

    existing_subnet = (
        await db.execute(
            select(Subnet).where(
                Subnet.tailscale_tenant_id == tenant.id,
                Subnet.network == cidr_norm,
            )
        )
    ).scalar_one_or_none()
    if existing_subnet is None:
        existing_subnet = Subnet(
            space_id=tenant.ipam_space_id,
            block_id=existing_block.id,
            network=cidr_norm,
            name=f"tailscale:{label}",
            description=f"Tailscale {label} for tenant {tenant.name}",
            tailscale_tenant_id=tenant.id,
            total_ips=_lan_total_ips(net),
        )
        db.add(existing_subnet)
        await db.flush()
        summary.subnets_created += 1
    return existing_subnet


# ── Apply: addresses ──────────────────────────────────────────────────


async def _apply_addresses(
    db: AsyncSession,
    tenant: TailscaleTenant,
    desired: list[_DesiredAddress],
    summary: ReconcileSummary,
) -> None:
    subnet_rows = (
        (await db.execute(select(Subnet).where(Subnet.space_id == tenant.ipam_space_id)))
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
            if row.tailscale_tenant_id == tenant.id:
                continue  # already ours
            if row.tailscale_tenant_id is not None:
                summary.warnings.append(
                    f"address {row.address} owned by another Tailscale tenant; not claiming"
                )
                continue
            if owned_by_other_integration(row, "tailscale_tenant_id"):
                summary.warnings.append(
                    f"address {row.address} owned by another integration; not claiming"
                )
                continue
            row.tailscale_tenant_id = tenant.id
            if row.user_modified_at is None:
                row.user_modified_at = datetime.now(UTC)
        await db.flush()

    res = await db.execute(select(IPAddress).where(IPAddress.tailscale_tenant_id == tenant.id))
    current = {str(a.address): a for a in res.scalars().all()}

    dirty_subnets: set[Any] = {s.id for s in subnets if s.tailscale_tenant_id == tenant.id}

    for addr, row in current.items():
        if addr not in desired_map:
            dirty_subnets.add(row.subnet_id)
            if row.user_modified_at is not None:
                # Operator has invested edits; un-claim, leave the
                # row as a "manually managed" entry rather than
                # silently deleting their data.
                row.tailscale_tenant_id = None
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
                if row.status != "tailscale-node":
                    row.status = "tailscale-node"
                    changed = True
                if (row.hostname or "") != d.hostname:
                    row.hostname = d.hostname
                    changed = True
                if (row.description or "") != d.description:
                    row.description = d.description
                    changed = True
                # Custom fields are reconciler-owned — operator
                # edits to soft fields don't lock these, since the
                # tailnet metadata (last_seen, version, tags) is
                # most useful when fresh.
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
                    status="tailscale-node",
                    hostname=d.hostname,
                    description=d.description,
                    custom_fields=d.custom_fields,
                    tailscale_tenant_id=tenant.id,
                )
            )
            dirty_subnets.add(subnet.id)
            summary.addresses_created += 1

    if dirty_subnets:
        await db.flush()
        for subnet_id in dirty_subnets:
            await _recompute_subnet_utilization(db, subnet_id)


# ── Phase 2: synthetic DNS zone + records ────────────────────────────


# TTL on synthesised records. Short by design — devices come and go,
# IP assignments shift after re-auth, etc. 300 s lets a stale record
# fall out of resolver caches within five minutes of the next sync.
_SYNTHESISED_RECORD_TTL = 300


def _device_records_for_tenant(
    devices: list[_TailscaleDevice],
    zone_name: str,
    tenant: TailscaleTenant,
) -> list[tuple[str, str, str]]:
    """Compute the desired (label, record_type, value) tuples.

    One A record per IPv4 address, one AAAA record per IPv6 address.
    The label is the device's short hostname (the leading part of
    its FQDN before the tailnet zone). Devices with no FQDN, or
    whose FQDN doesn't end in our zone, are skipped — Tailscale
    sometimes returns devices with truncated names while they're
    being onboarded.

    Devices with expired keys (and ``skip_expired=True``) are
    filtered out the same way the IPAM mirror handles them, so the
    DNS surface and the IPAM surface stay consistent.
    """
    suffix = "." + zone_name
    out: list[tuple[str, str, str]] = []
    for d in devices:
        if tenant.skip_expired and not d.key_expiry_disabled and _expires_in_past(d.expires):
            continue
        name = (d.name or "").strip().rstrip(".")
        if not name:
            continue
        if not name.endswith(suffix):
            # Belongs to a different tailnet (or the FQDN hasn't
            # converged yet) — skip rather than crash.
            continue
        label = name[: -len(suffix)] or "@"
        for ip in d.addresses:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if isinstance(addr, ipaddress.IPv4Address):
                out.append((label, "A", str(addr)))
            else:
                out.append((label, "AAAA", str(addr)))
    return out


async def _apply_synthetic_dns(
    db: AsyncSession,
    tenant: TailscaleTenant,
    devices: list[_TailscaleDevice],
    summary: ReconcileSummary,
) -> None:
    """Materialise ``<tailnet>.ts.net`` zone + per-device records.

    Skips silently when:

    * the tenant has no ``dns_group_id`` bound (operator opt-in;
      Phase 2 is on the form but not required);
    * we can't derive the tailnet domain from the device list (no
      device has a usable FQDN — empty tailnet, agent first-boot, etc).

    Refuses to claim a pre-existing operator-managed zone with the
    same name in the bound group: that would silently overwrite
    operator records every reconcile pass. The collision lands as a
    summary warning so the UI / audit log surface it.
    """
    if tenant.dns_group_id is None:
        summary.dns_skipped = True
        return
    if not summary.tailnet_domain:
        summary.dns_skipped = True
        return

    # BIND9 zone names canonically end with a trailing dot. Other
    # subsystems in this repo round-trip both shapes; we follow the
    # template's convention so the zone renders cleanly in
    # ``named.conf``.
    zone_name = summary.tailnet_domain.rstrip(".") + "."

    # Look for an existing zone in this tenant's bound group.
    res = await db.execute(
        select(DNSZone).where(
            DNSZone.group_id == tenant.dns_group_id,
            DNSZone.name == zone_name,
        )
    )
    zone = res.scalar_one_or_none()
    if zone is not None and zone.tailscale_tenant_id is None:
        summary.warnings.append(
            f"DNS zone {zone_name!r} already exists in the bound group and is "
            f"operator-managed; not synthesising. Delete it or rename to "
            f"unblock the Tailscale Phase 2 surface."
        )
        summary.dns_skipped = True
        return
    if zone is not None and zone.tailscale_tenant_id != tenant.id:
        summary.warnings.append(
            f"DNS zone {zone_name!r} owned by another Tailscale tenant; " f"not synthesising."
        )
        summary.dns_skipped = True
        return

    if zone is None:
        zone = DNSZone(
            group_id=tenant.dns_group_id,
            name=zone_name,
            zone_type="primary",
            kind="forward",
            ttl=_SYNTHESISED_RECORD_TTL,
            primary_ns=zone_name,
            admin_email=f"hostmaster.{zone_name}",
            is_auto_generated=True,
            tailscale_tenant_id=tenant.id,
        )
        db.add(zone)
        await db.flush()
        summary.dns_zones_created += 1

    # Compute desired records.
    desired = _device_records_for_tenant(devices, summary.tailnet_domain, tenant)
    desired_keys: set[tuple[str, str, str]] = set(desired)

    rec_res = await db.execute(
        select(DNSRecord).where(
            DNSRecord.zone_id == zone.id,
            DNSRecord.tailscale_tenant_id == tenant.id,
        )
    )
    current: list[DNSRecord] = list(rec_res.scalars().all())
    current_by_key: dict[tuple[str, str, str], DNSRecord] = {}
    for r in current:
        key = (r.name, r.record_type, r.value)
        # Multiple devices could in theory clash on (label, type, value)
        # — a duplicate IP claim across hosts. Keep the first; the
        # second won't show up in `desired_keys` and will be deleted.
        current_by_key.setdefault(key, r)

    # Delete records no longer in the desired set.
    for key, row in current_by_key.items():
        if key in desired_keys:
            continue
        await db.delete(row)
        summary.dns_records_deleted += 1

    # Insert records that are new.
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
                tailscale_tenant_id=tenant.id,
            )
        )
        summary.dns_records_created += 1


# ── Entry point ───────────────────────────────────────────────────────


async def reconcile_tenant(db: AsyncSession, tenant: TailscaleTenant) -> ReconcileSummary:
    summary = ReconcileSummary(ok=False)

    api_key = ""
    if tenant.api_key_encrypted:
        try:
            api_key = decrypt_str(tenant.api_key_encrypted)
        except ValueError as exc:
            summary.error = f"api-key decrypt failed: {exc}"
            tenant.last_sync_error = summary.error
            tenant.last_synced_at = datetime.now(UTC)
            await db.commit()
            return summary
    if not api_key:
        summary.error = "no API key configured"
        tenant.last_sync_error = summary.error
        tenant.last_synced_at = datetime.now(UTC)
        await db.commit()
        return summary

    try:
        async with TailscaleClient(api_key=api_key, tailnet=tenant.tailnet) as client:
            devices = await client.list_devices()
    except TailscaleClientError as exc:
        summary.error = str(exc)
        tenant.last_sync_error = summary.error
        tenant.last_synced_at = datetime.now(UTC)
        await db.commit()
        logger.warning(
            "tailscale_reconcile_fetch_failed", tenant=str(tenant.id), error=summary.error
        )
        return summary

    summary.device_count = len(devices)
    summary.tailnet_domain = derive_tailnet_domain(devices)

    # Ensure the IPv4 CGNAT + IPv6 ULA blocks exist. We always
    # create both — even on an IPv4-only tailnet, the IPv6 block is
    # cheap and ready when devices come online with v6.
    await _ensure_block_and_subnet(db, tenant, tenant.cgnat_cidr, "ipv4", summary)
    await _ensure_block_and_subnet(db, tenant, tenant.ipv6_cidr, "ipv6", summary)

    desired = _compute_desired(tenant, devices, summary)
    await _apply_addresses(db, tenant, desired, summary)

    # Phase 2 — synthesise the tailnet's DNS surface in the bound
    # DNS group. Skipped silently when the operator hasn't bound a
    # group; an existing operator-managed zone with the same name
    # is left alone (warning surfaced via summary.warnings).
    await _apply_synthetic_dns(db, tenant, devices, summary)

    tenant.last_synced_at = datetime.now(UTC)
    tenant.last_sync_error = None
    tenant.tailnet_domain = summary.tailnet_domain
    tenant.device_count = summary.device_count

    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="tailscale.reconcile",
            resource_type="tailscale_tenant",
            resource_id=str(tenant.id),
            resource_display=tenant.name,
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
        "tailscale_reconcile_ok",
        tenant=str(tenant.id),
        tailnet_domain=summary.tailnet_domain,
        devices=summary.device_count,
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


__all__ = ["ReconcileSummary", "reconcile_tenant"]
