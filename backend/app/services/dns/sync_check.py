"""IPAM ↔ DNS reconciliation: detect and fix drift between IPAM-allocated IPs
and the DNS records IPAM is supposed to be managing for them.

Drift buckets:

- **missing**:    IPAM expects an A or PTR record (allocated IP with hostname
                  + an effective forward/reverse zone), but no record exists
                  (either ``ip.dns_record_id`` is NULL, or it points to a row
                  that was deleted out-of-band).
- **mismatched**: A record exists for the IP but its name/value differs from
                  what IPAM would create today (e.g. hostname was renamed but
                  the record didn't update, or someone edited the record
                  manually in BIND).
- **stale**:      A DNSRecord exists with ``auto_generated=True`` and an
                  ``ip_address_id`` that no longer points at a live address in
                  this subnet. Most commonly: the IPAddress was deleted but
                  the record was left behind by an earlier code path.

The compute function is read-only. Apply happens via ``_sync_dns_record`` in
the IPAM router (for create/update) or direct row delete (for stale).
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import ColumnElement, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

# ── Drift report dataclasses ─────────────────────────────────────────────────


@dataclass
class MissingItem:
    ip_id: uuid.UUID
    ip_address: str
    hostname: str
    record_type: Literal["A", "AAAA", "PTR"]
    expected_name: str
    expected_value: str
    zone_id: uuid.UUID
    zone_name: str


@dataclass
class MismatchItem:
    record_id: uuid.UUID
    ip_id: uuid.UUID
    ip_address: str
    record_type: Literal["A", "AAAA", "PTR"]
    zone_id: uuid.UUID
    zone_name: str
    current_name: str
    current_value: str
    expected_name: str
    expected_value: str


@dataclass
class StaleItem:
    record_id: uuid.UUID
    record_type: str
    zone_id: uuid.UUID
    zone_name: str
    name: str
    value: str
    reason: str  # "ip-deleted" | "ip-orphan" | "no-hostname"


@dataclass
class DriftReport:
    subnet_id: uuid.UUID
    forward_zone_id: uuid.UUID | None
    forward_zone_name: str | None
    reverse_zone_id: uuid.UUID | None
    reverse_zone_name: str | None
    missing: list[MissingItem] = field(default_factory=list)
    mismatched: list[MismatchItem] = field(default_factory=list)
    stale: list[StaleItem] = field(default_factory=list)


# ── Effective DNS resolution (duplicated minimally to avoid a router import) ─


async def _effective_dns(db: AsyncSession, subnet: Subnet) -> tuple[list[str], uuid.UUID | None]:
    """Walk subnet → block ancestors → space, return
    ``(effective_dns_group_ids, effective_forward_zone_id)``.

    Ignoring the inherit flag here causes silent drift: a subnet flipped
    back to "inherit from parent" keeps pushing records to the server
    that was previously pinned on it. Don't bypass this helper.
    """
    if not subnet.dns_inherit_settings:
        zone_id = uuid.UUID(subnet.dns_zone_id) if subnet.dns_zone_id else None
        return (list(subnet.dns_group_ids or []), zone_id)

    current = await db.get(IPBlock, subnet.block_id) if subnet.block_id else None
    while current is not None:
        if not current.dns_inherit_settings:
            zone_id = uuid.UUID(current.dns_zone_id) if current.dns_zone_id else None
            return (list(current.dns_group_ids or []), zone_id)
        if current.parent_block_id:
            current = await db.get(IPBlock, current.parent_block_id)
        else:
            space = await db.get(IPSpace, current.space_id)
            if space is None:
                break
            zone_id = uuid.UUID(space.dns_zone_id) if space.dns_zone_id else None
            return (list(space.dns_group_ids or []), zone_id)
    return ([], None)


async def _effective_forward_zone_id(db: AsyncSession, subnet: Subnet) -> uuid.UUID | None:
    """Return the effective forward DNS zone UUID for a subnet."""
    _, zone_id = await _effective_dns(db, subnet)
    return zone_id


def ipam_authors_zone(zone: DNSZone) -> bool:
    """Whether IPAM may write records into ``zone``: only a zone SpatiumDDI
    serves as primary (spatiumddi#1419).

    A forward zone is a forwarders block with no zone file and no
    allow-update, and a secondary's or a stub's data comes from its primary:
    a record IPAM writes there is served by nobody, and its RFC 2136 update is
    refused.
    """
    return zone.zone_type == "primary"


def reverse_owner_candidates() -> ColumnElement[bool]:
    """The zones that can own a reverse name (spatiumddi#1419): every
    ``kind: reverse`` zone, and every zone named under ``arpa`` that is not
    primary, whatever its kind. Add Zone keeps the kind it is given for a
    forwarder, a secondary or a stub (#1310), so one named under in-addr.arpa
    may be stored ``forward`` and still own those names; a primary stored
    ``forward`` takes no PTR, as before. The name test only narrows the
    fetch — callers still match the name label-wise against the pointer."""
    return or_(
        DNSZone.kind == "reverse",
        and_(
            DNSZone.zone_type != "primary",
            or_(DNSZone.name.ilike("%arpa"), DNSZone.name.ilike("%arpa.")),
        ),
    )


def reverse_owner_key(zone: DNSZone) -> tuple[int, bool]:
    """Sort key for the owner of a reverse name among the candidate zones that
    cover it (spatiumddi#1419): the most specific zone owns the name, whatever
    its type, so IPAM writes no PTR into a less specific primary for names a
    forwarder, a secondary or a stub beneath it owns. At equal depth (one name
    in two views) a primary wins."""
    return (len(zone.name.rstrip(".")), ipam_authors_zone(zone))


async def _effective_reverse_zone(db: AsyncSession, subnet: Subnet) -> DNSZone | None:
    """Find the reverse zone for this subnet — first by ``linked_subnet_id``,
    then by longest-suffix match against the subnet's *effective* DNS group(s).

    Only a zone IPAM authors is returned (spatiumddi#1419), by the same rule
    as the IPAM router's ``_resolve_reverse_zone``: when the zone that owns
    the subnet's reverse names is a forwarder, a secondary or a stub, there is
    none, and the drift check expects no PTR.
    """
    res = await db.execute(
        select(DNSZone).where(
            DNSZone.linked_subnet_id == subnet.id,
            DNSZone.kind == "reverse",
        )
    )
    z = res.scalar_one_or_none()
    if z and ipam_authors_zone(z):
        return z

    group_ids, _ = await _effective_dns(db, subnet)
    if not group_ids:
        return None

    # Use the subnet network's reverse pointer for the suffix match.
    try:
        net = ipaddress.ip_network(subnet.network, strict=False)
    except ValueError:
        return None
    sample = net.network_address.reverse_pointer + "."

    res = await db.execute(
        select(DNSZone).where(
            DNSZone.group_id.in_(group_ids),
            reverse_owner_candidates(),
        )
    )
    best: DNSZone | None = None
    for cand in res.scalars().all():
        zname = cand.name.rstrip(".") + "."
        if sample.endswith("." + zname) or sample == zname:
            if best is None or reverse_owner_key(cand) > reverse_owner_key(best):
                best = cand
    return best if best is not None and ipam_authors_zone(best) else None


# ── Drift computation ────────────────────────────────────────────────────────


def _expected_a(hostname: str, addr: str, zone_name: str) -> tuple[str, str]:
    """Returns (record_name, record_value) for the A record IPAM would create."""
    return hostname, addr


def _expected_ptr(addr: str, hostname: str, zone_name: str) -> tuple[str, str]:
    """Returns (ptr_label, ptr_target_fqdn). ``ptr_label`` is "@" when the
    address's reverse_pointer equals the zone, otherwise the labels stripped
    of the zone suffix."""
    ip_obj = ipaddress.ip_address(addr)
    rev_full = ip_obj.reverse_pointer + "."
    z = zone_name.rstrip(".") + "."
    if rev_full == z:
        label = "@"
    else:
        label = rev_full[: -(len(z) + 1)]
    return label, hostname  # value rendered with trailing dot at apply time


async def compute_block_dns_drift(db: AsyncSession, block_id: uuid.UUID) -> DriftReport:
    """Aggregate drift across every subnet directly or transitively under
    the given block. Per-subnet zone summaries are dropped (multiple zones
    likely involved) — caller can fall back to a count."""
    # Walk the block subtree
    descendant_ids: list[uuid.UUID] = []
    queue = [block_id]
    while queue:
        bid = queue.pop()
        descendant_ids.append(bid)
        kids = (
            (await db.execute(select(IPBlock.id).where(IPBlock.parent_block_id == bid)))
            .scalars()
            .all()
        )
        queue.extend(kids)

    sn_ids = (
        (await db.execute(select(Subnet.id).where(Subnet.block_id.in_(descendant_ids))))
        .scalars()
        .all()
    )

    return await _aggregate(db, sn_ids)


async def compute_space_dns_drift(db: AsyncSession, space_id: uuid.UUID) -> DriftReport:
    """Aggregate drift across every subnet in the space."""
    sn_ids = (
        (await db.execute(select(Subnet.id).where(Subnet.space_id == space_id))).scalars().all()
    )
    return await _aggregate(db, sn_ids)


async def _aggregate(db: AsyncSession, subnet_ids: Sequence[uuid.UUID]) -> DriftReport:
    agg = DriftReport(
        subnet_id=uuid.UUID(int=0),
        forward_zone_id=None,
        forward_zone_name=None,
        reverse_zone_id=None,
        reverse_zone_name=None,
    )
    if not subnet_ids:
        return agg

    # Bulk-load the two biggest per-subnet reads ONCE across every subnet
    # instead of re-querying inside each compute_subnet_dns_drift call — the
    # loop was ~2 SELECTs/subnet (IPs + their auto-generated records), i.e.
    # O(N) round-trips for an N-subnet block (#483). The per-subnet zone
    # resolution stays inside the callee (its inheritance walks amortize via
    # the session identity map across sibling subnets).
    all_ips = list(
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id.in_(subnet_ids))))
        .scalars()
        .all()
    )
    ips_by_subnet: dict[uuid.UUID, list[IPAddress]] = {}
    for ip in all_ips:
        ips_by_subnet.setdefault(ip.subnet_id, []).append(ip)

    recs_by_ip: dict[uuid.UUID, list[DNSRecord]] = {}
    all_ip_ids = [ip.id for ip in all_ips]
    if all_ip_ids:
        for r in (
            (
                await db.execute(
                    select(DNSRecord).where(
                        DNSRecord.auto_generated.is_(True),
                        DNSRecord.ip_address_id.in_(all_ip_ids),
                    )
                )
            )
            .scalars()
            .all()
        ):
            if r.ip_address_id is not None:
                recs_by_ip.setdefault(r.ip_address_id, []).append(r)

    for sid in subnet_ids:
        sub_ips = ips_by_subnet.get(sid, [])
        sub_recs = {ip.id: recs_by_ip.get(ip.id, []) for ip in sub_ips}
        sub_report = await compute_subnet_dns_drift(
            db, sid, preloaded_ips=sub_ips, preloaded_recs_by_ip=sub_recs
        )
        agg.missing.extend(sub_report.missing)
        agg.mismatched.extend(sub_report.mismatched)
        agg.stale.extend(sub_report.stale)
    return agg


async def compute_subnet_dns_drift(
    db: AsyncSession,
    subnet_id: uuid.UUID,
    *,
    preloaded_ips: list[IPAddress] | None = None,
    preloaded_recs_by_ip: dict[uuid.UUID, list[DNSRecord]] | None = None,
) -> DriftReport:
    # ``preloaded_*`` let ``_aggregate`` batch the IP + auto-record loads once
    # across a whole block/space instead of re-querying per subnet (#483). When
    # omitted (the single-subnet call path) we load them here as before.
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        raise ValueError(f"Subnet {subnet_id} not found")

    forward_zone_id = await _effective_forward_zone_id(db, subnet)
    forward_zone = await db.get(DNSZone, forward_zone_id) if forward_zone_id else None
    reverse_zone = await _effective_reverse_zone(db, subnet)

    report = DriftReport(
        subnet_id=subnet_id,
        forward_zone_id=forward_zone.id if forward_zone else None,
        forward_zone_name=forward_zone.name if forward_zone else None,
        reverse_zone_id=reverse_zone.id if reverse_zone else None,
        reverse_zone_name=reverse_zone.name if reverse_zone else None,
    )

    # All live IPs in the subnet (batched by the caller, else loaded here).
    if preloaded_ips is not None:
        ips = preloaded_ips
    else:
        ips_res = await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id))
        ips = list(ips_res.scalars().all())

    # Scopes may opt out of DNS drift for their dynamic-pool lease mirrors:
    # a pulled lease carries a client-supplied hostname, so without this the
    # drift check flags every ephemeral lease with no DNS record as "out of
    # sync". Collect the dynamic-pool ranges of every scope on this subnet with
    # ``dns_track_dynamic_leases=False``; ``auto_from_lease`` IPs inside them
    # are skipped in the walk below (and any leftover auto-records for them are
    # treated as stale, so disabling the toggle offers to clean them up).
    from app.models.dhcp import DHCPPool, DHCPScope  # noqa: PLC0415 — lazy DNS→DHCP dep

    suppressed_ranges: list[tuple[int, int]] = []
    untracked_scope_ids = list(
        (
            await db.execute(
                select(DHCPScope.id).where(
                    DHCPScope.subnet_id == subnet_id,
                    DHCPScope.dns_track_dynamic_leases.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    if untracked_scope_ids:
        untracked_pools = (
            (
                await db.execute(
                    select(DHCPPool).where(
                        DHCPPool.scope_id.in_(untracked_scope_ids),
                        DHCPPool.pool_type == "dynamic",
                    )
                )
            )
            .scalars()
            .all()
        )
        for p in untracked_pools:
            try:
                lo = int(ipaddress.ip_address(str(p.start_ip)))
                hi = int(ipaddress.ip_address(str(p.end_ip)))
            except (ValueError, TypeError):
                continue
            suppressed_ranges.append((min(lo, hi), max(lo, hi)))

    def _dns_suppressed(ip_row: IPAddress) -> bool:
        if not getattr(ip_row, "auto_from_lease", False) or not suppressed_ranges:
            return False
        try:
            v = int(ipaddress.ip_address(str(ip_row.address)))
        except (ValueError, TypeError):
            return False
        return any(lo <= v <= hi for lo, hi in suppressed_ranges)

    # All auto-generated DNS records that point at IPs in this subnet.
    if preloaded_recs_by_ip is not None:
        recs_by_ip = preloaded_recs_by_ip
    else:
        if ips:
            rec_res = await db.execute(
                select(DNSRecord).where(
                    DNSRecord.auto_generated.is_(True),
                    DNSRecord.ip_address_id.in_([ip.id for ip in ips]),
                )
            )
            records = list(rec_res.scalars().all())
        else:
            records = []
        recs_by_ip = {}
        for r in records:
            if r.ip_address_id is not None:
                recs_by_ip.setdefault(r.ip_address_id, []).append(r)

    # Also pick up records that *think* they belong to a subnet IP but the IP
    # was deleted (FK is SET NULL on IPAddress delete) — these are stale.
    # Scope: records in either of the candidate zones for this subnet.
    candidate_zone_ids = [z.id for z in (forward_zone, reverse_zone) if z is not None]
    if candidate_zone_ids:
        orphan_res = await db.execute(
            select(DNSRecord).where(
                DNSRecord.auto_generated.is_(True),
                DNSRecord.ip_address_id.is_(None),
                DNSRecord.zone_id.in_(candidate_zone_ids),
            )
        )
        for r in orphan_res.scalars().all():
            zone_name = (
                forward_zone.name
                if forward_zone and r.zone_id == forward_zone.id
                else reverse_zone.name if reverse_zone and r.zone_id == reverse_zone.id else ""
            )
            report.stale.append(
                StaleItem(
                    record_id=r.id,
                    record_type=r.record_type,
                    zone_id=r.zone_id,
                    zone_name=zone_name,
                    name=r.name,
                    value=r.value,
                    reason="ip-deleted",
                )
            )

    # Walk each live IP and classify.
    for ip in ips:
        # Skip system rows (network/broadcast/gateway/orphan), rows with no
        # hostname, and dynamic-pool lease mirrors on a scope that opted out of
        # dynamic-lease DNS tracking — IPAM never publishes DNS for these.
        dns_suppressed = _dns_suppressed(ip)
        if ip.status in ("network", "broadcast", "orphan") or not ip.hostname or dns_suppressed:
            reason = (
                "dynamic-lease-untracked"
                if dns_suppressed
                else "ip-orphan" if ip.status == "orphan" else "no-hostname"
            )
            # If there are leftover auto-records pointing here, they're stale.
            for r in recs_by_ip.get(ip.id, []):
                zone_name = ""
                if forward_zone and r.zone_id == forward_zone.id:
                    zone_name = forward_zone.name
                elif reverse_zone and r.zone_id == reverse_zone.id:
                    zone_name = reverse_zone.name
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type=r.record_type,
                        zone_id=r.zone_id,
                        zone_name=zone_name,
                        name=r.name,
                        value=r.value,
                        reason=reason,
                    )
                )
            continue

        # Forward record family depends on the IP: AAAA for IPv6, A for IPv4.
        # Collect BOTH so a stale/mismatched AAAA on a v6 IP is surfaced — the
        # classifier was A-only, so IPv6 subnets never reported missing/stale
        # AAAA and "Sync DNS" always looked clean on them (#481).
        forward_rtype: Literal["A", "AAAA"] = (
            "AAAA" if ipaddress.ip_address(str(ip.address)).version == 6 else "A"
        )
        ip_forward_records = [
            r for r in recs_by_ip.get(ip.id, []) if r.record_type in ("A", "AAAA")
        ]
        ip_ptr_records = [r for r in recs_by_ip.get(ip.id, []) if r.record_type == "PTR"]

        # The default-named gateway placeholder (`hostname == "gateway"`) is
        # intentionally excluded from forward DNS — see the matching guard in
        # ``_sync_dns_record``. Renaming the IP turns forward sync back on.
        is_default_gateway = ip.hostname == "gateway"

        # ── Forward A / AAAA ─────────────────────────────────────────────────
        if forward_zone and not is_default_gateway:
            exp_name, exp_value = _expected_a(ip.hostname, str(ip.address), forward_zone.name)
            if not ip_forward_records:
                report.missing.append(
                    MissingItem(
                        ip_id=ip.id,
                        ip_address=str(ip.address),
                        hostname=ip.hostname,
                        record_type=forward_rtype,
                        expected_name=exp_name,
                        expected_value=exp_value,
                        zone_id=forward_zone.id,
                        zone_name=forward_zone.name,
                    )
                )
            else:
                for r in ip_forward_records:
                    # A wrong-family record (A on a v6 IP or vice-versa) is drift
                    # too, so diff the type alongside zone/name/value.
                    if (
                        r.record_type != forward_rtype
                        or r.zone_id != forward_zone.id
                        or r.name != exp_name
                        or r.value != exp_value
                    ):
                        report.mismatched.append(
                            MismatchItem(
                                record_id=r.id,
                                ip_id=ip.id,
                                ip_address=str(ip.address),
                                record_type=forward_rtype,
                                zone_id=r.zone_id,
                                zone_name=forward_zone.name if r.zone_id == forward_zone.id else "",
                                current_name=r.name,
                                current_value=r.value,
                                expected_name=exp_name,
                                expected_value=exp_value,
                            )
                        )
        elif is_default_gateway:
            # Forward A/AAAA records for default-gateway-named IPs are stale by
            # definition (see _sync_dns_record). Surface them so the user
            # can clean up.
            for r in ip_forward_records:
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type=r.record_type,
                        zone_id=r.zone_id,
                        zone_name=(
                            forward_zone.name
                            if forward_zone and r.zone_id == forward_zone.id
                            else ""
                        ),
                        name=r.name,
                        value=r.value,
                        reason="default-gateway-name",
                    )
                )
        elif not forward_zone and ip_forward_records:
            # Forward zone was unassigned (or inherited to null) after A/AAAA
            # records were already published. No effective zone to match
            # against → mark them stale so the user can delete them. Same
            # intent as the ``no-forward-zone`` PTR branch below: keeps
            # "Sync DNS" able to clean up after a zone disassociation even
            # though the classifier otherwise has nothing to diff against.
            for r in ip_forward_records:
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type=r.record_type,
                        zone_id=r.zone_id,
                        zone_name="",
                        name=r.name,
                        value=r.value,
                        reason="no-forward-zone",
                    )
                )

        # ── Reverse PTR ──────────────────────────────────────────────────────
        # Require BOTH zones: a PTR value has to be an FQDN, which means we
        # need a forward zone to supply the domain. Without a forward zone,
        # existing PTRs are stale (→ delete) rather than mismatched, because
        # there's no valid target to rewrite them to. See: if you only guard
        # on ``reverse_zone``, an un-assigned forward zone produces an
        # "expected" value of ``hostname.`` (bare label, no FQDN), and the
        # reconciler rewrites every PTR to that broken value instead of
        # deleting them.
        if reverse_zone and forward_zone:
            try:
                exp_label, _ = _expected_ptr(str(ip.address), ip.hostname, reverse_zone.name)
                exp_value = (ip.hostname + "." + forward_zone.name.rstrip(".")).rstrip(".") + "."
            except ValueError:
                continue

            if not ip_ptr_records:
                report.missing.append(
                    MissingItem(
                        ip_id=ip.id,
                        ip_address=str(ip.address),
                        hostname=ip.hostname,
                        record_type="PTR",
                        expected_name=exp_label,
                        expected_value=exp_value,
                        zone_id=reverse_zone.id,
                        zone_name=reverse_zone.name,
                    )
                )
            else:
                for r in ip_ptr_records:
                    if r.zone_id != reverse_zone.id or r.name != exp_label or r.value != exp_value:
                        report.mismatched.append(
                            MismatchItem(
                                record_id=r.id,
                                ip_id=ip.id,
                                ip_address=str(ip.address),
                                record_type="PTR",
                                zone_id=r.zone_id,
                                zone_name=reverse_zone.name if r.zone_id == reverse_zone.id else "",
                                current_name=r.name,
                                current_value=r.value,
                                expected_name=exp_label,
                                expected_value=exp_value,
                            )
                        )
        elif reverse_zone and not forward_zone:
            # Forward zone was unassigned after PTRs were already published.
            # There's no valid FQDN to point them at now — mark them stale
            # so they get cleaned up when the user applies the sync.
            for r in ip_ptr_records:
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type="PTR",
                        zone_id=r.zone_id,
                        zone_name=reverse_zone.name if r.zone_id == reverse_zone.id else "",
                        name=r.name,
                        value=r.value,
                        reason="no-forward-zone",
                    )
                )

    return report
