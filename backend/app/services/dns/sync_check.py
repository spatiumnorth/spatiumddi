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
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from typing import Literal

import structlog
from sqlalchemy import ColumnElement, String, and_, any_, func, literal, or_, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import name_in_zone_error
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.record_identity import ptr_target_key, zone_target_readings
from app.services.integration_ownership import dns_record_owned_elsewhere

logger = structlog.get_logger(__name__)

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
    reason: str  # "ip-deleted" | "ip-orphan" | "no-hostname" | ...
    # The live IPAM row the record is attached to, when there is one (absent
    # for ``ip-deleted``). Lets a client mark that row's DNS state as pending
    # cleanup instead of "in sync" (#2101).
    ip_id: uuid.UUID | None = None


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
    # Every reverse zone the subnet's addresses resolve to, in address order
    # (spatiumddi#1840: a /23 spans two, a /17 128). ``reverse_zone_id`` /
    # ``reverse_zone_name`` are the first of them, kept for older clients.
    reverse_zone_names: list[str] = field(default_factory=list)
    # #1932 — set when the subnet has no reverse zone because its DNS group
    # runs a cloud driver that has not opted in to auto-created reverse
    # zones: its PTRs are skipped, and this says why. None otherwise.
    reverse_zone_skipped_reason: str | None = None


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
    """Return the effective forward DNS zone UUID for a subnet, whatever the
    zone's type: it names the subnet's hosts. IPAM writes their A/AAAA records
    into it only if ``ipam_authors_zone`` says so (spatiumddi#1633)."""
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


def cidrs_overlap(a: object, b: object) -> bool:
    """True when two CIDR strings are the same address family and overlap.

    #844 uses this instead of a bare space-id comparison: reverse zones
    aggregate (``compute_reverse_zone_names``), so two NON-overlapping subnets
    in different spaces legitimately share one reverse zone — their PTR names
    are disjoint and nothing leaks. Only an actual CIDR overlap can fold two
    tenants' PTRs onto the same names.
    """
    try:
        na = ipaddress.ip_network(str(a), strict=False)
        nb = ipaddress.ip_network(str(b), strict=False)
    except (ValueError, TypeError):
        return False
    return na.version == nb.version and na.overlaps(nb)


def reverse_zone_pieces(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> list[ipaddress.IPv4Network] | list[ipaddress.IPv6Network]:
    """The zone-sized pieces ``net`` is split into, one reverse zone each
    (spatiumddi#1840) — see ``reverse_zone.compute_reverse_zone_names``.

    Each piece is either inside ``net`` or, for a subnet narrower than the
    unit, the one unit holding it: IPv4 /17–/32 → the /24, /9–/16 → the /16,
    /0–/8 → the /8; IPv6 → the next nibble boundary at or past the prefix
    length (a /55 → its two /56s). At most 256 pieces on IPv4 (a /0, /9 or
    /17), and at most 8 on IPv6 for any prefix but a /0.
    """
    if isinstance(net, ipaddress.IPv4Network):
        unit = 24 if net.prefixlen > 16 else 16 if net.prefixlen > 8 else 8
        if net.prefixlen >= unit:
            return [net.supernet(new_prefix=unit)] if net.prefixlen > unit else [net]
        return list(net.subnets(new_prefix=unit))
    unit6 = -(-net.prefixlen // 4) * 4 or 4
    if net.prefixlen >= unit6:
        return [net]
    return list(net.subnets(new_prefix=unit6))


def reverse_zone_network(name: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The network an octet-aligned ``in-addr.arpa`` (nibble-aligned
    ``ip6.arpa``) zone name covers — the inverse of
    ``reverse_zone.compute_reverse_zone_names``. ``None`` for any other name."""
    labels = name.lower().rstrip(".").split(".")
    if labels[-2:] == ["in-addr", "arpa"]:
        octets = labels[:-2][::-1]
        if not 1 <= len(octets) <= 3 or not all(o.isdigit() and int(o) <= 255 for o in octets):
            return None
        addr = ".".join(octets + ["0"] * (4 - len(octets)))
        return ipaddress.ip_network(f"{addr}/{8 * len(octets)}")
    if labels[-2:] == ["ip6", "arpa"]:
        nibbles = labels[:-2][::-1]
        if not 1 <= len(nibbles) <= 32 or not all(
            len(n) == 1 and n in "0123456789abcdef" for n in nibbles
        ):
            return None
        hexstr = "".join(nibbles).ljust(32, "0")
        addr = ":".join(hexstr[i : i + 4] for i in range(0, 32, 4))
        return ipaddress.ip_network(f"{addr}/{4 * len(nibbles)}")
    return None


def ptr_address(
    record_name: str, zone_name: str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a PTR named ``record_name`` in ``zone_name`` is for, or
    ``None`` when the owner name is not a full reverse pointer."""
    owner = (
        zone_name.rstrip(".")
        if record_name in ("", "@")
        else (f"{record_name.rstrip('.')}.{zone_name.rstrip('.')}")
    )
    labels = owner.lower().split(".")
    try:
        if labels[-2:] == ["in-addr", "arpa"] and len(labels) == 6:
            return ipaddress.IPv4Address(".".join(labels[:4][::-1]))
        if labels[-2:] == ["ip6", "arpa"] and len(labels) == 34:
            hexstr = "".join(labels[:32][::-1])
            return ipaddress.IPv6Address(":".join(hexstr[i : i + 4] for i in range(0, 32, 4)))
    except ValueError:
        return None
    return None


# #844 — log-dedupe for the cross-space skip. Per-IP call site, so an unfixed
# misconfig would warn once per IP per run forever; warn once per (subnet,
# zone) pair per process, debug after. Log suppression only.
_cross_space_skip_warned: set[tuple[str, str]] = set()


@dataclass(frozen=True)
class ReverseCandidate:
    zone: DNSZone
    linked_space_id: uuid.UUID | None
    linked_network: object | None
    in_group: bool  # from the effective DNS group(s), not only subnet-linked


async def load_reverse_candidates(
    db: AsyncSession, subnet: Subnet, group_ids: Sequence[object]
) -> list[ReverseCandidate]:
    """Every zone that could own a reverse name of ``subnet``'s addresses:
    the zones linked to the subnet, plus the reverse-owner zones of its
    effective DNS group(s). Load once per subnet and :func:`pick_reverse_zone`
    per address (spatiumddi#1840: a subnet wider than a /24 can span more than
    one zone, so the zone is a property of the ADDRESS, not of the subnet)."""
    out: dict[uuid.UUID, ReverseCandidate] = {}
    linked = (
        await db.execute(
            select(DNSZone).where(
                DNSZone.linked_subnet_id == subnet.id,
                DNSZone.kind == "reverse",
            )
        )
    ).scalars()
    for z in linked:
        out[z.id] = ReverseCandidate(z, subnet.space_id, subnet.network, False)
    if group_ids:
        rows = await db.execute(
            select(DNSZone, Subnet.space_id, Subnet.network)
            .outerjoin(Subnet, Subnet.id == DNSZone.linked_subnet_id)
            .where(DNSZone.group_id.in_(group_ids), reverse_owner_candidates())
        )
        for z, space_id, network in rows.all():
            out[z.id] = ReverseCandidate(z, space_id, network, True)
    return list(out.values())


def pick_reverse_zone(
    subnet: Subnet,
    ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    candidates: Sequence[ReverseCandidate],
) -> DNSZone | None:
    """The reverse zone IPAM writes ``ip_addr``'s PTR into, or ``None``.

    The ONE address → reverse-zone mapping: the IPAM router (PTR writes and
    the collision check) and the drift check both go through it.

    The most specific zone covering the address — among the zones linked to
    the subnet and those of its effective group(s) — owns the name whatever
    its type, and the PTR is written only when that is a zone IPAM authors
    (#1419). So a zone an operator made for a part of the subnet keeps winning over
    a wider zone that happens to cover them (#1840). A zone linked to
    an OVERLAPPING subnet in another IP space is never adopted (#844): both
    compute the same name, and a bare suffix match would fold two tenants'
    PTRs together.
    """
    rev_pointer = ip_addr.reverse_pointer + "."

    def covers(z: DNSZone) -> bool:
        zname = z.name.rstrip(".") + "."
        return rev_pointer.endswith("." + zname) or rev_pointer == zname

    best: DNSZone | None = None
    for c in candidates:
        z = c.zone
        own = z.linked_subnet_id == subnet.id and z.kind == "reverse"
        if not (own or c.in_group) or not covers(z):
            continue
        if (
            not own
            and c.linked_space_id is not None
            and c.linked_space_id != subnet.space_id
            and cidrs_overlap(c.linked_network, subnet.network)
        ):
            key = (str(subnet.id), str(z.id))
            log_fn = logger.debug if key in _cross_space_skip_warned else logger.warning
            _cross_space_skip_warned.add(key)
            log_fn(
                "reverse_zone_cross_space_skipped",
                subnet_id=str(subnet.id),
                zone_id=str(z.id),
                zone=z.name,
                note="zone is linked to an overlapping subnet in another "
                "IP space; PTR would leak across tenants (#844)",
            )
            continue
        if best is None or reverse_owner_key(z) > reverse_owner_key(best):
            best = z
    return best if best is not None and ipam_authors_zone(best) else None


def _subnet_reverse_zones(subnet: Subnet, candidates: Sequence[ReverseCandidate]) -> list[DNSZone]:
    """Every reverse zone that takes the PTR of at least one of ``subnet``'s
    addresses, in address order (spatiumddi#1840).

    The pick at the start of each piece of the subnet's zone set
    (``compute_reverse_zone_names``), plus any candidate zone overlapping the
    subnet that wins at its own first address inside it — an operator's zone
    for part of the subnet, which the per-piece picks can step over. Bounded:
    a subnet has at most 256 pieces.
    """
    try:
        net = ipaddress.ip_network(subnet.network, strict=False)
    except ValueError:
        return []
    starts = {int(p.network_address) for p in reverse_zone_pieces(net)}
    for c in candidates:
        covered = reverse_zone_network(c.zone.name)
        if covered is not None and covered.version == net.version and covered.overlaps(net):
            starts.add(max(int(covered.network_address), int(net.network_address)))
    out: list[DNSZone] = []
    seen: set[uuid.UUID] = set()
    for start in sorted(starts):
        z = pick_reverse_zone(subnet, ipaddress.ip_address(start), candidates)
        if z is not None and z.id not in seen:
            seen.add(z.id)
            out.append(z)
    return out


async def resolve_reverse_zone(
    db: AsyncSession,
    subnet: Subnet,
    ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    group_ids: Sequence[object],
) -> DNSZone | None:
    """:func:`pick_reverse_zone` over freshly loaded candidates."""
    cands = await load_reverse_candidates(db, subnet, group_ids)
    return pick_reverse_zone(subnet, ip_addr, cands)


# ── Drift computation ────────────────────────────────────────────────────────


def forward_zone_ids_in_order(
    primary_id: uuid.UUID | None, extra_zone_ids: Collection[object] | None
) -> list[uuid.UUID]:
    """The forward zones an address publishes to, before the zone filters.

    The primary first (when there is one), then each of ``extra_zone_ids`` in
    order, deduped; an entry that is not a UUID is skipped. One definition for
    ``_sync_dns_record``, which writes the records, and the drift check, which
    reads them, so the two cannot disagree about where a host record lives
    (#2107).
    """
    ordered: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    if primary_id is not None:
        ordered.append(primary_id)
        seen.add(primary_id)
    for raw in extra_zone_ids or []:
        try:
            extra = uuid.UUID(str(raw))
        except (ValueError, TypeError):
            continue
        if extra in seen:
            continue
        seen.add(extra)
        ordered.append(extra)
    return ordered


def _expected_a(hostname: str, addr: str, zone_name: str) -> tuple[str, str]:
    """Returns (record_name, record_value) for the A record IPAM would create."""
    return hostname, addr


def _own_alias_serves(recs: Sequence[DNSRecord], zone_id: uuid.UUID, name: str, rtype: str) -> bool:
    """True when one of the address's own aliases already holds ``(zone, name)`` (#2118).

    The same rule ``_own_alias_clashes`` applies on write (#2106): an
    ``ip_alias`` row of the address, same type, same zone, same name compared
    case-insensitively. ``_sync_dns_record`` skips the host record there, so
    drift must not expect it. ``recs`` are the address's own rows only, so
    another address's alias at the name never satisfies it.
    """
    want = name.strip().rstrip(".").lower()
    return any(
        r.ip_alias and r.zone_id == zone_id and r.record_type == rtype and r.name.lower() == want
        for r in recs
    )


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


async def compute_block_dns_drift(
    db: AsyncSession,
    block_id: uuid.UUID,
    *,
    subnet_ids: Collection[uuid.UUID] | None = None,
) -> DriftReport:
    """Aggregate drift across every subnet directly or transitively under
    the given block. Per-subnet zone summaries are dropped (multiple zones
    likely involved) — caller can fall back to a count.

    ``subnet_ids``, when given, limits the report to those subnets (a caller
    bound to specific subnets); ``None`` covers every subnet in the block."""
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

    return await _aggregate(db, _only(sn_ids, subnet_ids))


async def compute_space_dns_drift(
    db: AsyncSession,
    space_id: uuid.UUID,
    *,
    subnet_ids: Collection[uuid.UUID] | None = None,
) -> DriftReport:
    """Aggregate drift across every subnet in the space (or, with
    ``subnet_ids``, across those of them only)."""
    sn_ids = (
        (await db.execute(select(Subnet.id).where(Subnet.space_id == space_id))).scalars().all()
    )
    return await _aggregate(db, _only(sn_ids, subnet_ids))


def _only(found: Sequence[uuid.UUID], allowed: Collection[uuid.UUID] | None) -> Sequence[uuid.UUID]:
    if allowed is None:
        return found
    keep = set(allowed)
    return [sid for sid in found if sid in keep]


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


async def _cloud_reverse_optout_reason(
    db: AsyncSession, forward_zone: DNSZone | None, group_ids: Sequence[str]
) -> str | None:
    """Why a subnet with no reverse zone has none, when the reason is the
    #1932 cloud opt-out; None otherwise. The group is resolved the way the
    reverse-zone auto-create resolves it: the forward zone's group, else the
    first effective DNS group."""
    from app.services.dns.reverse_zone import (  # noqa: PLC0415
        cloud_reverse_optout_driver,
        cloud_reverse_optout_message,
    )

    group_id: uuid.UUID | None = forward_zone.group_id if forward_zone else None
    if group_id is None and group_ids:
        try:
            group_id = uuid.UUID(str(group_ids[0]))
        except ValueError:
            return None
    group = await db.get(DNSServerGroup, group_id) if group_id else None
    if group is None:
        return None
    driver = await cloud_reverse_optout_driver(db, group)
    return cloud_reverse_optout_message(group.name, driver) if driver else None


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
    # A subnet wider than a /24 spans several reverse zones (spatiumddi#1840),
    # so the zone is resolved per address below; the header lists every zone
    # the subnet's addresses resolve to.
    rev_group_ids, _ = await _effective_dns(db, subnet)
    rev_cands = await load_reverse_candidates(db, subnet, rev_group_ids)
    subnet_rev_zones = _subnet_reverse_zones(subnet, rev_cands)
    reverse_zone = subnet_rev_zones[0] if subnet_rev_zones else None
    rev_zones_by_id = {c.zone.id: c.zone for c in rev_cands}
    try:
        subnet_net: ipaddress.IPv4Network | ipaddress.IPv6Network | None = ipaddress.ip_network(
            subnet.network, strict=False
        )
    except ValueError:
        subnet_net = None

    report = DriftReport(
        subnet_id=subnet_id,
        forward_zone_id=forward_zone.id if forward_zone else None,
        forward_zone_name=forward_zone.name if forward_zone else None,
        reverse_zone_id=reverse_zone.id if reverse_zone else None,
        reverse_zone_name=reverse_zone.name if reverse_zone else None,
        reverse_zone_names=[z.name for z in subnet_rev_zones],
    )
    if not subnet_rev_zones:
        report.reverse_zone_skipped_reason = await _cloud_reverse_optout_reason(
            db, forward_zone, rev_group_ids
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
    # Scope: records in either of the candidate zones for this subnet, when
    # IPAM authors the zone: applying the sync would queue a delete op into a
    # forwarder, a secondary or a stub, which none of them can take
    # (spatiumddi#1633).
    # The reverse half is every zone the subnet's addresses resolve to — not
    # every reverse zone of the group, which would report other subnets'
    # orphans here (and once per subnet in a block or space aggregate).
    candidate_zone_ids = [
        z.id for z in (forward_zone, *subnet_rev_zones) if z is not None and ipam_authors_zone(z)
    ]
    rev_zone_ids = {z.id for z in subnet_rev_zones}
    if candidate_zone_ids:
        orphan_res = await db.execute(
            select(DNSRecord).where(
                DNSRecord.auto_generated.is_(True),
                DNSRecord.ip_address_id.is_(None),
                DNSRecord.zone_id.in_(candidate_zone_ids),
            )
        )
        for r in orphan_res.scalars().all():
            # #1554: records owned by an integration mirror, the DNS
            # pool pipeline, or ACME also carry no ip_address_id, but
            # they are not IPAM sync output — never report them stale
            # here (auto-sync would delete them and the owner would
            # recreate them on its next pass, flapping the name).
            if dns_record_owned_elsewhere(r):
                continue
            if r.record_type == "PTR" and r.zone_id in rev_zone_ids and subnet_net is not None:
                # A reverse zone is shared by every subnet in its /24 (a /25
                # pair, spatiumddi#1840): only a PTR for one of THIS subnet's
                # addresses is this subnet's orphan.
                addr = ptr_address(r.name, rev_zones_by_id[r.zone_id].name)
                if addr is not None and (
                    addr.version != subnet_net.version or addr not in subnet_net
                ):
                    continue
            zone_name = (
                forward_zone.name
                if forward_zone and r.zone_id == forward_zone.id
                else rev_zones_by_id[r.zone_id].name if r.zone_id in rev_zones_by_id else ""
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

    # #2107 — an address with ``extra_zone_ids`` also publishes its host record
    # into each of those zones IPAM authors, so it is checked in every one.
    # Every zone any address lists is loaded in one query for the subnet, the
    # subnet's own zone included: which zone is an address's primary is
    # decided per address in the walk below, not here.
    primary_id = forward_zone.id if forward_zone else None
    wanted_extra_ids = {
        z for ip_row in ips for z in forward_zone_ids_in_order(None, ip_row.extra_zone_ids)
    }
    extra_zones_by_id: dict[uuid.UUID, DNSZone] = {}
    if wanted_extra_ids:
        extra_zones_by_id = {
            z.id: z
            for z in (await db.execute(select(DNSZone).where(DNSZone.id.in_(wanted_extra_ids))))
            .scalars()
            .all()
            if ipam_authors_zone(z)
        }

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
                elif r.zone_id in rev_zones_by_id:
                    zone_name = rev_zones_by_id[r.zone_id].name
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type=r.record_type,
                        zone_id=r.zone_id,
                        zone_name=zone_name,
                        name=r.name,
                        value=r.value,
                        reason=reason,
                        ip_id=ip.id,
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
            # #2084 — an alias is an A / AAAA of the address too, but it is
            # not the host record: it would read as a mismatch and the sync
            # would rewrite it into the host name.
            r
            for r in recs_by_ip.get(ip.id, [])
            if r.record_type in ("A", "AAAA") and not r.ip_alias
        ]
        ip_ptr_records = [r for r in recs_by_ip.get(ip.id, []) if r.record_type == "PTR"]

        # The extra zones this address publishes to (#2107), minus any the name
        # does not fit in, as ``_sync_dns_record`` skips those too. A forward
        # record outside the primary zone and these is judged against the
        # primary, as before.
        extra_zones = [
            extra_zones_by_id[z]
            for z in forward_zone_ids_in_order(primary_id, ip.extra_zone_ids)
            if z != primary_id
            and z in extra_zones_by_id
            and name_in_zone_error(ip.hostname, extra_zones_by_id[z].name.rstrip("."), field="h")
            is None
        ]
        extra_zone_ids = {z.id for z in extra_zones}
        primary_forward_records = [r for r in ip_forward_records if r.zone_id not in extra_zone_ids]

        # The default-named gateway placeholder (`hostname == "gateway"`) is
        # intentionally excluded from forward DNS — see the matching guard in
        # ``_sync_dns_record``. Renaming the IP turns forward sync back on.
        is_default_gateway = ip.hostname == "gateway"

        # ── Forward A / AAAA ─────────────────────────────────────────────────
        # Only in a zone IPAM authors (spatiumddi#1633). A forwarder, a
        # secondary or a stub as the subnet's zone still names its hosts (the
        # PTR below points into it), but takes no A/AAAA from IPAM, so none is
        # expected; a row an earlier release wrote there leaves, with no op,
        # the next time IPAM syncs the address.
        if forward_zone and ipam_authors_zone(forward_zone) and not is_default_gateway:
            exp_name, exp_value = _expected_a(ip.hostname, str(ip.address), forward_zone.name)
            if not primary_forward_records and not _own_alias_serves(
                recs_by_ip.get(ip.id, []), forward_zone.id, exp_name, forward_rtype
            ):
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
                for r in primary_forward_records:
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
                        ip_id=ip.id,
                    )
                )
        elif not forward_zone and primary_forward_records:
            # Forward zone was unassigned (or inherited to null) after A/AAAA
            # records were already published. No effective zone to match
            # against → mark them stale so the user can delete them. Same
            # intent as the ``no-forward-zone`` PTR branch below: keeps
            # "Sync DNS" able to clean up after a zone disassociation even
            # though the classifier otherwise has nothing to diff against.
            for r in primary_forward_records:
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type=r.record_type,
                        zone_id=r.zone_id,
                        zone_name="",
                        name=r.name,
                        value=r.value,
                        reason="no-forward-zone",
                        ip_id=ip.id,
                    )
                )

        if not is_default_gateway:
            for xz in extra_zones:
                x_name, x_value = _expected_a(ip.hostname, str(ip.address), xz.name)
                x_recs = [r for r in ip_forward_records if r.zone_id == xz.id]
                if not x_recs and not _own_alias_serves(
                    recs_by_ip.get(ip.id, []), xz.id, x_name, forward_rtype
                ):
                    report.missing.append(
                        MissingItem(
                            ip_id=ip.id,
                            ip_address=str(ip.address),
                            hostname=ip.hostname,
                            record_type=forward_rtype,
                            expected_name=x_name,
                            expected_value=x_value,
                            zone_id=xz.id,
                            zone_name=xz.name,
                        )
                    )
                for r in x_recs:
                    if r.record_type != forward_rtype or r.name != x_name or r.value != x_value:
                        report.mismatched.append(
                            MismatchItem(
                                record_id=r.id,
                                ip_id=ip.id,
                                ip_address=str(ip.address),
                                record_type=forward_rtype,
                                zone_id=r.zone_id,
                                zone_name=xz.name,
                                current_name=r.name,
                                current_value=r.value,
                                expected_name=x_name,
                                expected_value=x_value,
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
        try:
            rz = pick_reverse_zone(subnet, ipaddress.ip_address(str(ip.address)), rev_cands)
        except ValueError:
            continue
        if rz and forward_zone:
            try:
                exp_label, _ = _expected_ptr(str(ip.address), ip.hostname, rz.name)
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
                        zone_id=rz.id,
                        zone_name=rz.name,
                    )
                )
            else:
                for r in ip_ptr_records:
                    if r.zone_id != rz.id or r.name != exp_label or r.value != exp_value:
                        report.mismatched.append(
                            MismatchItem(
                                record_id=r.id,
                                ip_id=ip.id,
                                ip_address=str(ip.address),
                                record_type="PTR",
                                zone_id=r.zone_id,
                                zone_name=rz.name if r.zone_id == rz.id else "",
                                current_name=r.name,
                                current_value=r.value,
                                expected_name=exp_label,
                                expected_value=exp_value,
                            )
                        )
        elif rz and not forward_zone:
            # Forward zone was unassigned after PTRs were already published.
            # There's no valid FQDN to point them at now — mark them stale
            # so they get cleaned up when the user applies the sync.
            for r in ip_ptr_records:
                report.stale.append(
                    StaleItem(
                        record_id=r.id,
                        record_type="PTR",
                        zone_id=r.zone_id,
                        zone_name=rz.name if r.zone_id == rz.id else "",
                        name=r.name,
                        value=r.value,
                        reason="no-forward-zone",
                        ip_id=ip.id,
                    )
                )

    report.missing = await _drop_operator_held(db, report.missing)
    return report


def _rr_identity(
    zone_id: uuid.UUID,
    name: str,
    rtype: str,
    value: str,
    readings: dict[uuid.UUID, tuple[str, bool]],
) -> tuple[str, ...]:
    """The #1230 identity of a record, as ``_operator_record_twin`` in the
    IPAM router matches it: owner name case-insensitive, value trimmed. A PTR
    target compares as the zone's servers serve it (#2045): case-insensitive,
    and a target without its trailing dot is relative to the reverse zone on
    BIND9 / Technitium / Windows Path A, so it does not hide a missing PTR
    there."""
    v = value.strip()
    if rtype.upper() == "PTR" and zone_id in readings:
        zone_name, relative = readings[zone_id]
        v = ptr_target_key(v, zone_name, relative=relative)
    return (str(zone_id), name.lower(), rtype.upper(), v)


async def _drop_operator_held(db: AsyncSession, missing: list[MissingItem]) -> list[MissingItem]:
    """Drop the "missing" records an operator already wrote (#1867).

    ``_sync_dns_record`` adopts an identical operator-written record instead
    of writing a twin, and the adopted row is neither ``auto_generated`` nor
    linked by ``ip_address_id``, so the classifier above cannot see it. Without
    this, an adopted address reads as missing on every check, and applying the
    sync changes nothing.
    """
    if not missing:
        return missing
    names = sorted({m.expected_name.lower() for m in missing})
    zone_ids = list({m.zone_id for m in missing})
    rows = (
        await db.execute(
            select(DNSRecord.zone_id, DNSRecord.name, DNSRecord.record_type, DNSRecord.value).where(
                DNSRecord.auto_generated.is_(False),
                DNSRecord.view_id.is_(None),
                DNSRecord.zone_id.in_(zone_ids),
                func.upper(DNSRecord.record_type).in_(["A", "AAAA", "PTR"]),
                DNSRecord.priority.is_(None),
                DNSRecord.weight.is_(None),
                DNSRecord.port.is_(None),
                # One array parameter: a /16's worth of names as an IN list
                # would pass asyncpg's bind-parameter limit.
                func.lower(DNSRecord.name) == any_(literal(names, ARRAY(String))),
            )
        )
    ).all()
    readings = await zone_target_readings(
        db, {m.zone_id for m in missing if m.record_type.upper() == "PTR"}
    )
    held = {_rr_identity(z, n, t, v, readings) for z, n, t, v in rows}
    return [
        m
        for m in missing
        if _rr_identity(m.zone_id, m.expected_name, m.record_type, m.expected_value, readings)
        not in held
    ]
