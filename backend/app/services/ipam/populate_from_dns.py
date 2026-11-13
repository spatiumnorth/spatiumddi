"""Populate IPAM addresses from DNS records that already exist (#2251).

An operator adopting SpatiumDDI over an existing DNS estate (zones pulled in
from a Windows DNS server, say) starts with an empty IPAM while every host
sits in DNS. This scans A / AAAA records, matches each address to the most
specific IPAM subnet in scope, and either previews or commits the result.

* **No DNS writes, ever.** The commit creates ``IPAddress`` rows and LINKS
  each to the record that is already there (``dns_record_id`` /
  ``forward_zone_id``, the adoption shape of #1867: the record keeps
  ``auto_generated`` false and gets no ``ip_address_id``, so no IPAM delete
  path touches it). Nothing is queued to a server, no zone serial moves, and
  the next Sync DNS reads the pair as in sync instead of writing a twin.
* **Stateless.** Both calls recompute the plan from the database, so the
  commit never trusts a client-supplied plan. The operator's choices
  (status, dynamic handling, exclusions, conflict resolutions) are the only
  input beyond the scope.
* **Idempotent.** A record already linked is a no-op on a re-run.
* **Conflicts are never overwritten silently.** Two records of different
  names at one address, or an existing row with a different hostname, stay
  untouched until the operator names the record that wins.
* **Dynamic records** (``DNSRecord.dynamic`` true: Windows DDNS / DHCP
  registered, read from the aging timestamp over WinRM) are held out by
  default; ``dynamic_action`` imports them as ``dhcp`` rows or as the chosen
  static status. ``dynamic`` NULL (AXFR, which carries no timestamp) reads as
  static and is counted so the preview can say the answer is unknown.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import validate_hostname
from app.core.permissions import token_scope_allows, user_has_permission
from app.models.audit import AuditLog
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.sync_check import ptr_address
from app.services.integration_ownership import dns_record_owned_elsewhere
from app.services.ipam.address_create_rules import boundary_address_refusal

logger = structlog.get_logger(__name__)

IMPORT_SOURCE = "dns"
DynamicAction = Literal["skip", "dhcp", "static"]
# Statuses an imported static row may take: the operator-settable ones that
# need nothing more than an address (``static_dhcp`` needs a MAC, ``orphan``
# is a state IPAM sets itself).
POPULATE_STATUSES: frozenset[str] = frozenset({"allocated", "reserved", "deprecated"})
_COMMIT_CHUNK = 500
MAX_OUTSIDE_GROUPS = 500


class PopulateError(ValueError):
    """Operator-facing refusal (maps to a 4xx at the router)."""

    def __init__(self, detail: str, status_code: int = 422) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


@dataclass
class PopulateOptions:
    zone_ids: list[uuid.UUID] | None = None
    view_id: uuid.UUID | None = None
    status: str = "allocated"
    dynamic_action: DynamicAction = "skip"
    link_ptr: bool = True
    # address -> record id that wins a conflict, or "keep" (leave as is).
    resolutions: dict[str, str] = field(default_factory=dict)
    # addresses the operator unticked.
    exclude: set[str] = field(default_factory=set)


@dataclass
class RecordView:
    id: str
    zone_id: str
    zone_name: str
    name: str
    fqdn: str
    record_type: str
    dynamic: bool | None


@dataclass
class Entry:
    address: str
    subnet_id: str
    subnet: str
    category: str  # new | link | linked | conflict | dynamic | skipped
    reason: str = ""
    hostname: str = ""
    existing_ip_id: str | None = None
    existing_hostname: str | None = None
    ptr: str = "none"  # none | match | mismatch
    records: list[RecordView] = field(default_factory=list)
    # internal, not serialised
    _ptr_zone_id: uuid.UUID | None = None
    _chosen: DNSRecord | None = None
    _all: list[DNSRecord] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "subnet_id": self.subnet_id,
            "subnet": self.subnet,
            "category": self.category,
            "reason": self.reason,
            "hostname": self.hostname,
            "existing_ip_id": self.existing_ip_id,
            "existing_hostname": self.existing_hostname,
            "ptr": self.ptr,
            "records": [r.__dict__ for r in self.records],
        }


@dataclass
class Plan:
    entries: list[Entry] = field(default_factory=list)
    outside: list[dict[str, Any]] = field(default_factory=list)
    outside_total: int = 0
    records_scanned: int = 0
    dynamic_unknown: int = 0
    subnets_in_scope: int = 0
    zones: list[dict[str, str]] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for e in self.entries:
            out[e.category] += 1
        return dict(out)

    def reasons(self) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for e in self.entries:
            if e.reason:
                out[f"{e.category}:{e.reason}"] += 1
        return dict(out)


@dataclass
class CommitResult:
    created: int = 0
    linked: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "linked": self.linked,
            "updated": self.updated,
            "skipped": self.skipped,
            "errors": self.errors[:100],
        }


# ── scope ─────────────────────────────────────────────────────────────


async def resolve_subnets(
    db: AsyncSession,
    *,
    space_id: uuid.UUID | None,
    block_id: uuid.UUID | None,
    subnet_id: uuid.UUID | None,
) -> list[Subnet]:
    """The subnets of the chosen scope (exactly one selector)."""
    given = [x for x in (space_id, block_id, subnet_id) if x is not None]
    if len(given) != 1:
        raise PopulateError("Pass exactly one of space_id, block_id, subnet_id")
    if subnet_id is not None:
        sn = await db.get(Subnet, subnet_id)
        if sn is None:
            raise PopulateError("Subnet not found", 404)
        return [sn]
    if space_id is not None:
        if await db.get(IPSpace, space_id) is None:
            raise PopulateError("IP space not found", 404)
        rows = await db.execute(select(Subnet).where(Subnet.space_id == space_id))
        return list(rows.scalars().all())
    assert block_id is not None
    root = await db.get(IPBlock, block_id)
    if root is None:
        raise PopulateError("IP block not found", 404)
    block_ids = {root.id}
    frontier = {root.id}
    while frontier:
        kids = await db.execute(select(IPBlock.id).where(IPBlock.parent_block_id.in_(frontier)))
        frontier = {k for (k,) in kids.all()} - block_ids
        block_ids |= frontier
    rows = await db.execute(select(Subnet).where(Subnet.block_id.in_(block_ids)))
    return list(rows.scalars().all())


class _SubnetIndex:
    """Most-specific-subnet lookup: exact network match per prefix length."""

    def __init__(self, subnets: Iterable[Subnet]) -> None:
        self._by: dict[tuple[int, int], dict[int, Subnet]] = defaultdict(dict)
        self._prefixes: dict[int, list[int]] = {4: [], 6: []}
        for sn in subnets:
            if sn.kind == "multicast":
                continue
            net = ipaddress.ip_network(str(sn.network), strict=False)
            self._by[(net.version, net.prefixlen)][int(net.network_address)] = sn
        for ver in (4, 6):
            self._prefixes[ver] = sorted({p for (v, p) in self._by if v == ver}, reverse=True)

    def find(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Subnet | None:
        bits = 32 if ip.version == 4 else 128
        n = int(ip)
        for plen in self._prefixes[ip.version]:
            masked = n >> (bits - plen) << (bits - plen)
            hit = self._by[(ip.version, plen)].get(masked)
            if hit is not None:
                return hit
        return None


def _label_of(rec: DNSRecord) -> str | None:
    """The host label IPAM would carry for ``rec``, or None when it has none."""
    name = (rec.name or "").strip()
    if name in ("", "@") or name.startswith("*"):
        return None
    try:
        return validate_hostname(name)
    except ValueError:
        return None


def _is_managed(rec: DNSRecord) -> bool:
    return dns_record_owned_elsewhere(rec)


# ── plan ──────────────────────────────────────────────────────────────


async def build_plan(
    db: AsyncSession,
    user: Any,
    subnets: list[Subnet],
    opts: PopulateOptions,
) -> Plan:
    """Classify every candidate record. Read-only."""
    plan = Plan()
    allowed_subnets = [s for s in subnets if token_scope_allows(user, "subnet", str(s.id))]
    plan.subnets_in_scope = len(allowed_subnets)
    index = _SubnetIndex(allowed_subnets)
    writable = {s.id: user_has_permission(user, "write", "subnet", s.id) for s in allowed_subnets}

    # Zones: explicit list (each must be readable) or every readable forward zone.
    zq = select(DNSZone)
    if opts.zone_ids:
        zq = zq.where(DNSZone.id.in_(opts.zone_ids))
    else:
        zq = zq.where(DNSZone.kind == "forward")
    zones = list((await db.execute(zq)).scalars().all())
    if opts.zone_ids:
        found = {z.id for z in zones}
        missing = [z for z in opts.zone_ids if z not in found]
        if missing:
            raise PopulateError("DNS zone not found", 404)
    readable: dict[uuid.UUID, DNSZone] = {}
    for z in zones:
        ok = user_has_permission(user, "read", "dns_zone", z.id) and token_scope_allows(
            user, "dns_zone", str(z.id)
        )
        if ok:
            readable[z.id] = z
        elif opts.zone_ids:
            raise PopulateError(f"Permission denied: need 'read' on DNS zone {z.name}", 403)
    plan.zones = [{"id": str(z.id), "name": z.name} for z in readable.values()]
    if not readable:
        return plan

    q = select(DNSRecord).where(
        DNSRecord.zone_id.in_(list(readable)),
        DNSRecord.record_type.in_(("A", "AAAA")),
    )
    if opts.view_id is not None:
        q = q.where(DNSRecord.view_id == opts.view_id)
    records = list((await db.execute(q.order_by(DNSRecord.fqdn, DNSRecord.id))).scalars().all())
    plan.records_scanned = len(records)

    by_addr: dict[str, list[DNSRecord]] = defaultdict(list)
    outside: dict[str, dict[str, Any]] = {}
    for rec in records:
        try:
            ip = ipaddress.ip_address(rec.value.strip())
        except ValueError:
            continue
        sn = index.find(ip)
        if sn is None:
            plen = 24 if ip.version == 4 else 64
            grp = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            g = outside.setdefault(str(grp), {"network": str(grp), "records": 0, "sample": []})
            g["records"] += 1
            if len(g["sample"]) < 3:
                g["sample"].append(f"{rec.fqdn}={ip}")
            continue
        by_addr[str(ip)].append(rec)
    plan.outside_total = len(outside)
    plan.outside = sorted(outside.values(), key=lambda g: -g["records"])[:MAX_OUTSIDE_GROUPS]

    # Existing rows and PTRs for just the addresses in play.
    addrs = list(by_addr)
    existing: dict[tuple[uuid.UUID, str], IPAddress] = {}
    for i in range(0, len(addrs), 5000):
        rows = await db.execute(
            select(IPAddress).where(
                IPAddress.subnet_id.in_([s.id for s in allowed_subnets]),
                IPAddress.address.in_(addrs[i : i + 5000]),
            )
        )
        for row in rows.scalars().all():
            existing[(row.subnet_id, str(row.address))] = row
    ptrs: dict[str, list[tuple[DNSRecord, DNSZone]]] = defaultdict(list)
    if opts.link_ptr and addrs:
        rzones = list(
            (await db.execute(select(DNSZone).where(DNSZone.kind == "reverse"))).scalars().all()
        )
        rz = {z.id: z for z in rzones if user_has_permission(user, "read", "dns_zone", z.id)}
        if rz:
            prow = await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id.in_(list(rz)), DNSRecord.record_type == "PTR"
                )
            )
            for pr in prow.scalars().all():
                pa = ptr_address(pr.name, rz[pr.zone_id].name)
                if pa is not None and str(pa) in by_addr:
                    ptrs[str(pa)].append((pr, rz[pr.zone_id]))

    for addr in sorted(
        by_addr, key=lambda a: (ipaddress.ip_address(a).version, int(ipaddress.ip_address(a)))
    ):
        recs = by_addr[addr]
        ip = ipaddress.ip_address(addr)
        sn = index.find(ip)
        assert sn is not None
        plan.entries.append(
            _classify(
                addr,
                sn,
                recs,
                existing.get((sn.id, addr)),
                ptrs.get(addr, []),
                opts,
                writable[sn.id],
                readable,
            )
        )
    plan.dynamic_unknown = sum(1 for e in plan.entries for r in e.records if r.dynamic is None)
    return plan


def _classify(
    addr: str,
    sn: Subnet,
    recs: list[DNSRecord],
    row: IPAddress | None,
    ptrs: list[tuple[DNSRecord, DNSZone]],
    opts: PopulateOptions,
    can_write: bool,
    zones: dict[uuid.UUID, DNSZone],
) -> Entry:
    e = Entry(address=addr, subnet_id=str(sn.id), subnet=str(sn.network), category="skipped")
    e._all = recs
    e.records = [
        RecordView(
            id=str(r.id),
            zone_id=str(r.zone_id),
            zone_name=zones[r.zone_id].name,
            name=r.name,
            fqdn=r.fqdn,
            record_type=r.record_type,
            dynamic=r.dynamic,
        )
        for r in recs
    ]
    if row is not None:
        e.existing_ip_id = str(row.id)
        e.existing_hostname = row.hostname
    if not can_write:
        e.reason = "no_permission"
        return e
    if all(_is_managed(r) for r in recs):
        e.reason = "integration_owned"
        return e
    # Records IPAM itself wrote are already linked by construction.
    cand = [r for r in recs if not _is_managed(r) and r.ip_address_id is None]
    if not cand:
        e.category, e.reason = "linked", "ipam_managed"
        return e
    labelled = [(r, _label_of(r)) for r in cand]
    labelled = [(r, h) for r, h in labelled if h is not None]
    if not labelled:
        e.reason = "no_host_label"
        return e
    names = {h for _, h in labelled}
    chosen_id = opts.resolutions.get(addr)
    chosen: DNSRecord | None = None
    if chosen_id and chosen_id != "keep":
        chosen = next((r for r, _ in labelled if str(r.id) == chosen_id), None)
    if chosen is None:
        # A static record over a dynamic one at the same address.
        chosen = sorted(labelled, key=lambda rh: rh[0].dynamic is True)[0][0]
    host = _label_of(chosen) or ""
    e._chosen, e.hostname = chosen, host
    if boundary_address_refusal(sn, addr) is not None and (
        row is None or row.status not in ("network", "broadcast")
    ):
        e.reason = "boundary_address"
        return e
    if row is not None and row.status in ("network", "broadcast"):
        e.reason = "boundary_address"
        return e

    # PTR: link only when it points at this host's name in a zone we know.
    if ptrs:
        want = f"{chosen.fqdn}".rstrip(".").lower()
        for pr, pz in ptrs:
            if pr.value.strip().rstrip(".").lower() == want:
                e.ptr, e._ptr_zone_id = "match", pz.id
                break
        else:
            e.ptr = "mismatch"

    dynamic_all = all(r.dynamic is True for r, _ in labelled)
    resolved = chosen_id in {str(r.id) for r, _ in labelled}
    if not resolved:
        if len(names) > 1:
            e.category, e.reason = "conflict", "several_names"
            return e
        if row is not None and row.hostname and row.hostname.lower() not in names:
            e.category, e.reason = "conflict", "hostname_differs"
            return e
    if (
        row is not None
        and row.hostname
        and row.hostname.lower() == host
        and row.dns_record_id is not None
    ):
        e.category, e.reason = "linked", "already_linked"
        return e
    if dynamic_all and opts.dynamic_action == "skip":
        e.category, e.reason = "dynamic", "ddns_registered"
        return e
    if row is not None and row.status not in ("available",):
        e.category = "link"
        return e
    e.category = "new"
    return e


# ── commit ────────────────────────────────────────────────────────────


def _status_for(entry: Entry, opts: PopulateOptions) -> str:
    dyn = bool(entry._chosen is not None and entry._chosen.dynamic is True)
    if dyn and opts.dynamic_action == "dhcp":
        return "dhcp"
    return opts.status


async def commit_plan(
    db: AsyncSession,
    user: Any,
    plan: Plan,
    opts: PopulateOptions,
    *,
    scope_type: str,
    scope_id: uuid.UUID,
) -> CommitResult:
    """Apply the plan in the caller's transaction. Writes no DNS."""
    if opts.status not in POPULATE_STATUSES:
        raise PopulateError(f"status must be one of {sorted(POPULATE_STATUSES)}")
    res = CommitResult()
    now = datetime.now(UTC)
    audit: list[AuditLog] = []
    touched: set[uuid.UUID] = set()
    todo = [e for e in plan.entries if e.address not in opts.exclude]
    for e in plan.entries:
        if e.address in opts.exclude:
            res.skipped += 1
    for i, e in enumerate(todo):
        rec = e._chosen
        if e.category in ("linked", "skipped", "conflict", "dynamic") or rec is None:
            res.skipped += 1
            continue
        sn_id = uuid.UUID(e.subnet_id)
        extras = sorted(
            {
                str(r.zone_id)
                for r in e._all
                if r.id != rec.id
                and (r.name or "").lower() == (rec.name or "").lower()
                and r.zone_id != rec.zone_id
                and r.ip_address_id is None
                and not _is_managed(r)
            }
        )
        try:
            if e.category == "new" and e.existing_ip_id is None:
                row = IPAddress(
                    subnet_id=sn_id,
                    address=e.address,
                    status=_status_for(e, opts),
                    hostname=e.hostname,
                    fqdn=rec.fqdn.rstrip("."),
                    description="",
                    forward_zone_id=rec.zone_id,
                    dns_record_id=rec.id,
                    extra_zone_ids=extras,
                    reverse_zone_id=e._ptr_zone_id,
                    import_source=IMPORT_SOURCE,
                    imported_at=now,
                    created_by_user_id=user.id,
                )
                db.add(row)
                await db.flush()
                res.created += 1
                audit.append(_audit(user, "create", row, e, None))
            else:
                row = (
                    await db.get(IPAddress, uuid.UUID(e.existing_ip_id))
                    if e.existing_ip_id
                    else None
                )
                if row is None:
                    res.errors.append(f"{e.address}: row vanished")
                    continue
                old = {
                    "hostname": row.hostname,
                    "status": row.status,
                    "dns_record_id": str(row.dns_record_id) if row.dns_record_id else None,
                }
                if e.category == "new":  # a free ``available`` slot: take it
                    row.status = _status_for(e, opts)
                    row.import_source = IMPORT_SOURCE
                    row.imported_at = now
                if not row.hostname or e.address in opts.resolutions:
                    row.hostname = e.hostname
                row.fqdn = rec.fqdn.rstrip(".")
                row.forward_zone_id = rec.zone_id
                row.dns_record_id = rec.id
                if extras:
                    row.extra_zone_ids = sorted(set(row.extra_zone_ids or []) | set(extras))
                if e._ptr_zone_id is not None:
                    row.reverse_zone_id = e._ptr_zone_id
                await db.flush()
                if e.category == "new":
                    res.updated += 1
                else:
                    res.linked += 1
                audit.append(_audit(user, "update", row, e, old))
            touched.add(sn_id)
        except Exception as exc:  # noqa: BLE001
            res.errors.append(f"{e.address}: {exc}")
        if (i + 1) % _COMMIT_CHUNK == 0:
            await db.flush()
    db.add_all(audit)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="populate_from_dns",
            resource_type=scope_type,
            resource_id=str(scope_id),
            resource_display=f"populate IPAM from DNS ({scope_type})",
            new_value={
                "created": res.created,
                "linked": res.linked,
                "updated": res.updated,
                "skipped": res.skipped,
                "errors": len(res.errors),
                "status": opts.status,
                "dynamic_action": opts.dynamic_action,
                "zones": [z["name"] for z in plan.zones][:50],
                "dns_writes": 0,
            },
            result="success",
        )
    )
    await db.flush()
    if touched:
        from app.api.v1.ipam.router import (  # noqa: PLC0415
            _update_blocks_utilization,
            _update_utilization,
        )

        blocks: set[uuid.UUID] = set()
        for sid in touched:
            await _update_utilization(db, sid)
            sn = await db.get(Subnet, sid)
            if sn is not None:
                blocks.add(sn.block_id)
        await db.flush()
        await _update_blocks_utilization(db, list(blocks))
    logger.info(
        "ipam_populate_from_dns",
        scope=scope_type,
        created=res.created,
        linked=res.linked,
        updated=res.updated,
        skipped=res.skipped,
        errors=len(res.errors),
    )
    return res


def _audit(user: Any, action: str, row: IPAddress, e: Entry, old: dict | None) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        user_display_name=user.display_name,
        auth_source=user.auth_source,
        action=action,
        resource_type="ip_address",
        resource_id=str(row.id),
        resource_display=f"{e.address} ({row.hostname or ''})",
        old_value=old,
        new_value={
            "address": e.address,
            "hostname": row.hostname,
            "status": row.status,
            "dns_record_id": str(row.dns_record_id) if row.dns_record_id else None,
            "import_source": IMPORT_SOURCE,
            "populate_from_dns": True,
        },
        result="success",
    )
