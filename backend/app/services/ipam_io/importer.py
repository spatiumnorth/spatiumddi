"""Import preview + commit for IPAM resources.

The importer accepts a :class:`ParsedPayload` (see :mod:`.parser`) plus a
target IP space (either by id or name). Subnets are matched to existing
rows by ``(space_id, network)`` — where the network is canonicalised via
``ipaddress.ip_network(..., strict=False)``.

Conflict resolution strategies:

- ``skip``       — ignore rows that already exist; still create new ones
- ``overwrite``  — update existing rows in place
- ``fail``       — raise 409 if any conflict is detected (default)

Parent block detection: for each subnet, if the row did not specify
``block`` / ``block_network``, the importer picks the smallest existing
block in the space whose CIDR contains the subnet. If none is found and
the strategy is not ``fail``, a block matching the subnet's own CIDR is
auto-created as a parent (because subnets require ``block_id``).
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import validate_hostname
from app.models.audit import AuditLog
from app.models.ipam import IP_STATUSES, IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.resize import _total_ips
from app.services.ipam_io.parser import ParsedPayload

logger = structlog.get_logger(__name__)

Strategy = Literal["skip", "overwrite", "fail"]


# ── Data classes ───────────────────────────────────────────────────────────────


@dataclass
class DiffRow:
    kind: str  # "subnet" | "block" | "address"
    action: str  # "create" | "update" | "conflict" | "skip"
    network: str
    name: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None


@dataclass
class ImportPreview:
    space_id: str
    space_name: str
    creates: list[DiffRow] = field(default_factory=list)
    updates: list[DiffRow] = field(default_factory=list)
    conflicts: list[DiffRow] = field(default_factory=list)
    errors: list[DiffRow] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "space_id": self.space_id,
            "space_name": self.space_name,
            "summary": {
                "creates": len(self.creates),
                "updates": len(self.updates),
                "conflicts": len(self.conflicts),
                "errors": len(self.errors),
            },
            "creates": [row.__dict__ for row in self.creates],
            "updates": [row.__dict__ for row in self.updates],
            "conflicts": [row.__dict__ for row in self.conflicts],
            "errors": [row.__dict__ for row in self.errors],
        }


@dataclass
class ImportResult:
    space_id: str
    created_subnets: int = 0
    updated_subnets: int = 0
    skipped: int = 0
    auto_created_blocks: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__


# ── Helpers ────────────────────────────────────────────────────────────────────


def _canon_network(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=False))


async def _resolve_space(
    db: AsyncSession,
    space_id: uuid.UUID | None,
    space_name: str | None,
) -> IPSpace:
    if space_id:
        space = await db.get(IPSpace, space_id)
        if space is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target IP space not found",
            )
        return space
    if space_name:
        result = await db.execute(select(IPSpace).where(IPSpace.name == space_name))
        space = result.scalar_one_or_none()
        if space is not None:
            return space
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Import requires a target space_id (or an existing space_name)",
    )


async def _load_existing_blocks(db: AsyncSession, space_id: uuid.UUID) -> list[IPBlock]:
    result = await db.execute(select(IPBlock).where(IPBlock.space_id == space_id))
    return list(result.scalars().all())


async def _load_existing_subnets(db: AsyncSession, space_id: uuid.UUID) -> dict[str, Subnet]:
    result = await db.execute(select(Subnet).where(Subnet.space_id == space_id))
    return {str(s.network): s for s in result.scalars().all()}


def _find_parent_block(
    subnet_net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    blocks: list[IPBlock],
) -> IPBlock | None:
    """Return the smallest (most-specific) existing block that contains the subnet."""
    candidates: list[IPBlock] = []
    for block in blocks:
        try:
            block_net = ipaddress.ip_network(str(block.network), strict=False)
        except ValueError:
            continue
        if subnet_net.version != block_net.version:
            continue
        if subnet_net.subnet_of(block_net):  # type: ignore[arg-type]
            candidates.append(block)
    if not candidates:
        return None
    # Most specific = highest prefixlen
    candidates.sort(
        key=lambda b: ipaddress.ip_network(str(b.network), strict=False).prefixlen,
        reverse=True,
    )
    return candidates[0]


def _first_overlap(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    others: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """First network in ``others`` that overlaps ``net`` but is not identical.

    The importer keys existing subnets/blocks by exact canonical CIDR, so
    exact matches are handled separately (skip/overwrite/fail). This catches
    the *partial/containment* overlaps that the exact-match dict misses — e.g.
    importing 10.0.0.0/23 into a space that already holds 10.0.0.0/24, which
    the subnet model has no DB constraint to reject (#495).
    """
    for other in others:
        if other.version != net.version:
            continue
        if other != net and other.overlaps(net):
            return other
    return None


# ── Preview ────────────────────────────────────────────────────────────────────


async def preview_import(
    db: AsyncSession,
    payload: ParsedPayload,
    *,
    space_id: uuid.UUID | None = None,
    space_name: str | None = None,
    strategy: Strategy = "fail",
) -> ImportPreview:
    space = await _resolve_space(db, space_id, space_name)
    preview = ImportPreview(space_id=str(space.id), space_name=space.name)

    existing_subnets = await _load_existing_subnets(db, space.id)
    existing_blocks = await _load_existing_blocks(db, space.id)
    existing_block_nets = {str(b.network) for b in existing_blocks}

    # Track auto-created blocks in this preview so the summary is consistent.
    planned_block_nets: set[str] = set()
    # Networks queued to be created in this same payload — so an intra-payload
    # overlap is caught in preview the way commit catches it (#495).
    planned_subnet_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    seen_networks: set[str] = set()
    for row in payload.subnets:
        raw_network = row.get("network")
        if not raw_network or not isinstance(raw_network, str):
            preview.errors.append(
                DiffRow(
                    kind="subnet",
                    action="error",
                    network=str(raw_network) if raw_network else "",
                    reason="Missing 'network' field",
                    details=row,
                )
            )
            continue
        try:
            canonical = _canon_network(raw_network.strip())
        except ValueError as exc:
            preview.errors.append(
                DiffRow(
                    kind="subnet",
                    action="error",
                    network=raw_network,
                    reason=f"Invalid CIDR: {exc}",
                    details=row,
                )
            )
            continue
        if canonical in seen_networks:
            preview.errors.append(
                DiffRow(
                    kind="subnet",
                    action="error",
                    network=canonical,
                    reason="Duplicate row in import payload",
                )
            )
            continue
        seen_networks.add(canonical)

        subnet_net = ipaddress.ip_network(canonical, strict=False)
        name = str(row.get("name") or "")

        # Parent block detection
        parent = _find_parent_block(subnet_net, existing_blocks)
        parent_network = str(parent.network) if parent else None
        if parent_network is None and canonical not in planned_block_nets:
            planned_block_nets.add(canonical)
            if canonical not in existing_block_nets:
                preview.creates.append(
                    DiffRow(
                        kind="block",
                        action="create",
                        network=canonical,
                        name=f"auto-parent for {canonical}",
                        reason="No containing block found; auto-parent will be created",
                    )
                )

        existing = existing_subnets.get(canonical)
        if existing is None:
            # Flag non-exact overlaps here so the preview matches what commit
            # will reject — otherwise the operator sees a clean "create" for a
            # row commit turns into an error (#495).
            clash = _first_overlap(
                subnet_net,
                [ipaddress.ip_network(c, strict=False) for c in existing_subnets]
                + list(planned_subnet_nets),
            )
            if clash is not None:
                preview.errors.append(
                    DiffRow(
                        kind="subnet",
                        action="error",
                        network=canonical,
                        reason=f"Overlaps existing subnet {clash}",
                        details=row,
                    )
                )
                continue
            planned_subnet_nets.append(subnet_net)
            preview.creates.append(
                DiffRow(
                    kind="subnet",
                    action="create",
                    network=canonical,
                    name=name,
                    details={**row, "network": canonical, "parent_block": parent_network},
                )
            )
            continue

        # Subnet exists — decide based on strategy
        old_snapshot = {
            "name": existing.name,
            "description": existing.description,
            "vlan_id": existing.vlan_id,
            "vxlan_id": existing.vxlan_id,
            "gateway": str(existing.gateway) if existing.gateway else None,
        }
        diff_details = {"old": old_snapshot, "new": {**row, "network": canonical}}
        if strategy == "overwrite":
            preview.updates.append(
                DiffRow(
                    kind="subnet",
                    action="update",
                    network=canonical,
                    name=name or existing.name,
                    details=diff_details,
                )
            )
        elif strategy == "skip":
            preview.conflicts.append(
                DiffRow(
                    kind="subnet",
                    action="skip",
                    network=canonical,
                    name=existing.name,
                    reason="Already exists; strategy=skip",
                    details=diff_details,
                )
            )
        else:  # fail
            preview.conflicts.append(
                DiffRow(
                    kind="subnet",
                    action="conflict",
                    network=canonical,
                    name=existing.name,
                    reason="Already exists; commit will fail unless strategy is set",
                    details=diff_details,
                )
            )

    return preview


# ── Commit ─────────────────────────────────────────────────────────────────────


def _audit_entry(
    user: Any, action: str, resource_id: str, display: str, new_value: dict
) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        user_display_name=user.display_name,
        auth_source=user.auth_source,
        action=action,
        resource_type="subnet",
        resource_id=resource_id,
        resource_display=display,
        new_value=new_value,
        result="success",
    )


async def commit_import(
    db: AsyncSession,
    payload: ParsedPayload,
    *,
    current_user: Any,
    space_id: uuid.UUID | None = None,
    space_name: str | None = None,
    strategy: Strategy = "fail",
) -> ImportResult:
    """Apply the import. All changes happen inside the caller's transaction —
    the caller (the route handler) owns the commit.
    """
    space = await _resolve_space(db, space_id, space_name)
    result_obj = ImportResult(space_id=str(space.id))

    existing_blocks = await _load_existing_blocks(db, space.id)
    existing_subnets = await _load_existing_subnets(db, space.id)

    # Pre-flight: if fail-strategy and any subnet conflicts, bail out early —
    # BEFORE the mutation loop runs any side effects. Catches both pre-existing
    # rows and intra-payload duplicates; without the latter, the second copy of
    # a duplicated row hit the in-loop 409 only after the first was created and
    # its DNS records pushed live (#504).
    if strategy == "fail":
        conflicts: list[str] = []
        seen_canon: set[str] = set()
        for row in payload.subnets:
            net = row.get("network")
            if not isinstance(net, str):
                continue
            canon = _safe_canon(net)
            if canon in existing_subnets:
                conflicts.append(net)
            elif canon in seen_canon:
                conflicts.append(net)
            else:
                seen_canon.add(canon)
        if conflicts:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{len(conflicts)} subnet(s) conflict (already exist or duplicated "
                "in the file); re-run with strategy='skip' or 'overwrite'",
            )

    for row in payload.subnets:
        raw_network = row.get("network")
        if not isinstance(raw_network, str):
            result_obj.errors.append("Row missing 'network'")
            continue
        try:
            canonical = _canon_network(raw_network.strip())
        except ValueError as exc:
            result_obj.errors.append(f"{raw_network}: {exc}")
            continue

        subnet_net = ipaddress.ip_network(canonical, strict=False)
        name = str(row.get("name") or "")
        description = str(row.get("description") or "")
        vlan_id = row.get("vlan_id")
        vxlan_id = row.get("vxlan_id")
        gateway = row.get("gateway") or None
        # Validate the gateway before it reaches the INET column — a malformed
        # literal would otherwise raise a DataError → 500 mid-commit (#504) —
        # and enforce the same in-subnet / same-family invariant create_subnet
        # applies, so the importer can't land a Subnet later endpoints assume
        # is valid (Copilot review of #504).
        if gateway is not None:
            try:
                gw_addr = ipaddress.ip_address(str(gateway).strip())
            except ValueError:
                result_obj.errors.append(f"{canonical}: invalid gateway {gateway!r}")
                continue
            if gw_addr not in subnet_net:
                result_obj.errors.append(f"{canonical}: gateway {gateway} is not within the subnet")
                continue
            gateway = str(gw_addr)
        custom_fields = row.get("custom_fields") or {}

        existing = existing_subnets.get(canonical)
        if existing is not None:
            if strategy == "skip":
                result_obj.skipped += 1
                continue
            if strategy == "overwrite":
                old = {
                    "name": existing.name,
                    "description": existing.description,
                    "vlan_id": existing.vlan_id,
                    "vxlan_id": existing.vxlan_id,
                    "gateway": str(existing.gateway) if existing.gateway else None,
                }
                existing.name = name or existing.name
                existing.description = description or existing.description
                if vlan_id is not None:
                    existing.vlan_id = vlan_id
                if vxlan_id is not None:
                    existing.vxlan_id = vxlan_id
                if gateway:
                    existing.gateway = gateway
                if custom_fields:
                    merged = dict(existing.custom_fields or {})
                    merged.update(custom_fields)
                    existing.custom_fields = merged
                db.add(
                    AuditLog(
                        user_id=current_user.id,
                        user_display_name=current_user.display_name,
                        auth_source=current_user.auth_source,
                        action="update",
                        resource_type="subnet",
                        resource_id=str(existing.id),
                        resource_display=f"{canonical} ({existing.name})",
                        old_value=old,
                        new_value={
                            "name": existing.name,
                            "description": existing.description,
                            "vlan_id": existing.vlan_id,
                            "vxlan_id": existing.vxlan_id,
                            "gateway": gateway,
                            "import": True,
                        },
                        result="success",
                    )
                )
                result_obj.updated_subnets += 1
                continue
            # strategy == "fail" handled above, but guard anyway
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Subnet {canonical} already exists",
            )

        # Reject a non-exact overlap with an existing (or already-imported)
        # subnet rather than silently creating an overlapping row — the model
        # has no DB overlap constraint, so this is the only guard (#495).
        clash = _first_overlap(
            subnet_net,
            [ipaddress.ip_network(c, strict=False) for c in existing_subnets],
        )
        if clash is not None:
            result_obj.errors.append(f"{canonical}: overlaps existing subnet {clash}")
            continue

        # Find or auto-create the parent block
        parent = _find_parent_block(subnet_net, existing_blocks)
        if parent is None:
            # _find_parent_block found no *containing* block; before carving a
            # new top-level block at this CIDR, make sure it doesn't partially
            # overlap (or swallow) an existing block (#495).
            block_clash = _first_overlap(
                subnet_net,
                [ipaddress.ip_network(str(b.network), strict=False) for b in existing_blocks],
            )
            if block_clash is not None:
                result_obj.errors.append(
                    f"{canonical}: auto-parent block would overlap existing block {block_clash}"
                )
                continue
            parent = IPBlock(
                space_id=space.id,
                parent_block_id=None,
                network=canonical,
                name=f"auto:{canonical}",
                description=f"Auto-created parent block for imported subnet {canonical}",
            )
            db.add(parent)
            await db.flush()
            existing_blocks.append(parent)
            result_obj.auto_created_blocks += 1
            db.add(
                AuditLog(
                    user_id=current_user.id,
                    user_display_name=current_user.display_name,
                    auth_source=current_user.auth_source,
                    action="create",
                    resource_type="ip_block",
                    resource_id=str(parent.id),
                    resource_display=f"{canonical} (auto:{canonical})",
                    new_value={"network": canonical, "auto": True},
                    result="success",
                )
            )

        # Use the shared clamped helper (mirrors the router / resize paths):
        # a raw ``num_addresses`` for an IPv6 /64 is 2**64, which overflows the
        # BIGINT column and 500s the whole commit (#503).
        total = _total_ips(subnet_net)
        subnet = Subnet(
            space_id=space.id,
            block_id=parent.id,
            network=canonical,
            name=name,
            description=description,
            vlan_id=vlan_id,
            vxlan_id=vxlan_id,
            gateway=gateway,
            status="active",
            total_ips=total,
            allocated_ips=0,
            utilization_percent=0.0,
            custom_fields=custom_fields,
        )
        db.add(subnet)
        await db.flush()
        existing_subnets[canonical] = subnet
        db.add(
            _audit_entry(
                current_user,
                "create",
                str(subnet.id),
                f"{canonical} ({name})",
                {
                    "network": canonical,
                    "name": name,
                    "description": description,
                    "vlan_id": vlan_id,
                    "gateway": gateway,
                    "import": True,
                },
            )
        )
        result_obj.created_subnets += 1

    logger.info(
        "ipam_import_committed",
        space_id=str(space.id),
        created=result_obj.created_subnets,
        updated=result_obj.updated_subnets,
        skipped=result_obj.skipped,
        auto_blocks=result_obj.auto_created_blocks,
    )
    return result_obj


def _safe_canon(value: str) -> str:
    try:
        return _canon_network(value.strip())
    except ValueError:
        return value


# ══ Address importer (subnet-scoped) ══════════════════════════════════════════
#
# Layered on top of the same preview/commit shape as the subnet importer so the
# frontend can reuse the diff table widget. Matching key is ``(subnet_id,
# address)``. Rows whose IP doesn't fall inside the subnet's CIDR are rejected
# as errors rather than silently routed elsewhere — migrations from another
# DDI tool almost always come as per-subnet dumps, and routing cross-subnet
# hides user mistakes.


# Accept every status the exporter can emit so a subnet's own export
# round-trips cleanly (#504): operator-settable + integration-owned (via
# IP_STATUSES) plus the network/broadcast placeholders. Rows match on
# (subnet, address), so re-importing an integration/placeholder row updates
# the existing row rather than creating a bogus duplicate.
_VALID_ADDRESS_STATUSES = IP_STATUSES | frozenset({"network", "broadcast"})

# Common MAC notations Postgres MACADDR accepts: 6 hex pairs (``:``/``-``/bare)
# or 3 hex quads (Cisco ``aabb.ccdd.eeff``). Validate before flush so a
# malformed value is an error row, not a DataError → 500 (#504).
_MAC_RE = re.compile(
    r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}$"
)


@dataclass
class AddressImportResult:
    subnet_id: str
    created: int = 0
    updated: int = 0
    skipped: int = 0
    # Rows skipped because the caller has no write permission on the IP
    # (subnet-wide nor any covering address set) — #103 delegation.
    skipped_no_perm: int = 0
    dns_synced: int = 0
    # #1628 — rows whose DHCP reservation the server-side sync created or
    # updated, and the rows it could not mirror (no scope, several
    # candidate scopes, or a conflicting reservation). Mirrors the
    # router's per-row ``dhcp_static_warning`` so an import reports the
    # same outcome a UI/API create would.
    dhcp_synced: int = 0
    dhcp_warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__


def _canon_ip(value: str) -> str:
    """Canonicalise a single IP (strip /prefix if the user pasted a host route)."""
    raw = value.strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    return str(ipaddress.ip_address(raw))


async def _load_subnet(db: AsyncSession, subnet_id: uuid.UUID) -> Subnet:
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target subnet not found")
    return subnet


async def _load_existing_addresses(db: AsyncSession, subnet_id: uuid.UUID) -> dict[str, IPAddress]:
    result = await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id))
    return {str(a.address): a for a in result.scalars().all()}


def _row_address_fields(
    row: dict[str, Any],
) -> tuple[str | None, dict[str, Any], str | None]:
    """Extract ``(canonical_ip, normalized_fields, error_reason)`` from a row.

    ``normalized_fields`` only includes keys the caller intends to write —
    omitted / blank values are left out so ``overwrite`` doesn't clobber an
    existing value with ``None`` (e.g. a hostname the user set via the UI).
    """
    raw_addr = row.get("address")
    if not raw_addr or not isinstance(raw_addr, str):
        return None, {}, "Missing 'address' / 'ip' column"
    try:
        canonical = _canon_ip(raw_addr)
    except ValueError as exc:
        return None, {}, f"Invalid IP address {raw_addr!r}: {exc}"

    fields: dict[str, Any] = {}
    if (s := row.get("status")) is not None:
        s = str(s).strip()
        if s and s not in _VALID_ADDRESS_STATUSES:
            return (
                None,
                {},
                (
                    f"status must be one of: {', '.join(sorted(_VALID_ADDRESS_STATUSES))} "
                    f"(got {s!r})"
                ),
            )
        if s:
            fields["status"] = s
    if (h := row.get("hostname")) is not None:
        h = str(h).strip() or None
        if h:
            # Validate as an RFC 1123 host name (issue #597). A malformed
            # hostname skips just this row with a clear reason, matching the
            # per-row error contract above (import never hard-fails a batch).
            try:
                fields["hostname"] = validate_hostname(h)
            except ValueError as exc:
                return None, {}, str(exc)
    if (m := row.get("mac_address")) is not None:
        m = str(m).strip() or None
        if m:
            if not _MAC_RE.match(m):
                return None, {}, f"Invalid MAC address {m!r}"
            fields["mac_address"] = m
    if (d := row.get("description")) is not None:
        d = str(d).strip()
        fields["description"] = d
    if (t := row.get("tags")) is not None:
        if isinstance(t, dict):
            fields["tags"] = t
    if (cf := row.get("custom_fields")) is not None and isinstance(cf, dict):
        fields["custom_fields"] = cf
    return canonical, fields, None


async def preview_address_import(
    db: AsyncSession,
    payload: ParsedPayload,
    *,
    subnet_id: uuid.UUID,
    strategy: Strategy = "fail",
    current_user: Any = None,
) -> ImportPreview:
    subnet = await _load_subnet(db, subnet_id)
    preview = ImportPreview(space_id=str(subnet.id), space_name=str(subnet.network))

    subnet_net = ipaddress.ip_network(str(subnet.network), strict=False)
    existing = await _load_existing_addresses(db, subnet.id)

    # #1628 — flag rows that will (or will not) get a DHCP reservation
    # from the server-side sync at commit, so the preview matches what
    # commit does: a ``static_dhcp`` row with a MAC syncs only when the
    # subnet has exactly one matching-family scope. Candidate scopes are
    # per (subnet, family), so cache them across rows.
    from app.services.dhcp.static_ipam import (
        _linked_static_for_row,
        candidate_scopes_for_ipam_row,
    )

    scopes_by_family: dict[str, list] = {}

    async def _dhcp_flag(
        canonical: str, fields: dict[str, Any], existing_ip: IPAddress | None
    ) -> dict[str, Any]:
        status = fields.get("status") or (existing_ip.status if existing_ip else None)
        mac = fields.get("mac_address") or (
            str(existing_ip.mac_address)
            if existing_ip is not None and existing_ip.mac_address
            else None
        )
        if status != "static_dhcp" or not mac:
            return {}
        # #1629 (GHSA-44ph) — the commit-side sync gates on the acting
        # user's ``dhcp_static`` grant; preview the same outcome when
        # the caller is known, or an IPAM-only importer's preview would
        # promise a reservation commit will refuse.
        if current_user is not None:
            from app.core.permissions import user_has_permission  # noqa: PLC0415

            if not user_has_permission(current_user, "write", "dhcp_static"):
                return {
                    "dhcp_static_warning": (
                        "No 'write' permission on DHCP reservations "
                        "(dhcp_static) — no reservation will be created."
                    )
                }
        # #1629 walk — preview must match commit for a *linked* row:
        # commit updates the linked reservation in place whatever the
        # candidate-scope count is (the sync's linked branch never
        # consults candidate scopes), so a two-scope subnet must not
        # preview "no reservation will be created" for such a row.
        if existing_ip is not None and await _linked_static_for_row(db, existing_ip) is not None:
            return {"dhcp_static_sync": True}
        family = "ipv6" if ipaddress.ip_address(canonical).version == 6 else "ipv4"
        if family not in scopes_by_family:
            probe = IPAddress(subnet_id=subnet.id, address=canonical)
            scopes_by_family[family] = await candidate_scopes_for_ipam_row(db, probe)
        scopes = scopes_by_family[family]
        if len(scopes) == 1:
            return {"dhcp_static_sync": True}
        if not scopes:
            return {
                "dhcp_static_warning": (
                    f"No DHCP scope serves {canonical} — no reservation will be "
                    "created. Create a scope for this subnet to pin the reservation."
                )
            }
        return {
            "dhcp_static_warning": (
                f"{len(scopes)} DHCP scopes serve this subnet — not guessing which "
                f"one should hold the reservation for {canonical}; no reservation "
                "will be created."
            )
        }

    seen: set[str] = set()
    for row in payload.addresses:
        canonical, fields, err = _row_address_fields(row)
        if err or canonical is None:
            preview.errors.append(
                DiffRow(
                    kind="address",
                    action="error",
                    network=str(row.get("address") or row.get("ip") or ""),
                    reason=err or "Invalid row",
                    details=dict(row),
                )
            )
            continue
        try:
            if ipaddress.ip_address(canonical) not in subnet_net:
                preview.errors.append(
                    DiffRow(
                        kind="address",
                        action="error",
                        network=canonical,
                        reason=f"IP is outside subnet {subnet_net}",
                    )
                )
                continue
        except ValueError:
            preview.errors.append(
                DiffRow(
                    kind="address",
                    action="error",
                    network=canonical,
                    reason="Invalid IP for subnet membership check",
                )
            )
            continue
        if canonical in seen:
            preview.errors.append(
                DiffRow(
                    kind="address",
                    action="error",
                    network=canonical,
                    reason="Duplicate row in import payload",
                )
            )
            continue
        seen.add(canonical)

        row_hostname = fields.get("hostname") or ""
        existing_ip = existing.get(canonical)
        if existing_ip is None:
            create_details: dict[str, Any] = {"fields": fields}
            create_details.update(await _dhcp_flag(canonical, fields, None))
            preview.creates.append(
                DiffRow(
                    kind="address",
                    action="create",
                    network=canonical,
                    name=row_hostname,
                    details=create_details,
                )
            )
            continue

        old = {
            "hostname": existing_ip.hostname,
            "status": existing_ip.status,
            "mac_address": (str(existing_ip.mac_address) if existing_ip.mac_address else None),
            "description": existing_ip.description,
        }
        diff_details = {"old": old, "new": fields}
        if strategy == "overwrite":
            diff_details.update(await _dhcp_flag(canonical, fields, existing_ip))
        if strategy == "overwrite":
            preview.updates.append(
                DiffRow(
                    kind="address",
                    action="update",
                    network=canonical,
                    name=row_hostname or (existing_ip.hostname or ""),
                    details=diff_details,
                )
            )
        elif strategy == "skip":
            preview.conflicts.append(
                DiffRow(
                    kind="address",
                    action="skip",
                    network=canonical,
                    name=existing_ip.hostname or "",
                    reason="Already exists; strategy=skip",
                    details=diff_details,
                )
            )
        else:  # fail
            preview.conflicts.append(
                DiffRow(
                    kind="address",
                    action="conflict",
                    network=canonical,
                    name=existing_ip.hostname or "",
                    reason="Already exists; commit will fail unless strategy is set",
                    details=diff_details,
                )
            )
    return preview


async def commit_address_import(
    db: AsyncSession,
    payload: ParsedPayload,
    *,
    current_user: Any,
    subnet_id: uuid.UUID,
    strategy: Strategy = "fail",
    can_write_ip: Callable[[str], bool] | None = None,
) -> AddressImportResult:
    """Apply the address import in the caller's transaction.

    Matching key: ``(subnet_id, address)``. After each create/update, we
    call the IPAM router's ``_sync_dns_record`` so imported rows with a
    hostname get an A + PTR record published via the same RFC 2136 path
    that the interactive UI uses. The import is equivalent to N calls to
    ``POST /ipam/addresses`` / ``PUT /ipam/addresses/{id}`` — same audit
    log, same DNS side-effects, and (since #1628) the same server-side
    DHCP reservation sync for ``static_dhcp`` rows.

    ``can_write_ip`` is the optional #103 address-set write-delegation gate
    (a closure over the caller's writable ranges). Rows the caller can't
    write are skipped and counted in ``skipped_no_perm`` rather than
    mutated. ``None`` means "no per-IP gate" (caller already proved
    subnet-wide write).
    """
    from app.api.v1.ipam.router import _sync_dns_record
    from app.services.dhcp.static_ipam import sync_static_for_ipam_row

    subnet = await _load_subnet(db, subnet_id)
    result_obj = AddressImportResult(subnet_id=str(subnet.id))

    async def _sync_dhcp(ip_row: IPAddress, canonical: str) -> None:
        """Mirror the router's server-side DHCP reservation sync (#1628).

        Runs for every row the import wrote, so a row flipped away from
        ``static_dhcp`` also drops its reservation, exactly like a UI
        edit. A warning (no scope / ambiguous scope / conflict) is
        collected, not raised; a driver push failure is appended to the
        per-row errors — the import never hard-fails a batch.
        """
        try:
            sync = await sync_static_for_ipam_row(
                db, ip_row, created_by_user_id=current_user.id, user=current_user
            )
        except Exception as exc:  # noqa: BLE001
            result_obj.errors.append(f"{canonical}: DHCP reservation sync failed: {exc}")
            return
        if sync.warning:
            result_obj.dhcp_warnings.append(f"{canonical}: {sync.warning}")
        elif sync.action:
            result_obj.dhcp_synced += 1

    subnet_net = ipaddress.ip_network(str(subnet.network), strict=False)
    existing = await _load_existing_addresses(db, subnet.id)

    # Pre-flight: fail-strategy bails out before mutating anything. A
    # permission-blocked row (#103 delegation gate) is skipped from the
    # duplicate check — we don't 409 a caller on a row they can't write
    # anyway — but it is NOT silent: it's counted below so a fully
    # permission-blocked import can't masquerade as a generic 0-created
    # success (#7).
    if strategy == "fail":
        seen_addr: set[str] = set()
        for row in payload.addresses:
            canonical, _, err = _row_address_fields(row)
            if err or canonical is None:
                continue
            if can_write_ip is not None and not can_write_ip(canonical):
                continue
            # Reject pre-existing AND intra-payload duplicates up front, before
            # the mutation loop runs any create + DNS side effect (#504).
            if canonical in existing or canonical in seen_addr:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"{canonical} already exists in {subnet.network} or is duplicated "
                        "in the file; re-run with strategy='skip' or 'overwrite'"
                    ),
                )
            seen_addr.add(canonical)

    allocated_delta = 0
    for row in payload.addresses:
        canonical, fields, err = _row_address_fields(row)
        if err or canonical is None:
            result_obj.errors.append(err or "invalid row")
            continue
        try:
            if ipaddress.ip_address(canonical) not in subnet_net:
                result_obj.errors.append(f"{canonical}: outside {subnet_net}")
                continue
        except ValueError:
            result_obj.errors.append(f"{canonical}: invalid IP")
            continue

        # Address-set write delegation (#103): skip rows outside the caller's
        # writable ranges.
        if can_write_ip is not None and not can_write_ip(canonical):
            result_obj.skipped_no_perm += 1
            continue

        existing_ip = existing.get(canonical)

        if existing_ip is not None:
            if strategy == "skip":
                result_obj.skipped += 1
                continue
            if strategy == "overwrite":
                old_snapshot = {
                    "hostname": existing_ip.hostname,
                    "status": existing_ip.status,
                    "mac_address": (
                        str(existing_ip.mac_address) if existing_ip.mac_address else None
                    ),
                    "description": existing_ip.description,
                }
                had_hostname = bool(existing_ip.hostname)
                for k, v in fields.items():
                    if k == "custom_fields":
                        merged = dict(existing_ip.custom_fields or {})
                        merged.update(v)
                        existing_ip.custom_fields = merged
                    elif k == "tags":
                        merged_tags = dict(existing_ip.tags or {})
                        merged_tags.update(v)
                        existing_ip.tags = merged_tags
                    else:
                        setattr(existing_ip, k, v)
                db.add(
                    AuditLog(
                        user_id=current_user.id,
                        user_display_name=current_user.display_name,
                        auth_source=current_user.auth_source,
                        action="update",
                        resource_type="ip_address",
                        resource_id=str(existing_ip.id),
                        resource_display=f"{canonical} ({existing_ip.hostname or ''})",
                        old_value=old_snapshot,
                        new_value={**fields, "import": True},
                        result="success",
                    )
                )
                await db.flush()
                if existing_ip.hostname and not had_hostname:
                    # Hostname was just assigned — publish new DNS record.
                    try:
                        await _sync_dns_record(db, existing_ip, subnet, action="create")
                        result_obj.dns_synced += 1
                    except Exception as exc:  # noqa: BLE001
                        result_obj.errors.append(f"{canonical}: DNS sync failed: {exc}")
                elif had_hostname and "hostname" in fields:
                    # Hostname changed — republish (sync handles update via re-create).
                    try:
                        await _sync_dns_record(db, existing_ip, subnet, action="create")
                        result_obj.dns_synced += 1
                    except Exception as exc:  # noqa: BLE001
                        result_obj.errors.append(f"{canonical}: DNS sync failed: {exc}")
                await _sync_dhcp(existing_ip, canonical)
                result_obj.updated += 1
                continue
            # strategy == "fail" already raised above; unreachable.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{canonical} already exists",
            )

        # New row
        ip_status = fields.get("status") or "allocated"
        new_ip = IPAddress(
            subnet_id=subnet.id,
            address=canonical,
            status=ip_status,
            hostname=fields.get("hostname"),
            mac_address=fields.get("mac_address"),
            description=fields.get("description") or "",
            tags=fields.get("tags") or {},
            custom_fields=fields.get("custom_fields") or {},
        )
        db.add(new_ip)
        await db.flush()
        existing[canonical] = new_ip
        allocated_delta += 1
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="create",
                resource_type="ip_address",
                resource_id=str(new_ip.id),
                resource_display=f"{canonical} ({new_ip.hostname or ''})",
                new_value={**fields, "address": canonical, "import": True},
                result="success",
            )
        )
        if new_ip.hostname:
            try:
                await _sync_dns_record(db, new_ip, subnet, action="create")
                result_obj.dns_synced += 1
            except Exception as exc:  # noqa: BLE001
                # Don't fail the whole import — user can re-run DNS Sync after.
                result_obj.errors.append(f"{canonical}: DNS sync failed: {exc}")
        if ip_status == "static_dhcp" and new_ip.mac_address:
            await _sync_dhcp(new_ip, canonical)
        result_obj.created += 1

    # #7: surface a permission-blocked batch distinctly. ``skipped_no_perm``
    # already carries the per-row count, but a fully RBAC-blocked import would
    # otherwise return created=0 / updated=0 with no ``errors`` entry — which
    # reads as a benign no-op rather than the authorization failure it is. When
    # nothing landed AND at least one row was permission-blocked, add a clear
    # error so the caller can tell "blocked" apart from "already exists" / empty.
    if result_obj.skipped_no_perm and not result_obj.created and not result_obj.updated:
        result_obj.errors.append(
            f"Permission denied: {result_obj.skipped_no_perm} row(s) fall outside "
            "the subnet or any address set you can write — nothing was imported."
        )

    # Keep the subnet's utilization counters roughly honest by applying the
    # net delta here — users expect the UI to reflect the new row count
    # immediately. This is an estimate (a re-imported existing row bumps the
    # delta but not the true count); the hourly
    # ``app.tasks.ipam_utilization_recount.recount_ipam_utilization`` sweep
    # reconciles any resulting drift against the live row count.
    if allocated_delta:
        subnet.allocated_ips = (subnet.allocated_ips or 0) + allocated_delta
        if subnet.total_ips:
            subnet.utilization_percent = round(100.0 * subnet.allocated_ips / subnet.total_ips, 2)

    logger.info(
        "ipam_address_import_committed",
        subnet_id=str(subnet.id),
        created=result_obj.created,
        updated=result_obj.updated,
        skipped=result_obj.skipped,
        skipped_no_perm=result_obj.skipped_no_perm,
        dns_synced=result_obj.dns_synced,
        errors=len(result_obj.errors),
    )
    return result_obj
