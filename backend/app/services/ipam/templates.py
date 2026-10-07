"""IPAM template apply / reapply / pre-fill service (issue #26).

Templates STAMP values onto blocks or subnets at apply time —
inheritance is a separate read-time mechanism. Re-apply is the
operator-driven way to refresh stamp values to match the latest
template definition.

Apply policy:
    - ``force=True``: every template-bearing column overwrites the
      target unconditionally.
    - ``force=False``: only empty/null target columns are filled
      from the template.

For ``applies_to='block'`` templates with a non-null ``child_layout``,
``carve_children`` walks the layout list and creates one Subnet per
child entry under the block. Idempotent — children already at a
target CIDR are left alone.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAMTemplate, IPBlock, Subnet


class TemplateError(Exception):
    """Raised by the template service when validation fails."""

    def __init__(self, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.status_code = status_code


_BIGINT_MAX = 2**63 - 1
_V4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
_V6_MULTICAST = ipaddress.ip_network("ff00::/8")


def _total_ips(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    """Mirror ``app.api.v1.ipam.router._total_ips`` so carved subnets carry
    the same ``total_ips`` create_subnet would compute (was left 0 → the
    utilization bar read 0/0 forever, #494)."""
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


def _subnet_kind(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """Mirror create_subnet's #126 multicast discriminator so a carved
    multicast leaf isn't left ``unicast`` (which would wrongly accept
    per-IP allocation, #494)."""
    mcast = _V4_MULTICAST if isinstance(net, ipaddress.IPv4Network) else _V6_MULTICAST
    return "multicast" if net.subnet_of(mcast) else "unicast"  # type: ignore[arg-type]


_TEMPLATE_FIELDS_COMMON: tuple[str, ...] = (
    "tags",
    "custom_fields",
    "dns_zone_id",
    "dns_additional_zone_ids",
    "ddns_enabled",
    "ddns_hostname_policy",
    "ddns_domain_override",
    "ddns_ttl",
)

# The DDNS columns ``ddns_inherit_settings`` switches on and off as one:
# with inheritance off, ``resolve_effective_ddns`` reads all four of them.
_DDNS_FIELDS: tuple[str, ...] = (
    "ddns_enabled",
    "ddns_hostname_policy",
    "ddns_domain_override",
    "ddns_ttl",
)


def _is_empty(value: Any) -> bool:
    """Treat None / empty dict / empty list / empty string as fillable."""
    if value is None:
        return True
    if isinstance(value, (dict, list, str)) and len(value) == 0:
        return True
    return False


def _stamp(target: Any, name: str, template_value: Any, *, force: bool) -> bool:
    """Stamp ``template_value`` onto ``target.{name}`` per apply policy.

    Returns True if the column was written.
    """
    current = getattr(target, name, None)
    if force or _is_empty(current):
        setattr(target, name, template_value)
        return True
    return False


def _stamp_dns_group_ids(target: Any, dns_group_id: uuid.UUID | None, *, force: bool) -> bool:
    """The template carries a single ``dns_group_id`` column; the IPAM
    carrier columns store ``dns_group_ids`` as a JSONB list of strings
    (legacy multi-group shape). Coerce single → list-of-one on stamp.
    """
    current = getattr(target, "dns_group_ids", None)
    if dns_group_id is None:
        # Template explicitly says "no DNS group" — only overwrite on
        # force. Otherwise leave whatever the operator already set.
        if force:
            target.dns_group_ids = []
            return True
        return False
    new_value = [str(dns_group_id)]
    if force or _is_empty(current):
        target.dns_group_ids = new_value
        return True
    return False


def _stamp_dhcp_group(target: Any, dhcp_group_id: uuid.UUID | None, *, force: bool) -> bool:
    if dhcp_group_id is None and not force:
        return False
    current = getattr(target, "dhcp_server_group_id", None)
    if force or current is None:
        target.dhcp_server_group_id = dhcp_group_id
        return True
    return False


def _ddns_fields_set_by(template: IPAMTemplate) -> list[str]:
    """The DDNS columns ``template`` sets away from the create schema's
    defaults: the values its DDNS lock exists to make take effect."""
    fields: list[str] = []
    if template.ddns_enabled:
        fields.append("ddns_enabled")
    if template.ddns_hostname_policy != "client_or_generated":
        fields.append("ddns_hostname_policy")
    if template.ddns_domain_override is not None:
        fields.append("ddns_domain_override")
    if template.ddns_ttl is not None:
        fields.append("ddns_ttl")
    return fields


def _locks_ddns(target: Any, template: IPAMTemplate) -> bool:
    """Whether applying ``template`` turns ``target``'s DDNS inheritance off.

    A template that sets DDNS locks its DDNS config in: the target stops
    inheriting so the template's values take effect. With inheritance off the
    target resolves all four of its own DDNS columns together
    (``resolve_effective_ddns``), so the lock comes with all four of the
    template's values. A lock that came with only the columns ``force=False``
    could fill pinned the target to its own stored DDNS, defaults included: a
    template that turned DDNS on turned it off (#1421). Writing all four
    overwrites nothing an operator set, because an inheriting target ignores
    its own DDNS columns. A target that already has its own DDNS has no lock
    to turn, and keeps its non-empty values unless ``force`` is set. Only
    relevant for IPBlock + Subnet — the IPSpace DDNS columns don't have an
    inherit flag.
    """
    return bool(getattr(target, "ddns_inherit_settings", False)) and bool(
        _ddns_fields_set_by(template)
    )


# ── Apply to existing carriers ────────────────────────────────────────


def _apply_to_carrier(
    template: IPAMTemplate, target: IPBlock | Subnet, *, force: bool
) -> list[str]:
    """Stamp ``template`` onto an existing block or subnet per the apply
    policy. Returns the column names that were actually written, the DDNS
    lock's ``ddns_inherit_settings`` included. Caller commits.
    """
    lock_ddns = _locks_ddns(target, template)
    written: list[str] = []
    for field in _TEMPLATE_FIELDS_COMMON:
        stamp_always = force or (lock_ddns and field in _DDNS_FIELDS)
        if _stamp(target, field, getattr(template, field), force=stamp_always):
            written.append(field)
    if _stamp_dns_group_ids(target, template.dns_group_id, force=force):
        written.append("dns_group_ids")
    if _stamp_dhcp_group(target, template.dhcp_group_id, force=force):
        written.append("dhcp_server_group_id")
    if lock_ddns:
        target.ddns_inherit_settings = False
        written.append("ddns_inherit_settings")
    target.applied_template_id = template.id
    return written


def apply_template_to_block(
    template: IPAMTemplate,
    block: IPBlock,
    *,
    force: bool = False,
) -> list[str]:
    """Stamp ``template`` values onto ``block``. Returns the list of
    column names that were actually written. Caller commits.
    """
    if template.applies_to != "block":
        raise TemplateError(
            f"Template {template.name!r} applies to {template.applies_to!r}, not 'block'."
        )
    return _apply_to_carrier(template, block, force=force)


def apply_template_to_subnet(
    template: IPAMTemplate,
    subnet: Subnet,
    *,
    force: bool = False,
) -> list[str]:
    if template.applies_to != "subnet":
        raise TemplateError(
            f"Template {template.name!r} applies to {template.applies_to!r}, not 'subnet'."
        )
    return _apply_to_carrier(template, subnet, force=force)


# ── Pre-fill on create ────────────────────────────────────────────────


def _prefill(body: Any, name: str, template_value: Any) -> None:
    """Fill ``body.{name}`` from ``template_value`` when the operator
    didn't explicitly set the field. Pydantic's ``model_fields_set``
    distinguishes "operator typed False" from "operator omitted the
    field" — booleans default to False on the create schema, so
    introspection is the only way to know which.

    When ``model_fields_set`` is unavailable (non-Pydantic body), we
    fall back to the empty-check used by the post-create apply path.
    """
    fields_set = getattr(body, "model_fields_set", None)
    if fields_set is not None:
        if name in fields_set:
            return
        setattr(body, name, template_value)
        return
    current = getattr(body, name, None)
    if _is_empty(current):
        setattr(body, name, template_value)


def _prefill_unset(body: Any, name: str, value: Any) -> None:
    """Pre-fill ``body.{name}`` only when Pydantic confirms the
    operator didn't supply it. Used for bookkeeping fields that the
    template spec maps onto a different body field name (e.g. the
    template's ``dns_group_id`` → body ``dns_group_ids`` list).
    """
    fields_set = getattr(body, "model_fields_set", None)
    if fields_set is not None and name in fields_set:
        return
    setattr(body, name, value)


def _supplied_fields(body: Any) -> set[str]:
    """The fields the request itself set. Read it before pre-filling:
    Pydantic counts an assignment as set, so ``_prefill`` adds every field
    it fills to ``model_fields_set``."""
    return set(getattr(body, "model_fields_set", None) or ())


def _lock_ddns_on_create(template: IPAMTemplate, body: Any, supplied: set[str]) -> None:
    """Turn the new carrier's DDNS inheritance off when a DDNS value the
    template sets was pre-filled, so that value takes effect. The lock goes
    with the template's values (#1304): when the request supplied every one
    of them itself, none is the template's, and the carrier's DDNS
    inheritance is what the same request gets without a template. A request
    that sets ``ddns_inherit_settings`` itself always keeps it.
    """
    if not hasattr(body, "ddns_inherit_settings"):
        return
    if any(name not in supplied for name in _ddns_fields_set_by(template)):
        _prefill_unset(body, "ddns_inherit_settings", False)


def apply_template_on_create_block(template: IPAMTemplate, body: Any) -> None:
    """Pre-fill an IPBlockCreate body in-place. ``template`` is the
    fully-loaded ORM row.
    """
    if template.applies_to != "block":
        raise TemplateError(
            f"Template {template.name!r} applies to {template.applies_to!r}, not 'block'."
        )
    supplied = _supplied_fields(body)
    for field in _TEMPLATE_FIELDS_COMMON:
        _prefill(body, field, getattr(template, field))
    if template.dns_group_id is not None:
        _prefill_unset(body, "dns_group_ids", [str(template.dns_group_id)])
    if template.dhcp_group_id is not None:
        _prefill_unset(body, "dhcp_server_group_id", template.dhcp_group_id)
    _lock_ddns_on_create(template, body, supplied)


def apply_template_on_create_subnet(template: IPAMTemplate, body: Any) -> None:
    if template.applies_to != "subnet":
        raise TemplateError(
            f"Template {template.name!r} applies to {template.applies_to!r}, not 'subnet'."
        )
    supplied = _supplied_fields(body)
    for field in _TEMPLATE_FIELDS_COMMON:
        _prefill(body, field, getattr(template, field))
    if template.dns_group_id is not None:
        _prefill_unset(body, "dns_group_ids", [str(template.dns_group_id)])
    if template.dhcp_group_id is not None:
        _prefill_unset(body, "dhcp_server_group_id", template.dhcp_group_id)
    _lock_ddns_on_create(template, body, supplied)


# ── Child layout carving (block templates only) ───────────────────────


@dataclass
class CarvedChild:
    cidr: str
    name: str
    skipped: bool  # True if a Subnet at this CIDR already existed


def _render_child_name(
    template: str,
    *,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    index: int,
) -> str:
    """Render ``name_template`` with the same token vocabulary as
    bulk-allocate: ``{n}`` / ``{n:03d}`` / ``{oct1}``–``{oct4}``.
    """
    tokens: dict[str, Any] = {"n": index}
    if isinstance(network, ipaddress.IPv4Network):
        octets = str(network.network_address).split(".")
        for i, oct_value in enumerate(octets, start=1):
            tokens[f"oct{i}"] = oct_value
    try:
        return template.format(**tokens)
    except (KeyError, ValueError, IndexError):
        # Bad template → fall back to the network string so we never
        # crash the carve. UI-side validation catches these earlier.
        return str(network)


def _validate_child_layout(layout: dict[str, Any], parent_prefix: int) -> list[dict[str, Any]]:
    if not isinstance(layout, dict):
        raise TemplateError("child_layout must be an object with a 'children' array.")
    children = layout.get("children")
    if not isinstance(children, list) or not children:
        raise TemplateError("child_layout.children must be a non-empty array.")
    cleaned: list[dict[str, Any]] = []
    for idx, raw in enumerate(children):
        if not isinstance(raw, dict):
            raise TemplateError(f"child_layout.children[{idx}] must be an object.")
        prefix = raw.get("prefix")
        if not isinstance(prefix, int) or prefix <= parent_prefix:
            raise TemplateError(
                f"child_layout.children[{idx}].prefix must be an int strictly "
                f"greater than the carrier's /{parent_prefix} (got {prefix!r})."
            )
        name_template = raw.get("name_template", "")
        if not isinstance(name_template, str):
            raise TemplateError(f"child_layout.children[{idx}].name_template must be a string.")
        cleaned.append(
            {
                "prefix": prefix,
                "name_template": name_template,
                "description": raw.get("description", "") or "",
                "tags": raw.get("tags") or {},
                "custom_fields": raw.get("custom_fields") or {},
            }
        )
    return cleaned


async def _existing_subnets_under_block(db: AsyncSession, block: IPBlock) -> set[str]:
    rows = (
        await db.execute(
            select(Subnet.network).where(
                Subnet.block_id == block.id,
                Subnet.deleted_at.is_(None),
            )
        )
    ).all()
    return {str(r[0]) for r in rows}


async def carve_children(
    db: AsyncSession,
    template: IPAMTemplate,
    block: IPBlock,
) -> list[CarvedChild]:
    """Carve sub-subnets per ``template.child_layout``. Idempotent —
    skips any CIDR that already has a Subnet under this block.

    Children are carved sequentially: the layout consumes blocks of
    each child's prefix size starting at the block's network address.
    Caller is responsible for committing.
    """
    if template.child_layout is None:
        return []
    if template.applies_to != "block":
        raise TemplateError("child_layout is only valid on block templates.")

    parent_net = ipaddress.ip_network(str(block.network), strict=False)
    spec = _validate_child_layout(template.child_layout, parent_net.prefixlen)
    existing = await _existing_subnets_under_block(db, block)
    existing_nets = [ipaddress.ip_network(c, strict=False) for c in existing]
    results: list[CarvedChild] = []

    cursor = int(parent_net.network_address)
    end = int(parent_net.broadcast_address)
    for idx, entry in enumerate(spec, start=1):
        prefix = entry["prefix"]
        size = 1 << ((parent_net.max_prefixlen) - prefix)
        # Align the cursor UP to this child's prefix boundary. A /p network
        # must start on a multiple of its size; the old code snapped the
        # cursor DOWN (ip_network(..., strict=False)), which for a layout
        # like [/26, /25] on a /24 rewound the /25 back over the /26 and
        # created two overlapping subnets (#494). Rounding up leaves a gap
        # instead — valid, non-overlapping CIDR.
        aligned = (cursor + size - 1) & ~(size - 1)
        if aligned + size - 1 > end:
            raise TemplateError(
                f"child_layout overflows the carrier {block.network}: "
                f"child[{idx-1}] /{prefix} would extend past the block range."
            )
        aligned_addr = (
            ipaddress.IPv4Address(aligned)
            if isinstance(parent_net, ipaddress.IPv4Network)
            else ipaddress.IPv6Address(aligned)
        )
        child_net = ipaddress.ip_network(f"{aligned_addr}/{prefix}", strict=True)
        cidr = str(child_net)
        rendered_name = (
            _render_child_name(entry["name_template"] or "", network=child_net, index=idx)
            if entry["name_template"]
            else ""
        )
        cursor = aligned + size
        if cidr in existing:
            results.append(CarvedChild(cidr=cidr, name=rendered_name, skipped=True))
            continue
        # Idempotency is exact-CIDR above; also refuse to carve into a
        # *different* subnet that already overlaps this range rather than
        # silently creating an overlap the model has no DB constraint to
        # catch (#494).
        clash = next((n for n in existing_nets if n.overlaps(child_net)), None)
        if clash is not None:
            raise TemplateError(
                f"child_layout child /{prefix} at {cidr} overlaps existing "
                f"subnet {clash} under block {block.network}."
            )
        # Carved subnets skip the network/broadcast auto-address rows
        # because we're not going through ``create_subnet``. Operator
        # can flesh them out via the IPAM UI afterward; the row exists
        # in the tree.
        sub = Subnet(
            space_id=block.space_id,
            block_id=block.id,
            network=cidr,
            name=rendered_name,
            description=entry["description"],
            tags=entry["tags"],
            custom_fields=entry["custom_fields"],
            applied_template_id=template.id,
            total_ips=_total_ips(child_net),
            kind=_subnet_kind(child_net),
        )
        db.add(sub)
        existing_nets.append(child_net)
        results.append(CarvedChild(cidr=cidr, name=rendered_name, skipped=False))

    return results


# ── Reapply across instances ──────────────────────────────────────────


async def find_block_instances(db: AsyncSession, template_id: uuid.UUID) -> list[IPBlock]:
    rows = (
        (
            await db.execute(
                select(IPBlock).where(
                    IPBlock.applied_template_id == template_id,
                    IPBlock.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def find_subnet_instances(db: AsyncSession, template_id: uuid.UUID) -> list[Subnet]:
    rows = (
        (
            await db.execute(
                select(Subnet).where(
                    Subnet.applied_template_id == template_id,
                    Subnet.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)
