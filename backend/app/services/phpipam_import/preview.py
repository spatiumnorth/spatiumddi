"""Side-effect-free preview orchestrator for the phpIPAM importer (issue #4734).

:func:`preview_phpipam_import` is the read-only half of the preview ->
(stateless round-trip) -> commit flow the NetBox importer (#36) established:
it opens one :class:`PhpipamClient`, pulls every in-scope controller, maps the
objects onto the canonical IR with **zero DB writes**, and flags every entity
whose key already exists through
:func:`app.services.netbox_import.commit.detect_conflicts`. The IR goes back to
the operator and returns verbatim as the commit plan, so the server stores
nothing between the two calls.

Cross-references that need the whole pull in hand live here:

* **Spaces** — ``per_section`` (default) makes one ``IPSpace`` per phpIPAM
  section. A section whose subnets sit in more than one VRF (or in a VRF and
  out of any) is split into one space per VRF, ``"<section> / <vrf>"``, because
  an ``IPSpace`` has one VRF and overlapping CIDRs in different VRFs must stay
  apart. ``single`` collapses everything into the operator's ``target_space_id``.
* **Block vs subnet** — phpIPAM nests subnets through ``masterSubnetId``;
  here a subnet that encloses another in the same space becomes an ``IPBlock``,
  a leaf a ``Subnet`` (the same rule as the NetBox importer, so overlapping
  subnets cannot both be subnets).
* **VLAN** — a subnet's ``vlanId`` is the VLAN row's id, resolved to its VID.
* **Addresses** — pulled one subnet at a time (phpIPAM has no bulk endpoint);
  an address that sits in a container subnet and in none of its leaf subnets
  cannot be stored and is reported, not dropped silently.

Everything phpIPAM carries that the IR cannot model lands in
``ImportPreview.warnings``: the preview is where an operator learns what will
not map.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

import structlog

from app.services.netbox_import.canonical import (
    ImportedAddress,
    ImportedBlock,
    ImportedCustomField,
    ImportedSpace,
    ImportedSubnet,
    ImportedVLAN,
    ImportedVRF,
    ImportPreview,
)
from app.services.netbox_import.mapping import classify_prefixes

from .client import PULL_CEILING, PhpipamClient, PhpipamClientError
from .fetch import (
    CUSTOM_FIELD_CONTROLLERS,
    fetch_addresses,
    fetch_custom_field_defs,
    fetch_l2_domains,
    fetch_sections,
    fetch_subnets,
    fetch_tags,
    fetch_vlans,
    fetch_vrfs,
)
from .mapping import (
    build_cf_map,
    build_state_map,
    cf_collisions,
    custom_field_defs,
    map_address,
    map_block,
    map_subnet,
    map_vlan,
    map_vrf,
    subnet_network,
    to_int,
    truthy,
)

logger = structlog.get_logger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# SpatiumDDI custom-field resource types a phpIPAM table feeds. A subnet row
# lands as a Subnet or an IPBlock depending on nesting, so its fields are
# defined for both.
_SUBNET_CF_TYPES = ("subnet", "ip_block")
_ADDRESS_CF_TYPES = ("ip_address",)


async def _safe_cf_defs(ipam: PhpipamClient, controller: str) -> dict[str, dict[str, Any]]:
    """Custom-field definitions of one controller; ``{}`` when the install has none.

    Best effort on purpose: an old phpIPAM without the endpoint must not fail an
    import that never needed custom fields.
    """
    try:
        return await fetch_custom_field_defs(ipam, controller)
    except PhpipamClientError:
        return {}


async def preview_phpipam_import(
    db: Any,  # AsyncSession — typed Any to keep this importable without a live session
    *,
    base_url: str,
    app_id: str,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_tls: bool = True,
    space_strategy: str = "per_section",
    target_space_id: uuid.UUID | None = None,
    filters: dict[str, Any] | None = None,
) -> ImportPreview:
    """Pull a phpIPAM install and build the canonical IR (no DB writes).

    ``filters``: ``section_ids`` (only those sections' subnets), ``family``
    (4 / 6), ``within_include`` (only subnets inside, or equal to, this CIDR).
    VRFs and VLANs are always pulled whole. Raises :class:`PhpipamClientError`
    on an unreachable / unauthorised phpIPAM, and when the pull would pass
    :data:`PULL_CEILING` prefix + address rows.
    """
    from app.services.netbox_import.commit import detect_conflicts

    filters = filters or {}
    section_filter: set[int] | None = (
        {int(i) for i in filters["section_ids"]} if filters.get("section_ids") else None
    )
    family_filter = filters.get("family")
    within: IPNetwork | None = None
    if filters.get("within_include"):
        try:
            within = ipaddress.ip_network(str(filters["within_include"]), strict=False)
        except ValueError as exc:
            raise PhpipamClientError(f"within_include is not a CIDR: {exc}") from exc

    use_sections = space_strategy == "per_section"
    warnings: list[str] = []

    async with PhpipamClient(
        base_url=base_url,
        app_id=app_id,
        token=token,
        username=username,
        password=password,
        verify_tls=verify_tls,
    ) as ipam:
        raw_sections = await fetch_sections(ipam)
        raw_vrfs = await fetch_vrfs(ipam)
        raw_vlans = await fetch_vlans(ipam)
        raw_domains = await fetch_l2_domains(ipam)
        state_map = build_state_map(await fetch_tags(ipam))
        cf_defs = {c: await _safe_cf_defs(ipam, c) for c in CUSTOM_FIELD_CONTROLLERS}

        # ── Subnets, section by section ──────────────────────────────
        sections = [s for s in raw_sections if to_int(s.get("id")) is not None]
        if section_filter is not None:
            sections = [s for s in sections if to_int(s["id"]) in section_filter]
        subnets_raw: list[tuple[int, dict[str, Any]]] = []  # (section id, subnet row)
        for sec in sections:
            sec_id = int(to_int(sec["id"]) or 0)
            for row in await fetch_subnets(ipam, sec_id):
                subnets_raw.append((sec_id, row))
            if len(subnets_raw) > PULL_CEILING:
                raise PhpipamClientError(_ceiling_message(len(subnets_raw)))

        # Parse + scope the subnets before any address request is made.
        folders = 0
        usable: list[tuple[int, dict[str, Any], IPNetwork]] = []
        for sec_id, row in subnets_raw:
            if truthy(row.get("isFolder")):
                folders += 1
                continue
            net = subnet_network(row)
            if net is None:
                warnings.append(
                    f"phpIPAM subnet id={row.get('id')} "
                    f"({row.get('subnet')!r}/{row.get('mask')!r}) is unparseable; skipped."
                )
                continue
            if family_filter and net.version != family_filter:
                continue
            if within is not None and not (
                net.version == within.version and net.subnet_of(within)  # type: ignore[arg-type]
            ):
                continue
            usable.append((sec_id, row, net))

        # ── Spaces (decided before addresses, which carry their subnet's) ──
        vrf_names = {to_int(v.get("vrfId")): str(v.get("name") or "").strip() for v in raw_vrfs}
        section_name = _section_names(sections)
        sec_vrfs: dict[int, set[int]] = {}
        for sec_id, row, _net in usable:
            sec_vrfs.setdefault(sec_id, set()).add(to_int(row.get("vrfId")) or 0)

        def space_for(sec_id: int, vrf_id: int) -> tuple[str, str | None]:
            """``(space name, vrf name to link)`` for a subnet of a section."""
            base = section_name[sec_id]
            vrfs_here = sec_vrfs.get(sec_id, set())
            if len(vrfs_here) <= 1:
                vname = vrf_names.get(vrf_id) if vrf_id else None
                return base, vname or None
            if not vrf_id:
                return base, None
            vname = vrf_names.get(vrf_id)
            return (f"{base} / {vname}" if vname else f"{base} / VRF {vrf_id}"), vname or None

        def space_name_of(sec_id: int, row: dict[str, Any]) -> str | None:
            if not use_sections:
                return None
            return space_for(sec_id, to_int(row.get("vrfId")) or 0)[0]

        # ── Addresses, subnet by subnet, under the ceiling ───────────
        addr_rows: list[tuple[str | None, dict[str, Any], IPNetwork]] = []
        total = len(usable)
        if total > PULL_CEILING:
            raise PhpipamClientError(_ceiling_message(total))
        for sec_id, row, net in usable:
            sid = to_int(row.get("id"))
            if sid is None:
                continue
            sp_of_subnet = space_name_of(sec_id, row)
            for a in await fetch_addresses(ipam, sid):
                addr_rows.append((sp_of_subnet, a, net))
            if total + len(addr_rows) > PULL_CEILING:
                raise PhpipamClientError(_ceiling_message(total + len(addr_rows)))

    # ── Custom-field definitions (IR) ────────────────────────────────
    sub_cf = build_cf_map(cf_defs["subnets"])
    addr_cf = build_cf_map(cf_defs["addresses"])
    cf_def_rows: list[ImportedCustomField] = []
    cf_def_rows += custom_field_defs(_SUBNET_CF_TYPES, sub_cf)
    cf_def_rows += custom_field_defs(_ADDRESS_CF_TYPES, addr_cf)
    if any(a.get("owner") and str(a["owner"]).strip() for _sp, a, _n in addr_rows):
        cf_def_rows.append(
            ImportedCustomField(
                resource_type="ip_address",
                name="phpipam_owner",
                label="Owner (phpIPAM)",
                field_type="text",
                source_name="owner",
            )
        )
    for controller in ("subnets", "addresses"):
        lost = cf_collisions(cf_defs[controller])
        if lost:
            warnings.append(
                f"phpIPAM {controller} custom field(s) {sorted(lost)} sanitise to a name another "
                "field already uses; their values are not imported."
            )
    for controller in ("vlan", "vrf"):
        if cf_defs[controller]:
            warnings.append(
                f"phpIPAM {controller} custom field(s) {sorted(cf_defs[controller])} are not "
                f"imported (SpatiumDDI has no custom fields on {controller} rows)."
            )

    # ── VRFs ─────────────────────────────────────────────────────────
    vrfs: list[ImportedVRF] = []
    for v in raw_vrfs:
        iv = map_vrf(v)
        if iv is None:
            warnings.append(f"phpIPAM VRF id={v.get('vrfId')} has no name; skipped.")
            continue
        vrfs.append(iv)

    # ── VLANs (one synthetic router) — dedupe on vid + name ──────────
    vlans: list[ImportedVLAN] = []
    vlan_id_to_vid: dict[int, int] = {}
    seen_vids: set[int] = set()
    seen_names: set[str] = set()
    for rv in raw_vlans:
        vl = map_vlan(rv)
        if vl is None:
            warnings.append(
                f"phpIPAM VLAN id={rv.get('vlanId')} has no usable VID (1-4094) / name; skipped."
            )
            continue
        if vl.vid in seen_vids or vl.name in seen_names:
            warnings.append(
                f"VLAN {vl.vid} ({vl.name!r}) clashes with an earlier VLAN under the one import "
                "router (uniqueness is (router, vid) and (router, name)); skipped."
            )
            continue
        seen_vids.add(vl.vid)
        seen_names.add(vl.name)
        vlans.append(vl)
        if vl.netbox_id is not None:
            vlan_id_to_vid[vl.netbox_id] = vl.vid
    if len(raw_domains) > 1:
        warnings.append(
            f"phpIPAM has {len(raw_domains)} VLAN domains; VLANs from all of them are imported "
            "under one router, so a VID used in two domains is imported once."
        )

    # ── Spaces ───────────────────────────────────────────────────────
    spaces: list[ImportedSpace] = []
    space_seen: set[str] = set()

    def add_space(name: str, vrf_name: str | None, description: str) -> None:
        if name not in space_seen:
            space_seen.add(name)
            spaces.append(
                ImportedSpace(
                    name=name, vrf_name=vrf_name, is_default=False, description=description
                )
            )

    if use_sections:
        for sec in sections:
            sec_id = int(to_int(sec["id"]) or 0)
            for vrf_id in sorted(sec_vrfs.get(sec_id, {0})):
                name, vname = space_for(sec_id, vrf_id)
                add_space(name, vname, str(sec.get("description") or "").strip())
    elif target_space_id is None:
        warnings.append(
            "space_strategy='single' requires target_space_id; the commit will reject this plan."
        )

    # ── Block vs subnet, per space ───────────────────────────────────
    seen_cidr: set[tuple[str | None, str]] = set()
    unique: list[tuple[int, dict[str, Any], IPNetwork, str | None]] = []
    for sec_id, row, net in usable:
        sp = space_name_of(sec_id, row)
        key = (sp, str(net))
        if key in seen_cidr:
            warnings.append(
                f"Subnet {net} (phpIPAM id={row.get('id')}) appears twice in "
                f"{'space ' + repr(sp) if sp else 'the target space'}; the first is imported."
            )
            continue
        seen_cidr.add(key)
        unique.append((sec_id, row, net, sp))

    decisions = classify_prefixes(
        [
            {"id": to_int(row.get("id")), "prefix": str(net), "status": None, "vrf": {"id": sp}}
            for _sec, row, net, sp in unique
        ]
    )
    blocks: list[ImportedBlock] = []
    subnets: list[ImportedSubnet] = []
    leaf_nets: dict[str | None, list[IPNetwork]] = {}
    for _sec, row, net, sp in unique:
        sid = to_int(row.get("id"))
        if decisions.get(sid if sid is not None else -1, "subnet") == "block":
            blocks.append(map_block(row, network=net, space_name=sp, cf_map=sub_cf))
            continue
        vlan_ref = to_int(row.get("vlanId"))
        vid = vlan_id_to_vid.get(vlan_ref) if vlan_ref else None
        if vlan_ref and vid is None:
            warnings.append(
                f"Subnet {net} references phpIPAM VLAN id={vlan_ref} that was not imported; "
                "imported without a VLAN link."
            )
        subnet = map_subnet(row, network=net, space_name=sp, vlan_vid=vid, cf_map=sub_cf)
        if subnet.kind == "multicast":
            warnings.append(
                f"Subnet {net} is multicast; addresses inside it are skipped "
                "(create a multicast group after the import instead)."
            )
        subnets.append(subnet)
        leaf_nets.setdefault(sp, []).append(net)

    # ── Addresses ────────────────────────────────────────────────────
    addresses: list[ImportedAddress] = []
    seen_addr: set[tuple[str | None, str]] = set()
    orphaned: dict[str, int] = {}
    dup_addrs = 0
    device_links = 0
    for sp, raw_a, net in addr_rows:
        ia = map_address(
            raw_a,
            subnet_cidr=str(net),
            space_name=sp,
            state_map=state_map,
            cf_map=addr_cf,
            mask=net.prefixlen,
        )
        if ia is None:
            warnings.append(
                f"phpIPAM address id={raw_a.get('id')} ({raw_a.get('ip')!r}) is unparseable; "
                "skipped."
            )
            continue
        if to_int(raw_a.get("deviceId")):
            device_links += 1
        addr = ipaddress.ip_address(ia.address)
        if not any(
            n.version == addr.version and addr in n for n in leaf_nets.get(sp, [])  # type: ignore[operator]
        ):
            orphaned[str(net)] = orphaned.get(str(net), 0) + 1
            continue
        if (sp, ia.address) in seen_addr:
            dup_addrs += 1
            continue
        seen_addr.add((sp, ia.address))
        addresses.append(ia)
    for cidr, count in sorted(orphaned.items()):
        warnings.append(
            f"{count} address(es) of container subnet {cidr} fall in none of its leaf subnets; "
            "they are not imported."
        )
    if dup_addrs:
        warnings.append(f"{dup_addrs} duplicate address row(s) skipped (first one imported).")
    if device_links:
        warnings.append(
            f"{device_links} address(es) reference a phpIPAM device; devices are not imported, "
            "so that link is dropped."
        )
    if folders:
        warnings.append(
            f"{folders} phpIPAM folder(s) not imported (a folder has no network); the subnets "
            "inside one are imported at the level of the enclosing subnet."
        )
    nested = sum(1 for s in sections if to_int(s.get("masterSection")))
    if nested:
        warnings.append(
            f"{nested} nested section(s) imported as flat spaces (a space has no parent)."
        )
    missing_vrf = {
        to_int(r.get("vrfId"))
        for _s, r, _n in usable
        if to_int(r.get("vrfId")) and to_int(r.get("vrfId")) not in vrf_names
    }
    if missing_vrf:
        warnings.append(
            f"Subnets reference phpIPAM VRF id(s) {sorted(i for i in missing_vrf if i is not None)} that do not exist."
        )

    preview = ImportPreview(
        source="phpipam",
        vrfs=vrfs,
        spaces=spaces,
        vlans=vlans,
        blocks=blocks,
        subnets=subnets,
        addresses=addresses,
        custom_field_defs=cf_def_rows,
        warnings=warnings,
    )
    preview.conflicts = await detect_conflicts(
        db,
        preview=preview,
        space_strategy=space_strategy,
        target_space_id=target_space_id,
    )
    logger.info(
        "phpipam_import.preview",
        endpoint=base_url,
        space_strategy=space_strategy,
        spaces=len(spaces),
        vrfs=len(vrfs),
        vlans=len(vlans),
        blocks=len(blocks),
        subnets=len(subnets),
        addresses=len(addresses),
        conflicts=len(preview.conflicts),
        warnings=len(warnings),
    )
    return preview


def _section_names(sections: list[dict[str, Any]]) -> dict[int, str]:
    """Unique space name per section id (a duplicate or empty name gets its id)."""
    out: dict[int, str] = {}
    used: set[str] = set()
    for sec in sections:
        sec_id = int(to_int(sec.get("id")) or 0)
        name = str(sec.get("name") or "").strip() or f"Section {sec_id}"
        if name in used:
            name = f"{name} ({sec_id})"
        used.add(name)
        out[sec_id] = name
    return out


def _ceiling_message(rows: int) -> str:
    return (
        f"phpIPAM pull would import {rows} prefix+address rows, over the {PULL_CEILING} "
        "ceiling. Narrow the import with a section / family / within_include filter and re-run."
    )
