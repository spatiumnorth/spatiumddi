"""Pure phpIPAM-shape -> canonical-IR mappers (issue #4734).

phpIPAM's scalars are integers or strings depending on the column (and version),
so every reader here goes through :func:`to_int` / :func:`truthy`; it names its keys by table column
(``vlanId`` is a VLAN's id, ``number`` its VID, ``tag`` an address's state id),
and carries custom fields as extra keys named after their columns. These
functions take one raw object and return an IR dataclass from
:mod:`app.services.netbox_import.canonical`; no DB access, no network.

The load-bearing rules:

* **Subnet CIDR** is ``subnet`` + ``mask`` (the address may arrive dotted or as
  a decimal integer, depending on the phpIPAM version).
* **Address state** goes through the ``/tools/tags/`` table: Reserved ->
  ``reserved``, anything deprecated/decommissioned -> ``deprecated``, everything
  else (Used, Offline, DHCP, custom) -> ``allocated``. The integration-owned
  ``dhcp`` status is never produced, and the source's own state name is kept in
  ``custom_fields["phpipam_state"]`` when it carries more than the status says.
* **Custom fields** keep their values under a sanitised key and get a
  ``CustomFieldDefinition`` of the matching type (``custom_field_defs``), so
  they show up as real fields rather than loose JSON.
* **Provenance**: ``phpipam_id`` rides in ``custom_fields`` of every row with
  that column, in the ``netbox_id`` IR field (the #36 name) for the audit row.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from app.services.netbox_import.canonical import (
    ImportedAddress,
    ImportedBlock,
    ImportedCustomField,
    ImportedSubnet,
    ImportedVLAN,
    ImportedVRF,
)
from app.services.netbox_import.commit import _clean_mac
from app.services.netbox_import.mapping import _multicast_kind, _split_dns_name

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# phpIPAM's default ip-tag ids (``/tools/tags/``): used only when that endpoint
# is unavailable, so an old install still maps Reserved.
_DEFAULT_TAG_STATUS: dict[int, str] = {
    1: "allocated",
    2: "allocated",
    3: "reserved",
    4: "allocated",
}

# SpatiumDDI IPAddress.role has no "gateway" mapping beyond this one.
_GATEWAY_ROLE = "gateway"

_CF_NAME_RE = re.compile(r"[^a-z0-9_]+")
_ENUM_RE = re.compile(r"^enum\((.*)\)$", re.IGNORECASE)


def to_int(value: Any) -> int | None:
    """``"12"`` -> 12; anything not an integer -> ``None``."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def ip_text(value: Any, *, mask: int | None = None) -> str | None:
    """A readable IP from a dotted / colon string or a decimal integer."""
    raw = _text(value)
    if not raw:
        return None
    if raw.isdigit():
        number = int(raw)
        # An IPv4 integer fits 32 bits; an IPv6 prefix longer than 32 never does.
        is_v6 = number >= 2**32 or (mask is not None and mask > 32)
        try:
            return str(ipaddress.IPv6Address(number) if is_v6 else ipaddress.IPv4Address(number))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def subnet_network(raw: dict[str, Any]) -> IPNetwork | None:
    """The network of a phpIPAM subnet row, or ``None`` (folder / unparseable)."""
    mask = to_int(raw.get("mask"))
    addr = ip_text(raw.get("subnet"), mask=mask)
    if addr is None or mask is None:
        return None
    try:
        return ipaddress.ip_network(f"{addr}/{mask}", strict=False)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Custom fields.
# --------------------------------------------------------------------------- #


def sanitize_cf_name(column: str) -> str:
    """phpIPAM column name -> a SpatiumDDI custom-field name (``^[a-z][a-z0-9_]*$``)."""
    name = _CF_NAME_RE.sub("_", column.strip().lower()).strip("_")
    if not name:
        name = "field"
    if not name[0].isalpha():
        name = f"f_{name}"
    return name[:100]


def _field_type(sql_type: str) -> tuple[str, list[str] | None]:
    t = sql_type.strip().lower()
    enum = _ENUM_RE.match(sql_type.strip())
    if enum:
        options = [o.strip().strip("'\"") for o in enum.group(1).split(",")]
        options = [o for o in options if o]
        if options:
            return "select", options
        return "text", None
    if t.startswith("tinyint(1)") or t.startswith("bool") or t.startswith("bit"):
        return "boolean", None
    if re.match(r"^(tiny|small|medium|big)?int|^decimal|^float|^double|^numeric", t):
        return "number", None
    if t == "date":
        return "date", None
    return "text", None


def build_cf_map(
    definitions: dict[str, dict[str, Any]],
) -> dict[str, tuple[str, str, list[str] | None, str]]:
    """``{column: (name, field_type, options, label)}`` for one controller.

    Two columns that sanitise to the same name keep the first; the preview
    warns about the rest through :func:`cf_collisions`.
    """
    out: dict[str, tuple[str, str, list[str] | None, str]] = {}
    seen: set[str] = set()
    for column, definition in definitions.items():
        name = sanitize_cf_name(column)
        if name in seen:
            continue
        seen.add(name)
        ftype, options = _field_type(_text(definition.get("type")))
        label = _text(definition.get("Comment")) or _text(definition.get("name")) or column
        out[column] = (name, ftype, options, label[:255])
    return out


def cf_collisions(definitions: dict[str, dict[str, Any]]) -> list[str]:
    seen: dict[str, str] = {}
    lost: list[str] = []
    for column in definitions:
        name = sanitize_cf_name(column)
        if name in seen:
            lost.append(column)
        else:
            seen[name] = column
    return lost


def custom_field_defs(
    resource_types: tuple[str, ...],
    cf_map: dict[str, tuple[str, str, list[str] | None, str]],
) -> list[ImportedCustomField]:
    return [
        ImportedCustomField(
            resource_type=rt,
            name=name,
            label=label,
            field_type=ftype,
            options=options,
            source_name=column,
        )
        for rt in resource_types
        for column, (name, ftype, options, label) in cf_map.items()
    ]


def _cf_value(value: Any, field_type: str) -> Any:
    """Typed value, or ``None`` when empty (the caller drops it)."""
    text = _text(value)
    if not text or text.startswith("0000-00-00"):
        return None
    if field_type == "boolean":
        return truthy(text)
    if field_type == "number":
        try:
            return int(text) if re.fullmatch(r"-?\d+", text) else float(text)
        except ValueError:
            return None
    return text


def extract_custom_fields(
    raw: dict[str, Any],
    cf_map: dict[str, tuple[str, str, list[str] | None, str]],
    source_id: int | None,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for column, (name, ftype, _options, _label) in cf_map.items():
        if column in raw:
            value = _cf_value(raw[column], ftype)
            if value is not None:
                out[name] = value
    if source_id is not None:
        out["phpipam_id"] = source_id
    return out


# --------------------------------------------------------------------------- #
# VRF / VLAN.
# --------------------------------------------------------------------------- #


def map_vrf(raw: dict[str, Any]) -> ImportedVRF | None:
    name = _text(raw.get("name"))
    if not name:
        return None
    vrf_id = to_int(raw.get("vrfId"))
    cf: dict[str, Any] = {}
    if vrf_id is not None:
        cf["phpipam_id"] = vrf_id
    return ImportedVRF(
        name=name,
        rd=_text(raw.get("rd")) or None,
        description=_text(raw.get("description")),
        custom_fields=cf,
        netbox_id=vrf_id,
    )


def map_vlan(raw: dict[str, Any]) -> ImportedVLAN | None:
    """phpIPAM VLAN -> IR; ``None`` when the VID or name is missing / out of range."""
    vid = to_int(raw.get("number"))
    name = _text(raw.get("name"))
    if vid is None or not 1 <= vid <= 4094 or not name:
        return None
    return ImportedVLAN(
        vid=vid,
        name=name,
        description=_text(raw.get("description")),
        netbox_id=to_int(raw.get("vlanId")),
    )


# --------------------------------------------------------------------------- #
# Address states.
# --------------------------------------------------------------------------- #


def build_state_map(tags: list[dict[str, Any]]) -> dict[int, tuple[str, str]]:
    """``{tag id: (status, state name)}`` from ``/tools/tags/``."""
    out: dict[int, tuple[str, str]] = {}
    for tag in tags:
        tid = to_int(tag.get("id"))
        if tid is None:
            continue
        name = _text(tag.get("type"))
        low = name.lower()
        if "reserv" in low:
            status = "reserved"
        elif "deprecat" in low or "decom" in low:
            status = "deprecated"
        else:
            status = "allocated"
        out[tid] = (status, name)
    if not out:
        names = {1: "Offline", 2: "Used", 3: "Reserved", 4: "DHCP"}
        out = {tid: (st, names[tid]) for tid, st in _DEFAULT_TAG_STATUS.items()}
    return out


# --------------------------------------------------------------------------- #
# Subnet / block / address.
# --------------------------------------------------------------------------- #


def _subnet_common(
    raw: dict[str, Any],
    cf_map: dict[str, tuple[str, str, list[str] | None, str]],
) -> dict[str, Any]:
    sid = to_int(raw.get("id"))
    cf = extract_custom_fields(raw, cf_map, sid)
    if truthy(raw.get("isPool")):
        cf["phpipam_is_pool"] = True
    if truthy(raw.get("isFull")):
        cf["phpipam_is_full"] = True
    return {"cf": cf, "sid": sid, "description": _text(raw.get("description"))}


def map_subnet(
    raw: dict[str, Any],
    *,
    network: IPNetwork,
    space_name: str | None,
    vlan_vid: int | None,
    cf_map: dict[str, tuple[str, str, list[str] | None, str]],
) -> ImportedSubnet:
    c = _subnet_common(raw, cf_map)
    return ImportedSubnet(
        network=str(network),
        name=c["description"],
        description=c["description"],
        space_name=space_name,
        status="active",
        vlan_vid=vlan_vid,
        kind=_multicast_kind(network),
        custom_fields=c["cf"],
        netbox_id=c["sid"],
    )


def map_block(
    raw: dict[str, Any],
    *,
    network: IPNetwork,
    space_name: str | None,
    cf_map: dict[str, tuple[str, str, list[str] | None, str]],
) -> ImportedBlock:
    c = _subnet_common(raw, cf_map)
    return ImportedBlock(
        network=str(network),
        # ``auto:`` is reserved for the committer's synthesised wrapper blocks.
        name=c["description"] or str(network),
        description=c["description"],
        space_name=space_name,
        custom_fields=c["cf"],
        netbox_id=c["sid"],
    )


def map_address(
    raw: dict[str, Any],
    *,
    subnet_cidr: str,
    space_name: str | None,
    state_map: dict[int, tuple[str, str]],
    cf_map: dict[str, tuple[str, str, list[str] | None, str]],
    mask: int | None,
) -> ImportedAddress | None:
    """phpIPAM address -> IR; ``None`` when ``ip`` is not an address."""
    ip = ip_text(raw.get("ip"), mask=mask)
    if ip is None:
        return None
    aid = to_int(raw.get("id"))
    cf = extract_custom_fields(raw, cf_map, aid)

    # The address's state id is ``tag`` on the API (``state`` on some versions).
    state_id = to_int(raw.get("tag"))
    if state_id is None:
        state_id = to_int(raw.get("state"))
    state = state_map.get(state_id) if state_id is not None else None
    status = state[0] if state else "allocated"
    if state and state[1] and state[1].lower() not in {"used", "reserved"}:
        cf["phpipam_state"] = state[1]

    owner = _text(raw.get("owner"))
    if owner:
        cf["phpipam_owner"] = owner
    mac_raw = _text(raw.get("mac"))
    mac = _clean_mac(mac_raw)
    if mac_raw and mac is None:
        # Free text that is not a MAC: keep what the operator typed.
        cf["phpipam_mac"] = mac_raw

    description = _text(raw.get("description"))
    note = _text(raw.get("note"))
    if note:
        description = f"{description}\n{note}".strip()

    hostname, fqdn = _split_dns_name(_text(raw.get("hostname")))
    return ImportedAddress(
        address=ip,
        status=status,
        role=_GATEWAY_ROLE if truthy(raw.get("is_gateway")) else None,
        hostname=hostname,
        fqdn=fqdn,
        description=description,
        subnet_cidr=subnet_cidr,
        space_name=space_name,
        mac_address=mac,
        custom_fields=cf,
        netbox_id=aid,
    )
