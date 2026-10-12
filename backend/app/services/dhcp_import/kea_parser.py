"""Kea JSON config importer (issue #129 Phase 1).

The cleanest source — a Kea ``kea-dhcp4.conf`` / ``kea-dhcp6.conf`` is
exactly the shape SpatiumDDI's own Kea driver renders, just running on
a *non-managed* daemon. We invert the driver's render path: walk the
``Dhcp4`` / ``Dhcp6`` structure and emit the canonical IR.

Pipeline:

1. Operator uploads the raw Kea config file (``.conf`` / ``.json``).
2. We strip Kea's JSON-with-comments extensions (``//`` + ``#`` line
   comments, ``/* */`` block comments — string-aware so a ``#`` inside
   an option value survives) and ``json.loads`` the result.
3. We accept either a wrapped config (top-level ``{"Dhcp4": {...}}``)
   or a bare ``Dhcp4`` body (``{"subnet4": [...]}``) — operators paste
   both.
4. Each ``subnet4`` / ``subnet6`` becomes an :class:`ImportedScope`;
   ``pools`` → :class:`ImportedPool`, ``reservations`` →
   :class:`ImportedReservation`, ``option-data`` → canonical options.
   Top-level ``client-classes`` become :class:`ImportedClientClass`.

We deliberately don't carry hook libraries (HA / host-cache /
lease-cmds), control-agent config, or the lease database across — those
are surfaced in the "didn't import" panel; the operator wires HA up
server-side post-import (SpatiumDDI's HA is implicit at the group level).
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from .canonical import (
    ImportedClientClass,
    ImportedPool,
    ImportedReservation,
    ImportedScope,
    ImportPreview,
)
from .options import coerce_option_value, kea_option_to_canonical, normalise_mac

# Hard cap on uploaded config. A Kea config with thousands of
# reservations is still well under this; 25 MB stops a pathological
# upload from blowing out memory on parse.
MAX_CONFIG_BYTES = 25 * 1024 * 1024

# Kea top-level keys we explicitly note as "not imported" when present.
_UNSUPPORTED_KEYS: dict[str, str] = {
    "hooks-libraries": "Kea hook libraries (HA / host-cache / lease-cmds) are not imported — "
    "SpatiumDDI's HA is implicit at the server-group level; configure it post-import.",
    "control-socket": "Kea control-socket config is not imported (SpatiumDDI's agent owns the "
    "control channel).",
    "lease-database": "Kea lease database config is not imported — leases are transient and "
    "repopulate from the running daemon once a server is attached.",
    "loggers": "Kea logger config is not imported.",
}


class KeaImportError(ValueError):
    """Raised when the upload itself can't be parsed as Kea JSON.

    Per-scope issues don't raise this — they land in
    ``ImportPreview.warnings`` / ``ImportedScope.parse_warnings`` so the
    operator sees partial success and can fix-and-reupload.
    """


def _strip_jsonc(text: str) -> str:
    """Strip ``//`` + ``#`` line comments and ``/* */`` block comments,
    string-aware so a comment marker inside a quoted value survives."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _split_option_value(data: str) -> Any:
    """Kea ``option-data`` ``data`` is a comma-separated string. Split
    into a list when multi-valued, keep scalar otherwise — matching how
    the Kea driver re-joins lists with ``", "``."""
    if "," in data:
        parts = [p.strip() for p in data.split(",")]
        return parts
    return data.strip()


def _parse_option_data(raw: list[dict[str, Any]] | None, *, address_family: str) -> dict[str, Any]:
    """Translate a Kea ``option-data`` list into a ``{name: value}`` map
    in SpatiumDDI's canonical vocabulary. ``code``-form options (vendor
    options with no Kea name) become ``code:NN`` keys — the same shape
    the Kea driver round-trips."""
    out: dict[str, Any] = {}
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        data = entry.get("data")
        if data is None:
            continue
        value = _split_option_value(str(data))
        if entry.get("name"):
            key = kea_option_to_canonical(str(entry["name"]), address_family=address_family)
        elif entry.get("code") is not None:
            key = f"code:{entry['code']}"
        else:
            continue
        out[key] = coerce_option_value(value)
    return out


def _parse_pool(entry: dict[str, Any]) -> ImportedPool | None:
    """Kea pool: ``{"pool": "10.0.0.10 - 10.0.0.100"}`` or
    ``{"pool": "10.0.0.0/25"}``."""
    raw = entry.get("pool")
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    if " - " in raw or " -" in raw or "- " in raw:
        start, _, end = raw.partition("-")
        start_ip, end_ip = start.strip(), end.strip()
    elif "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None
        start_ip, end_ip = str(net[0]), str(net[-1])
    else:
        # Single address pool.
        start_ip = end_ip = raw
    if not start_ip or not end_ip:
        return None
    return ImportedPool(
        start_ip=start_ip,
        end_ip=end_ip,
        pool_type="dynamic",
        class_restriction=entry.get("client-class"),
    )


def _parse_reservation(entry: dict[str, Any], *, address_family: str) -> ImportedReservation | None:
    if not isinstance(entry, dict):
        return None
    mac = normalise_mac(entry.get("hw-address"))
    if mac is None:
        # DUID-only v6 reservations have no MAC — we can't model those
        # (DHCPStaticAssignment is MAC-keyed). Caller records a warning.
        return None
    if address_family == "ipv6":
        addrs = entry.get("ip-addresses") or []
        ip = str(addrs[0]) if addrs else None
    else:
        ip = entry.get("ip-address")
    if not ip:
        return None
    return ImportedReservation(
        ip_address=str(ip),
        mac_address=mac,
        hostname=str(entry.get("hostname") or ""),
        client_id=entry.get("client-id"),
        options=_parse_option_data(entry.get("option-data"), address_family=address_family),
    )


def _parse_subnet(
    entry: dict[str, Any],
    *,
    address_family: str,
    global_options: dict[str, Any],
    global_lease_time: int,
    global_ddns: bool,
    warnings: list[str],
) -> ImportedScope | None:
    cidr = entry.get("subnet")
    if not cidr or not isinstance(cidr, str):
        warnings.append("Skipped a subnet with no 'subnet' CIDR field.")
        return None
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        warnings.append(f"Skipped subnet {cidr!r} — not a valid CIDR.")
        return None
    canonical = str(net)

    parse_warnings: list[str] = []
    pools: list[ImportedPool] = []
    for p in entry.get("pools") or []:
        if isinstance(p, dict):
            pool = _parse_pool(p)
            if pool is not None:
                pools.append(pool)

    reservations: list[ImportedReservation] = []
    skipped_duid = 0
    for r in entry.get("reservations") or []:
        res = _parse_reservation(r, address_family=address_family)
        if res is not None:
            reservations.append(res)
        elif isinstance(r, dict) and not r.get("hw-address"):
            skipped_duid += 1
    if skipped_duid:
        parse_warnings.append(
            f"{skipped_duid} DUID-only reservation(s) skipped — only MAC-keyed reservations import."
        )

    # Scope options override global option-data so the imported scope
    # behaves identically without a separate group-options surface.
    scope_options = _parse_option_data(entry.get("option-data"), address_family=address_family)
    options = {**global_options, **scope_options}

    lease_time = int(entry.get("valid-lifetime") or global_lease_time or 86400)
    min_lt = entry.get("min-valid-lifetime")
    max_lt = entry.get("max-valid-lifetime")
    ddns_enabled = bool(entry.get("ddns-send-updates", global_ddns))

    return ImportedScope(
        subnet_cidr=canonical,
        address_family=address_family,
        name=str(entry.get("comment") or ""),
        lease_time=lease_time,
        min_lease_time=int(min_lt) if min_lt is not None else None,
        max_lease_time=int(max_lt) if max_lt is not None else None,
        is_active=True,
        options=options,
        pools=pools,
        reservations=reservations,
        ddns_enabled=ddns_enabled,
        v6_address_mode="stateful",
        parse_warnings=parse_warnings,
    )


def _parse_client_classes(
    raw: list[dict[str, Any]] | None, *, address_family: str
) -> list[ImportedClientClass]:
    out: list[ImportedClientClass] = []
    for entry in raw or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            continue
        # Skip the built-in DROP class SpatiumDDI's own MAC-blocklist
        # renders — re-importing it would be noise.
        name = str(entry["name"])
        if name == "DROP":
            continue
        out.append(
            ImportedClientClass(
                name=name,
                match_expression=str(entry.get("test") or ""),
                address_family=address_family,
                options=_parse_option_data(entry.get("option-data"), address_family=address_family),
                supported=True,
            )
        )
    return out


def _merge_family_twins(classes: list[ImportedClientClass]) -> list[ImportedClientClass]:
    """One class per name across the Dhcp4 and Dhcp6 blocks (#1229).

    A class defined in both blocks under one name is how a dual-stack Kea
    config spells "this class in both daemons"; the commit keys on the name,
    so the second copy would be skipped as existing and the class would
    silently vanish from Dhcp6. Same test and no conflicting option → one
    ``dual`` class holding both option sets (``options_for_family`` routes
    each). Otherwise the twin cannot be expressed as one row, and it goes to
    manual review rather than being dropped without a word.
    """
    by_name: dict[str, ImportedClientClass] = {}
    out: list[ImportedClientClass] = []
    for cc in classes:
        twin = by_name.get(cc.name)
        if twin is None:
            by_name[cc.name] = cc
            out.append(cc)
            continue
        shared = set(twin.options) & set(cc.options)
        if twin.match_expression == cc.match_expression and all(
            twin.options[k] == cc.options[k] for k in shared
        ):
            twin.address_family = "dual"
            twin.options = {**twin.options, **cc.options}
            continue
        cc.supported = False
        cc.warning = (
            f"class '{cc.name}' is defined in both Dhcp4 and Dhcp6 with a different "
            "test or option values; SpatiumDDI holds one class per name, so the "
            f"{cc.address_family} copy needs recreating by hand"
        )
        out.append(cc)
    return out


def _dhcp_block(obj: dict[str, Any], wrapper: str, subnet_key: str) -> dict[str, Any] | None:
    """Resolve the Dhcp4 / Dhcp6 body whether the config is wrapped
    (``{"Dhcp4": {...}}``) or bare (``{"subnet4": [...]}``)."""
    if wrapper in obj and isinstance(obj[wrapper], dict):
        return obj[wrapper]
    if subnet_key in obj:
        return obj
    return None


def parse_kea_config(data: bytes) -> ImportPreview:
    """Parse an uploaded Kea config into the canonical import preview."""
    if len(data) > MAX_CONFIG_BYTES:
        raise KeaImportError(f"Upload exceeds {MAX_CONFIG_BYTES // (1024 * 1024)} MB limit")
    if not data:
        raise KeaImportError("Empty upload")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KeaImportError(f"File is not UTF-8 text: {exc}") from exc

    try:
        obj = json.loads(_strip_jsonc(text))
    except json.JSONDecodeError as exc:
        raise KeaImportError(f"Not valid Kea JSON (after comment stripping): {exc}") from exc
    if not isinstance(obj, dict):
        raise KeaImportError("Top-level Kea config must be a JSON object")

    warnings: list[str] = []
    unsupported: list[str] = []
    scopes: list[ImportedScope] = []
    client_classes: list[ImportedClientClass] = []

    for wrapper, subnet_key, af in (("Dhcp4", "subnet4", "ipv4"), ("Dhcp6", "subnet6", "ipv6")):
        block = _dhcp_block(obj, wrapper, subnet_key)
        if block is None:
            continue
        global_options = _parse_option_data(block.get("option-data"), address_family=af)
        global_lease_time = int(block.get("valid-lifetime") or 86400)
        global_ddns = bool(block.get("ddns-send-updates", False))
        if global_options:
            warnings.append(
                f"{wrapper}: {len(global_options)} global option(s) applied to every "
                f"imported {af} scope (SpatiumDDI has no group-wide option surface on import)."
            )
        for raw_subnet in block.get(subnet_key) or []:
            if not isinstance(raw_subnet, dict):
                continue
            scope = _parse_subnet(
                raw_subnet,
                address_family=af,
                global_options=global_options,
                global_lease_time=global_lease_time,
                global_ddns=global_ddns,
                warnings=warnings,
            )
            if scope is not None:
                scopes.append(scope)
        client_classes.extend(_parse_client_classes(block.get("client-classes"), address_family=af))
        for key, note in _UNSUPPORTED_KEYS.items():
            if key in block:
                unsupported.append(note)

    client_classes = _merge_family_twins(client_classes)

    if not scopes and not client_classes:
        raise KeaImportError(
            "No Dhcp4/Dhcp6 subnets or client-classes found — is this a Kea config file?"
        )

    af_hist: dict[str, int] = {}
    for s in scopes:
        af_hist[s.address_family] = af_hist.get(s.address_family, 0) + 1

    return ImportPreview(
        source="kea",
        scopes=scopes,
        client_classes=client_classes,
        conflicts=[],  # populated by the router against the target group
        warnings=warnings,
        unsupported=sorted(set(unsupported)),
        total_pools=sum(len(s.pools) for s in scopes),
        total_reservations=sum(len(s.reservations) for s in scopes),
        address_family_histogram=af_hist,
    )
