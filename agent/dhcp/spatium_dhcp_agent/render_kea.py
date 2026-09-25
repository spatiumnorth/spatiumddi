"""Neutral ConfigBundle → Kea ``Dhcp4`` + ``Dhcp6`` JSON renderer.

The control plane emits a backend-neutral ConfigBundle describing scopes,
pools, statics, client classes, reservations and global/scope-level options.
This module converts that into a Kea-specific config document carrying BOTH
a ``Dhcp4`` and a ``Dhcp6`` block (the agent runs both daemons always-on;
the ``Dhcp6`` block is an idle skeleton when no v6 scopes exist). The two
blocks are split into separate files by ``sync.py`` because ``kea-dhcp4 -t``
rejects a stray ``Dhcp6`` key (and vice-versa).

A minimal bundle looks like::

    {
        "etag": "sha256:...",
        "schema_version": 1,
        "server": {"name": "dhcp1", "interfaces": ["eth0"]},
        "global_options": {
            "dns_servers": ["1.1.1.1"],
            "ntp_servers": ["192.0.2.123"],   # rendered as DHCP option 42
            "domain_name": "example.com",
            "domain_search": ["example.com"],
            "lease_time": 3600,
        },
        "subnets": [
            {
                "id": 1,
                "subnet": "192.0.2.0/24",
                "pools": [{"pool": "192.0.2.100 - 192.0.2.200"}],
                "options": {"routers": ["192.0.2.1"], "ntp_servers": ["192.0.2.5"]},
                "reservations": [
                    {"hw_address": "aa:bb:cc:dd:ee:ff",
                     "ip_address": "192.0.2.50",
                     "hostname": "printer1"}
                ],
                "client_class": null,
                "valid_lifetime": 3600,
            }
        ],
        "client_classes": [
            {"name": "voip", "test": "substring(option[60].hex,0,12) == 'Cisco-Phone'"}
        ],
    }

NTP servers are REQUIRED to be emitted as DHCP option 42 (RFC 2132). Users
rely on clients receiving the NTP server list via DHCP.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse, urlunparse

import structlog

_log = structlog.get_logger(__name__)

# Well-known DHCPv4 option codes we emit by name when present in the bundle.
# Kea accepts ``{"name": "ntp-servers", ...}`` natively; we include explicit
# ``code`` entries for resilience against older Kea versions.
_OPTION_CODES: dict[str, int] = {
    "routers": 3,
    "domain-name-servers": 6,
    "domain-name": 15,
    "ntp-servers": 42,  # RFC 2132 § 8.3 — DO NOT OMIT
    "domain-search": 119,
}

# Map of canonical SpatiumDDI option-name → Kea Dhcp4 ``option-data`` name.
# This MUST stay in step with ``_KEA_OPTION_NAMES`` in
# ``backend/app/drivers/dhcp/kea.py`` and with ``STANDARD_OPTION_NAMES`` in
# ``backend/app/drivers/dhcp/base.py``, which is the vocabulary the bundle
# actually carries.
#
# #856: this table replaces a hand-written list of per-option ``_put(...)``
# lookups that had drifted from that vocabulary. Option 6 is stored
# canonically as ``dns-servers``, but the old code looked only for
# ``dns_servers`` / ``domain-name-servers`` and so dropped it from every
# rendered config — silently, because a missing key is indistinguishable
# from an unset option. ``routers`` survived purely because it happens to
# be spelled the same on both sides. Driving both directions off one table
# is what stops that class of bug recurring: a new option is added in one
# place or it is not supported at all.
_KEA_OPTION_NAMES_V4: dict[str, str] = {
    "routers": "routers",
    "dns-servers": "domain-name-servers",
    "domain-name": "domain-name",
    "broadcast-address": "broadcast-address",
    "ntp-servers": "ntp-servers",
    "tftp-server-name": "tftp-server-name",
    "bootfile-name": "boot-file-name",
    "tftp-server-address": "tftp-server-address",
    "domain-search": "domain-search",
    "mtu": "interface-mtu",
    "time-offset": "time-offset",
}

# Keys that legitimately appear alongside options in an options mapping but
# are NOT options — excluded from the "unsupported option dropped" warning.
# ``lease_time`` rides in ``global_options``; ``option_data`` is the raw
# pass-through list handled separately in ``_options_from_mapping``.
_NON_OPTION_KEYS: frozenset[str] = frozenset({"lease_time", "option_data"})

# Legacy input spellings accepted for backward compatibility with bundles
# from an older control plane (and with hand-written test fixtures). Values
# are canonical names in ``_KEA_OPTION_NAMES_V4``. Kea's own IANA spellings
# are accepted too, so a bundle that already speaks Kea passes through.
# Declaration order is load-bearing: two aliases of the same canonical name
# resolve in this order, so the result never depends on input dict ordering.
_LEGACY_OPTION_ALIASES_V4: dict[str, str] = {
    "dns_servers": "dns-servers",
    "domain-name-servers": "dns-servers",
    "ntp_servers": "ntp-servers",
    "gateway": "routers",
    "domain_name": "domain-name",
    "domain_search": "domain-search",
    "tftp_server": "tftp-server-name",
    "boot_file": "bootfile-name",
    "boot-file-name": "bootfile-name",
    "broadcast_address": "broadcast-address",
    "interface-mtu": "mtu",
    "time_offset": "time-offset",
    "tftp_server_address": "tftp-server-address",
}

# Options Kea has no built-in definition for, mapped to the ``option-def``
# entry that makes them loadable.
#
# Option 150 (Cisco TFTP server address) is NOT a standard Kea option:
# ``kea-dhcp4 -t`` fails the WHOLE config with "definition for the option
# 'dhcp4.tftp-server-address' does not exist", which takes DHCP down rather
# than dropping one option. Verified against Kea 3.0.3. So emitting it
# requires shipping the definition alongside it.
#
# KEYED BY THE RENDERED KEA NAME, not the canonical SpatiumDDI one, because
# that is what ``_collect_option_defs`` sees in the assembled ``option-data``.
# The two happen to be spelled identically for option 150; they are NOT for
# e.g. ``bootfile-name`` → ``boot-file-name``, and keying this table the other
# way would emit that option with no definition and fail the whole config.
_OPTION_DEFS_V4: dict[str, dict[str, Any]] = {
    "tftp-server-address": {
        "name": "tftp-server-address",
        "code": 150,
        "space": "dhcp4",
        "type": "ipv4-address",
        "array": True,
    },
}

# Map of SpatiumDDI / bundle-neutral option-name → Kea Dhcp6 ``option-data``
# name. DHCPv6 uses a different option-code space + names from v4; only
# options with a true v6 equivalent are forwarded. Mirrors
# ``_KEA_OPTION_NAMES_V6`` in ``backend/app/drivers/dhcp/kea.py``. Both the
# snake_case (``dns_servers``) and hyphenated (``dns-servers``) input keys
# the control plane may emit are accepted via the ``_put`` calls in
# ``_options_from_mapping_v6``.
_KEA_OPTION_NAMES_V6: dict[str, str] = {
    "dns-servers": "dns-servers",  # DHCPv6 option 23
    "domain-search": "domain-search",  # DHCPv6 option 24
    "ntp-servers": "sntp-servers",  # DHCPv6 option 31 (SNTP)
    "bootfile-name": "bootfile-url",  # DHCPv6 option 59 (URL form)
}

# Options that have no DHCPv6 equivalent — dropped from v6 scopes with a
# warning so a misconfigured inherited option surfaces to the operator
# instead of Kea silently rejecting the whole config on reload. Mirrors
# ``_DHCP4_ONLY_OPTION_NAMES`` in the backend driver.
_DHCP4_ONLY_OPTION_NAMES: frozenset[str] = frozenset(
    {
        "routers",
        "broadcast-address",
        "mtu",
        "time-offset",
        "domain-name",
        "tftp-server-name",
        "tftp-server-address",
    }
)


def _opt(name: str, value: Any) -> dict[str, Any]:
    """Build one Kea option-data entry."""
    if isinstance(value, list):
        data = ", ".join(str(v) for v in value)
    else:
        data = str(value)
    entry: dict[str, Any] = {"name": name, "data": data}
    if name in _OPTION_CODES:
        entry["code"] = _OPTION_CODES[name]
        entry["space"] = "dhcp4"
    return entry


def _canonicalize_v4(options: dict[str, Any]) -> dict[str, Any]:
    """Resolve legacy / Kea-native input spellings onto canonical names.

    A canonical key already present always wins over an alias resolving onto
    it, and two aliases of the SAME canonical name (``dns_servers`` and
    ``domain-name-servers``) resolve in ``_LEGACY_OPTION_ALIASES_V4``
    declaration order — so the outcome never depends on the input dict's
    ordering either way.
    """
    out: dict[str, Any] = {k: v for k, v in options.items() if k in _KEA_OPTION_NAMES_V4}
    for alias, canon in _LEGACY_OPTION_ALIASES_V4.items():
        if canon in out or alias not in options:
            continue
        out[canon] = options[alias]
    return out


def _options_from_mapping(options: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Translate bundle-neutral keys to Kea Dhcp4 ``option-data`` entries.

    Keys are the canonical SpatiumDDI option names in
    ``_KEA_OPTION_NAMES_V4``; the legacy snake_case and Kea-native spellings
    in ``_LEGACY_OPTION_ALIASES_V4`` are accepted for older bundles (#856).

    Emission order follows ``_KEA_OPTION_NAMES_V4`` rather than the caller's
    dict order, so the rendered file is byte-stable across restarts and an
    unchanged bundle never triggers a spurious config rewrite + Kea reload.
    """
    if not options:
        return []
    canon = _canonicalize_v4(options)
    out: list[dict[str, Any]] = []
    for name, kea_name in _KEA_OPTION_NAMES_V4.items():
        val = canon.get(name)
        if val in (None, "", []):
            continue
        out.append(_opt(kea_name, val))

    # #858 — options addressed by raw code (``code:NN``), which is how phone
    # profiles and the importers carry a vendor option with no canonical name.
    # Emitted in Kea's ``{"code": NN}`` form, mirroring ``_render_option_data``
    # in the backend driver. Kea types an unknown code as BINARY, so a string
    # value only loads when the bundle also ships an ``option-def`` for it —
    # the control plane resolves those (it owns the option catalogues) and
    # ``render()`` emits them; see ``_option_defs_from_bundle``.
    for key, val in options.items():
        if not key.startswith("code:"):
            continue
        try:
            code_int = int(key[5:])
        except ValueError:
            _log.warning("kea_option_bad_code_key", option=key)
            continue
        data = ", ".join(str(x) for x in val) if isinstance(val, list) else str(val)
        out.append({"code": code_int, "data": data})

    # Anything else outside the table is still dropped — emitting an option
    # name Kea has no definition for fails the WHOLE config, which is worse
    # than not serving it. But drop it LOUDLY: #856 was invisible precisely
    # because a dropped key looks identical to an unset option.
    for key in options:
        if key in _NON_OPTION_KEYS or key in _KEA_OPTION_NAMES_V4:
            continue
        if key in _LEGACY_OPTION_ALIASES_V4 or key.startswith("code:"):
            continue
        _log.warning("kea_option_dropped_unsupported", option=key)

    # Pass through any raw Kea-style list already shaped correctly.
    raw = options.get("option_data")
    if isinstance(raw, list):
        out.extend(raw)
    return out


def _strip_undefined_code_options(node: Any, defined_codes: set[int]) -> None:
    """Remove ``{"code": NN}`` option-data entries with no matching definition.

    Mutates in place, walking the same structures ``_collect_option_defs``
    does so subnet / pool / reservation / client-class / global option-data are
    all covered. Emitting an undefined code fails the entire config, so this is
    the guard that keeps a stray vendor option from taking DHCP down.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if key == "option-data" and isinstance(val, list):
                kept = []
                for entry in val:
                    code = entry.get("code") if isinstance(entry, dict) else None
                    # Entries carrying a name are Kea built-ins, already safe.
                    if (
                        isinstance(code, int)
                        and not (isinstance(entry, dict) and entry.get("name"))
                        and code not in defined_codes
                    ):
                        _log.warning("kea_option_dropped_no_definition", code=code)
                        continue
                    kept.append(entry)
                node[key] = kept
            else:
                _strip_undefined_code_options(val, defined_codes)
    elif isinstance(node, list):
        for item in node:
            _strip_undefined_code_options(item, defined_codes)


def _collect_option_defs(dhcp4: dict[str, Any]) -> list[dict[str, Any]]:
    """``option-def`` entries required by whatever the render actually emitted.

    Kea rejects the ENTIRE config for an option it has no definition for, so
    a non-standard option must ship its definition or not be emitted at all.

    This walks the assembled ``Dhcp4`` block rather than each options mapping
    on the way in, so it cannot miss a source: subnet, pool, reservation,
    client-class and global option-data are all covered by construction, as
    is anything a future caller adds.
    """
    seen: set[str] = set()

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if key == "option-data" and isinstance(val, list):
                    for entry in val:
                        if isinstance(entry, dict):
                            name = entry.get("name")
                            if isinstance(name, str) and name in _OPTION_DEFS_V4:
                                seen.add(name)
                else:
                    _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(dhcp4)
    # Stable order, keyed off ``_OPTION_DEFS_V4`` (Kea names, same namespace
    # as ``seen``) rather than set iteration.
    return [d for n, d in _OPTION_DEFS_V4.items() if n in seen]


def _options_from_mapping_v6(options: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Translate bundle-neutral option keys into Kea ``Dhcp6`` option-data.

    DHCPv6 has a separate option-code space and a different set of names
    from v4 — see ``_KEA_OPTION_NAMES_V6``. v4-only options (routers,
    domain-name, mtu, …) have no v6 analogue and are dropped with a
    warning rather than emitted under the wrong space (which would make
    Kea reject the config on reload). Mirrors ``_render_option_data(
    address_family="ipv6")`` in the backend driver.

    Both snake_case and hyphenated input keys are accepted, matching the
    v4 ``_options_from_mapping`` behaviour.
    """
    if not options:
        return []
    out: list[dict[str, Any]] = []

    def _put(key: str, val: Any) -> None:
        if val in (None, "", []):
            return
        if isinstance(val, list):
            data = ", ".join(str(v) for v in val)
        else:
            data = str(val)
        out.append({"name": _KEA_OPTION_NAMES_V6[key], "data": data})

    _put("dns-servers", options.get("dns_servers") or options.get("dns-servers"))
    _put("domain-search", options.get("domain_search") or options.get("domain-search"))
    _put("ntp-servers", options.get("ntp_servers") or options.get("ntp-servers"))
    _put("bootfile-name", options.get("boot_file") or options.get("bootfile-name"))

    # Warn on any v4-only option the operator inherited onto a v6 scope so
    # the misconfig is visible — the option is simply not emitted.
    for k in options:
        normalized = k.replace("_", "-")
        if normalized in _DHCP4_ONLY_OPTION_NAMES:
            _log.warning("kea_option_skipped_v6_no_equivalent", option=k)
        elif k.startswith("code:"):
            # #858 — raw-code options are v4-only here. The definitions the
            # control plane ships declare ``space: dhcp4``, so emitting the
            # code under Dhcp6 would reference a definition that does not
            # exist in that space and fail the whole config. Dropped, but
            # loudly: the silent version of this is the bug #858 exists to fix.
            _log.warning("kea_option_skipped_v6_raw_code", option=k)

    # Pass through any raw Kea-style list already shaped correctly.
    raw = options.get("option_data")
    if isinstance(raw, list):
        out.extend(raw)
    return out


def _reservation_v6(res: dict[str, Any]) -> dict[str, Any]:
    """Render a single Dhcp6 host reservation.

    Dhcp6 reservations use ``ip-addresses`` (plural list) rather than the
    v4 ``ip-address`` scalar. Mirrors ``_render_reservation(
    address_family="ipv6")`` in the backend driver.
    """
    out: dict[str, Any] = {}
    # DHCPv6 clients are identified by DUID (issue #368): when a duid is set we
    # key the reservation on it and drop hw-address, mirroring the backend
    # driver. Otherwise fall back to hw-address (matched via the subnet's
    # host-reservation-identifiers).
    if res.get("duid"):
        out["duid"] = res["duid"]
    else:
        raw_hw = res.get("hw_address") or res.get("mac")
        if raw_hw:
            # Same canonicalization as the v4 path (#476): a non-canonical MAC
            # emitted verbatim makes Kea reject the whole subnet6 on reload.
            # Drop an invalid MAC rather than emit it malformed.
            norm = _normalize_mac_for_kea(str(raw_hw))
            if norm is not None:
                out["hw-address"] = norm
    addr = res.get("ip_address") or res.get("ip")
    if addr:
        out["ip-addresses"] = [addr]
    if res.get("hostname"):
        out["hostname"] = res["hostname"]
    opts = _options_from_mapping_v6(res.get("options"))
    if opts:
        out["option-data"] = opts
    return out


def _pxe_class(p: dict[str, Any]) -> dict[str, Any]:
    """Render a PXE / iPXE client class (#51) — Dhcp4 only.

    Mirrors ``_render_pxe_class`` in ``backend/app/drivers/dhcp/kea.py``.
    ``next-server`` + ``boot-file-name`` on the class win over scope-level
    defaults when Kea matches the packet, which is what lets one scope serve
    a different boot binary per architecture. An empty ``match_expression``
    means "always match" — a low-priority fallthrough — so the key is omitted
    rather than emitted empty, which Kea would reject.
    """
    out: dict[str, Any] = {
        "name": p["name"],
        "boot-file-name": p.get("boot_file_name") or "",
    }
    # ``next-server`` must be an IPv4 literal — Kea rejects the WHOLE config on
    # a hostname or a typo, and the control plane only checks the field is a
    # non-empty string. Omitting it falls back to the scope / global value,
    # which is a served lease with a wrong boot server rather than no DHCP.
    next_server = (p.get("next_server") or "").strip()
    if next_server:
        try:
            ipaddress.IPv4Address(next_server)
        except ValueError:
            _log.warning(
                "kea_pxe_next_server_invalid", pxe_class=p.get("name"), value=next_server
            )
        else:
            out["next-server"] = next_server
    if p.get("match_expression"):
        out["test"] = p["match_expression"]
    return out


def _phone_class(c: dict[str, Any]) -> dict[str, Any]:
    """Render a VoIP phone-profile client class.

    Mirrors ``_render_phone_class`` in the backend driver. Vendor options Kea
    does not know by name ride as ``code:NN`` keys, which
    ``_options_from_mapping`` emits in ``{"code": NN}`` form.
    """
    out: dict[str, Any] = {"name": c["name"]}
    if c.get("match_expression"):
        out["test"] = c["match_expression"]
    opts = _options_from_mapping(c.get("options"))
    if opts:
        out["option-data"] = opts
    return out


def _device_policy_class(c: dict[str, Any]) -> dict[str, Any] | None:
    """Render a fingerprint-driven device-policy class (#700).

    Mirrors ``_render_device_policy_class`` in ``backend/app/drivers/dhcp/kea.py``.

    **Dhcp4 only, by construction.** The compiled expressions test options
    55 and 60, which are DHCPv4 option codes; under Dhcp6 those numbers
    address entirely different options (and the v6 equivalents are the ORO
    and vendor-class, options 6 and 16). The v6 branch below builds its
    class list from the generic ``client_classes`` alone, so nothing here
    reaches it — same as the v4-only DROP class, and same as the backend
    driver.

    Returns ``None`` — rather than a class with no ``test`` — when the
    expression is missing. The control plane already drops these, so
    reaching here means a hand-crafted or truncated bundle; a testless Kea
    class matches every packet, which would hand this policy's option set
    and lease time to the whole network. Failing closed is the only safe
    reading of a malformed device policy.
    """
    expr = c.get("match_expression") or c.get("test")
    if not expr:
        _log.warning("kea_device_policy_class_no_test", policy_class=c.get("name"))
        return None
    out: dict[str, Any] = {"name": c["name"], "test": expr}
    lease_time = c.get("lease_time")
    if lease_time is not None:
        out["valid-lifetime"] = lease_time
    opts = _options_from_mapping(c.get("options"))
    if opts:
        out["option-data"] = opts
    return out


def _dynamic_pool(p: dict[str, Any], *, address_family: str) -> dict[str, Any]:
    """Render one dynamic address pool, with its per-pool option overrides.

    #858 — ``options_override`` is settable, ETag-hashed and rendered by the
    control-plane driver, but the wire bundle never carried it and this
    renderer never read it, so a per-pool option could not reach Kea at all.
    Mirrors ``_render_pool`` in ``backend/app/drivers/dhcp/kea.py``.

    ``class_restriction`` rides along for the same reason: the backend driver
    emits it as Kea's ``client-class``, scoping the pool to one class.
    """
    out: dict[str, Any] = {"pool": f"{p['start_ip']} - {p['end_ip']}"}
    if p.get("class_restriction"):
        out["client-class"] = p["class_restriction"]
    opts = (
        _options_from_mapping_v6(p.get("options_override"))
        if address_family == "ipv6"
        else _options_from_mapping(p.get("options_override"))
    )
    if opts:
        out["option-data"] = opts
    return out


def _pd_pool_v6(p: dict[str, Any]) -> dict[str, Any] | None:
    """Render a DHCPv6 prefix-delegation pool dict (issue #368).

    Mirrors the backend driver's ``_render_pd_pool``. Returns ``None`` on a
    malformed row so one bad pool can't fail the whole render.
    """
    pd_prefix = p.get("pd_prefix")
    delegated = p.get("delegated_length")
    if not pd_prefix or not delegated:
        return None
    try:
        net = ipaddress.ip_network(pd_prefix, strict=False)
    except ValueError:
        return None
    out: dict[str, Any] = {
        "prefix": str(net.network_address),
        "prefix-len": net.prefixlen,
        "delegated-len": int(delegated),
    }
    excluded = p.get("excluded_prefix")
    if excluded:
        try:
            ex = ipaddress.ip_network(excluded, strict=False)
            out["excluded-prefix"] = str(ex.network_address)
            out["excluded-prefix-len"] = ex.prefixlen
        except ValueError:
            # Malformed excluded-prefix: render the pd-pool without it rather
            # than dropping the pool. The control plane validates it on create/
            # update, so this is defensive against an unexpected wire value.
            _log.warning("dhcp_pd_excluded_prefix_invalid", value=excluded)
    if p.get("class_restriction"):
        out["client-class"] = p["class_restriction"]
    return out


def _apply_lease_cache(out: dict[str, Any], scope: dict[str, Any]) -> None:
    """Emit Kea's ``cache-threshold`` / ``cache-max-age`` on a rendered subnet.

    Issue #637. Kea 3.0 enables lease caching by default (``cache-threshold``
    0.25): a client re-requesting a lease with >75% of its lifetime left gets
    the same lease back with an unchanged expiry and NO lease-database write.
    That silently starves SpatiumDDI's lease pipeline, which is driven by
    memfile CSV writes (leases.py tails the file → lease-events → DDNS + the
    IPAM lease mirror), so the control plane renders an explicit value rather
    than inheriting Kea's default.

    ``None`` means "inherit the group". Nothing resolves that here: the key is
    simply OMITTED from the subnet, and Kea itself falls back to the
    ``cache-threshold`` / ``cache-max-age`` emitted on the ``Dhcp4`` / ``Dhcp6``
    root. Do not "fix" this by coalescing None to the group value at the call
    site — the absence of the key IS the inheritance mechanism.

    **0.0 is a real value** (caching explicitly disabled — the pre-3.0
    behaviour), so this guards on ``is not None``; a truthiness check would drop
    it and the subnet would silently inherit the group's threshold instead.
    """
    threshold = scope.get("lease_cache_threshold")
    if threshold is not None:
        out["cache-threshold"] = float(threshold)
    max_age = scope.get("lease_cache_max_age")
    if max_age is not None:
        out["cache-max-age"] = int(max_age)


def _scope_to_subnet6(scope: dict[str, Any]) -> dict[str, Any]:
    """Translate a wire-shape v6 ScopeDef dict into a Kea ``subnet6`` entry.

    Mirrors the backend driver's ``_render_scope`` for ``address_family
    == "ipv6"``: the ``v6_address_mode`` discriminator gates what Kea
    serves —

      * ``stateful``  → address pools + option-data
      * ``stateless`` → no pools, option-data only (Information-Request)
      * ``slaac``     → no pools, no option-data (the router's RA does it)

    Wire shape (from ``backend/app/api/v1/dhcp/agents.py``):
      {subnet_cidr, lease_time, options, address_family, v6_address_mode,
       pools:[{start_ip,end_ip,pool_type}],
       statics:[{ip_address,mac_address,hostname}], ddns_enabled}
    """
    cidr = scope["subnet_cidr"]
    mode = scope.get("v6_address_mode") or "stateful"
    serve_addresses = mode == "stateful"
    serve_options = mode in ("stateful", "stateless")

    out: dict[str, Any] = {
        "id": _stable_subnet_id(cidr),
        "subnet": cidr,
    }
    # Only dynamic pools become Kea lease pools; excluded/reserved ranges
    # are IPAM-level bookkeeping. SLAAC / stateless subnets serve no pools.
    if serve_addresses:
        dyn = [
            p
            for p in (scope.get("pools") or [])
            if (p.get("pool_type") or "dynamic") == "dynamic"
        ]
        if dyn:
            out["pools"] = [_dynamic_pool(p, address_family="ipv6") for p in dyn]
        # Prefix-delegation pools (issue #368) — drop malformed rows.
        pd = [
            p
            for p in (scope.get("pools") or [])
            if (p.get("pool_type") or "dynamic") == "pd"
        ]
        if pd:
            rendered_pd = [r for r in (_pd_pool_v6(p) for p in pd) if r is not None]
            if rendered_pd:
                out["pd-pools"] = rendered_pd
    if serve_options:
        opts = _options_from_mapping_v6(scope.get("options"))
        if opts:
            out["option-data"] = opts
    # A pure-SLAAC subnet has no DHCP role, so host reservations (which
    # assign addresses / host-specific options) are dropped too.
    if serve_addresses or serve_options:
        resv = [
            _reservation_v6(
                {
                    "ip_address": s["ip_address"],
                    "hw_address": s["mac_address"],
                    "duid": s.get("duid"),
                    "hostname": s.get("hostname") or "",
                    "options": s.get("options_override"),
                }
            )
            for s in (scope.get("statics") or [])
        ]
        if resv:
            out["reservations"] = resv
    if scope.get("lease_time"):
        out["valid-lifetime"] = int(scope["lease_time"])
    # #430 — honour the per-scope min/max lease bounds (Kea clamps the
    # client-requested lease into [min, max]). Omitted → Kea defaults.
    if scope.get("min_lease_time"):
        out["min-valid-lifetime"] = int(scope["min_lease_time"])
    if scope.get("max_lease_time"):
        out["max-valid-lifetime"] = int(scope["max_lease_time"])
    _apply_lease_cache(out, scope)
    relay = scope.get("relay_addresses")
    if relay:
        out["relay"] = {"ip-addresses": list(relay)}
    return out


def _normalize_mac_for_kea(raw: str) -> str | None:
    """Return a normalized colon-separated lowercase MAC, or None if invalid.

    Kea's ``hexstring(pkt4.mac, ':')`` yields a lowercase colon-separated
    form — we must match that exactly. We accept operator input in the
    common variants (``AA-BB-CC-DD-EE-FF``, ``aabbccddeeff``, etc.) and
    coerce to the canonical shape. Anything that doesn't yield exactly
    12 hex chars is dropped with a warning rather than emitted malformed
    — a single bad row shouldn't take the whole Kea config down.
    """
    cleaned = "".join(ch for ch in raw.lower() if ch in "0123456789abcdef")
    if len(cleaned) != 12:
        _log.warning("drop_mac_invalid", raw=raw)
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _build_drop_expression(mac_blocks: list[dict[str, Any]]) -> str:
    """Build a Kea client-class ``test`` expression for the DROP list.

    Returns ``""`` when the list is empty — caller skips DROP rendering
    entirely in that case. We use ``hexstring(pkt4.mac, ':') == '...'``
    per MAC and OR them together. Kea has no upper limit on expression
    length in practice; at ~70 chars per clause a 10k-entry blocklist
    is ~700KB which Kea handles (validated against 2.6).
    """
    norms: list[str] = []
    for entry in mac_blocks:
        mac = entry.get("mac_address") if isinstance(entry, dict) else None
        if not mac:
            continue
        n = _normalize_mac_for_kea(str(mac))
        if n is not None:
            norms.append(n)
    if not norms:
        return ""
    return " or ".join(f"hexstring(pkt4.mac, ':') == '{m}'" for m in norms)


def _reservation(res: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    raw_hw = res.get("hw_address") or res.get("mac")
    if raw_hw:
        # Canonicalize to Kea's lowercase colon form. A reservation MAC
        # entered non-canonically (Cisco-dotted ``aabb.ccdd.eeff`` or
        # run-together ``aabbccddeeff``) would otherwise be emitted verbatim
        # and make Kea REJECT the whole ``subnet4`` on reload, or silently
        # fail to match the client on-wire (#476). Same normalization the
        # DROP-class path already uses. An invalid MAC is dropped with a
        # warning rather than emitted malformed — leaving the reservation to
        # match on client-id / duid if present, instead of tanking the config.
        norm = _normalize_mac_for_kea(str(raw_hw))
        if norm is not None:
            out["hw-address"] = norm
    # Guard on a truthy value, not key presence: the wire ScopeDef path
    # (``_scope_to_subnet``) always injects ``client_id`` (``None`` when the
    # static has none), and emitting ``"client-id": null`` makes kea-dhcp4
    # REJECT the whole config on reload ("unexpected null, expecting constant
    # string" — issue #537). Mirrors the backend driver's ``if s.client_id``.
    if res.get("client_id"):
        out["client-id"] = res["client_id"]
    if res.get("duid"):
        out["duid"] = res["duid"]
    if "ip_address" in res or "ip" in res:
        out["ip-address"] = res.get("ip_address") or res.get("ip")
    if res.get("hostname"):
        out["hostname"] = res["hostname"]
    opts = _options_from_mapping(res.get("options"))
    if opts:
        out["option-data"] = opts
    if res.get("client_classes"):
        out["client-classes"] = list(res["client_classes"])
    return out


def _subnet(subnet: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": int(subnet["id"]),
        "subnet": subnet["subnet"],
    }
    pools = subnet.get("pools") or []
    if pools:
        out["pools"] = [
            {"pool": p["pool"]} if isinstance(p, dict) else {"pool": str(p)}
            for p in pools
        ]
    opts = _options_from_mapping(subnet.get("options"))
    if opts:
        out["option-data"] = opts
    resv = [_reservation(r) for r in (subnet.get("reservations") or [])]
    if resv:
        out["reservations"] = resv
    if subnet.get("valid_lifetime"):
        out["valid-lifetime"] = int(subnet["valid_lifetime"])
    if subnet.get("renew_timer"):
        out["renew-timer"] = int(subnet["renew_timer"])
    if subnet.get("rebind_timer"):
        out["rebind-timer"] = int(subnet["rebind_timer"])
    if subnet.get("client_class"):
        out["client-class"] = subnet["client_class"]
    if subnet.get("require_client_classes"):
        out["require-client-classes"] = list(subnet["require_client_classes"])
    if subnet.get("interface"):
        out["interface"] = subnet["interface"]
    if subnet.get("relay_ips"):
        out["relay"] = {"ip-addresses": list(subnet["relay_ips"])}
    return out


def _stable_subnet_id(cidr: str) -> int:
    """Derive a deterministic Kea subnet-id from the CIDR.

    Kea tracks leases by subnet-id and loses them if the id changes
    between renders. The control-plane wire format carries no numeric
    id, so we hash the CIDR into a stable uint32. Never zero (Kea
    treats 0 as "unassigned").
    """
    digest = hashlib.sha256(cidr.encode("utf-8")).digest()
    n = int.from_bytes(digest[:4], "big")
    return n or 1


def _scope_to_subnet(scope: dict[str, Any]) -> dict[str, Any]:
    """Translate a wire-shape ScopeDef dict into a Kea subnet4 entry.

    Wire shape (from ``backend/app/api/v1/dhcp/agents.py``):
      {subnet_cidr, lease_time, options, pools:[{start_ip,end_ip,pool_type}],
       statics:[{ip_address,mac_address,hostname}], ddns_enabled}
    """
    cidr = scope["subnet_cidr"]
    out: dict[str, Any] = {
        "id": _stable_subnet_id(cidr),
        "subnet": cidr,
    }
    # Only dynamic pools are Kea lease pools; excluded/reserved ranges
    # are IPAM-level bookkeeping and must NOT be offered as pools.
    dyn = [
        p
        for p in (scope.get("pools") or [])
        if (p.get("pool_type") or "dynamic") == "dynamic"
    ]
    if dyn:
        out["pools"] = [_dynamic_pool(p, address_family="ipv4") for p in dyn]
    opts = _options_from_mapping(scope.get("options"))
    if opts:
        out["option-data"] = opts
    resv = [
        _reservation(
            {
                "ip_address": s["ip_address"],
                "hw_address": s["mac_address"],
                "hostname": s.get("hostname") or "",
                "client_id": s.get("client_id"),
                "options": s.get("options_override"),
            }
        )
        for s in (scope.get("statics") or [])
    ]
    if resv:
        out["reservations"] = resv
    if scope.get("lease_time"):
        out["valid-lifetime"] = int(scope["lease_time"])
    # #430 — honour the per-scope min/max lease bounds (Kea clamps the
    # client-requested lease into [min, max]). Omitted → Kea defaults.
    if scope.get("min_lease_time"):
        out["min-valid-lifetime"] = int(scope["min_lease_time"])
    if scope.get("max_lease_time"):
        out["max-valid-lifetime"] = int(scope["max_lease_time"])
    _apply_lease_cache(out, scope)
    # Relay-agent matching (issue #337) — Kea selects this subnet for
    # packets whose giaddr is one of these relay IPs. Required for
    # subnets not directly attached to a centralized server.
    relay = scope.get("relay_addresses")
    if relay:
        out["relay"] = {"ip-addresses": list(relay)}
    return out


def _resolve_peer_url(url: str) -> str:
    """Kea's HA hook parses peer URLs with Boost asio directly, so
    ``url`` must resolve to a literal IP address — hostnames aren't
    looked up by Kea itself. We resolve agent-side via the container's
    resolver (Docker DNS on compose, k8s DNS on Kubernetes) so operator-
    friendly hostnames like ``http://dhcp-kea-2:8000/`` keep working.

    Already-IP hosts are passed through unchanged. Resolution failures
    return the original URL so Kea surfaces a readable error instead of
    us silently swallowing a misconfig.
    """
    if not url:
        return url
    try:
        p = urlparse(url)
        host = p.hostname
        if not host:
            return url
        # Already a valid IPv4/IPv6 literal — nothing to do.
        try:
            ipaddress.ip_address(host)
            return url
        except ValueError:
            pass
        ip = socket.gethostbyname(host)
        port_part = f":{p.port}" if p.port else ""
        netloc = f"{ip}{port_part}"
        resolved = urlunparse(
            (p.scheme, netloc, p.path or "/", p.params, p.query, p.fragment)
        )
        _log.info("ha_peer_url_resolved", hostname=host, ip=ip, url=resolved)
        return resolved
    except (OSError, ValueError) as exc:
        _log.warning("ha_peer_url_resolve_failed", url=url, error=str(exc))
        return url


# #980 — see the ``multi-threading`` block in _ha_hook for why the HA hook's
# HTTP pools are pinned rather than left to follow the packet-worker pool.
_HA_HTTP_THREADS = 4


def _ha_hook(failover: dict[str, Any]) -> dict[str, Any]:
    """Render the ``libdhcp_ha.so`` hook entry from a failover payload.

    Shape mirrors Kea's HA hook reference (ARM §14.3): the hook takes
    a ``parameters`` dict that in turn contains a ``high-availability``
    list with one entry per relationship. Each entry has
    ``this-server-name``, ``mode``, a ``peers`` array, and heartbeat
    tuning.
    """
    peers = [
        {
            "name": p["name"],
            "url": _resolve_peer_url(p["url"]),
            "role": p["role"],
            "auto-failover": bool(p.get("auto-failover", True)),
        }
        for p in failover["peers"]
    ]
    relationship = {
        # #980 — pin the HA hook's OWN thread pools.
        #
        # ``http-listener-threads`` / ``http-client-threads`` default to 0,
        # which Kea reads as "same as the core ``thread-pool-size``" — NOT as
        # an independent auto-size. Verified by counting OS threads on
        # kea-dhcp4 3.0.3 with the HA hook loaded: pool=1 gave 8 threads and
        # pool=8 gave 29, a delta of 21 for a pool delta of 7, i.e. three
        # pools of N. So #980's drop of the packet-worker pool to 1 would
        # also have taken HA's peer HTTP concurrency to 1, serialising lease
        # updates to the partner — an unmeasured side effect on a code path
        # #980 never tested, in exactly the device-rush conditions it is
        # about.
        #
        # 4 is a decoupling constant, not a tuned one: the point is that the
        # packet-path fix must not silently change HA's concurrency, and the
        # HA threads do short LAN HTTP POSTs that never contend for the
        # receive thread the pool size exists to protect. With this block the
        # same measurement gives 14 threads at pool=1 and 21 at pool=8 — a
        # delta of exactly the core pool.
        "multi-threading": {
            "enable-multi-threading": True,
            "http-dedicated-listener": True,
            "http-listener-threads": _HA_HTTP_THREADS,
            "http-client-threads": _HA_HTTP_THREADS,
        },
        "this-server-name": failover["this_server_name"],
        "mode": failover["mode"],
        "heartbeat-delay": int(failover.get("heartbeat_delay_ms", 10000)),
        "max-response-delay": int(failover.get("max_response_delay_ms", 60000)),
        "max-ack-delay": int(failover.get("max_ack_delay_ms", 10000)),
        "max-unacked-clients": int(failover.get("max_unacked_clients", 5)),
        "peers": peers,
    }
    return {
        "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
        "parameters": {"high-availability": [relationship]},
    }


def _log_outputs(daemon: str) -> list[dict[str, Any]]:
    """The two appenders every Kea logger in this config writes to.

    Two outputs by design:
      * stdout — picked up by ``docker logs`` for the existing operator
        workflow.
      * file — tailed by ``LogShipper`` and shipped to the control plane for
        the Logs UI's "DHCP Activity" tab. Kea rotates the file in-process
        via ``maxsize`` / ``maxver`` so we don't need external logrotate.

    Shared by the Dhcp4 and Dhcp6 root loggers so the path is defined once.
    The #980 ``.packets`` override deliberately does NOT use this — it
    inherits instead, so there is only ever one appender per file.
    """
    return [
        {"output": "stdout"},
        {
            "output": f"/var/log/kea/{daemon}.log",
            "maxsize": 50_000_000,
            "maxver": 5,
            "flush": True,
        },
    ]


def _quiet_packet_logger(daemon: str, server: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``kea-dhcpN.packets`` override, or nothing (#980).

    Kea writes four INFO lines per transaction. Two of them —
    ``DHCP4_PACKET_RECEIVED`` and ``DHCP4_PACKET_SEND``, both from the
    ``.packets`` child logger — restate a transaction the ``.dhcp4`` and
    ``.leases`` lines already record, adding the source address and the
    receiving interface. Raising just that child to WARN measured 1.30x more
    packets served on a CPU-constrained node (24,997-26,077 against
    19,026-20,403 at 0.25 CPU and 12,000 offered pkt/s).

    Only that one child. ``kea-dhcpN.dhcpN`` is the obvious-looking second
    candidate and it also carries ``DHCP4_OPEN_SOCKETS_FAILED`` — a genuine
    failure Kea logs at INFO — plus ``DHCP4_CONFIG_COMPLETE``,
    ``DHCP4_STARTED`` and ``DHCP4_MULTI_THREADING_INFO``, which is the line
    that reports whether the #980 pool size took effect. Silencing it would
    trade a diagnosis for a throughput number.

    Absent from the bundle means True — an older control plane's bundle must
    keep the logging its operator can see today.

    **No ``output_options``, deliberately.** A child logger configured with
    only a severity inherits the parent's appenders — verified against
    kea-dhcp4 3.0.3: with the child at DEBUG and no outputs of its own, every
    ``DHCP4_PACKET_RECEIVED`` still reached both stdout and the shipped file,
    and at WARN none did while the parent's INFO lines kept flowing. Giving
    it a copy of the parent's appenders also works, but puts a SECOND
    RollingFileAppender on ``/var/log/kea/<daemon>.log`` with its own
    independent rotation state: at the 50 MB threshold one appender renames
    the file while the other still holds the old descriptor, so lines land in
    the rotated copy and the next rotation clobbers it. Inheriting avoids
    that for free.
    """
    if server.get("kea_packet_logging", True):
        return []
    return [{"name": f"{daemon}.packets", "severity": "WARN"}]


def _multi_threading(server: dict[str, Any]) -> dict[str, Any]:
    """Render Kea's ``multi-threading`` block from the bundle (#980).

    Kea leaves ``thread-pool-size`` at 0, meaning "one worker per CPU the
    machine reports" — ``hardware_concurrency()``, which knows nothing about
    the cgroup quota or weight the container is actually held to. Those
    workers then compete, inside that one cgroup, with the single thread that
    has to drain the receive socket, and when it is late the kernel drops
    datagrams before Kea can see them. That loss is invisible to every
    counter Kea keeps: measured on kea-dhcp4 3.0.3, a run that lost 9,700
    datagrams that way reported ``pkt4-receive-drop`` 0 throughout.

    Fewer workers measured strictly better at every CPU allocation tried
    (12,000 relayed pkt/s, memfile, median of 4; packets served): at 0.25
    CPU 19,381 for one worker against 11,119 for two and 6,723 for four; with
    four CPUs and no quota, 93,717 / 73,089 / 55,957. Hence the control
    plane's default of 1.

    ``enable-multi-threading`` stays **true** even at a pool of one, so this
    is a resize and not a mode change: the receive thread remains separate
    from the worker (with MT off, one thread must do both, which measured
    15,170 socket drops in a run where a pool of one measured none), and
    host-reservation lookup order and the disabling of ``dhcp-queue-control``
    are unchanged.

    A bundle from a control plane older than #980 carries no value; 1 is
    assumed rather than Kea's 0, because "the field is absent" and "the
    operator asked for auto-sizing" must not render the same way — the whole
    point is that auto is the wrong answer here. An explicit 0 IS honoured
    and hands sizing back to Kea.
    """
    size = server.get("kea_thread_pool_size")
    return {
        "enable-multi-threading": True,
        "thread-pool-size": 1 if size is None else int(size),
    }


def _v6_interfaces(
    interfaces: list[str] | tuple[str, ...], unicast: list[tuple[str, str]] | None
) -> list[str]:
    """The bundle's interface list plus ``"<iface>/<address>"`` entries.

    Additive: Kea keeps every socket the plain entries open and adds a
    unicast one per ``iface/addr``. With an explicit interface list rather
    than ``"*"``, only addresses on the listed interfaces are added — an
    entry for an unlisted interface would widen what Kea serves.
    """
    out = list(interfaces)
    wildcard = "*" in out
    for ifname, addr in unicast or []:
        if not wildcard and ifname not in out:
            continue
        entry = f"{ifname}/{addr}"
        if entry not in out:
            out.append(entry)
    return out


def render(
    bundle: dict[str, Any],
    *,
    control_socket: str = "/run/kea/kea4-ctrl-socket",
    lease_file: str = "/var/lib/kea/kea-leases4.csv",
    control_socket_v6: str | None = None,
    lease_file_v6: str | None = None,
    v6_unicast: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Render a ConfigBundle into a Kea config document.

    Always returns BOTH a ``{"Dhcp4": {...}}`` and a ``{"Dhcp6": {...}}``
    block — the agent container runs kea-dhcp4 AND kea-dhcp6 always-on
    (dual-stack). When the bundle carries no ``address_family == "ipv6"``
    scope the Dhcp6 block is an idle skeleton (empty ``subnet6``, no
    option-data / client-classes) that binds nothing; when v6 scopes are
    present they render into ``subnet6``. Each daemon is a separate Kea
    process with its own control socket + lease store. This mirrors the
    v4/v6 split in ``backend/app/drivers/dhcp/kea.py``.

    NOTE: the two blocks MUST be written to SEPARATE config files —
    ``kea-dhcp4 -t`` rejects a document containing a stray ``Dhcp6`` key
    (and vice-versa). ``sync.py`` splits this combined return into
    ``kea-dhcp4.conf`` (Dhcp4 only) and ``kea-dhcp6.conf`` (Dhcp6 only).

    ``control_socket_v6`` / ``lease_file_v6`` default to the v4 paths with
    the ``4`` swapped for ``6`` (``kea4-ctrl-socket`` → ``kea6-ctrl-socket``,
    ``kea-leases4.csv`` → ``kea-leases6.csv``) so the v6 daemon never
    collides with the v4 daemon's socket / lease store.

    ``v6_unicast`` is the host's bindable global IPv6 addresses
    (``v6_unicast.global_ipv6_addresses``). With v6 scopes present each one
    becomes an ``"<iface>/<address>"`` entry beside the bundle's interfaces,
    so kea-dhcp6 opens the unicast socket a relay's Relay-Forward is sent to
    (#1140). Passed in rather than read here so the render stays a pure
    function of its arguments.
    """
    server = bundle.get("server", {}) or {}
    interfaces = server.get("interfaces") or ["*"]

    dhcp4: dict[str, Any] = {
        "interfaces-config": {
            "interfaces": list(interfaces),
            # Issue #365 — default to ``raw`` (AF_PACKET) so Kea hears
            # broadcast DISCOVERs from directly-attached clients. The
            # control plane sends the resolved value (``raw`` for group
            # socket_mode "direct", ``udp`` for "relay"); the ``raw``
            # fallback only applies to bundles from an older control plane
            # that predates the ``server`` block. ``raw`` needs CAP_NET_RAW
            # (granted on the appliance DaemonSet + compose Kea services).
            "dhcp-socket-type": server.get("dhcp_socket_type", "raw"),
        },
        "control-socket": {
            "socket-type": "unix",
            "socket-name": control_socket,
        },
        "lease-database": {
            "type": "memfile",
            "persist": True,
            "name": lease_file,
            "lfc-interval": 3600,
        },
        "expired-leases-processing": {
            "reclaim-timer-wait-time": 10,
            "flush-reclaimed-timer-wait-time": 25,
            "hold-reclaimed-time": 3600,
            "max-reclaim-leases": 100,
            "max-reclaim-time": 250,
            "unwarned-reclaim-cycles": 5,
        },
        "valid-lifetime": int(
            bundle.get("global_options", {}).get("lease_time") or 3600
        ),
        # #637 — group-wide Kea lease cache. Rendered explicitly (not left to
        # Kea's default) because Kea 3.0 flipped that default from "off" to
        # 0.25, which would silently suppress the memfile writes that drive
        # lease-events → DDNS + the IPAM lease mirror. See _apply_lease_cache.
        "cache-threshold": float(server.get("lease_cache_threshold") or 0.0),
        # #980 — see _multi_threading. Rendered on every bundle, so the ETag
        # already covers it via the "server" block it reads from.
        "multi-threading": _multi_threading(server),
        "renew-timer": 900,
        "rebind-timer": 1800,
        "hooks-libraries": [
            {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
        ],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output_options": _log_outputs("kea-dhcp4"),
                "severity": "INFO",
            },
            # #980 — appended, not merged into the parent: log4cplus resolves
            # the most specific logger name, so this raises ONLY the two
            # per-packet codes and leaves everything else at INFO.
            *_quiet_packet_logger("kea-dhcp4", server),
        ],
    }

    # #637 — group-wide ``cache-max-age`` is optional (None = uncapped, which is
    # Kea's own default), so it is set conditionally rather than in the literal.
    _global_max_age = server.get("lease_cache_max_age")
    if _global_max_age is not None:
        dhcp4["cache-max-age"] = int(_global_max_age)

    # HA hook — only present when the control plane pins this server to
    # a DHCPFailoverChannel. Kea rejects a config that references
    # ``libdhcp_ha.so`` without matching ``libdhcp_lease_cmds.so``, so
    # the lease_cmds hook above is load-bearing here too.
    failover = bundle.get("failover")
    if isinstance(failover, dict) and failover.get("peers"):
        dhcp4["hooks-libraries"].append(_ha_hook(failover))

    opts = _options_from_mapping(bundle.get("global_options"))
    if opts:
        dhcp4["option-data"] = opts

    # Prefer the canonical control-plane wire shape (``scopes``). Fall
    # back to the legacy pre-translated ``subnets`` shape for tests /
    # hand-crafted bundles that still use it.
    #
    # Split the canonical wire scopes by address family: v4 scopes render
    # into ``subnet4`` here, v6 scopes into a ``Dhcp6`` block below. The
    # legacy ``subnets`` shape is v4-only by construction.
    scopes = bundle.get("scopes")
    v6_scopes: list[dict[str, Any]] = []
    if scopes is not None:
        v4_scopes = [s for s in scopes if (s.get("address_family") or "ipv4") != "ipv6"]
        v6_scopes = [s for s in scopes if (s.get("address_family") or "ipv4") == "ipv6"]
        dhcp4["subnet4"] = [_scope_to_subnet(s) for s in v4_scopes]
    else:
        dhcp4["subnet4"] = [_subnet(s) for s in (bundle.get("subnets") or [])]

    # Client classes: wire carries ``match_expression``, legacy/hand-
    # crafted fixtures carry ``test``. Accept either.
    classes = bundle.get("client_classes") or []
    rendered_classes: list[dict[str, Any]] = [
        {
            "name": c["name"],
            **(
                {"test": c.get("test") or c.get("match_expression")}
                if (c.get("test") or c.get("match_expression"))
                else {}
            ),
            **(
                {"option-data": _options_from_mapping(c.get("options"))}
                if c.get("options")
                else {}
            ),
        }
        for c in classes
    ]

    # #858 — PXE + phone classes. Both were folded into the bundle ETag and
    # rendered by the control-plane driver, but never serialized onto the wire
    # and never read here, so neither could reach agent-managed Kea — which is
    # how both the appliance and the Compose stack run DHCP. Order matches the
    # backend driver: operator classes, then PXE, then phone. Kea evaluates
    # client-classes in declaration order, so this is behaviour, not style.
    rendered_classes += [_pxe_class(p) for p in (bundle.get("pxe_classes") or [])]
    rendered_classes += [_phone_class(c) for c in (bundle.get("phone_classes") or [])]
    # #700 — device policies last, matching the backend driver's order, so an
    # operator's own class of the same shape is evaluated first. Kea stops at
    # the first match, so this is precedence rather than presentation.
    rendered_classes += [
        rc
        for rc in (
            _device_policy_class(c)
            for c in (bundle.get("device_policy_classes") or [])
        )
        if rc is not None
    ]

    # MAC blocklist — render as Kea's reserved ``DROP`` class. Any packet
    # whose hardware address matches the OR-ed expression is silently
    # dropped before allocation. ``DROP`` is a Kea built-in name, not
    # something the operator can reuse — so if a user-defined class is
    # already named ``DROP`` we skip blocklist rendering to avoid
    # clobbering it (defensive; the API already reserves the name).
    drop_expr = _build_drop_expression(bundle.get("mac_blocks") or [])
    if drop_expr and not any(c.get("name") == "DROP" for c in rendered_classes):
        rendered_classes.append({"name": "DROP", "test": drop_expr})

    if rendered_classes:
        dhcp4["client-classes"] = rendered_classes

    # #856 — ship definitions for any non-standard option we just emitted.
    # Must run after every option-data producer above, and Kea requires
    # ``option-def`` to precede nothing in particular, so placement is free.
    #
    # #858 — plus the definitions the control plane resolved for raw-code
    # vendor options. Those cannot be derived here: the type comes from the
    # option catalogues, which live in the backend package. Deduplicated by
    # code so a definition supplied both ways is emitted once — Kea rejects a
    # duplicate definition for the same code.
    option_defs = _collect_option_defs(dhcp4)
    seen_def_codes = {d.get("code") for d in option_defs}
    for d in bundle.get("option_defs") or []:
        if isinstance(d, dict) and d.get("code") not in seen_def_codes:
            option_defs.append(d)
            seen_def_codes.add(d.get("code"))

    # A raw-code option is only safe to emit once a definition for it exists:
    # Kea types an undefined code as BINARY and REJECTS THE WHOLE CONFIG when
    # the value isn't hex. Dropping one option is survivable; a rejected config
    # is not, and `sync.py` writes the file before `config-test`, so a bad
    # render outlives the process that made it.
    #
    # This also covers the two cases where no definitions arrive at all: the
    # on-disk last-known-good cache written before #858, and an older control
    # plane that doesn't send them. Both then behave exactly as they did before
    # #858 — the option is dropped, loudly — rather than wedging the daemon at
    # the moment the cache matters most (non-negotiable #5).
    _strip_undefined_code_options(dhcp4, {c for c in seen_def_codes if isinstance(c, int)})

    if option_defs:
        dhcp4["option-def"] = option_defs

    out: dict[str, Any] = {"Dhcp4": dhcp4}

    # Dhcp6 block — ALWAYS emitted. The agent container runs kea-dhcp6
    # always-on (dual-stack), so a valid Dhcp6 doc must always be
    # rendered. When the bundle carries no v6 scopes the block is an
    # idle skeleton: no host interfaces bound (``interfaces: []``, safe
    # on IPv6-less hosts), empty ``subnet6``, and no global option-data /
    # client-classes. When v6 scopes ARE present the daemon binds the
    # bundle's interfaces and serves them. The Dhcp6 daemon is a separate
    # Kea process with its own control socket + lease store; option-data
    # renders through the v6 name map (v4-only options dropped with a
    # warning), and reservations use the v6 ``ip-addresses`` (plural)
    # shape. Mirrors the ``Dhcp6`` block in
    # ``backend/app/drivers/dhcp/kea.py``.
    ctrl6 = control_socket_v6 or control_socket.replace("kea4", "kea6")
    lease6 = lease_file_v6 or lease_file.replace("leases4", "leases6")
    # Idle skeleton binds nothing; an active v6 config binds the bundle's
    # interfaces just like Dhcp4, plus a unicast socket per global address
    # the agent found on the host (#1140) — ``"*"`` alone binds link-local
    # and ff02::1:2 only, so a relay's Relay-Forward to the server's global
    # address had no socket to land on. See ``v6_unicast`` for why the
    # addresses are detected live rather than configured.
    v6_interfaces = _v6_interfaces(interfaces, v6_unicast) if v6_scopes else []
    dhcp6: dict[str, Any] = {
        "interfaces-config": {"interfaces": v6_interfaces},
        # Match host reservations on DUID (v6-native, issue #368) then
        # hw-address. Mirrors the backend Dhcp6 block.
        "host-reservation-identifiers": ["duid", "hw-address"],
        "control-socket": {
            "socket-type": "unix",
            "socket-name": ctrl6,
        },
        "lease-database": {
            "type": "memfile",
            "persist": True,
            "name": lease6,
            "lfc-interval": 3600,
        },
        "expired-leases-processing": {
            "reclaim-timer-wait-time": 10,
            "flush-reclaimed-timer-wait-time": 25,
            "hold-reclaimed-time": 3600,
            "max-reclaim-leases": 100,
            "max-reclaim-time": 250,
            "unwarned-reclaim-cycles": 5,
        },
        "valid-lifetime": int(
            bundle.get("global_options", {}).get("lease_time") or 3600
        ),
        # #637 — see the Dhcp4 block. Same group-wide lease-cache default.
        "cache-threshold": float(server.get("lease_cache_threshold") or 0.0),
        # #980 — same pool size as Dhcp4. kea-dhcp6 is a separate process with
        # its own pool, and it shares the node's CPU with kea-dhcp4, so
        # leaving it on auto would put back most of the threads Dhcp4 just
        # dropped.
        "multi-threading": _multi_threading(server),
        "renew-timer": 900,
        "rebind-timer": 1800,
        "hooks-libraries": [
            {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
        ],
        "subnet6": [_scope_to_subnet6(s) for s in v6_scopes],
        "loggers": [
            {
                "name": "kea-dhcp6",
                "output_options": _log_outputs("kea-dhcp6"),
                "severity": "INFO",
            },
            # #980 — see the Dhcp4 block.
            *_quiet_packet_logger("kea-dhcp6", server),
        ],
    }
    # #637 — see the Dhcp4 block. Optional, so set conditionally.
    if _global_max_age is not None:
        dhcp6["cache-max-age"] = int(_global_max_age)

    # Global option-data + client classes only apply when v6 scopes are
    # being served — the idle skeleton stays bare so it can't reject on
    # an inherited v4-only global option.
    if v6_scopes:
        opts6 = _options_from_mapping_v6(bundle.get("global_options"))
        if opts6:
            dhcp6["option-data"] = opts6
        # Client classes render through the v6 name map. The MAC blocklist
        # DROP class is v4-only (Kea v6 has no ``pkt4.mac``) so it is not
        # carried into Dhcp6 — matching the backend driver.
        rendered_classes_v6: list[dict[str, Any]] = [
            {
                "name": c["name"],
                **(
                    {"test": c.get("test") or c.get("match_expression")}
                    if (c.get("test") or c.get("match_expression"))
                    else {}
                ),
                **(
                    {"option-data": _options_from_mapping_v6(c.get("options"))}
                    if c.get("options")
                    else {}
                ),
            }
            for c in classes
        ]
        if rendered_classes_v6:
            dhcp6["client-classes"] = rendered_classes_v6
    out["Dhcp6"] = dhcp6

    return out
