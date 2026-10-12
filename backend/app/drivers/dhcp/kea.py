"""Kea DHCP driver.

Renders the SpatiumDDI ``ConfigBundle`` into a Kea Dhcp4 JSON config
structure (see https://kea.readthedocs.io/). The agent container pushes
that config via the Kea control-agent HTTP API (config-set + config-reload)
or by writing ``/etc/kea/kea-dhcp4.conf`` + restarting the daemon.

Only a minimal control-channel implementation is included here — heavy
lifting happens in the agent runtime. The control plane is responsible
for *shape* (valid JSON) and *auditing*, not daemon transport.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from typing import Any

import structlog

from app.drivers.dhcp.base import (
    ClientClassDef,
    ConfigBundle,
    DevicePolicyClassDef,
    DHCPDriver,
    PhoneClassDef,
    PoolDef,
    PXEClassDef,
    ScopeDef,
    StaticAssignmentDef,
)

logger = structlog.get_logger(__name__)


# Map of SpatiumDDI option-name → Kea option-data ``name`` in the default
# ``dhcp4`` option space. Kea accepts standard DHCPv4 options by their
# IANA names here.
_KEA_OPTION_NAMES: dict[str, str] = {
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

# Options Kea has no built-in definition for, mapped to the ``option-def``
# that makes them loadable.
#
# #856: option 150 (Cisco TFTP server address) is not a standard Kea option.
# Emitting it by name alone fails the WHOLE config —
# ``definition for the option 'dhcp4.tftp-server-address' does not exist``
# (verified against Kea 3.0.3) — which takes DHCP down rather than dropping
# one option, so the definition has to ship with it.
#
# KEYED BY THE RENDERED KEA NAME, not the canonical SpatiumDDI one, because
# that is what ``_collect_option_defs`` sees in the assembled ``option-data``.
# The two happen to be spelled identically for option 150; they are NOT for
# e.g. ``bootfile-name`` → ``boot-file-name``, and keying this table the other
# way would emit that option with no definition and fail the whole config.
# Vendor / phone-profile options addressed by RAW CODE (``code:NN`` keys,
# which is how ``_assemble_phone_classes`` emits an option the operator picked
# from the VoIP vendor catalogue rather than by name).
#
# #858: Kea does not reject these as undefined — it types them as BINARY, so
# an operator's string value fails with "not a valid string of hexadecimal
# digits" and takes the whole config down. Declaring the real type fixes it.
#
# The membership of this table is MEASURED against Kea 3.0.3, not assumed,
# because the rule is not derivable: Kea REFUSES to redefine an option it
# already types correctly ("unable to override definition of option '66' in
# standard option space"), so a blanket definition for every code is just as
# fatal as none. Every code below was confirmed to (a) fail bare with a
# type-appropriate value and (b) accept the definition given here. Types come
# from ``app/data/dhcp_voip_options.json``'s ``kind``.
#
# Re-measure with `kea-dhcp4 -t` before adding a code here.
_KEA_VENDOR_OPTION_DEFS: dict[int, dict[str, Any]] = {
    43: {"name": "spatium-opt-43", "code": 43, "space": "dhcp4", "type": "binary"},
    # #972 Phase 2 — RFC 6225 GeoConf (123). ``binary`` because the payload
    # is a 128-bit packed bitfield with no Kea type that describes it; the
    # bytes are built by ``services/e911/dhcp_options`` and shipped as hex.
    #
    # **There is deliberately NO entry for option 99 here.** Measured against
    # kea-dhcp4 3.0.3: Kea ships its own standard definition for 99 and
    # refuses to let one be overridden —
    #   "unable to override definition of option '99' in standard option
    #    space 'dhcp4'"
    # — which fails the ENTIRE configuration, not just that option. So 99 is
    # emitted by Kea's own name, ``geoconf-civic``, and 123 (which has no
    # standard definition; every name tried was rejected) by ours. Both
    # verified with ``kea-dhcp4 -t``, per the instruction above this table.
    123: {"name": "spatium-opt-123", "code": 123, "space": "dhcp4", "type": "binary"},
    132: {"name": "spatium-opt-132", "code": 132, "space": "dhcp4", "type": "string"},
    150: {
        "name": "spatium-opt-150",
        "code": 150,
        "space": "dhcp4",
        "type": "ipv4-address",
        "array": True,
    },
    160: {"name": "spatium-opt-160", "code": 160, "space": "dhcp4", "type": "string"},
    161: {"name": "spatium-opt-161", "code": 161, "space": "dhcp4", "type": "string"},
    176: {"name": "spatium-opt-176", "code": 176, "space": "dhcp4", "type": "string"},
    242: {"name": "spatium-opt-242", "code": 242, "space": "dhcp4", "type": "string"},
}

_KEA_OPTION_DEFS: dict[str, dict[str, Any]] = {
    "tftp-server-address": {
        "name": "tftp-server-address",
        "code": 150,
        "space": "dhcp4",
        "type": "ipv4-address",
        "array": True,
    },
}


def _dedupe_defs_by_code(
    named: list[dict[str, Any]], vendor: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """One definition per code — Kea rejects a config that declares two.

    #858: option 150 is reachable both ways, as the canonical
    ``tftp-server-address`` name and as a raw ``code:150`` from a Cisco phone
    profile. A scope using one and a profile using the other produced two
    definitions for code 150 and a config Kea refuses. The NAMED definition
    wins: it is the one the rendered ``option-data`` references by name, and a
    name with no matching definition is itself fatal.
    """
    out = list(named)
    seen = {d.get("code") for d in out}
    for d in vendor:
        if d.get("code") not in seen:
            out.append(d)
            seen.add(d.get("code"))
    return out


def option_defs_for_option_maps(maps: Iterable[dict[str, Any] | None]) -> list[dict[str, Any]]:
    """``option-def`` entries needed by the given SpatiumDDI option mappings.

    The agent renders its own Kea config but cannot compute these: the type
    for a raw ``code:NN`` comes from the VoIP / option-code catalogues, which
    live in the backend package. So the control plane resolves them once and
    ships the result on the wire (#858) — the agent emits it verbatim rather
    than keeping a second copy of a table that would drift, which is the
    mistake #856 was.

    Takes the neutral ``{name: value}`` mappings, not a rendered document, so
    it can run at bundle-assembly time before any driver is involved.
    """
    codes: set[int] = set()
    names: set[str] = set()
    for m in maps:
        for key, value in (m or {}).items():
            if key == "option_data":
                # The raw Kea-shaped passthrough. Scanned too, because an
                # entry here needs its definition exactly as much as a
                # ``code:NN`` key does — and without it Kea rejects the WHOLE
                # config ("definition for the option 'dhcp4.x' does not
                # exist"), not just that option.
                #
                # This was a real hole, not a hypothetical one: #972's DHCP
                # location options ride on this passthrough, and their
                # option-def went unshipped until the integration test caught
                # it. Any future raw producer is covered now.
                for entry in value if isinstance(value, list) else ():
                    if not isinstance(entry, dict):
                        continue
                    code = entry.get("code")
                    if isinstance(code, int):
                        codes.add(code)
                continue
            if key.startswith("code:"):
                try:
                    codes.add(int(key[5:]))
                except ValueError:
                    continue
            else:
                kea_name = _KEA_OPTION_NAMES.get(key)
                if kea_name in _KEA_OPTION_DEFS:
                    names.add(str(kea_name))
    return _dedupe_defs_by_code(
        [d for n, d in _KEA_OPTION_DEFS.items() if n in names],
        [d for c, d in _KEA_VENDOR_OPTION_DEFS.items() if c in codes],
    )


def _collect_option_defs(dhcp4: dict[str, Any]) -> list[dict[str, Any]]:
    """``option-def`` entries required by whatever this render emitted.

    Walks the assembled ``Dhcp4`` block rather than each options mapping on
    the way in, so subnet, pool, reservation, client-class and global
    option-data are all covered — including any future producer.
    """
    seen_names: set[str] = set()
    seen_codes: set[int] = set()

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if key == "option-data" and isinstance(val, list):
                    for entry in val:
                        if not isinstance(entry, dict):
                            continue
                        if entry.get("name") in _KEA_OPTION_DEFS:
                            seen_names.add(str(entry["name"]))
                        # #858 — code-addressed vendor options need the same
                        # treatment; they are emitted by ``code:NN`` keys and
                        # carry no ``name`` to match on.
                        code = entry.get("code")
                        if isinstance(code, int) and code in _KEA_VENDOR_OPTION_DEFS:
                            seen_codes.add(code)
                else:
                    _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(dhcp4)
    # Stable order, keyed off the definition tables (whose keys share a
    # namespace with what was collected) rather than set iteration.
    return _dedupe_defs_by_code(
        [d for n, d in _KEA_OPTION_DEFS.items() if n in seen_names],
        [d for c, d in _KEA_VENDOR_OPTION_DEFS.items() if c in seen_codes],
    )


# Map of SpatiumDDI option-name → Kea Dhcp6 ``option-data`` name. DHCPv6
# uses a different option-code space + cmdlet names; only options that
# have a true v6 equivalent are forwarded. Options with no v6 analogue
# (``routers`` — v6 uses Router Advertisements; ``broadcast-address`` —
# no broadcast in v6; ``mtu`` / ``time-offset`` — no native option) are
# dropped from v6 scopes with a warning log so the operator can spot
# misconfigured inheritance rather than Kea silently rejecting the
# config on reload.
_KEA_OPTION_NAMES_V6: dict[str, str] = {
    "dns-servers": "dns-servers",  # DHCPv6 option 23
    "domain-search": "domain-search",  # DHCPv6 option 24
    "ntp-servers": "sntp-servers",  # DHCPv6 option 31 (SNTP)
    "bootfile-name": "bootfile-url",  # DHCPv6 option 59 (URL form)
}

# Options that have no DHCPv6 equivalent — dropped from v6 scopes.
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


def _render_option_data(
    options: dict[str, Any], *, address_family: str = "ipv4"
) -> list[dict[str, Any]]:
    """Translate a {name: value} options map into Kea's ``option-data`` list.

    ``address_family="ipv6"`` routes through the Dhcp6 name map and
    drops options that don't exist in DHCPv6 — emitting a v4 option
    under the Dhcp6 block would make Kea reject the config on reload.

    Keys prefixed with ``code:NN`` are emitted with ``"code": NN`` form
    rather than ``"name"`` — used by phone-profile classes for vendor-
    specific options (option 160 / 161 / 242 / etc) that Kea doesn't
    recognise by name without a separate ``option-def``.
    """
    is_v6 = address_family == "ipv6"
    name_map = _KEA_OPTION_NAMES_V6 if is_v6 else _KEA_OPTION_NAMES
    out: list[dict[str, Any]] = []

    # The raw Kea-shaped passthrough (#972's location options ride on it).
    # Mirrors the agent renderer's handling, which has always had it — without
    # this the control-plane preview stringified the whole list into a single
    # bogus ``{"name": "option_data", "data": "{'name': 'geoconf-civic'...}"}``
    # entry and omitted the real ones, so the rendered-config tab showed an
    # operator something that would not load.
    raw = options.get("option_data")
    if isinstance(raw, list):
        out.extend(e for e in raw if isinstance(e, dict))

    for key, val in options.items():
        if key == "option_data":
            continue
        if is_v6 and key in _DHCP4_ONLY_OPTION_NAMES:
            logger.warning(
                "kea_option_skipped_v6_no_equivalent",
                option=key,
                reason="no DHCPv6 equivalent",
            )
            continue
        if isinstance(val, list):
            data = ", ".join(str(x) for x in val)
        else:
            data = str(val)
        if key.startswith("code:"):
            try:
                code_int = int(key[5:])
            except ValueError:
                continue
            out.append({"code": code_int, "data": data})
            continue
        kea_name = name_map.get(key, key)
        out.append({"name": kea_name, "data": data})
    return out


def _render_pool(pool: PoolDef, *, address_family: str = "ipv4") -> dict[str, Any]:
    # Kea expresses "excluded" / "reserved" pools indirectly via
    # reservations + pool boundaries. We emit dynamic pools only; excluded
    # ranges are conveyed to the agent as metadata for boundary splitting.
    d: dict[str, Any] = {"pool": f"{pool.start_ip} - {pool.end_ip}"}
    if pool.class_restriction:
        d["client-class"] = pool.class_restriction
    if pool.options_override:
        d["option-data"] = _render_option_data(pool.options_override, address_family=address_family)
    return d


def _render_pd_pool(pool: PoolDef) -> dict[str, Any] | None:
    """Render a DHCPv6 prefix-delegation pool (issue #368).

    Kea's ``pd-pools`` entry is ``{"prefix", "prefix-len", "delegated-len"}``
    plus an optional RFC 6603 ``excluded-prefix`` / ``excluded-prefix-len``.
    Returns ``None`` (skipped) when the pool is malformed so one bad row can't
    fail the whole render.
    """
    if not pool.pd_prefix or not pool.delegated_length:
        return None
    try:
        net = ipaddress.ip_network(pool.pd_prefix, strict=False)
    except ValueError:
        return None
    d: dict[str, Any] = {
        "prefix": str(net.network_address),
        "prefix-len": net.prefixlen,
        "delegated-len": int(pool.delegated_length),
    }
    if pool.excluded_prefix:
        try:
            ex = ipaddress.ip_network(pool.excluded_prefix, strict=False)
            d["excluded-prefix"] = str(ex.network_address)
            d["excluded-prefix-len"] = ex.prefixlen
        except ValueError:
            # Malformed excluded-prefix: render the pd-pool without it rather
            # than dropping the whole pool. The create/update API validates the
            # excluded-prefix (services pools._validate_pd), so this is purely
            # defensive against legacy/hand-edited rows.
            logger.warning("kea_pd_excluded_prefix_invalid", value=pool.excluded_prefix)
    if pool.class_restriction:
        d["client-class"] = pool.class_restriction
    return d


def _render_reservation(s: StaticAssignmentDef, *, address_family: str = "ipv4") -> dict[str, Any]:
    # Dhcp6 reservations use ``ip-addresses`` (plural, list). DHCPv6 clients are
    # identified by DUID, so when a ``duid`` is set we key the reservation on it
    # (issue #368); otherwise we fall back to ``hw-address`` (Kea can match it
    # via the subnet's ``host-reservation-identifiers``).
    if address_family == "ipv6":
        if s.duid:
            r: dict[str, Any] = {"duid": s.duid, "ip-addresses": [s.ip_address]}
        else:
            r = {"hw-address": s.mac_address, "ip-addresses": [s.ip_address]}
    else:
        r = {
            "hw-address": s.mac_address,
            "ip-address": s.ip_address,
        }
    if s.hostname:
        r["hostname"] = s.hostname
    if s.client_id and address_family != "ipv6":
        r["client-id"] = s.client_id
    if s.options_override:
        r["option-data"] = _render_option_data(s.options_override, address_family=address_family)
    return r


def _render_scope(scope: ScopeDef) -> dict[str, Any]:
    af = scope.address_family  # "ipv4" | "ipv6"
    # DHCPv6 operating mode (issue #52) gates what Kea serves for a v6
    # subnet6. v4 always serves both addresses + options (mode is ignored).
    #   stateful  → address pools + option-data
    #   stateless → no pools, option-data only (Information-Request)
    #   slaac     → no pools, no option-data (the router's RA does it all)
    mode = getattr(scope, "v6_address_mode", "stateful") or "stateful"
    if af == "ipv6":
        serve_addresses = mode == "stateful"
        serve_options = mode in ("stateful", "stateless")
    else:
        serve_addresses = True
        serve_options = True

    dynamic_pools = [p for p in scope.pools if p.pool_type == "dynamic"] if serve_addresses else []
    # DHCPv6 prefix delegation (issue #368) — pd-pools render only on a
    # stateful v6 subnet6. v4 / stateless / slaac never carry them.
    pd_pools = (
        [p for p in scope.pools if p.pool_type == "pd"]
        if (serve_addresses and af == "ipv6")
        else []
    )
    out: dict[str, Any] = {
        # Kea names the CIDR field "subnet" and the pool list "pools" in
        # both Dhcp4 and Dhcp6 modes.
        "subnet": scope.subnet_cidr,
        "pools": [_render_pool(p, address_family=af) for p in dynamic_pools],
        # A pure-SLAAC subnet has no DHCP role, so host reservations (which
        # assign addresses / host-specific options) are dropped too.
        "reservations": (
            [_render_reservation(s, address_family=af) for s in scope.statics]
            if (serve_addresses or serve_options)
            else []
        ),
        "valid-lifetime": scope.lease_time,
    }
    if scope.min_lease_time is not None:
        out["min-valid-lifetime"] = scope.min_lease_time
    if scope.max_lease_time is not None:
        out["max-valid-lifetime"] = scope.max_lease_time
    # #637 — per-scope lease-cache override. None = inherit the group-wide value
    # emitted on the Dhcp4/Dhcp6 root; 0.0 is meaningful (caching explicitly off).
    if scope.lease_cache_threshold is not None:
        out["cache-threshold"] = scope.lease_cache_threshold
    if scope.lease_cache_max_age is not None:
        out["cache-max-age"] = scope.lease_cache_max_age
    if scope.options and serve_options:
        out["option-data"] = _render_option_data(scope.options, address_family=af)
    # Relay-agent matching (issue #337). Kea selects this subnet for
    # packets whose ``giaddr`` is one of these relay IPs — required when
    # the subnet isn't directly attached to the server. Valid in both
    # Dhcp4 (``subnet4``) and Dhcp6 (``subnet6``) blocks.
    if scope.relay_addresses:
        out["relay"] = {"ip-addresses": list(scope.relay_addresses)}
    # Prefix-delegation pools (issue #368) — drop malformed rows rather than
    # failing the whole render.
    if pd_pools:
        rendered_pd = [r for r in (_render_pd_pool(p) for p in pd_pools) if r is not None]
        if rendered_pd:
            out["pd-pools"] = rendered_pd
    return out


def _render_client_class(c: ClientClassDef, *, address_family: str = "ipv4") -> dict[str, Any]:
    """One operator class for one daemon. The caller filters on
    ``c.in_family`` first (#1229): a class whose test uses ``pkt4`` makes
    kea-dhcp6 reject the whole config, and the mirror image for ``pkt6``."""
    d: dict[str, Any] = {"name": c.name}
    if c.match_expression:
        d["test"] = c.match_expression
    options = c.options_v6 if address_family == "ipv6" else c.options_v4
    if options:
        d["option-data"] = _render_option_data(options, address_family=address_family)
    return d


def _render_phone_class(p: PhoneClassDef) -> dict[str, Any]:
    """Render a VoIP phone client-class for Dhcp4 ``client-classes``
    (issue #112).

    Same shape as a regular client-class — ``name``, ``test``,
    ``option-data`` — but option-data goes through the
    ``code:NN`` aware renderer so vendor options that Kea doesn't know
    by name (160 / 161 / 242 / etc) emit with ``"code": NN`` form
    instead of producing a load-time error.
    """
    d: dict[str, Any] = {"name": p.name}
    if p.match_expression:
        d["test"] = p.match_expression
    if p.options:
        d["option-data"] = _render_option_data(p.options, address_family="ipv4")
    return d


def _render_device_policy_class(p: DevicePolicyClassDef) -> dict[str, Any]:
    """Render a fingerprint-driven device-policy class (issue #700).

    ``valid-lifetime`` on a client class is honoured by Kea per-class —
    verified against kea-dhcp4 3.0.3 rather than assumed, because a
    silently-ignored lease time is the difference between a quarantine
    that expires and one that never does.

    The ``test`` key is emitted unconditionally: the assembler never
    produces a device-policy class with an empty expression, since a Kea
    class with no ``test`` matches every packet — which for this feature
    would apply a quarantine policy to the whole network.
    """
    d: dict[str, Any] = {"name": p.name, "test": p.match_expression}
    if p.lease_time is not None:
        d["valid-lifetime"] = p.lease_time
    if p.options:
        d["option-data"] = _render_option_data(p.options, address_family="ipv4")
    return d


def _render_pxe_class(p: PXEClassDef) -> dict[str, Any]:
    """Render a PXE / iPXE class for Dhcp4 ``client-classes`` (issue #51).

    PXE classes are Dhcp4-only — the v6 PXE story uses option 59
    (Bootfile-URL) which is a different flow and is deferred. The
    ``next-server`` + ``boot-file-name`` fields on the class win
    over scope-level defaults when Kea matches the packet, so each
    arch / vendor combo can serve a different boot binary.

    The ``test`` expression is whatever the bundle assembler
    composed from the operator's ``vendor_class_match`` substring +
    ``arch_codes`` enumeration. An empty test means "always match"
    — typically a low-priority fallthrough.
    """
    d: dict[str, Any] = {
        "name": p.name,
        "next-server": p.next_server,
        "boot-file-name": p.boot_file_name,
    }
    if p.match_expression:
        d["test"] = p.match_expression
    return d


def _packet_logging_override(bundle: ConfigBundle, daemon: str) -> dict[str, Any]:
    """The ``kea-dhcpN.packets`` severity override, for the preview (#980).

    Returns ``{}`` when packet logging is on, so the rendered preview is
    unchanged for the default.

    Only the override, not a full ``loggers`` block: this render is a
    *preview*, not the file the agent writes. It already omits the control
    socket, hooks, timers and expired-lease processing — and does not parse
    as a Kea config at all — so duplicating the agent's appender paths here
    would add a third copy of them to drift, for no gain. What belongs in
    the preview is the group tunables an operator just set, which is the
    same rule ``dhcp_socket_type`` (#365) and ``cache-threshold`` (#637)
    already follow.
    """
    if bundle.kea_packet_logging:
        return {}
    return {"loggers": [{"name": f"{daemon}.packets", "severity": "WARN"}]}


class KeaDriver(DHCPDriver):
    """Kea DHCPv4 driver — emits a ``Dhcp4`` JSON config structure."""

    name = "kea"

    def render_config(self, bundle: ConfigBundle) -> str:
        # Split scopes by address family. The Kea daemons Dhcp4 and Dhcp6
        # are separate processes; the agent runs whichever process(es) it
        # has scopes for. We emit both top-level blocks so the agent can
        # consume a single bundle regardless of family mix.
        v4_scopes = [s for s in bundle.scopes if s.is_active and s.address_family != "ipv6"]
        v6_scopes = [s for s in bundle.scopes if s.is_active and s.address_family == "ipv6"]

        out: dict[str, Any] = {}
        if v4_scopes or not v6_scopes:
            out["Dhcp4"] = {
                "valid-lifetime": bundle.options.lease_time,
                # #637 — group-wide Kea lease cache, rendered explicitly because
                # Kea 3.0 flipped the default from off to 0.25.
                "cache-threshold": bundle.lease_cache_threshold,
                # #980 — rendered explicitly because Kea's own default sizes
                # the packet-worker pool from the machine's CPU count, not
                # from the cgroup share the container holds. See
                # ``DHCPServerGroup.kea_thread_pool_size`` for the numbers.
                "multi-threading": {
                    "enable-multi-threading": True,
                    "thread-pool-size": bundle.kea_thread_pool_size,
                },
                # Issue #365 — ``raw`` (group socket_mode "direct") receives
                # broadcast DISCOVERs from directly-attached clients; ``udp``
                # is relay-only. v6 below has no socket-type concept.
                "interfaces-config": {
                    "interfaces": ["*"],
                    "dhcp-socket-type": bundle.dhcp_socket_type,
                },
                "lease-database": {
                    "type": "memfile",
                    "persist": True,
                    "name": "/var/lib/kea/kea-leases4.csv",
                },
                "subnet4": [_render_scope(s) for s in v4_scopes],
                "client-classes": [
                    _render_client_class(c, address_family="ipv4")
                    for c in bundle.client_classes
                    if c.in_family("ipv4")
                ]
                + [_render_pxe_class(p) for p in bundle.pxe_classes]
                + [_render_phone_class(p) for p in bundle.phone_classes]
                # #700 — last, so an operator's hand-written class of the
                # same shape is evaluated first. Kea stops at the first
                # match, so declaration order is precedence.
                + [_render_device_policy_class(p) for p in bundle.device_policy_classes],
                "option-data": _render_option_data(bundle.options.options, address_family="ipv4"),
                **_packet_logging_override(bundle, "kea-dhcp4"),
            }
            # #856 — ship definitions for any non-standard option emitted above.
            option_defs = _collect_option_defs(out["Dhcp4"])
            if option_defs:
                out["Dhcp4"]["option-def"] = option_defs
        if v6_scopes:
            # Kea names the subnet list "subnet6" in Dhcp6 mode. Options /
            # client-class options render through the Dhcp6 name map;
            # v4-only options (routers, mtu, …) are dropped with a
            # warning log rather than emitted under the wrong space.
            out["Dhcp6"] = {
                "valid-lifetime": bundle.options.lease_time,
                "interfaces-config": {"interfaces": ["*"]},
                # Match host reservations on DUID (the v6-native identifier,
                # issue #368) and hw-address (when the operator only knows the
                # MAC). Order = match precedence.
                "host-reservation-identifiers": ["duid", "hw-address"],
                # #637 — see the Dhcp4 block.
                "cache-threshold": bundle.lease_cache_threshold,
                # #980 — see the Dhcp4 block. Separate process, separate pool,
                # same node's CPU.
                "multi-threading": {
                    "enable-multi-threading": True,
                    "thread-pool-size": bundle.kea_thread_pool_size,
                },
                "lease-database": {
                    "type": "memfile",
                    "persist": True,
                    "name": "/var/lib/kea/kea-leases6.csv",
                },
                "subnet6": [_render_scope(s) for s in v6_scopes],
                "client-classes": [
                    _render_client_class(c, address_family="ipv6")
                    for c in bundle.client_classes
                    if c.in_family("ipv6")
                ],
                "option-data": _render_option_data(bundle.options.options, address_family="ipv6"),
                **_packet_logging_override(bundle, "kea-dhcp6"),
            }
        # #637 — group-wide ``cache-max-age`` is optional (None = uncapped, Kea's
        # own default), so it is applied conditionally rather than in the literals.
        if bundle.lease_cache_max_age is not None:
            for family in ("Dhcp4", "Dhcp6"):
                if family in out:
                    out[family]["cache-max-age"] = bundle.lease_cache_max_age
        # Kea's parser refuses an empty ``"client-classes": []`` as a syntax
        # error (measured, kea-dhcp4/6 3.0.3), and a family filter (#1229) can
        # leave one empty. The agent renderer already omits the key.
        for family in ("Dhcp4", "Dhcp6"):
            if family in out and not out[family].get("client-classes", True):
                del out[family]["client-classes"]
        return json.dumps(out, indent=2, sort_keys=True)

    async def apply_config(self, server: Any, bundle: ConfigBundle) -> None:
        logger.info(
            "kea_apply_config",
            server_id=str(getattr(server, "id", "?")),
            etag=bundle.etag,
        )
        # Agent-side: POST to Kea control-agent. Control plane just logs +
        # enqueues; the real call happens in the agent runtime.

    async def reload(self, server: Any) -> None:
        logger.info("kea_reload", server_id=str(getattr(server, "id", "?")))

    async def restart(self, server: Any) -> None:
        logger.info("kea_restart", server_id=str(getattr(server, "id", "?")))

    async def get_leases(self, server: Any) -> list[dict[str, Any]]:
        # Agent pushes leases via /agents/lease-events; control plane read
        # goes through the lease table, not the driver.
        return []

    async def health_check(self, server: Any) -> tuple[bool, str]:
        return True, "ok"

    def validate_config(self, bundle: ConfigBundle) -> tuple[bool, list[str]]:
        errors: list[str] = []
        seen_subnets: set[str] = set()
        for s in bundle.scopes:
            if s.subnet_cidr in seen_subnets:
                errors.append(f"duplicate subnet: {s.subnet_cidr}")
            seen_subnets.add(s.subnet_cidr)
            for p in s.pools:
                if not p.start_ip or not p.end_ip:
                    errors.append(f"pool in {s.subnet_cidr} missing start/end")
        return (not errors), errors

    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "kea",
            "version": "2.x",
            "options": sorted(_KEA_OPTION_NAMES.keys()),
            "features": {
                "client_classes": True,
                "reservations": True,
                "ddns": True,
                "ha": True,
            },
        }


__all__ = ["KeaDriver"]
