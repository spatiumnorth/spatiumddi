"""IPv6 Router-Advertisement (radvd) config assembly + rendering (issue #524).

SpatiumDDI ships DHCPv6 via Kea, but Kea does not emit Router Advertisements.
This module turns the per-subnet RA settings on ``DHCPScope`` (opt-in
``ra_enabled`` + the existing ``v6_address_mode`` / ``ra_managed_flag`` /
``ra_other_flag`` intent columns) into a rendered ``radvd.conf`` that rides the
DHCP ConfigBundle to the agent, which writes it and runs radvd.

Everything here is pure (no DB session) so it is unit-testable against
in-memory ``DHCPScope`` / ``Subnet`` rows: ``build_ra_config`` derives one
:class:`RAConfigDef` from a scope + its subnet (M/O flags, RDNSS/DNSSL,
lifetimes), and ``render_radvd_conf`` renders the final config text.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Any

import structlog

from app.core.dns_names import validate_fqdn
from app.drivers.dhcp.base import RAConfigDef

logger = structlog.get_logger(__name__)

# Linux IFNAMSIZ - 1 = 15 chars; no whitespace, braces, semicolons, quotes or
# newlines can match. These values are interpolated verbatim into radvd.conf,
# so this is the injection boundary (GHSA-6235-5gh6-4hr2).
_IFACE_RE = re.compile(r"^[A-Za-z0-9._-]{1,15}$")


def validate_ra_interface(name: str) -> str:
    """Return *name* if it is a safe Linux interface name, else raise ValueError."""
    if not _IFACE_RE.fullmatch(name) or name in (".", ".."):
        raise ValueError(
            "ra_interface must be a Linux interface name: 1-15 characters of "
            "letters, digits, '.', '_' or '-'"
        )
    return name


def validate_dnssl_name(name: str) -> str:
    """Return the normalized DNSSL domain, or raise ValueError.

    RFC 2181 labels, as every other domain field takes them (an underscore is
    not radvd syntax): no whitespace, quote, brace, semicolon or newline can
    pass, so nothing can break out of the ``DNSSL … {};`` statement.
    """
    return validate_fqdn(name, field="domain")


# M/O flags derived from the DHCPv6 operating mode when the operator hasn't
# set an explicit override. Mirrors the mapping documented on
# ``DHCPScope.v6_address_mode``:
#   stateful  → M=1, O=1   (Kea hands out addresses + options)
#   stateless → M=0, O=1   (SLAAC address, DHCPv6 options only)
#   slaac     → M=0, O=0   (router does everything)
_MODE_TO_MO: dict[str, tuple[bool, bool]] = {
    "stateful": (True, True),
    "stateless": (False, True),
    "slaac": (False, False),
}


def derive_mo_flags(
    v6_address_mode: str,
    *,
    mo_override: bool,
    managed_flag: bool,
    other_flag: bool,
) -> tuple[bool, bool]:
    """Resolve the advertised (M, O) flags for an RA-enabled scope.

    When ``mo_override`` is set the operator's ``managed_flag`` /
    ``other_flag`` are used verbatim; otherwise they are derived from the
    DHCPv6 ``v6_address_mode``.
    """
    if mo_override:
        return bool(managed_flag), bool(other_flag)
    return _MODE_TO_MO.get(v6_address_mode or "stateful", (True, True))


def _as_list(value: Any) -> list[str]:
    """Coerce a scope-option value (list, comma-string, or scalar) to a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _ipv6_only(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        try:
            addr = ipaddress.ip_address(v)
        except ValueError:
            continue
        if addr.version == 6:
            out.append(str(addr))
    return out


def resolve_rdnss(
    scope_options: dict[str, Any] | None, subnet_dns: Sequence[str] | None
) -> list[str]:
    """RDNSS list — IPv6 resolvers the RA advertises (RFC 8106).

    Prefers the scope's own ``dns-servers`` option, falling back to the
    subnet's ``dns_servers``. Only IPv6 addresses are advertised (RDNSS is
    v6-only); v4 resolvers configured for the same subnet are ignored here.
    """
    opts = scope_options or {}
    from_scope = _ipv6_only(_as_list(opts.get("dns-servers")))
    if from_scope:
        return from_scope
    return _ipv6_only(_as_list(list(subnet_dns or [])))


def resolve_dnssl(scope_options: dict[str, Any] | None, subnet_domain: str | None) -> list[str]:
    """DNSSL search-domain list (RFC 8106).

    Prefers the scope's ``domain-search`` option, then its ``domain-name``,
    then the subnet's ``domain_name``. Entries that are not valid hostnames
    are dropped (logged) — the subnet field in particular is writable by
    non-superadmins and is interpolated into ``radvd.conf``.
    """
    opts = scope_options or {}
    candidates = _as_list(opts.get("domain-search"))
    if not candidates:
        candidates = _as_list(opts.get("domain-name"))
    if not candidates and subnet_domain:
        candidates = _as_list(subnet_domain)
    out: list[str] = []
    for c in candidates:
        try:
            out.append(validate_dnssl_name(c))
        except ValueError:
            logger.warning("radvd_dnssl_dropped", value=c[:80])
    return out


def build_ra_config(scope: Any, subnet: Any) -> RAConfigDef | None:
    """Build one :class:`RAConfigDef` from a scope + its subnet, or None.

    Returns None when RA is not applicable: the scope isn't RA-enabled, it's
    not an IPv6 scope, or the subnet has no IPv6 prefix.
    """
    if not getattr(scope, "ra_enabled", False):
        return None
    if (getattr(scope, "address_family", "ipv4") or "ipv4") != "ipv6":
        return None
    network = getattr(subnet, "network", None)
    if not network:
        return None
    try:
        prefix = ipaddress.ip_network(str(network), strict=False)
    except ValueError:
        return None
    if prefix.version != 6:
        return None

    managed, other = derive_mo_flags(
        getattr(scope, "v6_address_mode", "stateful") or "stateful",
        mo_override=bool(getattr(scope, "ra_mo_override", False)),
        managed_flag=bool(getattr(scope, "ra_managed_flag", True)),
        other_flag=bool(getattr(scope, "ra_other_flag", True)),
    )
    rdnss = resolve_rdnss(getattr(scope, "options", None), getattr(subnet, "dns_servers", None))
    dnssl = resolve_dnssl(getattr(scope, "options", None), getattr(subnet, "domain_name", None))
    return RAConfigDef(
        subnet_cidr=str(prefix),
        interface=(getattr(scope, "ra_interface", "") or "").strip(),
        managed_flag=managed,
        other_flag=other,
        router_lifetime=int(getattr(scope, "ra_router_lifetime", 1800)),
        max_interval=int(getattr(scope, "ra_max_interval", 600)),
        prefix_on_link=bool(getattr(scope, "ra_prefix_on_link", True)),
        prefix_autonomous=bool(getattr(scope, "ra_prefix_autonomous", True)),
        prefix_valid_lifetime=int(getattr(scope, "ra_prefix_valid_lifetime", 86400)),
        prefix_preferred_lifetime=int(getattr(scope, "ra_prefix_preferred_lifetime", 14400)),
        rdnss=tuple(rdnss),
        dnssl=tuple(dnssl),
    )


def _bool(value: bool) -> str:
    return "on" if value else "off"


def render_radvd_conf(ra_configs: Sequence[RAConfigDef], *, default_iface: str = "eth0") -> str:
    """Render a full ``radvd.conf`` from RA config entries.

    Entries are grouped by interface (an empty ``interface`` maps to
    ``default_iface``). Each interface stanza carries one ``prefix`` block
    per subnet plus shared RDNSS/DNSSL. Deterministic ordering so the
    ConfigBundle etag doesn't churn.
    """
    if not ra_configs:
        return ""

    by_iface: dict[str, list[RAConfigDef]] = {}
    for cfg in ra_configs:
        iface = (cfg.interface or default_iface).strip() or default_iface
        # Defence in depth: the API validates, but a legacy row or a caller
        # that built the dataclass by hand must still not reach the file.
        try:
            validate_ra_interface(iface)
        except ValueError:
            logger.warning("radvd_interface_dropped", subnet=cfg.subnet_cidr, value=iface[:80])
            continue
        by_iface.setdefault(iface, []).append(cfg)
    if not by_iface:
        return ""

    lines: list[str] = [
        "# Managed by SpatiumDDI — IPv6 Router Advertisements (issue #524).",
        "# Do not edit by hand; changes are overwritten on the next config push.",
        "",
    ]
    for iface in sorted(by_iface):
        entries = sorted(by_iface[iface], key=lambda c: c.subnet_cidr)
        # Interface-level M/O + default lifetime come from the first entry;
        # radvd sets these per interface, not per prefix. Where multiple
        # subnets share an interface the lowest-index (sorted) entry wins —
        # operators keep one RA policy per L2 segment in practice.
        head = entries[0]
        lines.append(f"interface {iface} {{")
        lines.append("    AdvSendAdvert on;")
        lines.append(f"    AdvManagedFlag {_bool(head.managed_flag)};")
        lines.append(f"    AdvOtherConfigFlag {_bool(head.other_flag)};")
        lines.append(f"    AdvDefaultLifetime {head.router_lifetime};")
        lines.append(f"    MaxRtrAdvInterval {int(head.max_interval)};")
        seen_rdnss: list[str] = []
        seen_dnssl: list[str] = []
        for cfg in entries:
            prefix = str(ipaddress.ip_network(cfg.subnet_cidr, strict=False))
            lines.append(f"    prefix {prefix} {{")
            lines.append(f"        AdvOnLink {_bool(cfg.prefix_on_link)};")
            lines.append(f"        AdvAutonomous {_bool(cfg.prefix_autonomous)};")
            lines.append(f"        AdvValidLifetime {cfg.prefix_valid_lifetime};")
            lines.append(f"        AdvPreferredLifetime {cfg.prefix_preferred_lifetime};")
            lines.append("    };")
            for r in _ipv6_only(cfg.rdnss):
                if r not in seen_rdnss:
                    seen_rdnss.append(r)
            for d in cfg.dnssl:
                try:
                    d = validate_dnssl_name(d)
                except ValueError:
                    logger.warning("radvd_dnssl_dropped", value=d[:80])
                    continue
                if d not in seen_dnssl:
                    seen_dnssl.append(d)
        if seen_rdnss:
            lines.append(f"    RDNSS {' '.join(seen_rdnss)} {{}};")
        if seen_dnssl:
            lines.append(f"    DNSSL {' '.join(seen_dnssl)} {{}};")
        lines.append("};")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "RAConfigDef",
    "build_ra_config",
    "derive_mo_flags",
    "render_radvd_conf",
    "resolve_dnssl",
    "resolve_rdnss",
    "validate_dnssl_name",
    "validate_ra_interface",
]
