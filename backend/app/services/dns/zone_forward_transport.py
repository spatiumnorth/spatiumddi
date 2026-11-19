"""Can a group serve a forward zone's own upstream transport? (#2121)

A forward zone carries its own ``forward_transport`` and
``forward_tls_hostname``; the group's ``forward_transport`` covers the
group's resolver forwarders only. This module holds the one check that says
whether a given group can serve a given forward zone's transport, so every
path that puts a zone into a group answers the same way: zone create and
update in the DNS router, and the #935 zone move, whose preview reports the
refusal its commit raises.

Pure: the caller resolves the group's drivers and passes them in.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.services.dns.resolver_presets import (
    encrypted_only_presets,
    find_forwarder_conflict,
    preset_for_address,
)

# The drivers that can forward a ZONE over each encrypted transport. A
# forward zone exists only on drivers that render forward zones, and of those
# only BIND9 and Technitium speak TLS to an upstream. Windows DNS conditional
# forwarders and the cloud drivers are plain DNS only.
ZONE_TRANSPORT_DRIVER_GATE: dict[str, frozenset[str]] = {
    "tls": frozenset({"bind9", "technitium"}),
    "https": frozenset({"technitium"}),
    "quic": frozenset({"technitium"}),
}


def zone_forward_transport_refusal(
    *,
    zone_name: str,
    transport: str | None,
    hostname: str | None,
    forwarders: list[str],
    drivers: Iterable[str],
) -> str | None:
    """Why a group running ``drivers`` cannot serve this forward zone, or None.

    ``drivers`` empty means a group with no servers yet, read as BIND9, the
    same default the router's ``_group_driver_names`` applies.
    """
    transport = transport or "do53"
    if transport != "do53" and not hostname:
        return (
            f"forward_tls_hostname is required when a forward zone uses forward_transport "
            f"{transport!r}: it is the name the upstream's certificate is checked "
            "against. Set the upstream's DoT / DoH hostname, or use do53."
        )
    driver_set = set(drivers) or {"bind9"}
    allowed = ZONE_TRANSPORT_DRIVER_GATE.get(transport)
    if allowed is not None and (incompatible := driver_set - allowed):
        return (
            f"forward_transport {transport!r} is not supported for a forward zone by "
            f"{', '.join(sorted(incompatible))} in this group. BIND9 forwards a zone "
            "over do53 or tls only; https and quic are Technitium-only, and the other "
            "drivers forward plain DNS."
        )
    # One certificate name per forwarder set (#877), applied to the zone: the
    # zone checks every one of its forwarders against its single hostname.
    if transport != "do53" and (conflict := find_forwarder_conflict(forwarders)):
        detail = ", ".join(
            f"{entry} ({preset.name}, {preset.tls_hostname})"
            for entry in forwarders
            if (preset := preset_for_address(entry)) is not None
        )
        return (
            f"Forward zone {zone_name!r} forwards to upstreams that present different TLS "
            f"certificate names ({', '.join(conflict.hostnames)}): {detail}. The zone checks "
            f"every one of its forwarders against its single forward_tls_hostname "
            f"{hostname!r}, so at least one would fail verification and its queries would "
            "SERVFAIL. Keep only this zone's forwarders that share one certificate name, and "
            "set forward_tls_hostname to that name."
        )
    # An upstream that answers only over an encrypted transport refuses plain
    # DNS, so a do53 zone pointed at it resolves nothing.
    if transport == "do53" and (encrypted_only := encrypted_only_presets(forwarders)):
        names = ", ".join(sorted(p.name for p in encrypted_only))
        return (
            f"{names} only answers over an encrypted transport and returns REFUSED on "
            "plaintext port 53, so this forward zone would fail every query. Set the "
            "zone's forward_transport to tls (with the provider's hostname)."
        )
    return None
