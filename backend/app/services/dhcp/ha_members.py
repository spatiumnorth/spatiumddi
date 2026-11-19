"""Which Kea members of a DHCP group take part in its HA relationship (#3151).

One rule, read by everything that has to agree on it: the config bundle (the
HA hook and which members serve the group's scopes), the per-node HA firewall
rule, the upgrade pre-flight and the group API.

* The **participants** are the group's Kea members that carry an
  ``ha_peer_url``, sorted by id (the first is ``primary``, the second
  ``secondary`` / ``standby``, any further ones ``backup``, #332). HA renders
  only in an HA-mode group with at least two of them.
* A Kea member WITHOUT a URL in a group whose HA does render is **sidelined**:
  it is left out of the peers list and serves none of the group's scopes. It
  cannot be in the relationship (its partners have no address to reach it),
  and serving the group's pools beside a running pair, with no lease sync
  between them, would hand the same address to two clients.

Before #3151 one URL-less member suppressed HA for the whole group. Since a
third appliance member's URL is deliberately left empty (#2963: roles follow
server-id order, so a joiner could take ``primary`` from a live pair), assigning
a third node to a working pair's group switched HA off for the pair, leaving
three members serving the same pools uncoordinated.

A group with one or two Kea members is unaffected: with two, HA renders only
when both carry a URL, so nothing is ever sidelined there.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from app.models.dhcp import HA_MODES, DHCPServer

# Advertised by an agent that renders the HA hook into Dhcp6 too (#1258).
HA_V6_CAPABILITY = "ha_v6"


@dataclass
class KeaHAMembers:
    # Sorted by id; empty when the group renders no HA hook.
    participants: list[DHCPServer] = field(default_factory=list)
    # URL-less Kea members of a group whose HA renders: no hook, no scopes.
    sidelined: list[DHCPServer] = field(default_factory=list)

    @property
    def renders_ha(self) -> bool:
        return bool(self.participants)


def kea_ha_members(mode: str | None, servers: Iterable[DHCPServer]) -> KeaHAMembers:
    """Split a group's members into HA participants and sidelined Kea members."""
    if mode not in HA_MODES:
        return KeaHAMembers()
    kea = sorted((s for s in servers if s.driver == "kea"), key=lambda s: str(s.id))
    with_url = [s for s in kea if s.ha_peer_url]
    if len(with_url) < 2:
        return KeaHAMembers()
    return KeaHAMembers(
        participants=with_url,
        sidelined=[s for s in kea if not s.ha_peer_url],
    )


def v6_peer_url(url: str) -> str | None:
    """The DHCPv6 HA listener URL derived from a member's ``ha_peer_url`` (#1258).

    Kea runs one HTTP listener per daemon, so kea-dhcp6's HA hook cannot share
    the port kea-dhcp4's already holds. The v6 listener is the v4 one's port
    plus one, on the same host: nothing new for the operator to configure, and
    every consumer (the config bundle, the appliance firewall, the agent's
    published container ports) derives it from the same URL. A URL with no
    port means the scheme default (80 / 443), as ``ha_firewall.listener_port``
    reads it. None when the URL has no usable port or the next one is out of
    range, in which case the group simply has no v6 HA.
    """
    try:
        parts = urlsplit(url.strip())
        port = parts.port
        host = parts.hostname
    except ValueError:
        return None
    if port is None:
        port = {"http": 80, "https": 443}.get(parts.scheme.lower())
    if port is None or not host or not 1 <= port < 65535:
        return None
    host = f"[{host}]" if ":" in host else host
    return urlunsplit((parts.scheme, f"{host}:{port + 1}", parts.path, parts.query, parts.fragment))


def v6_peer_port(url: str) -> int | None:
    """The port of :func:`v6_peer_url`, or None when the group has no v6 HA."""
    derived = v6_peer_url(url)
    return urlsplit(derived).port if derived else None


def supports_ha_v6(capabilities: object) -> bool:
    return isinstance(capabilities, list) and HA_V6_CAPABILITY in capabilities
