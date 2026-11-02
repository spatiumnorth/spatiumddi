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

from app.models.dhcp import HA_MODES, DHCPServer


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
