"""What this agent tells the control plane it renders (#1171).

Every request carries ``X-Spatium-Agent-Features``, a comma list. A header
rather than a body field: the control plane's heartbeat body is strict
(``extra="forbid"``), so a new field would 422 every heartbeat this agent sends
to a control plane older than itself, and a cluster's DNS pods can roll before
its control plane does. An older control plane ignores the header.

``soa-timers`` — the BIND9 driver writes a zone's ``refresh`` / ``retry`` /
``expire`` / ``minimum`` from the bundle into its SOA (``_soa_timers``). An
agent of an older release writes ``3600 600 86400 300`` for every zone, so a
group's bundles carry the zone's own timers only once every BIND9 agent in it
says this; until then they carry that literal, and the control plane moves
the zones' serials when it switches. PowerDNS and Technitium keep their own
SOA, and the control plane counts only BIND9 servers.
"""

from __future__ import annotations

FEATURES_HEADER = "X-Spatium-Agent-Features"
FEATURES: tuple[str, ...] = ("soa-timers",)


def headers() -> dict[str, str]:
    """The header every client of this agent sends."""
    return {FEATURES_HEADER: ",".join(FEATURES)}
