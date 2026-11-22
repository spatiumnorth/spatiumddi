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

``served-serials`` — the BIND9 driver reports, for a secondary / stub zone, the
serial named serves (and nothing for a zone it holds no copy of) instead of the
bundle's serial 0 (#3940). The control plane then counts a BIND9 secondary
serving 0 as not synced, whatever the agent's release (an older agent's start-up
report already carries real served serials, and its 0 means "not reported").

``packed-blocklists`` (#4040) — the agent reads a blocklist's ``entries`` as
packed runs (``blocklist_entries``) as well as one object per entry. The
control plane sends the packed shape only to a server whose agent said so, and
the per-entry shape to every other.

``per-view-ops`` (#2242, BIND9 only) — the agent applies a record op into the
view the op names, signed with that view's update key. The control plane then
stops re-rendering a group with views on every record change and ships this
server its ops instead; for an agent that does not say so, it keeps the
re-render. Only the BIND9 driver can (the others have no view-scoped update),
so ``headers`` adds it for that driver alone.
"""

from __future__ import annotations

FEATURES_HEADER = "X-Spatium-Agent-Features"
FEATURES: tuple[str, ...] = ("soa-timers", "served-serials", "packed-blocklists")
#: What only the BIND9 driver says, after ``FEATURES``.
BIND9_FEATURES: tuple[str, ...] = ("per-view-ops",)


def headers(driver: str | None = None) -> dict[str, str]:
    """The header every client of this agent sends. ``driver`` is the agent's
    (``AgentConfig.driver``): a driver-specific feature is named only for it."""
    names = FEATURES + (BIND9_FEATURES if driver == "bind9" else ())
    return {FEATURES_HEADER: ",".join(names)}
