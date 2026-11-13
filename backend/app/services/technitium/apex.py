"""A Technitium primary zone's apex: the NS set and SOA a zone row asks for (#1774).

The agentless ``technitium_api`` driver's counterpart of the agent's
``_zone_apex`` (``agent/dns/spatium_dns_agent/drivers/technitium.py``), which
the agent cannot share because it ships as its own package. The two are kept
in step by ``tests/test_technitium_apex_parity_1774.py``.

Technitium writes its own apex when it creates a zone: one NS and an SOA MNAME
naming the server's host name, a placeholder RNAME, and a serial that starts at
1. Left alone, the zone's Primary NS / Admin Email / SOA timers / TTL never
reach the wire (#1490 for the agent, #1774 here) and every server in a group
serves a different serial (#1779).
"""

from __future__ import annotations

from typing import Any

from app.services.technitium.rdata import qualified_name

# SOA fields the zone row owns, besides MNAME / RNAME.
SOA_TIMERS = ("refresh", "retry", "expire", "minimum")


def host_name(value: Any) -> str | None:
    """``value`` as the bare, lower-case host name Technitium reads back, or
    None when it cannot be one.

    ``primary_ns`` is stored with or without the trailing dot (the zone form
    keeps it, the importers strip it) and both mean an absolute name, the
    reading the BIND9 renderer gives it too (#1153). Technitium returns
    names un-dotted and lower-case, so comparing in that form is what keeps
    a converged apex from looking changed.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".").lower()
    if not name or name == "@" or not name.isascii() or ".." in name:
        return None
    if any(c.isspace() for c in name):
        return None
    return name


def responsible_person(value: Any) -> str | None:
    """A zone's ``admin_email`` in the ``user@domain`` form Technitium stores.

    The zone row keeps the RNAME in SOA form (``hostmaster.example.com.``,
    the first unescaped dot standing for the ``@``). Technitium converts that
    itself on write, but reads it back as an address, so the comparison has
    to happen in that form. An address that already has an ``@`` is kept.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".")
    if not name or not name.isascii() or any(c.isspace() for c in name):
        return None
    if "@" in name:
        return name.lower()
    i = 0
    while True:
        i = name.find(".", i)
        if i <= 0:
            return None
        if name[i - 1] != "\\":
            break
        i += 1
    local, domain = name[:i].replace("\\.", "."), name[i + 1 :]
    return f"{local}@{domain}".lower() if domain else None


def zone_apex(zone_name: str, zone: dict[str, Any]) -> dict[str, Any] | None:
    """The apex a primary zone should serve: its NS set and SOA fields.

    Technitium writes its own apex when it creates a zone: one NS and an
    SOA MNAME naming the server's host name, which in a pod is the pod
    name, plus a placeholder RNAME. Left alone, every server in a group
    answers with a different, unresolvable name server, and the zone's own
    Primary NS / Admin Email / SOA timers never reach the wire.

    Same precedence as the BIND9 renderer (#1153): the zone's own apex NS
    records are the NS set, else its ``primary_ns``. MNAME is ``primary_ns``,
    else the first declared NS. A field the zone does not set is left out,
    so the daemon's value stands; a zone that sets neither apex NS, Primary
    NS nor Admin Email returns None and its apex is not touched at all. The
    bundle ships every zone's SOA timers since #1171, defaults included, so
    they cannot mean the zone set anything: they ride along only with an
    apex the zone does set.
    """
    zname = zone_name.rstrip(".").lower()
    declared: list[str] = []
    declared_ttls: list[int] = []
    zone_ttl = zone.get("ttl")
    for rec in zone.get("records") or []:
        if (rec.get("type") or "").upper() != "NS":
            continue
        if qualified_name(zname, rec.get("name") or "@").lower() != zname:
            continue
        value = str(rec.get("value") or "").strip()
        # Read the target as a zone file would: ``@`` is the apex, a name
        # without the trailing dot is relative to the zone.
        if value in ("", "@"):
            host: str | None = zname
        elif value.endswith("."):
            host = host_name(value)
        else:
            host = host_name(f"{value}.{zname}")
        if host and host not in declared:
            declared.append(host)
        if host:
            rec_ttl = rec.get("ttl") if rec.get("ttl") is not None else zone_ttl
            if isinstance(rec_ttl, int) and not isinstance(rec_ttl, bool) and rec_ttl >= 0:
                declared_ttls.append(rec_ttl)

    primary = host_name(zone.get("primary_ns"))
    ns = declared or ([primary] if primary else [])

    soa: dict[str, Any] = {}
    mname = primary or (declared[0] if declared else None)
    if mname:
        soa["primaryNameServer"] = mname
    rname = responsible_person(zone.get("admin_email"))
    if rname:
        soa["responsiblePerson"] = rname
    if not ns and not soa:
        return None
    for field in SOA_TIMERS:
        timer = zone.get(field)
        if isinstance(timer, int) and not isinstance(timer, bool) and timer >= 0:
            soa[field] = timer
    ttl = zone.get("ttl")
    apex: dict[str, Any] = {"ns": ns, "soa": soa}
    if declared and declared_ttls:
        # One TTL for the whole set (Technitium keeps one per RRset), the
        # minimum, as the op path writes it (#1768).
        apex["ns_ttl"] = min(declared_ttls)
    if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl > 0:
        # The SOA record's own TTL caps negative caching together with
        # MINIMUM (RFC 2308), and BIND serves it at the zone's $TTL.
        apex["ttl"] = ttl
    return apex
