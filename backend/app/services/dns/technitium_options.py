"""Group options the agent-managed Technitium driver cannot apply (#1763).

The Options tab and ``PUT /dns/groups/{id}/options`` are driver-agnostic, but
the Technitium agent honours only a subset. Each option below has no setting
Technitium exposes (verified against APIDOCS.md, "Set DNS Settings" and "Set
Zone Options", TechnitiumSoftware/DnsServer v15.4.0), so a non-default value
would be stored, shipped in the bundle and ignored: the UI would say one thing
and the daemon do another. The API refuses to *change* one to a non-default
value for a group with a Technitium server; re-saving what is already stored
stays allowed, since the form posts every field on every save.

What the agent *does* apply is not listed here: ``dnssec_validation`` (the
server-wide ``dnssecValidation`` setting) and ``allow_query`` (per-zone
``queryAccess``), the latter only for the grammar ``allow_query_problem``
accepts.
"""

from __future__ import annotations

import ipaddress
from typing import Any

#: field -> (default, why Technitium cannot honour another value)
#:
#: The forwarding options (``forward_policy``, ``forward_tls_verify``) are
#: deliberately absent: what Technitium does with forwarders, and which of
#: those values is the honest default for it, is #1764's to settle.
UNSUPPORTED_OPTIONS: dict[str, tuple[Any, str]] = {
    "minimal_responses": (False, "Technitium has no minimal-responses setting"),
    "tcp_clients": (None, "Technitium has no TCP client limit setting"),
    "clients_per_query": (None, "Technitium has no clients-per-query setting"),
    "max_clients_per_query": (None, "Technitium has no clients-per-query setting"),
}


def allow_query_problem(elements: list[str] | None) -> str | None:
    """Why a group ``allow_query`` list cannot be expressed as a Technitium
    zone query ACL, or ``None`` if it can.

    Mirrors the agent's ``_query_access``: addresses, CIDRs, ``any``/``none``
    and ``!``-negations of them. ``localhost``, ``localnets``, ``key X`` and
    named ACLs have no Technitium counterpart.
    """
    for element in elements or []:
        body = str(element).strip()
        if body.startswith("!"):
            body = body[1:].strip()
        if body.lower() in ("any", "none"):
            continue
        try:
            ipaddress.ip_network(body, strict=False)
        except ValueError:
            return (
                f"allow_query element {element!r} cannot be applied by Technitium, which "
                "takes addresses and CIDR prefixes only (optionally '!'-negated, or 'any' / "
                "'none'); 'localhost', 'localnets', 'key …' and ACL names have no equivalent"
            )
    return None


def refusals(changes: dict[str, Any], stored: Any) -> list[str]:
    """Messages for every changed option Technitium would silently ignore."""
    out: list[str] = []
    for field, (default, why) in UNSUPPORTED_OPTIONS.items():
        if field not in changes:
            continue
        value = changes[field]
        if value == default or value == getattr(stored, field, None):
            continue
        out.append(f"{field}: {why}")
    if "allow_query" in changes and changes["allow_query"] != getattr(stored, "allow_query", None):
        problem = allow_query_problem(changes["allow_query"])
        if problem:
            out.append(problem)
    return out


def stored_warnings(stored: Any) -> list[str]:
    """What a group's STORED options say that a Technitium server in it will
    not do (#1763).

    The PUT gate only sees a change. A row saved before it, or a Technitium
    server joining a group that already holds such a value (agent
    registration, a server move or a Fleet role assignment, none of which
    can usefully refuse), never passes through it, so the options response
    carries these instead and the Options tab shows them.
    """
    if stored is None:
        return []
    out = [
        f"{field}: {why}"
        for field, (default, why) in UNSUPPORTED_OPTIONS.items()
        if getattr(stored, field, default) != default
    ]
    problem = allow_query_problem(getattr(stored, "allow_query", None))
    if problem:
        out.append(problem + "; query access is left as each zone has it")
    return out
