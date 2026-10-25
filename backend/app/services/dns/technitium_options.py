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
server-wide ``dnssecValidation`` setting), ``allow_query`` (per-zone
``queryAccess``) and ``allow_transfer`` (per-zone ``zoneTransfer``), the last
two only for the grammar ``translate_address_match`` accepts (#1765).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

#: field -> (default, why Technitium cannot honour another value)
#:
#: ``forward_policy`` is not in this table: its default (``first``) is the
#: value Technitium cannot honour, so it has its own rule (``refusals``).
UNSUPPORTED_OPTIONS: dict[str, tuple[Any, str]] = {
    "minimal_responses": (False, "Technitium has no minimal-responses setting"),
    "tcp_clients": (None, "Technitium has no TCP client limit setting"),
    "clients_per_query": (None, "Technitium has no clients-per-query setting"),
    "max_clients_per_query": (None, "Technitium has no clients-per-query setting"),
    "allow_query_cache": (
        ["localhost", "localnets"],
        "Technitium has no separate cache-access ACL (allow_recursion is the "
        "recursion ACL it honours)",
    ),
    # #2267: Technitium has no separate allow-notify. A Secondary zone accepts
    # NOTIFY from its configured primary name servers only (and a Primary has
    # no incoming-NOTIFY handling at all), so a list of other senders is
    # stored, shipped and never consulted.
    "allow_notify": (
        [],
        "Technitium has no allow-notify setting (a secondary zone accepts NOTIFY "
        "only from its own primary name servers)",
    ),
    # #2263: BIND's ``blackhole`` drops a client's queries unanswered. Technitium
    # has no server setting that refuses a client by address (its access
    # controls are per zone, and answer REFUSED rather than nothing).
    "blackhole": ([], "Technitium has no setting to drop queries from a client address"),
    "forward_tls_verify": (
        True,
        "Technitium always validates an encrypted upstream's certificate and has no "
        "setting to skip it, so opportunistic DoT (verification off) cannot be honoured",
    ),
}

#: Why ``forward_policy = first`` is not true on Technitium (#1764). With
#: forwarders set the daemon resolves through them and never falls back to
#: recursing from the root when they fail (it answers SERVFAIL), which is
#: BIND's ``forward only``. ``only`` is therefore the one honest value.
FORWARD_FIRST_WHY = (
    "forward_policy 'first' is not what Technitium does: with forwarders set it resolves "
    "only through them and never falls back to recursion (BIND's 'only')"
)


# ── BIND address-match translation (#1765)
#
# SpatiumDDI stores ``allow_query`` / ``allow_transfer`` as BIND address-match
# lists. Technitium has no such grammar: a network ACL is an ordered list of
# addresses / CIDRs where a leading ``!`` denies and the first match wins
# (APIDOCS "Set Zone Options", ``NetworkAccessControl.cs``), no match denies,
# and transfer TSIG keys are a SEPARATE set that is ANDed with the ACL
# (``DnsServer.cs``: ``IsZoneTransferAllowed`` then ``IsTsigAuthenticated``).
# This block translates what can be translated exactly and raises
# ``AddressMatchError`` for everything else, because a guess either widens
# access or locks the zone out. It is shared, byte for byte, with the agent
# (``test_technitium_acl_parity.py``).
_OPEN_ACL: list[str] = ["0.0.0.0/0", "::/0"]
_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_KEY_ELEMENT = re.compile(r'^key\s+"?([A-Za-z0-9][A-Za-z0-9_.-]*)"?$', re.IGNORECASE)


class AddressMatchError(ValueError):
    """The list holds an element Technitium cannot express exactly."""


def _flatten_address_match(
    elements: list[Any], acls: dict[str, list[tuple[str, bool]]], trail: tuple[str, ...]
) -> list[tuple[bool, str, str]]:
    """Ordered ``(negated, kind, value)`` items, named ACLs expanded inline.

    ``kind`` is ``net`` / ``any`` / ``key`` (``none`` arrives as a negated
    ``any``, which is what BIND compiles it to). BIND flattens a nested
    ACL into the list that cites it, so first-match order is preserved.
    """
    items: list[tuple[bool, str, str]] = []
    for raw in elements:
        text = str(raw).strip()
        if not text:
            continue
        neg = text.startswith("!")
        body = text[1:].strip() if neg else text
        low = body.lower()
        if low == "any":
            items.append((neg, "any", ""))
            continue
        if low == "none":
            # BIND compiles ``none`` as ``!any`` (aclconf.c: "none == !any"):
            # a match that DENIES everyone, ending the list there. So
            # ``["none", "10.0.0.0/8"]`` admits nobody, and ``!none`` admits
            # everyone. Dropping it instead would let the later elements grant.
            items.append((not neg, "any", ""))
            continue
        if low == "localhost":
            if neg:
                raise AddressMatchError(
                    "'!localhost' cannot be applied: Technitium has no equivalent of the "
                    "server's own addresses, so the exclusion would be lost"
                )
            items.append((False, "net", "127.0.0.1/32"))
            items.append((False, "net", "::1/128"))
            continue
        if low == "localnets":
            raise AddressMatchError(
                "'localnets' cannot be applied: Technitium has no equivalent of the "
                "server's directly attached networks"
            )
        key = _KEY_ELEMENT.match(body)
        if key:
            if neg:
                raise AddressMatchError(f"'!{body}' cannot be applied: a key cannot be negated")
            items.append((False, "key", key.group(1)))
            continue
        try:
            net = ipaddress.ip_network(body, strict=False)
        except ValueError:
            pass
        else:
            if net.version == 6 and net.subnet_of(_V4_MAPPED):  # type: ignore[arg-type]
                raise AddressMatchError(
                    f"{body!r} cannot be applied: Technitium matches an IPv4-mapped client "
                    "as IPv4, so an IPv4-mapped prefix would never match; write the IPv4 "
                    "prefix instead"
                )
            items.append((neg, "net", str(net)))
            continue
        if body not in acls:
            raise AddressMatchError(
                f"{body!r} is not an address, a CIDR prefix, 'key <name>' or an ACL defined in "
                "this group"
            )
        if body in trail:
            raise AddressMatchError(f"ACL {body!r} refers to itself")
        inner = _flatten_address_match(
            [
                ("!" if n or v.startswith("!") else "") + v.lstrip("!").strip()
                for v, n in acls[body]
            ],
            acls,
            (*trail, body),
        )
        if neg:
            if any(i[0] or i[1] == "key" for i in inner):
                raise AddressMatchError(
                    f"'!{body}' cannot be applied: the ACL holds a negation or a key, and "
                    "inverting it is not a prefix list"
                )
            inner = [(True, k, v) for _, k, v in inner]
        items.extend(inner)
    return items


def translate_address_match(
    elements: Any,
    acls: dict[str, list[tuple[str, bool]]] | None = None,
    *,
    allow_keys: bool = False,
) -> tuple[list[str], list[str]]:
    """BIND address-match list -> ``(technitium_acl, key_names)``.

    ``acl`` is an ordered list for ``*NetworkACL`` (``!`` kept, ``any`` as both
    default routes, ``none`` as their negation); ``key_names`` are the ``key X`` elements.
    With keys present the result is the negations followed by the open ACL, to
    be ANDed with the key set: that is exact only while every address element
    is a negation placed before the first key. A positive address beside a key
    is an OR in BIND and an AND here, so it is refused rather than narrowed.
    """
    items = _flatten_address_match(list(elements or []), acls or {}, ())
    # A deny-everyone match (``none`` / ``!any``) ends evaluation in BIND and in
    # Technitium alike, so nothing after it is reachable: drop the tail rather
    # than refuse an element that can never take effect.
    deny_all = next((i for i, it in enumerate(items) if it[0] and it[1] == "any"), None)
    if deny_all is not None:
        items = items[: deny_all + 1]
    first_key = next((i for i, it in enumerate(items) if it[1] == "key"), None)
    if first_key is not None and deny_all is not None and deny_all > first_key:
        # ``[key X, none]``: after the keys, a final deny-all only restates
        # "no match denies", which holds in both systems.
        items = items[:deny_all]
    if first_key is not None and not allow_keys:
        raise AddressMatchError("'key <name>' cannot be applied to this list")
    acl: list[str] = []
    keys: list[str] = []
    for index, (neg, kind, value) in enumerate(items):
        if kind == "key":
            if value not in keys:
                keys.append(value)
            continue
        if first_key is not None:
            if not neg:
                raise AddressMatchError(
                    "an address listed next to 'key <name>' is an OR in BIND but Technitium "
                    "requires the address AND the key, so it cannot be applied"
                )
            if index > first_key:
                raise AddressMatchError(
                    "a negation listed after 'key <name>' cannot be applied: BIND lets the key "
                    "through first, Technitium would still apply the exclusion"
                )
        for net in _OPEN_ACL if kind == "any" else [value]:
            acl.append(("!" if neg else "") + net)
    if first_key is not None:
        acl.extend(_OPEN_ACL)
    return acl, keys


# ── end of the block shared with the agent


#: ``name -> [(value, negate)]``, the shape of a group's named ACLs.
AclDefinitions = dict[str, list[tuple[str, bool]]]


def address_match_problem(
    elements: list[str] | None,
    acls: AclDefinitions | None = None,
    *,
    field: str,
    allow_keys: bool,
) -> str | None:
    """Why a BIND address-match list cannot be applied by Technitium, or
    ``None`` if it can (#1765). Same translation the agent runs, so a value
    accepted here is one the daemon will be given exactly."""
    try:
        translate_address_match(elements, acls, allow_keys=allow_keys)
    except AddressMatchError as exc:
        return f"{field}: {exc}"
    return None


def allow_query_problem(
    elements: list[str] | None, acls: AclDefinitions | None = None
) -> str | None:
    """Why a group ``allow_query`` list cannot be expressed as a Technitium
    zone query ACL, or ``None`` if it can (``key X`` has no meaning for a
    query ACL here)."""
    return address_match_problem(elements, acls, field="allow_query", allow_keys=False)


def allow_transfer_problem(
    elements: list[str] | None, acls: AclDefinitions | None = None
) -> str | None:
    """Why an ``allow_transfer`` list (group or zone) cannot be expressed as a
    Technitium transfer ACL + TSIG key set, or ``None`` if it can."""
    return address_match_problem(elements, acls, field="allow_transfer", allow_keys=True)


def also_notify_problem(elements: list[str] | None) -> str | None:
    """Why an ``also_notify`` list (group or zone) cannot be applied by
    Technitium, or ``None`` if it can (#2267). Its notify list takes bare IP
    addresses, so a port, a key or a hostname has no equivalent."""
    bad = []
    for entry in elements or []:
        text = str(entry).strip()
        if not text:
            continue
        try:
            ipaddress.ip_address(text)
        except ValueError:
            bad.append(text)
    if not bad:
        return None
    return (
        "also_notify: Technitium notifies bare IP addresses only (no port, key or "
        "hostname); not expressible: " + ", ".join(bad)
    )


def refusals(changes: dict[str, Any], stored: Any, acls: AclDefinitions | None = None) -> list[str]:
    """Messages for every changed option Technitium would silently ignore."""
    out: list[str] = []
    for field, (default, why) in UNSUPPORTED_OPTIONS.items():
        if field not in changes:
            continue
        value = changes[field]
        if value == default or value == getattr(stored, field, None):
            continue
        out.append(f"{field}: {why}")
    # Changing TO 'first' is refused; 'first' re-posted over a stored 'first'
    # (the column default, which the form sends on every save) is tolerated.
    if (
        changes.get("forward_policy") == "first"
        and getattr(stored, "forward_policy", "first") != "first"
    ):
        out.append(FORWARD_FIRST_WHY)
    if "also_notify" in changes and changes["also_notify"] != getattr(stored, "also_notify", None):
        problem = also_notify_problem(changes["also_notify"])
        if problem:
            out.append(problem)
    if "allow_query" in changes and changes["allow_query"] != getattr(stored, "allow_query", None):
        problem = allow_query_problem(changes["allow_query"], acls)
        if problem:
            out.append(problem)
    if "allow_transfer" in changes and changes["allow_transfer"] != getattr(
        stored, "allow_transfer", None
    ):
        problem = allow_transfer_problem(changes["allow_transfer"], acls)
        if problem:
            out.append(problem)
    return out


def stored_warnings(stored: Any, acls: AclDefinitions | None = None) -> list[str]:
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
    if getattr(stored, "forward_policy", "first") == "first" and getattr(
        stored, "forwarders", None
    ):
        out.append(FORWARD_FIRST_WHY + "; set it to 'only' to match")
    transport = getattr(stored, "forward_transport", "do53") or "do53"
    if transport != "do53" and not getattr(stored, "forward_tls_hostname", None):
        out.append(
            f"forward_transport {transport!r} without forward_tls_hostname: Technitium "
            "always validates the upstream certificate against a name, so these "
            "forwarders are not applied; set forward_tls_hostname"
        )
    problem = also_notify_problem(getattr(stored, "also_notify", None))
    if problem:
        out.append(problem + "; those entries are not notified")
    problem = allow_query_problem(getattr(stored, "allow_query", None), acls)
    if problem:
        out.append(problem + "; query access is left as each zone has it")
    problem = allow_transfer_problem(getattr(stored, "allow_transfer", None), acls)
    if problem:
        out.append(problem + "; zone transfer is left as each zone has it")
    return out
