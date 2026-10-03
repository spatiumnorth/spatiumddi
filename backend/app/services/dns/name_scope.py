"""Classify a DNS zone name by its TLD (#986).

``validate_fqdn`` tells us a zone name is *syntactically* a domain and
stops there, so ``corp.example.com``, ``ad.contoso.local``, ``lab`` and
``acme.lan`` all render identically in the zone table — while the first is
a name the public internet resolves, the second collides with mDNS, and
the last two sit on TLDs nobody has delegated. This module answers which.

Four scopes, evaluated **in this order** because each earlier rule would
otherwise be swallowed by a later one:

``reverse``
    Anything under ``in-addr.arpa`` / ``ip6.arpa``. Checked first because
    ``.arpa`` is a real delegated TLD, so these would otherwise read as
    ``public`` — and they are always ours (#41 auto-creates them), so
    they must not read as "reserved" either.

``reserved``
    A suffix match against the hand-curated special-use table:
    ``.local`` (RFC 6762), ``.localhost`` / ``.test`` / ``.example`` /
    ``.invalid`` (RFC 6761), ``.onion`` (7686), ``.alt`` (9476),
    ``home.arpa`` (8375), ``example.com`` / ``.net`` / ``.org`` (2606),
    ``.internal`` (ICANN 2024), and ``.corp`` / ``.home`` / ``.mail``
    (withheld from delegation indefinitely by ICANN's name-collision
    work). Checked
    before ``public`` because ``example.com`` sits under a public TLD
    and is still reserved, and ``home.arpa`` under a public one too.

``public``
    Last label is in IANA's root-zone list.

``undelegated``
    None of the above — ``.lab``, ``.lan``, ``.intranet``, ``.private``,
    and typos. Works today, protected by nothing.

**Nothing here refuses anything.** ``.local`` is a warning because
Microsoft told a generation of admins to build Active Directory on it and
plenty of real installs run it; ``undelegated`` is a hint for the same
reason. Both are a pill and a tooltip, never a 422.

``.lan`` / ``.intranet`` / ``.private`` are deliberately **not** in the
reserved table. SSAC's collision work considered them and did not protect
them, so calling them reserved would tell the operator they are safe when
they are exactly as unprotected as a typo.

Pure functions, no DB and no IO beyond an ``lru_cache``d read of the
bundled data file, so they can be called from serialisation, from the
importer preview, and from tests with no setup.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.services.dns.tld_registry import load_bundled, load_special_use

NameScope = Literal["public", "reserved", "undelegated", "reverse"]
ZoneKind = Literal["forward", "reverse"]

# Suffixes that make a zone a reverse zone. Both are under ``.arpa``.
_REVERSE_SUFFIXES: tuple[tuple[str, ...], ...] = (
    ("in-addr", "arpa"),
    ("ip6", "arpa"),
)


@dataclass(frozen=True)
class ZoneNameScope:
    """The classification of one zone name.

    ``matched_suffix`` is the special-use entry or TLD the decision rests
    on, so the UI tooltip can say *why* rather than just *what*.
    """

    scope: NameScope
    reason: str
    matched_suffix: str | None = None
    rfc: str | None = None
    # ``.local`` only: an authoritative zone by this name collides with
    # mDNS / Bonjour on the same LAN. Drives the amber pill variant.
    mdns_conflict: bool = False


def _labels(name: str) -> tuple[str, ...]:
    """Normalise a zone name to lowercase labels, root dot stripped."""
    return tuple(lbl for lbl in name.strip().rstrip(".").lower().split(".") if lbl)


def _suffix_matches(labels: tuple[str, ...], suffix_labels: tuple[str, ...]) -> bool:
    """Label-wise suffix test.

    Deliberately not a string ``endswith``: ``mylocal`` must not match
    ``.local`` and ``notexample.com`` must not match ``example.com``. The
    suffix also matches the name *itself* — a zone literally called
    ``example.com`` is reserved, not just its children.
    """
    return len(labels) >= len(suffix_labels) and labels[-len(suffix_labels) :] == suffix_labels


def zone_kind_for_name(name: str) -> ZoneKind:
    """The lookup kind of a zone named ``name`` (#1310).

    ``reverse`` for a name under ``in-addr.arpa`` / ``ip6.arpa`` (the names
    :func:`classify_zone_name` scopes ``reverse``, by the same label-wise
    test) and ``forward`` for every other name. A zone's ``kind`` is what
    IPAM keys on: it publishes PTR records only into kind ``reverse`` zones.
    """
    labels = _labels(name)
    if any(_suffix_matches(labels, suffix) for suffix in _REVERSE_SUFFIXES):
        return "reverse"
    return "forward"


def classify_zone_name(name: str, *, tlds: frozenset[str] | None = None) -> ZoneNameScope:
    """Classify ``name``. ``tlds`` defaults to the bundled root-zone list.

    Callers that have already resolved the effective registry (bundled vs.
    operator snapshot) pass its ``tlds`` in; everything else gets the
    bundled list, which is always present.
    """
    labels = _labels(name)

    # The root zone. Unusual as a served zone but legal, and it is the
    # top of the public namespace rather than an unprotected private one.
    if not labels:
        return ZoneNameScope(
            scope="public",
            reason="The DNS root zone.",
            matched_suffix=".",
        )

    for suffix in _REVERSE_SUFFIXES:
        if _suffix_matches(labels, suffix):
            joined = ".".join(suffix)
            return ZoneNameScope(
                scope="reverse",
                reason=f"Reverse-lookup zone under {joined}.",
                matched_suffix=joined,
            )

    # Longest special-use suffix wins, so ``home.arpa`` beats nothing and
    # a future two-label entry cannot be shadowed by a one-label one.
    best: tuple[int, dict[str, object]] | None = None
    for entry in load_special_use():
        suffix_labels = _labels(str(entry["suffix"]))
        if not suffix_labels or not _suffix_matches(labels, suffix_labels):
            continue
        if best is None or len(suffix_labels) > best[0]:
            best = (len(suffix_labels), entry)
    if best is not None:
        entry = best[1]
        return ZoneNameScope(
            scope="reserved",
            reason=str(entry.get("reason", "")),
            matched_suffix=str(entry["suffix"]),
            rfc=str(entry["rfc"]) if entry.get("rfc") else None,
            mdns_conflict=bool(entry.get("mdns_conflict", False)),
        )

    effective = tlds if tlds is not None else load_bundled().tlds
    tld = labels[-1]
    if tld in effective:
        return ZoneNameScope(
            scope="public",
            reason=f".{tld} is a delegated top-level domain in the IANA root zone.",
            matched_suffix=tld,
        )

    return ZoneNameScope(
        scope="undelegated",
        reason=(
            f".{tld} is not a delegated top-level domain. This resolves inside your "
            "network today, but nothing protects the name — ICANN could delegate it, "
            "and queries that escape your resolvers leak to the root. .internal is the "
            "name reserved for this."
        ),
        matched_suffix=None,
    )
